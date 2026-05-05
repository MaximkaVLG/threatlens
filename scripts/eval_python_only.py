"""Day 9 — evaluate the Python-only model on the real-world test sets.

Goal: see if removing Java-extracted CIC-2017/2018 from training closes
the real-world recall gap. Day 6 baseline (combined_v2 model) recall on
real_pcap ATTACK class was ~10%. User target: 80-92% (280-320 of ~347
attack flows detected).

Test sets (both Python-extracted, so no train/test feature drift):
  1. real_pcap/  -- 9 Stratosphere/Wireshark captures, NEVER seen in any
                    training run. Pulled from results/real_world_flows_cache.parquet
                    (cached by Day 8's eval_selective_sweep.py).
  2. CTU 30% hold-out -- saved by train_python_only.py as
                          results/python_only/ctu_test_holdout.parquet.

Compares python_only vs combined_v2 side-by-side. Critical metric:
ATTACK recall on real_pcap. If python_only >> combined_v2 there,
the drift hypothesis is confirmed and we ship.

Usage:
    python scripts/eval_python_only.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Dict, List

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score,
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import CIC_FEATURE_COLUMNS  # noqa: E402
from threatlens.network.spectral_features import SPECTRAL_FEATURE_COLUMNS  # noqa: E402
from threatlens.network.payload_yara import YARA_FEATURE_COLUMNS  # noqa: E402
from threatlens.ml.selective import MahalanobisAbstainer  # noqa: E402

ALL_FEATURES = (list(CIC_FEATURE_COLUMNS) + list(SPECTRAL_FEATURE_COLUMNS)
                + list(YARA_FEATURE_COLUMNS))

OLD_DIR = ROOT / "results" / "combined_v2"
NEW_DIR = ROOT / "results" / "python_only"   # default candidate dir; --new-dir overrides
CACHE_PARQUET = ROOT / "results" / "real_world_flows_cache.parquet"


def to_binary(label: str) -> str:
    return "BENIGN" if label == "BENIGN" else "ATTACK"


def predict_with_pipeline(model, pipeline, df: pd.DataFrame) -> np.ndarray:
    """Align columns + scale + predict + decode labels."""
    expected = pipeline.feature_names
    df = df.copy()
    for c in expected:
        if c not in df.columns:
            df[c] = 0.0
    X = df[expected].apply(lambda s: pd.to_numeric(s, errors="coerce")) \
                    .replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X_scaled = pipeline.scaler.transform(X.values.astype(np.float64))
    y_int = model.predict(X_scaled)
    return pipeline.label_encoder.inverse_transform(y_int)


def predict_proba_max(model, pipeline, df: pd.DataFrame) -> np.ndarray:
    expected = pipeline.feature_names
    df = df.copy()
    for c in expected:
        if c not in df.columns:
            df[c] = 0.0
    X = df[expected].apply(lambda s: pd.to_numeric(s, errors="coerce")) \
                    .replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X_scaled = pipeline.scaler.transform(X.values.astype(np.float64))
    proba = model.predict_proba(X_scaled)
    return proba.max(axis=1)


def per_capture_breakdown(df: pd.DataFrame, preds: np.ndarray,
                          true_bin: np.ndarray) -> List[Dict]:
    """For each __source PCAP, count predictions vs ground truth."""
    out = []
    pred_bin = np.array([to_binary(l) for l in preds])
    for src, idx in df.groupby("__source").groups.items():
        idx = list(idx)
        n = len(idx)
        n_attack_true = int((true_bin[idx] == "ATTACK").sum())
        n_attack_pred = int((pred_bin[idx] == "ATTACK").sum())
        # Per-capture detected = attack-flows where we predicted ATTACK
        attack_mask = (true_bin[idx] == "ATTACK")
        if attack_mask.any():
            detected = int((pred_bin[idx][attack_mask] == "ATTACK").sum())
            recall = detected / attack_mask.sum()
        else:
            detected = 0
            recall = float("nan")
        # What classes did the model predict?
        from collections import Counter
        cnt = Counter(preds[idx])
        out.append({
            "source": src,
            "n_flows": n,
            "n_attack_true": n_attack_true,
            "n_attack_pred": n_attack_pred,
            "n_attack_detected": detected,
            "attack_recall": recall,
            "label_distribution": dict(cnt.most_common(8)),
        })
    return out


def predict_with_abstainer(model, pipeline, abstainer, df):
    """Same as predict_with_pipeline but also returns an abstain mask."""
    expected = pipeline.feature_names
    df = df.copy()
    for c in expected:
        if c not in df.columns:
            df[c] = 0.0
    X = df[expected].apply(lambda s: pd.to_numeric(s, errors="coerce")) \
                    .replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X_scaled = pipeline.scaler.transform(X.values.astype(np.float64))
    y_int = model.predict(X_scaled)
    abstain_mask, _ = abstainer.should_abstain(X_scaled, y_int)
    raw_labels = pipeline.label_encoder.inverse_transform(y_int)
    return raw_labels, abstain_mask


def evaluate(name: str, df: pd.DataFrame, true_bin: np.ndarray,
             model, pipeline, abstainer=None) -> Dict:
    preds = predict_with_pipeline(model, pipeline, df)
    confidences = predict_proba_max(model, pipeline, df)
    pred_bin = np.array([to_binary(l) for l in preds])

    n = len(true_bin)
    tp = int(((pred_bin == "ATTACK") & (true_bin == "ATTACK")).sum())
    fp = int(((pred_bin == "ATTACK") & (true_bin == "BENIGN")).sum())
    tn = int(((pred_bin == "BENIGN") & (true_bin == "BENIGN")).sum())
    fn = int(((pred_bin == "BENIGN") & (true_bin == "ATTACK")).sum())

    result = {
        "name": name,
        "n_flows": n,
        "n_attack_true": int((true_bin == "ATTACK").sum()),
        "n_benign_true": int((true_bin == "BENIGN").sum()),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": float(accuracy_score(true_bin, pred_bin)),
        "f1_attack": float(f1_score(true_bin, pred_bin, pos_label="ATTACK",
                                    average="binary", zero_division=0)),
        "precision_attack": float(precision_score(true_bin, pred_bin,
                                                  pos_label="ATTACK",
                                                  zero_division=0)),
        "recall_attack": float(recall_score(true_bin, pred_bin,
                                            pos_label="ATTACK",
                                            zero_division=0)),
        "confusion_matrix": confusion_matrix(true_bin, pred_bin,
                                             labels=["BENIGN", "ATTACK"]).tolist(),
        "mean_confidence_overall": float(confidences.mean()),
        "mean_confidence_correct": float(confidences[pred_bin == true_bin].mean()
                                          if (pred_bin == true_bin).any() else 0.0),
        "mean_confidence_wrong": float(confidences[pred_bin != true_bin].mean()
                                        if (pred_bin != true_bin).any() else 0.0),
        "per_capture": per_capture_breakdown(df, preds, true_bin),
    }

    # Optional: apply Mahalanobis abstainer and report selective metrics
    if abstainer is not None:
        _, abstain_mask = predict_with_abstainer(model, pipeline, abstainer, df)
        accepted = ~abstain_mask
        # Treat abstained predictions as 'no alert' (silent — would surface
        # to analyst as UNKNOWN, not auto-classified as either class)
        sel_pred = np.where(abstain_mask, "BENIGN", pred_bin)
        sel_tp = int(((sel_pred == "ATTACK") & (true_bin == "ATTACK") & accepted).sum())
        sel_fp = int(((sel_pred == "ATTACK") & (true_bin == "BENIGN") & accepted).sum())
        sel_tn = int(((sel_pred == "BENIGN") & (true_bin == "BENIGN") & accepted).sum())
        sel_fn = int(((sel_pred == "BENIGN") & (true_bin == "ATTACK") & accepted).sum())
        result["selective"] = {
            "n_abstain": int(abstain_mask.sum()),
            "abstain_rate": float(abstain_mask.mean()),
            "abstain_rate_attack": float(abstain_mask[true_bin == "ATTACK"].mean()
                                          if (true_bin == "ATTACK").any() else 0.0),
            "abstain_rate_benign": float(abstain_mask[true_bin == "BENIGN"].mean()
                                          if (true_bin == "BENIGN").any() else 0.0),
            "accepted_tp": sel_tp, "accepted_fp": sel_fp,
            "accepted_tn": sel_tn, "accepted_fn": sel_fn,
            "accepted_recall_attack": float(sel_tp / (sel_tp + sel_fn))
                                       if (sel_tp + sel_fn) > 0 else 0.0,
            "accepted_precision_attack": float(sel_tp / (sel_tp + sel_fp))
                                          if (sel_tp + sel_fp) > 0 else 0.0,
            "accepted_specificity": float(sel_tn / (sel_tn + sel_fp))
                                      if (sel_tn + sel_fp) > 0 else 0.0,
            "all_flows_recall_attack": float(sel_tp / int((true_bin == "ATTACK").sum()))
                                         if (true_bin == "ATTACK").any() else 0.0,
        }
    return result


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--new-dir", type=Path, default=NEW_DIR,
                         help="Directory with the candidate model "
                              "(xgboost.joblib + feature_pipeline.joblib + "
                              "ctu_test_holdout.parquet + optional "
                              "mahalanobis_abstainer.joblib). Default "
                              "results/python_only/. Use results/v2/ for the "
                              "Phase 1 v2 retrain.")
    parser.add_argument("--out-json", type=Path, default=None,
                         help="Override the output JSON path. Default: "
                              "<new-dir>/real_world_eval.json.")
    args = parser.parse_args()

    new_dir = args.new_dir
    abstainer_path = new_dir / "mahalanobis_abstainer.joblib"
    ctu_holdout = new_dir / "ctu_test_holdout.parquet"
    out_json = args.out_json or (new_dir / "real_world_eval.json")

    t0 = time.time()
    print(f"[1/5] Loading models  (candidate dir: {new_dir.name})")
    old_model = joblib.load(OLD_DIR / "xgboost.joblib")
    old_pipe = joblib.load(OLD_DIR / "feature_pipeline.joblib")
    new_model = joblib.load(new_dir / "xgboost.joblib")
    new_pipe = joblib.load(new_dir / "feature_pipeline.joblib")
    abstainer = None
    if abstainer_path.exists():
        abstainer = joblib.load(abstainer_path)
        print(f"  abstainer:        loaded ({abstainer_path.name})")
    else:
        print(f"  abstainer:        not found at {abstainer_path} "
              "(skip selective eval)")
    print(f"  combined_v2 (old): {len(old_pipe.feature_names)} features, "
          f"{len(old_pipe.label_encoder.classes_)} classes, "
          f"{list(old_pipe.label_encoder.classes_)}")
    print(f"  python_only (new): {len(new_pipe.feature_names)} features, "
          f"{len(new_pipe.label_encoder.classes_)} classes, "
          f"{list(new_pipe.label_encoder.classes_)}")

    # ---- 2. Pull real_pcap flows from cache ----
    print("\n[2/5] Loading cached real-world flows")
    if not CACHE_PARQUET.exists():
        print(f"ERROR: cache not found at {CACHE_PARQUET}")
        print("Run scripts/eval_selective_sweep.py first to populate cache.")
        return 1
    cache = pd.read_parquet(CACHE_PARQUET)
    real_pcap_df = cache[~cache["__source"].str.startswith("botnet-")].copy()
    real_pcap_df.reset_index(drop=True, inplace=True)
    real_true = real_pcap_df["__label_binary"].values
    print(f"  real_pcap flows: {len(real_pcap_df)} (ATTACK={(real_true=='ATTACK').sum()}, "
          f"BENIGN={(real_true=='BENIGN').sum()})")
    print(f"  captures: {sorted(real_pcap_df['__source'].unique())}")

    # ---- 3. CTU 30% hold-out ----
    print("\n[3/5] Loading CTU 30% hold-out")
    if not ctu_holdout.exists():
        print(f"ERROR: CTU hold-out not found at {ctu_holdout}")
        print("Run scripts/train_python_only.py first.")
        return 1
    ctu_df = pd.read_parquet(ctu_holdout)
    ctu_df.reset_index(drop=True, inplace=True)
    # All CTU flows are ATTACK by construction (botnet captures only)
    ctu_true = np.array(["ATTACK"] * len(ctu_df))
    if "__source" not in ctu_df.columns:
        ctu_df["__source"] = "ctu_holdout"
    print(f"  CTU hold-out flows: {len(ctu_df)} (all ATTACK)")
    print(f"  scenarios: {sorted(ctu_df['__source'].unique())}")

    # ---- 4. Evaluate both models on both sets ----
    print("\n[4/5] Running evaluations")
    print("  real_pcap | combined_v2 ...", end=" ", flush=True)
    res_old_real = evaluate("real_pcap_combined_v2", real_pcap_df, real_true,
                             old_model, old_pipe)
    print(f"recall ATK = {res_old_real['recall_attack']:.4f}")
    print("  real_pcap | python_only ...", end=" ", flush=True)
    res_new_real = evaluate("real_pcap_python_only", real_pcap_df, real_true,
                             new_model, new_pipe, abstainer=abstainer)
    print(f"recall ATK = {res_new_real['recall_attack']:.4f}")
    print("  ctu_holdout | combined_v2 ...", end=" ", flush=True)
    res_old_ctu = evaluate("ctu_holdout_combined_v2", ctu_df, ctu_true,
                            old_model, old_pipe)
    print(f"recall ATK = {res_old_ctu['recall_attack']:.4f}")
    print("  ctu_holdout | python_only ...", end=" ", flush=True)
    res_new_ctu = evaluate("ctu_holdout_python_only", ctu_df, ctu_true,
                            new_model, new_pipe, abstainer=abstainer)
    print(f"recall ATK = {res_new_ctu['recall_attack']:.4f}")

    # ---- 5. Print summary table ----
    print("\n[5/5] Side-by-side")
    print("=" * 100)
    print(f"{'Test set':<22}{'Model':<16}{'TP':>6}{'FN':>6}{'FP':>6}{'TN':>6}"
          f"{'Recall ATK':>12}{'Prec ATK':>11}{'F1 ATK':>10}{'Mean conf':>11}")
    print("-" * 100)
    for label, r in [
        ("real_pcap (n={})".format(len(real_pcap_df)), res_old_real),
        ("", res_new_real),
        ("ctu_holdout (n={})".format(len(ctu_df)), res_old_ctu),
        ("", res_new_ctu),
    ]:
        model_name = "combined_v2" if "combined_v2" in r["name"] else "python_only"
        print(f"{label:<22}{model_name:<16}{r['tp']:>6}{r['fn']:>6}{r['fp']:>6}{r['tn']:>6}"
              f"{r['recall_attack']:>12.4f}{r['precision_attack']:>11.4f}"
              f"{r['f1_attack']:>10.4f}{r['mean_confidence_overall']:>11.4f}")
    print("=" * 100)

    # Per-capture detail (real_pcap only — captures matter for the user
    # target of "280-320 of 347 attacks detected")
    print("\nPer-capture (real_pcap, python_only):")
    for cap in res_new_real["per_capture"]:
        rec = cap["attack_recall"]
        rec_str = f"{rec:.3f}" if not np.isnan(rec) else "n/a"
        print(f"  {cap['source']:<48} flows={cap['n_flows']:>4}  "
              f"true_ATK={cap['n_attack_true']:>4}  "
              f"detected={cap['n_attack_detected']:>4}  "
              f"recall={rec_str}")
    total_attack_real = sum(c["n_attack_true"] for c in res_new_real["per_capture"])
    total_detected_old = sum(c["n_attack_detected"] for c in res_old_real["per_capture"])
    total_detected_new = sum(c["n_attack_detected"] for c in res_new_real["per_capture"])
    print(f"\n  TOTAL real_pcap attack flows: {total_attack_real}")
    print(f"  combined_v2 detected: {total_detected_old}/{total_attack_real} "
          f"({100*total_detected_old/total_attack_real:.1f}%)")
    print(f"  python_only detected: {total_detected_new}/{total_attack_real} "
          f"({100*total_detected_new/total_attack_real:.1f}%)")

    if "selective" in res_new_real:
        sel = res_new_real["selective"]
        print(f"\n  python_only + abstainer (real_pcap):")
        print(f"    abstain rate     overall:{sel['abstain_rate']*100:>5.1f}%  "
              f"ATTACK:{sel['abstain_rate_attack']*100:>5.1f}%  "
              f"BENIGN:{sel['abstain_rate_benign']*100:>5.1f}%")
        print(f"    accepted recall:    {sel['accepted_recall_attack']:.4f}")
        print(f"    accepted precision: {sel['accepted_precision_attack']:.4f}")
        print(f"    accepted specificity: {sel['accepted_specificity']:.4f}  "
              f"(BENIGN correctly NOT alerted)")
        print(f"    all-flows recall (treating abstain as silent): "
              f"{sel['all_flows_recall_attack']:.4f}")
        sel_c = res_new_ctu.get("selective")
        if sel_c:
            print(f"  python_only + abstainer (ctu_holdout):")
            print(f"    abstain rate {sel_c['abstain_rate']*100:.1f}%, "
                  f"all-flows recall {sel_c['all_flows_recall_attack']:.4f}")

    # ---- Persist ----
    payload = {
        "real_pcap": {
            "combined_v2": res_old_real,
            "python_only": res_new_real,
        },
        "ctu_holdout": {
            "combined_v2": res_old_ctu,
            "python_only": res_new_ctu,
        },
        "headline": {
            "real_pcap_total_attack_flows": int(total_attack_real),
            "real_pcap_combined_v2_detected": int(total_detected_old),
            "real_pcap_python_only_detected": int(total_detected_new),
            "real_pcap_recall_old": float(res_old_real["recall_attack"]),
            "real_pcap_recall_new": float(res_new_real["recall_attack"]),
            "real_pcap_recall_delta": float(res_new_real["recall_attack"]
                                             - res_old_real["recall_attack"]),
            "real_pcap_f1_attack_old": float(res_old_real["f1_attack"]),
            "real_pcap_f1_attack_new": float(res_new_real["f1_attack"]),
            "real_pcap_f1_attack_delta": float(res_new_real["f1_attack"]
                                                - res_old_real["f1_attack"]),
        },
    }
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, default=str),
                         encoding="utf-8")
    print(f"\nWall time: {(time.time()-t0):.1f}s")
    print(f"Saved: {out_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
