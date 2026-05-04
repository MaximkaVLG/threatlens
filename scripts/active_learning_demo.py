"""Day 12 — mini active-learning demo.

Goal: quantify the marginal value of a single analyst's 5 labels in a
realistic workflow. The python_only model has 14 false positives on
`wireshark_dns-mdns.pcap` (benign mDNS / link-local / SSDP broadcasts
it calls `Bot`). Imagine an analyst spends 30 seconds labeling 5 of
them as BENIGN. Does re-training with those 5 extra labels fix the
remaining 9 mDNS FPs? And does it break anything else?

This is a realistic deployment scenario — not a synthetic benchmark.
The demo:

 1. Trains a BASELINE model from the same training data as `python_only`
    (30 743 rows from synthetic + CTU + diverse_benign + attack_volume).
 2. Picks the 14 FP flows on the mDNS capture, splits them 5 labeled /
    9 held-out (random_state=42 so reproducible).
 3. Trains a CORRECTED model on (BASELINE training set + 5 labeled mDNS
    flows marked BENIGN with 20x sample weight so they meaningfully
    affect the fit).
 4. Compares BASELINE vs CORRECTED on:
      a) the 9 held-out mDNS flows (expect FP count to drop)
      b) all 347 real_pcap attack flows (recall must NOT regress)
      c) the remaining 84 benign flows from other captures (shouldn't
         introduce new FPs)

This is the Day 12 deliverable from `docs/improvement_plan.md`:
"If everything succeeded ahead of schedule: add a 4th comparison point
— eval on Stratosphere PCAP after the user labels 5 flows (mini active
learning demo)."

Usage:
    python scripts/active_learning_demo.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import CIC_FEATURE_COLUMNS  # noqa: E402
from threatlens.network.spectral_features import SPECTRAL_FEATURE_COLUMNS  # noqa: E402
from threatlens.network.payload_yara import YARA_FEATURE_COLUMNS  # noqa: E402
from threatlens.ml.features import FeaturePipeline  # noqa: E402
from threatlens.ml.models import build_xgboost  # noqa: E402

ALL_FEATURES = (list(CIC_FEATURE_COLUMNS) + list(SPECTRAL_FEATURE_COLUMNS)
                + list(YARA_FEATURE_COLUMNS))

MODEL_DIR = ROOT / "results" / "python_only"
CACHE_PARQUET = ROOT / "results" / "real_world_flows_cache.parquet"
OUT_JSON = MODEL_DIR / "active_learning_demo.json"

N_LABELED = 5             # analyst labels 5 flows
LABEL_WEIGHT = 20.0       # 20x sample weight on user labels
TARGET_SOURCE = "wireshark_dns-mdns.pcap"
RANDOM_STATE = 42


def load_training_set() -> pd.DataFrame:
    """Same composition as scripts/train_python_only.py.
    Reuses the helper in that script to stay DRY."""
    from scripts.train_python_only import (
        load_synthetic_with_cap, load_diverse_benign,
        load_attack_volume, get_ctu_flows_from_cache,
    )

    syn = load_synthetic_with_cap(10_000, RANDOM_STATE)
    ctu = get_ctu_flows_from_cache()
    diverse_benign = load_diverse_benign()
    attack_volume = load_attack_volume()

    # Reproduce the 70/30 CTU split (same random state)
    rng = np.random.default_rng(RANDOM_STATE)
    ctu_train_parts = []
    for src, g in ctu.groupby("__source"):
        idx = np.arange(len(g))
        rng.shuffle(idx)
        n_train = int(len(g) * 0.70)
        ctu_train_parts.append(g.iloc[idx[:n_train]])
    ctu_train = pd.concat(ctu_train_parts, ignore_index=True)

    parts = [syn, ctu_train]
    if not diverse_benign.empty:
        parts.append(diverse_benign)
    if not attack_volume.empty:
        parts.append(attack_volume)
    train = pd.concat(parts, ignore_index=True, sort=False)
    # Drop under-represented labels (<5 samples)
    counts = train["Label"].value_counts()
    keep = counts[counts >= 5].index
    train = train[train["Label"].isin(keep)].reset_index(drop=True)
    # Fill missing feature columns + coerce numeric
    for c in ALL_FEATURES:
        if c not in train.columns:
            train[c] = 0.0
    train[ALL_FEATURES] = (
        train[ALL_FEATURES]
        .apply(lambda s: pd.to_numeric(s, errors="coerce"))
        .astype("float64")
        .replace([np.inf, -np.inf], np.nan)
        .fillna(0.0)
    )
    return train


def fit_model(train_df: pd.DataFrame,
               extra_flows: pd.DataFrame = None,
               extra_weight: float = 1.0) -> Tuple[object, FeaturePipeline]:
    """Fit XGBoost on train_df plus optional extra_flows (same columns,
    labeled + weighted extra_weight)."""
    pipeline = FeaturePipeline()
    if extra_flows is None or extra_flows.empty:
        combined = train_df
        extra_len = 0
    else:
        extra = extra_flows[ALL_FEATURES + ["Label"]].copy()
        combined = pd.concat([train_df[ALL_FEATURES + ["Label"]], extra],
                              ignore_index=True)
        extra_len = len(extra)

    X_p, y_e = pipeline.fit_transform(combined[ALL_FEATURES], combined["Label"])

    # Inverse-frequency class weights, same as train_python_only.py
    classes_unique, class_counts = np.unique(y_e, return_counts=True)
    class_weight = {int(c): float(len(y_e) / (len(classes_unique) * cnt))
                    for c, cnt in zip(classes_unique, class_counts)}
    sample_weight = np.array([class_weight[int(c)] for c in y_e],
                              dtype=np.float64)
    # Bump the extra user-labeled rows (the last extra_len rows)
    if extra_len > 0:
        sample_weight[-extra_len:] *= extra_weight

    clf = build_xgboost(random_state=RANDOM_STATE)
    clf.fit(X_p, y_e, sample_weight=sample_weight)
    return clf, pipeline


def evaluate(clf, pipeline, X_df: pd.DataFrame) -> np.ndarray:
    """Run predict and return decoded labels."""
    expected = pipeline.feature_names
    df = X_df.copy()
    for c in expected:
        if c not in df.columns:
            df[c] = 0.0
    X = df[expected].apply(lambda s: pd.to_numeric(s, errors="coerce")) \
                    .replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X_scaled = pipeline.scaler.transform(X.values.astype(np.float64))
    y_int = clf.predict(X_scaled)
    return pipeline.label_encoder.inverse_transform(y_int)


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print("[1/6] Loading training data")
    t0 = time.time()
    train = load_training_set()
    print(f"  training rows: {len(train):,}")

    print("\n[2/6] Loading real_pcap cache + identifying mDNS FPs")
    cache = pd.read_parquet(CACHE_PARQUET)
    real_pcap = cache[~cache["__source"].str.startswith("botnet-")].reset_index(drop=True)
    mdns = real_pcap[real_pcap["__source"] == TARGET_SOURCE].reset_index(drop=True)

    # Identify FPs using the shipped python_only model
    shipped_clf = joblib.load(MODEL_DIR / "xgboost.joblib")
    shipped_pipe = joblib.load(MODEL_DIR / "feature_pipeline.joblib")
    mdns_pred = evaluate(shipped_clf, shipped_pipe, mdns)
    fp_mask = mdns_pred != "BENIGN"
    fp_indices = np.where(fp_mask)[0]
    print(f"  mDNS flows: {len(mdns)}, FPs from shipped model: {len(fp_indices)}")

    if len(fp_indices) < N_LABELED + 3:
        print(f"  WARNING: only {len(fp_indices)} FPs — expected at least 14")

    # Deterministic split: first N labeled, rest held-out
    rng = np.random.default_rng(RANDOM_STATE)
    shuffled = rng.permutation(fp_indices)
    labeled_idx = shuffled[:N_LABELED]
    holdout_idx = shuffled[N_LABELED:]
    print(f"  labeled (train augmentation): {labeled_idx.tolist()}")
    print(f"  held-out (test): {holdout_idx.tolist()}")

    # Build the 5 user-labeled extra rows
    labeled_flows = mdns.iloc[labeled_idx].copy()
    labeled_flows["Label"] = "BENIGN"
    for c in ALL_FEATURES:
        if c not in labeled_flows.columns:
            labeled_flows[c] = 0.0

    print("\n[3/6] Fitting BASELINE model (no augmentation)")
    t1 = time.time()
    baseline_clf, baseline_pipe = fit_model(train)
    print(f"  fit: {time.time()-t1:.1f}s")

    print("\n[4/6] Fitting CORRECTED model (+5 mDNS BENIGN @20x weight)")
    t1 = time.time()
    corrected_clf, corrected_pipe = fit_model(
        train, extra_flows=labeled_flows, extra_weight=LABEL_WEIGHT)
    print(f"  fit: {time.time()-t1:.1f}s")

    print("\n[5/6] Evaluating both models on held-out slices")

    # (a) 9 held-out mDNS FPs
    holdout_flows = mdns.iloc[holdout_idx]
    base_preds_mdns = evaluate(baseline_clf, baseline_pipe, holdout_flows)
    corr_preds_mdns = evaluate(corrected_clf, corrected_pipe, holdout_flows)

    # (b) attack captures — recall
    attack_captures = [
        "slips_ssh-bruteforce.pcap",
        "slips_test7_malicious.pcap",
        "slips_test8_malicious.pcap",
    ]
    attack_flows = real_pcap[real_pcap["__source"].isin(attack_captures)].reset_index(drop=True)
    base_preds_atk = evaluate(baseline_clf, baseline_pipe, attack_flows)
    corr_preds_atk = evaluate(corrected_clf, corrected_pipe, attack_flows)

    # (c) other benign captures — should not regress
    other_benign = real_pcap[
        (~real_pcap["__source"].isin(attack_captures))
        & (real_pcap["__source"] != TARGET_SOURCE)
    ].reset_index(drop=True)
    base_preds_oth = evaluate(baseline_clf, baseline_pipe, other_benign)
    corr_preds_oth = evaluate(corrected_clf, corrected_pipe, other_benign)

    print("\n[6/6] Summary")
    print("=" * 90)
    print(f"{'Slice':<35}{'Truth':<10}{'BASELINE':<18}{'CORRECTED':<18}{'Delta'}")
    print("-" * 90)

    # a) Held-out mDNS FPs
    base_fp_mdns = int((base_preds_mdns != "BENIGN").sum())
    corr_fp_mdns = int((corr_preds_mdns != "BENIGN").sum())
    print(f"{'Held-out mDNS (9 flows)':<35}{'BENIGN':<10}"
          f"{'FP='+str(base_fp_mdns)+'/9':<18}"
          f"{'FP='+str(corr_fp_mdns)+'/9':<18}"
          f"{base_fp_mdns - corr_fp_mdns:+d} FPs")

    # b) Attack captures
    base_det_atk = int((base_preds_atk != "BENIGN").sum())
    corr_det_atk = int((corr_preds_atk != "BENIGN").sum())
    n_atk = len(attack_flows)
    print(f"{'Attack captures ('+str(n_atk)+' flows)':<35}{'ATTACK':<10}"
          f"{'TP='+str(base_det_atk)+'/'+str(n_atk):<18}"
          f"{'TP='+str(corr_det_atk)+'/'+str(n_atk):<18}"
          f"{corr_det_atk - base_det_atk:+d} TPs")

    # c) Other benign captures
    n_oth = len(other_benign)
    base_fp_oth = int((base_preds_oth != "BENIGN").sum())
    corr_fp_oth = int((corr_preds_oth != "BENIGN").sum())
    print(f"{'Other benign captures ('+str(n_oth)+' flows)':<35}{'BENIGN':<10}"
          f"{'FP='+str(base_fp_oth)+'/'+str(n_oth):<18}"
          f"{'FP='+str(corr_fp_oth)+'/'+str(n_oth):<18}"
          f"{base_fp_oth - corr_fp_oth:+d} FPs")
    print("=" * 90)

    # Interpretation
    recall_delta = (corr_det_atk - base_det_atk) / max(n_atk, 1)
    fp_delta_mdns = (corr_fp_mdns - base_fp_mdns) / 9
    print(f"\nRecall delta on attack captures:  {recall_delta*100:+.2f} pt  "
          f"(acceptable if |delta| <= 1 pt)")
    print(f"FP delta on held-out mDNS:        {fp_delta_mdns*100:+.1f} pt  "
          f"(target: strongly negative)")
    if corr_fp_mdns < base_fp_mdns and abs(recall_delta) <= 0.01:
        verdict = "WIN — 5 labels reduced FPs on similar flows without recall loss"
    elif corr_fp_mdns < base_fp_mdns:
        verdict = "MIXED — FPs dropped but recall took a small hit"
    elif corr_fp_mdns == base_fp_mdns:
        verdict = "NEUTRAL — 5 labels didn't transfer (training distribution dominates)"
    else:
        verdict = "LOSS — corrected model has MORE FPs (oversampling artifact)"
    print(f"\nVerdict: {verdict}")

    # Save
    OUT_JSON.write_text(json.dumps({
        "n_labeled": N_LABELED,
        "label_weight": LABEL_WEIGHT,
        "target_source": TARGET_SOURCE,
        "random_state": RANDOM_STATE,
        "baseline": {
            "fp_mdns_holdout": base_fp_mdns,
            "tp_attack_captures": base_det_atk,
            "fp_other_benign": base_fp_oth,
        },
        "corrected": {
            "fp_mdns_holdout": corr_fp_mdns,
            "tp_attack_captures": corr_det_atk,
            "fp_other_benign": corr_fp_oth,
        },
        "n_attack_flows": n_atk,
        "n_other_benign": n_oth,
        "recall_delta_attack_pt": float(recall_delta * 100),
        "fp_delta_mdns_holdout": corr_fp_mdns - base_fp_mdns,
        "verdict": verdict,
        "wall_time_s": round(time.time() - t0, 2),
    }, indent=2), encoding="utf-8")
    print(f"\nSaved: {OUT_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
