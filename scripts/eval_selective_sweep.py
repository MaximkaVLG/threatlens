"""Day 8 — abstention threshold sweep on real-world PCAPs.

The default target_coverage=0.99 abstainer was too conservative on
real-world: 19.7% abstention but only +0.011 F1 lift. This sweep
tests a range of coverage levels to find the precision-vs-coverage
operating point that's most useful for the IDS:

  coverage=0.99 -> very few abstentions, may miss most OOD
  coverage=0.95 -> moderate abstentions
  coverage=0.90 -> aggressive
  coverage=0.80 -> "abstain unless you're really sure"

For each coverage level, re-tune the per-class thresholds, then
apply to the same fixed flow set extracted ONCE (cached to parquet
so we don't pay the 16-minute CTU extraction cost N times).

Output: results/selective_sweep.json with the precision-recall curve
across thresholds + a recommendation for which to ship.

Usage:
    python scripts/eval_selective_sweep.py
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

from threatlens.network.flow_extractor import FlowExtractor  # noqa: E402
from threatlens.ml.selective import (  # noqa: E402
    MahalanobisAbstainer, ABSTAIN_LABEL,
)
from scripts.train_combined import (  # noqa: E402
    load_cic2017, load_cic2018, load_synthetic_balanced, ALL_FEATURE_COLUMNS,
)

MODEL_DIR = ROOT / "results" / "combined_v2"
REAL_PCAP_DIR = ROOT / "data" / "real_pcap"
CTU_DIR = ROOT / "data" / "ctu_malware"
CACHE_PARQUET = ROOT / "results" / "real_world_flows_cache.parquet"
OUT_JSON = ROOT / "results" / "selective_sweep.json"

REAL_PCAP_LABELS = {
    "slips_ssh-bruteforce.pcap":              "ATTACK",
    "slips_test12_icmp-portscan.pcap":        "ATTACK",
    "slips_test7_malicious.pcap":             "ATTACK",
    "slips_test8_malicious.pcap":             "ATTACK",
    "wireshark_dns-mdns.pcap":                "BENIGN",
    "wireshark_http2-data-reassembly.pcap":   "BENIGN",
    "wireshark_http2_follow_multistream.pcapng": "BENIGN",
    "wireshark_tls-renegotiation.pcap":       "BENIGN",
    "wireshark_tls12-chacha20.pcap":          "BENIGN",
}

COVERAGES = [0.99, 0.95, 0.90, 0.85, 0.80, 0.70, 0.50]


def extract_or_load_real_world(extractor: FlowExtractor) -> pd.DataFrame:
    """Cache real-world flow extraction in parquet to avoid the 16-min cost."""
    if CACHE_PARQUET.exists():
        print(f"[cache hit] {CACHE_PARQUET}")
        return pd.read_parquet(CACHE_PARQUET)

    print(f"[cache miss] extracting all real-world PCAPs (~16 min)")
    frames: List[pd.DataFrame] = []
    for fname, label_bin in REAL_PCAP_LABELS.items():
        p = REAL_PCAP_DIR / fname
        if not p.exists():
            continue
        print(f"  extracting {fname}...")
        df = extractor.extract(str(p))
        if df.empty:
            continue
        df["__label_binary"] = label_bin
        df["__source"] = fname
        frames.append(df)
    for sub in sorted(CTU_DIR.iterdir()):
        if not sub.is_dir():
            continue
        for p in sorted(sub.glob("botnet-capture-*.pcap")):
            print(f"  extracting {sub.name}/{p.name} ({p.stat().st_size // 1_000_000} MB)...")
            t0 = time.time()
            df = extractor.extract(str(p))
            print(f"    {len(df)} flows in {time.time()-t0:.1f}s")
            if df.empty:
                continue
            df["__label_binary"] = "ATTACK"
            df["__source"] = f"{sub.name}/{p.name}"
            frames.append(df)

    combined = pd.concat(frames, ignore_index=True, sort=False)
    # Parquet doesn't like mixed dtypes; force feature columns to float
    for c in ALL_FEATURE_COLUMNS:
        if c in combined.columns:
            combined[c] = pd.to_numeric(combined[c], errors="coerce").fillna(0.0)
    CACHE_PARQUET.parent.mkdir(parents=True, exist_ok=True)
    combined.to_parquet(CACHE_PARQUET, index=False)
    print(f"  cached: {CACHE_PARQUET} ({CACHE_PARQUET.stat().st_size // 1_000_000} MB)")
    return combined


def fit_fresh_abstainer(coverage: float, random_state: int = 7) -> Tuple[MahalanobisAbstainer, object, object]:
    """Re-fit abstainer at a given coverage. Reuses Day 8's tuning data."""
    clf = joblib.load(MODEL_DIR / "xgboost.joblib")
    pipeline = joblib.load(MODEL_DIR / "feature_pipeline.joblib")

    cic17 = load_cic2017(100_000, random_state)
    cic18 = load_cic2018(100_000, random_state)
    syn = load_synthetic_balanced(3_000, random_state)
    combined = pd.concat([cic17, cic18, syn], ignore_index=True, sort=False)
    keep = set(pipeline.label_encoder.classes_)
    combined = combined[combined["Label"].isin(keep)].reset_index(drop=True)

    for c in ALL_FEATURE_COLUMNS:
        combined[c] = pd.to_numeric(combined[c], errors="coerce")
    combined[ALL_FEATURE_COLUMNS] = (combined[ALL_FEATURE_COLUMNS]
                                     .replace([np.inf, -np.inf], np.nan).fillna(0.0))
    X_raw = combined[pipeline.feature_names]
    X_scaled = pipeline.scaler.transform(X_raw.values)
    y = pipeline.label_encoder.transform(combined["Label"].astype(str).values)

    from sklearn.model_selection import train_test_split
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_scaled, y, test_size=0.30, random_state=random_state, stratify=y,
    )

    abstainer = MahalanobisAbstainer().fit(
        X_fit, y_fit, classes=list(range(len(pipeline.label_encoder.classes_))))
    y_val_pred = clf.predict(X_val)
    abstainer.tune_thresholds(X_val, y_val, y_val_pred, target_coverage=coverage)
    return abstainer, clf, pipeline


def to_binary(label: str) -> str:
    return "BENIGN" if label == "BENIGN" else "ATTACK"


def evaluate_at_coverage(coverage: float, flows_df: pd.DataFrame) -> Dict:
    """Re-fit abstainer at coverage, apply to flows_df, return metrics."""
    print(f"\n  fitting abstainer at coverage={coverage:.2f}...")
    abstainer, clf, pipeline = fit_fresh_abstainer(coverage)

    # Apply to real-world flows
    expected = pipeline.feature_names
    df = flows_df.copy()
    for c in expected:
        if c not in df.columns:
            df[c] = 0.0
    X = df[expected].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X_scaled = pipeline.scaler.transform(X.values)
    y_pred_int = clf.predict(X_scaled)
    raw_labels = pipeline.label_encoder.inverse_transform(y_pred_int)
    abstain_mask, _ = abstainer.should_abstain(X_scaled, y_pred_int)

    pred_bin = np.array([to_binary(l) for l in raw_labels])
    true_bin = flows_df["__label_binary"].values
    accepted = ~abstain_mask

    from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix
    pred_silent = np.where(abstain_mask, "BENIGN", pred_bin)
    all_f1 = float(f1_score(true_bin, pred_silent, pos_label="ATTACK",
                            average="binary", zero_division=0))
    if accepted.sum() > 0:
        accepted_f1 = float(f1_score(true_bin[accepted], pred_bin[accepted],
                                     pos_label="ATTACK", average="binary", zero_division=0))
        accepted_precision = float(precision_score(true_bin[accepted], pred_bin[accepted],
                                                   pos_label="ATTACK", zero_division=0))
        accepted_recall = float(recall_score(true_bin[accepted], pred_bin[accepted],
                                             pos_label="ATTACK", zero_division=0))
        cm_acc = confusion_matrix(true_bin[accepted], pred_bin[accepted],
                                   labels=["BENIGN", "ATTACK"]).tolist()
    else:
        accepted_f1 = accepted_precision = accepted_recall = None
        cm_acc = []

    return {
        "coverage_target": coverage,
        "n_total": int(len(true_bin)),
        "n_abstained": int(abstain_mask.sum()),
        "n_accepted": int(accepted.sum()),
        "abstention_rate": float(abstain_mask.mean()),
        "all_flows_f1_attack": all_f1,
        "accepted_f1_attack": accepted_f1,
        "accepted_precision_attack": accepted_precision,
        "accepted_recall_attack": accepted_recall,
        "confusion_accepted": cm_acc,
        # What fraction of true-attack flows did we abstain on (vs predict on)?
        "attack_abstention_rate": float(abstain_mask[true_bin == "ATTACK"].mean()
                                         if (true_bin == "ATTACK").any() else 0.0),
        "benign_abstention_rate": float(abstain_mask[true_bin == "BENIGN"].mean()
                                         if (true_bin == "BENIGN").any() else 0.0),
    }


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    extractor = FlowExtractor()
    flows = extract_or_load_real_world(extractor)
    print(f"\nReal-world flows: {len(flows)} total")
    print(f"  ATTACK: {(flows['__label_binary'] == 'ATTACK').sum()}")
    print(f"  BENIGN: {(flows['__label_binary'] == 'BENIGN').sum()}")

    sweep = []
    for cov in COVERAGES:
        result = evaluate_at_coverage(cov, flows)
        sweep.append(result)
        print(f"  cov={cov:.2f} -> abstention={result['abstention_rate']:.3f} "
              f"(ATK abstention={result['attack_abstention_rate']:.3f}, "
              f"BENIGN abstention={result['benign_abstention_rate']:.3f}) "
              f"  all_F1={result['all_flows_f1_attack']:.4f}, "
              f"accepted_F1={result['accepted_f1_attack']:.4f}, "
              f"accepted_recall={result['accepted_recall_attack']:.4f}")

    # ---- Summary table ----
    print("\n" + "=" * 100)
    print(f"{'Coverage':>10}{'Abstn %':>10}{'ATK abstn %':>13}{'BEN abstn %':>13}"
          f"{'All F1 ATK':>13}{'Acc F1 ATK':>13}{'Acc Prec':>11}{'Acc Recall':>13}")
    print("-" * 100)
    for r in sweep:
        print(f"{r['coverage_target']:>10.2f}"
              f"{r['abstention_rate']*100:>10.1f}"
              f"{r['attack_abstention_rate']*100:>13.1f}"
              f"{r['benign_abstention_rate']*100:>13.1f}"
              f"{r['all_flows_f1_attack']:>13.4f}"
              f"{(r['accepted_f1_attack'] or 0):>13.4f}"
              f"{(r['accepted_precision_attack'] or 0):>11.4f}"
              f"{(r['accepted_recall_attack'] or 0):>13.4f}")
    print("=" * 100)

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps({"sweep": sweep,
                                     "n_attack": int((flows['__label_binary']=='ATTACK').sum()),
                                     "n_benign": int((flows['__label_binary']=='BENIGN').sum())},
                                    indent=2, default=str), encoding="utf-8")
    print(f"\nSaved: {OUT_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
