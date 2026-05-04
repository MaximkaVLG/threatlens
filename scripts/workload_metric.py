"""Day 11 — workload-reduction headline metric.

The original 12-day plan (Day 11 deliverable #6) called for a
single business-language number to anchor the prize submission:

    "X % of inbound traffic auto-classified at FP rate Y %"

This script computes that number from the same real-world test set
used in Day 9e (real_pcap + 30 % CTU hold-out), broken down at four
operating points:

  - lenient:       no abstainer, max recall
  - safe:          abstainer @ coverage 0.95, mild OOD filter
  - strict:        abstainer @ coverage 0.80, aggressive OOD filter
  - paranoid:      abstainer @ coverage 0.50, only the most-confident

For each operating point we report:

  * AUTO-CLASSIFIED (%): flows that get a confident label (BENIGN or
    ATTACK) — the operator does NOT have to look at them
  * REVIEW QUEUE  (%): flows the abstainer flagged for human review
  * FALSE POSITIVE RATE: of the auto-classified BENIGN flows, what
    fraction are actually attacks (= leaked into the auto-pile)
  * FALSE NEGATIVE RATE: same for auto-classified ATTACK flows
  * RECALL ATTACK: detected attacks / total attacks (across both
    auto-classified and review-queue piles, since review still gets
    looked at by a human)

Output: results/python_only/workload_metric.json + console table.

Usage:
    python scripts/workload_metric.py
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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import CIC_FEATURE_COLUMNS  # noqa: E402
from threatlens.network.spectral_features import SPECTRAL_FEATURE_COLUMNS  # noqa: E402
from threatlens.network.payload_yara import YARA_FEATURE_COLUMNS  # noqa: E402

ALL_FEATURES = (list(CIC_FEATURE_COLUMNS) + list(SPECTRAL_FEATURE_COLUMNS)
                + list(YARA_FEATURE_COLUMNS))

MODEL_DIR = ROOT / "results" / "python_only"
CACHE_PARQUET = ROOT / "results" / "real_world_flows_cache.parquet"
CTU_HOLDOUT = MODEL_DIR / "ctu_test_holdout.parquet"
OUT_JSON = MODEL_DIR / "workload_metric.json"

# Operating points to sweep — each maps to a coverage value used by
# fit_selective_python_only.py. We re-fit fresh abstainers per point.
OPERATING_POINTS = [
    {"name": "lenient",  "coverage": None,  # no abstainer at all
     "comment": "Maximum throughput — every flow gets a label"},
    {"name": "safe",     "coverage": 0.95,
     "comment": "Mild OOD filter (default for shipped python_only)"},
    {"name": "strict",   "coverage": 0.80,
     "comment": "Aggressive — abstain on >20% of OOD-suspicious flows"},
    {"name": "paranoid", "coverage": 0.50,
     "comment": "Only the most-confident predictions kept"},
]


def fit_abstainer_at_coverage(coverage: float):
    """Re-fit Mahalanobis abstainer at given coverage. Imports the
    existing fit script's helper to stay DRY."""
    from scripts.fit_selective_python_only import load_train_set
    from threatlens.ml.selective import MahalanobisAbstainer

    clf = joblib.load(MODEL_DIR / "xgboost.joblib")
    pipeline = joblib.load(MODEL_DIR / "feature_pipeline.joblib")

    train = load_train_set()
    counts = train["Label"].value_counts()
    keep = counts[counts >= 5].index
    train = train[train["Label"].isin(keep)].reset_index(drop=True)
    for c in ALL_FEATURES:
        if c not in train.columns:
            train[c] = 0.0
    train[ALL_FEATURES] = (train[ALL_FEATURES]
                            .apply(lambda s: pd.to_numeric(s, errors="coerce"))
                            .astype("float64")
                            .replace([np.inf, -np.inf], np.nan)
                            .fillna(0.0))
    X = train[pipeline.feature_names].to_numpy(dtype=np.float64)
    X_scaled = pipeline.scaler.transform(X)
    y = pipeline.label_encoder.transform(train["Label"].astype(str).values)

    from sklearn.model_selection import train_test_split
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_scaled, y, test_size=0.30, random_state=42, stratify=y)
    abstainer = MahalanobisAbstainer().fit(
        X_fit, y_fit,
        classes=list(range(len(pipeline.label_encoder.classes_))))
    y_val_pred = clf.predict(X_val)
    abstainer.tune_thresholds(X_val, y_val, y_val_pred,
                                target_coverage=coverage)
    return clf, pipeline, abstainer


def to_binary(label: str) -> str:
    return "BENIGN" if label == "BENIGN" else "ATTACK"


def evaluate_workload_at_point(point: Dict, X_scaled: np.ndarray,
                                 true_bin: np.ndarray, clf, pipeline,
                                 abstainer=None) -> Dict:
    """For a single operating point, compute the workload-reduction
    numbers on the test set."""
    y_pred_int = clf.predict(X_scaled)
    raw_labels = pipeline.label_encoder.inverse_transform(y_pred_int)
    pred_bin = np.array([to_binary(l) for l in raw_labels])

    if abstainer is not None:
        abstain_mask, _ = abstainer.should_abstain(X_scaled, y_pred_int)
    else:
        abstain_mask = np.zeros(len(true_bin), dtype=bool)

    n = len(true_bin)
    accepted = ~abstain_mask
    n_accepted = int(accepted.sum())
    n_review = int(abstain_mask.sum())

    # Among accepted flows: confusion matrix
    auto_pred = pred_bin[accepted]
    auto_true = true_bin[accepted]
    tp = int(((auto_pred == "ATTACK") & (auto_true == "ATTACK")).sum())
    fp = int(((auto_pred == "ATTACK") & (auto_true == "BENIGN")).sum())
    tn = int(((auto_pred == "BENIGN") & (auto_true == "BENIGN")).sum())
    fn = int(((auto_pred == "BENIGN") & (auto_true == "ATTACK")).sum())

    # FP rate = false positives among the auto-pile / total auto
    fp_rate_auto = float(fp / max(n_accepted, 1))
    # FN rate = missed attacks among auto-classified BENIGN
    fn_rate_auto = float(fn / max(n_accepted, 1))
    # Specificity: of all BENIGN that got auto-classified, what % were correct
    n_benign_auto = int((auto_true == "BENIGN").sum())
    auto_specificity = float(tn / max(n_benign_auto, 1))

    # Total recall: even abstained ATTACK flows still go to review and
    # presumably get caught by the human, so they count toward recall.
    n_total_attacks = int((true_bin == "ATTACK").sum())
    n_attacks_caught = tp + int(((pred_bin == "ATTACK") & abstain_mask
                                 & (true_bin == "ATTACK")).sum()
                                 if n_review > 0 else 0)
    # The honest "all caught" = TP + (any review-queue attacks the human
    # would inspect). But reviewer might miss them too, so we report two
    # numbers: auto-recall (model alone) and pipeline-recall (with reviewer).
    auto_recall = float(tp / max(n_total_attacks, 1))
    pipeline_recall = float((tp + int(((true_bin == "ATTACK") & abstain_mask).sum()))
                              / max(n_total_attacks, 1))

    return {
        "name": point["name"],
        "coverage": point["coverage"],
        "comment": point["comment"],
        "n_total": n,
        "n_auto_classified": n_accepted,
        "n_review_queue": n_review,
        "auto_classified_pct": float(100 * n_accepted / max(n, 1)),
        "review_queue_pct": float(100 * n_review / max(n, 1)),
        "auto_tp": tp, "auto_fp": fp, "auto_tn": tn, "auto_fn": fn,
        "auto_fp_rate": fp_rate_auto,
        "auto_fp_pct": fp_rate_auto * 100,
        "auto_fn_rate": fn_rate_auto,
        "auto_specificity": auto_specificity,
        "auto_recall_attack": auto_recall,
        "pipeline_recall_attack_with_review": pipeline_recall,
    }


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print("[1/4] Loading test set (real_pcap + CTU hold-out)")
    if not CACHE_PARQUET.exists():
        print(f"ERROR: {CACHE_PARQUET} not found")
        return 1
    cache = pd.read_parquet(CACHE_PARQUET)
    real_pcap = cache[~cache["__source"].str.startswith("botnet-")].copy()
    real_pcap.reset_index(drop=True, inplace=True)
    real_true = real_pcap["__label_binary"].values

    if not CTU_HOLDOUT.exists():
        print(f"ERROR: {CTU_HOLDOUT} not found")
        return 1
    ctu = pd.read_parquet(CTU_HOLDOUT)
    ctu.reset_index(drop=True, inplace=True)
    ctu_true = np.array(["ATTACK"] * len(ctu))

    test_df = pd.concat([real_pcap, ctu], ignore_index=True, sort=False)
    test_true = np.concatenate([real_true, ctu_true])
    print(f"  total flows: {len(test_df)} "
          f"(ATTACK={(test_true=='ATTACK').sum()}, "
          f"BENIGN={(test_true=='BENIGN').sum()})")

    # Pre-scale once — model + pipeline are identical across operating points
    print("\n[2/4] Pre-scaling features")
    clf = joblib.load(MODEL_DIR / "xgboost.joblib")
    pipeline = joblib.load(MODEL_DIR / "feature_pipeline.joblib")
    expected = pipeline.feature_names
    for c in expected:
        if c not in test_df.columns:
            test_df[c] = 0.0
    X_raw = test_df[expected].apply(
        lambda s: pd.to_numeric(s, errors="coerce")) \
        .replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X_scaled = pipeline.scaler.transform(
        X_raw.values.astype(np.float64))

    # Sweep operating points
    print("\n[3/4] Evaluating workload at each operating point")
    results: List[Dict] = []
    for point in OPERATING_POINTS:
        t0 = time.time()
        if point["coverage"] is None:
            r = evaluate_workload_at_point(
                point, X_scaled, test_true, clf, pipeline, abstainer=None)
        else:
            print(f"  fitting abstainer @ cov={point['coverage']:.2f}...")
            _, _, abstainer = fit_abstainer_at_coverage(point["coverage"])
            r = evaluate_workload_at_point(
                point, X_scaled, test_true, clf, pipeline, abstainer=abstainer)
        r["wall_time_s"] = round(time.time() - t0, 2)
        results.append(r)

    # Print table
    print("\n[4/4] Workload reduction table")
    print("=" * 110)
    print(f"{'Mode':<10}{'Cov':>6}{'Auto %':>10}{'Review %':>11}"
          f"{'FP %':>9}{'Specif':>9}{'Recall ATK':>13}"
          f"{'+Review':>11}")
    print("-" * 110)
    for r in results:
        cov = f"{r['coverage']:.2f}" if r["coverage"] is not None else " - "
        print(f"{r['name']:<10}{cov:>6}"
              f"{r['auto_classified_pct']:>10.1f}"
              f"{r['review_queue_pct']:>11.1f}"
              f"{r['auto_fp_pct']:>9.2f}"
              f"{r['auto_specificity']*100:>9.1f}"
              f"{r['auto_recall_attack']*100:>13.1f}"
              f"{r['pipeline_recall_attack_with_review']*100:>11.1f}")
    print("=" * 110)
    print(("Cov = abstainer target coverage (None = no abstainer). "
           "Auto % = flows the model labels confidently — operator never "
           "looks at them. Review % = flows surfaced to a human. "
           "FP % = false positives in the auto pile / total auto. "
           "Specif = of auto-BENIGN, fraction correctly NOT flagged. "
           "Recall ATK = of total attacks, fraction the model auto-flagged. "
           "+Review = same recall but counting review-queue attacks too "
           "(assumes reviewer catches them)."))

    # Headline number — pick the operating point with FP <= 1 % and
    # highest auto-classified percentage. That's the "X % auto-classified
    # at FP <= Y %" the application form wants.
    headline = None
    for r in results:
        if r["auto_fp_pct"] <= 1.0:
            if headline is None or r["auto_classified_pct"] > headline["auto_classified_pct"]:
                headline = r
    if headline is None:
        # If no point hits FP <= 1 %, report the best precision
        headline = min(results, key=lambda r: r["auto_fp_pct"])

    print()
    print("HEADLINE: " + (
        f"{headline['auto_classified_pct']:.1f} % of inbound traffic "
        f"auto-classified at FP rate {headline['auto_fp_pct']:.2f} %  "
        f"(operating point: {headline['name']}, "
        f"recall ATK = {headline['auto_recall_attack']*100:.1f} %)"))

    OUT_JSON.write_text(json.dumps({
        "operating_points": results,
        "headline": headline,
        "n_total": int(len(test_df)),
        "n_attack": int((test_true == "ATTACK").sum()),
        "n_benign": int((test_true == "BENIGN").sum()),
    }, indent=2, default=str), encoding="utf-8")
    print(f"\nSaved: {OUT_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
