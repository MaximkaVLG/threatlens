"""Fit the Mahalanobis abstainer on top of the combined XGBoost model.

Loads ``results/combined_v2/{xgboost,feature_pipeline}.joblib``, samples
a batch of combined training flows to compute class means and covariance,
uses a separate validation split to tune per-class thresholds at
``target_coverage`` = 0.99, then saves the fitted abstainer to
``results/combined_v2/mahalanobis_abstainer.joblib``.

Usage:
    python scripts/fit_selective.py
    python scripts/fit_selective.py --target-coverage 0.95  # more abstain-aggressive

The script rebuilds the same combined DataFrame that
``scripts/train_combined.py`` does (CIC-2017 + CIC-2018 + synthetic) so
mean and covariance are computed over the full training distribution,
not just one slice.
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.ml.selective import MahalanobisAbstainer  # noqa: E402

# Reuse the combined-train loaders — identical sampling strategy as Day 5
from scripts.train_combined import (  # noqa: E402
    load_cic2017, load_cic2018, load_synthetic_balanced, ALL_FEATURE_COLUMNS,
)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("fit_selective")

MODEL_DIR = ROOT / "results" / "combined_v2"


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser()
    parser.add_argument("--cic2017-sample", type=int, default=200_000,
                        help="Stratified sample size from CIC-2017 (smaller than train)")
    parser.add_argument("--cic2018-sample", type=int, default=200_000)
    parser.add_argument("--hulk-cap", type=int, default=5_000)
    parser.add_argument("--target-coverage", type=float, default=0.99,
                        help="Fraction of correct training predictions that should NOT be abstained")
    parser.add_argument("--val-fraction", type=float, default=0.30,
                        help="Fraction of loaded data held out for threshold tuning")
    parser.add_argument("--ridge", type=float, default=1e-4)
    parser.add_argument("--random-state", type=int, default=7)  # different from train's 42
    args = parser.parse_args()

    t0 = time.time()

    print(f"[1/5] Loading combined model from {MODEL_DIR}")
    clf = joblib.load(MODEL_DIR / "xgboost.joblib")
    pipeline = joblib.load(MODEL_DIR / "feature_pipeline.joblib")
    print(f"  classifier: {type(clf).__name__}")
    print(f"  pipeline features: {len(pipeline.feature_names)}")
    print(f"  classes: {len(pipeline.label_encoder.classes_)}")

    print(f"\n[2/5] Re-loading combined training sources (smaller sample)")
    cic17 = load_cic2017(args.cic2017_sample, args.random_state)
    cic18 = load_cic2018(args.cic2018_sample, args.random_state)
    syn = load_synthetic_balanced(args.hulk_cap, args.random_state)

    import pandas as pd
    combined = pd.concat([cic17, cic18, syn], ignore_index=True, sort=False)
    # Drop classes too small to stratify / that weren't seen at training time
    keep = set(pipeline.label_encoder.classes_)
    combined = combined[combined["Label"].isin(keep)].reset_index(drop=True)
    print(f"  combined: {len(combined):,} rows after filtering unseen labels")

    # Transform through the frozen pipeline (same scaler, same feature set
    # as training — do NOT refit)
    for c in ALL_FEATURE_COLUMNS:
        combined[c] = pd.to_numeric(combined[c], errors="coerce")
    combined[ALL_FEATURE_COLUMNS] = (combined[ALL_FEATURE_COLUMNS]
                                     .replace([np.inf, -np.inf], np.nan).fillna(0.0))

    X_raw = combined[pipeline.feature_names]
    X_scaled = pipeline.scaler.transform(X_raw.values)
    y = pipeline.label_encoder.transform(combined["Label"].astype(str).values)
    print(f"  X: {X_scaled.shape}, y: {y.shape}, classes={len(set(y))}")

    # 70/30 fit/val split (stratified)
    from sklearn.model_selection import train_test_split
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_scaled, y,
        test_size=args.val_fraction,
        random_state=args.random_state,
        stratify=y,
    )
    print(f"  fit rows: {len(X_fit):,}   val rows: {len(X_val):,}")

    print(f"\n[3/5] Fitting Mahalanobis (ridge={args.ridge}, pooled covariance)")
    abstainer = MahalanobisAbstainer(
        ridge=args.ridge, use_pooled_covariance=True,
    ).fit(X_fit, y_fit, classes=list(range(len(pipeline.label_encoder.classes_))))

    print(f"\n[4/5] Tuning per-class thresholds at coverage={args.target_coverage}")
    y_val_pred = clf.predict(X_val)
    abstainer.tune_thresholds(X_val, y_val, y_val_pred,
                              target_coverage=args.target_coverage)

    # Print per-class diagnostic
    print(f"\n  Per-class threshold (tau) and accepted fraction on validation:")
    print(f"  {'class':<30} {'n_correct':>10} {'tau':>10} {'accepted %':>12}")
    for c_id, c_name in enumerate(pipeline.label_encoder.classes_):
        sel_pred = (y_val_pred == c_id)
        if sel_pred.sum() == 0:
            continue
        tau = abstainer.thresholds.get(c_id, abstainer._global_fallback)
        dists_c = abstainer.distances(X_val[sel_pred], y_val_pred[sel_pred])
        accepted = float((dists_c <= tau).mean() * 100)
        n_correct = int(((y_val_pred == y_val) & (y_val_pred == c_id)).sum())
        print(f"  {str(c_name)[:30]:<30} {n_correct:>10} {tau:>10.3f} {accepted:>12.1f}")

    print(f"\n[5/5] Saving abstainer to {MODEL_DIR}")
    out_path = MODEL_DIR / "mahalanobis_abstainer.joblib"
    abstainer.save(str(out_path))
    print(f"  written: {out_path}  ({out_path.stat().st_size // 1024} KB)")

    print(f"\nWall time: {(time.time() - t0) / 60:.1f} min")
    return 0


if __name__ == "__main__":
    sys.exit(main())
