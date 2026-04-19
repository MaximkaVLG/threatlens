"""Train and compare all models on CIC-IDS2017.

Usage:
    # On real CIC-IDS2017 data:
    python -m threatlens.ml.train --data-dir ./data/cicids2017 --output ./results

    # On synthetic data (for pipeline validation):
    python -m threatlens.ml.train --synthetic --samples 10000

    # Quick test with small sample from real data:
    python -m threatlens.ml.train --data-dir ./data/cicids2017 --sample-size 50000
"""

import os
import sys
import argparse
import logging
import json

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from threatlens.ml.dataset import load_cicids2017, load_synthetic, split_features_labels
from threatlens.ml.features import FeaturePipeline
from threatlens.ml.models import (
    build_random_forest, build_xgboost, IsolationForestDetector,
)
from threatlens.ml.evaluate import (
    evaluate_model, print_comparison, print_feature_importance,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("threatlens.ml.train")


def main():
    parser = argparse.ArgumentParser(description="Train IDS models on CIC-IDS2017")
    parser.add_argument("--data-dir", default=None, help="Directory with CIC-IDS2017 CSV files")
    parser.add_argument("--synthetic", action="store_true", help="Use synthetic data (for testing pipeline)")
    parser.add_argument("--samples", type=int, default=10000, help="Synthetic sample size")
    parser.add_argument("--sample-size", type=int, default=None, help="Subsample real data")
    parser.add_argument("--balance", action="store_true", help="Balance classes by downsampling BENIGN")
    parser.add_argument("--output", default="./results", help="Output directory for models and metrics")
    parser.add_argument("--test-size", type=float, default=0.2, help="Test split fraction")
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    # ---- Load data ----
    if args.synthetic:
        logger.info("Loading synthetic data (%d samples)", args.samples)
        df = load_synthetic(n_samples=args.samples, random_state=args.random_state)
    else:
        if not args.data_dir:
            logger.error("Either --data-dir or --synthetic must be provided")
            sys.exit(1)
        logger.info("Loading CIC-IDS2017 from %s", args.data_dir)
        df = load_cicids2017(
            args.data_dir,
            sample_size=args.sample_size,
            balance=args.balance,
            random_state=args.random_state,
        )

    logger.info("Data loaded: %d rows, %d columns", len(df), df.shape[1])
    logger.info("Class distribution:\n%s", df["Label"].value_counts().to_string())

    # ---- Split features/labels ----
    X, y_multi, y_binary = split_features_labels(df)
    logger.info("Feature matrix shape: %s", X.shape)

    # ---- Train/test split ----
    X_train, X_test, y_train, y_test, y_binary_train, y_binary_test = train_test_split(
        X, y_multi, y_binary,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y_multi if y_multi.value_counts().min() > 1 else None,
    )
    logger.info("Train: %d, Test: %d", len(X_train), len(X_test))

    # ---- Preprocess ----
    pipeline = FeaturePipeline()
    X_train_proc, y_train_enc = pipeline.fit_transform(X_train, y_train)
    X_test_proc, y_test_enc = pipeline.transform(X_test, y_test)

    # ---- Train and evaluate models ----
    all_metrics = []

    # 1. Random Forest
    logger.info("=== Random Forest ===")
    rf = build_random_forest(random_state=args.random_state)
    rf_metrics = evaluate_model(
        rf, X_train_proc, y_train_enc, X_test_proc, y_test_enc,
        model_name="RandomForest", feature_names=pipeline.feature_names,
    )
    all_metrics.append(rf_metrics)
    joblib.dump(rf, os.path.join(args.output, "random_forest.joblib"))

    # 2. XGBoost
    try:
        logger.info("=== XGBoost ===")
        xgb = build_xgboost(random_state=args.random_state)
        xgb_metrics = evaluate_model(
            xgb, X_train_proc, y_train_enc, X_test_proc, y_test_enc,
            model_name="XGBoost", feature_names=pipeline.feature_names,
        )
        all_metrics.append(xgb_metrics)
        joblib.dump(xgb, os.path.join(args.output, "xgboost.joblib"))
    except ImportError as e:
        logger.warning("XGBoost unavailable: %s", e)

    # 3. Isolation Forest (unsupervised, trained on benign only)
    logger.info("=== Isolation Forest (anomaly detection) ===")
    benign_mask = y_binary_train == 0
    if benign_mask.sum() > 100:
        # Get processed benign subset (re-transform)
        X_benign = X_train[benign_mask]
        X_benign_proc, _ = pipeline.transform(X_benign, None)
        # Estimate contamination from full training set
        contamination = min(0.5, max(0.01, (y_binary_train == 1).mean()))

        iso = IsolationForestDetector(contamination=contamination, random_state=args.random_state)
        iso_metrics = evaluate_model(
            iso, X_benign_proc, np.zeros(len(X_benign_proc)),  # fit on benign only
            X_test_proc, y_binary_test.values,
            model_name="IsolationForest(binary)",
            average="binary",
        )
        all_metrics.append(iso_metrics)
        joblib.dump(iso, os.path.join(args.output, "isolation_forest.joblib"))
    else:
        logger.warning("Not enough benign samples (%d) for Isolation Forest", benign_mask.sum())

    # ---- Save pipeline ----
    joblib.dump(pipeline, os.path.join(args.output, "feature_pipeline.joblib"))

    # ---- Comparison ----
    comparison_df = print_comparison(
        all_metrics,
        out_file=os.path.join(args.output, "comparison.csv"),
    )

    # ---- Feature importance ----
    for m in all_metrics:
        if m.feature_importance:
            print_feature_importance(m, top_n=15)

    # ---- Save detailed metrics ----
    metrics_json = []
    for m in all_metrics:
        metrics_json.append({
            "name": m.name,
            "accuracy": m.accuracy,
            "precision": m.precision,
            "recall": m.recall,
            "f1": m.f1,
            "roc_auc": m.roc_auc,
            "train_time_sec": m.train_time,
            "predict_time_sec": m.predict_time,
            "per_class_report": m.per_class_report,
            "confusion_matrix": m.confusion,
            "top_features": [[name, float(imp)] for name, imp in m.feature_importance[:20]],
        })
    with open(os.path.join(args.output, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics_json, f, indent=2, ensure_ascii=False)

    logger.info("Results saved to %s", args.output)
    logger.info("Best model by F1: %s", comparison_df["F1"].idxmax())


if __name__ == "__main__":
    main()
