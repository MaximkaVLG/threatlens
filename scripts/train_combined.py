"""Combined retraining: CIC-IDS2017 + CIC-IDS2018 + synthetic, 81 features.

Day 5 of the Defense-in-Depth improvement plan. Folds together every
training source we have:

  - CIC-IDS2017 (3.8M flows, 70 CIC features): the original training set
  - CIC-IDS2018 (5.2M flows, 80 features with abbreviated names): fixes
    the cross-dataset collapse (F1=0.50 -> hopefully much higher)
  - Synthetic (143K flows, 81 features): introduces controlled netem
    variation and exercises the new spectral + YARA features

Key alignment trick: CIC-2017 and CIC-2018 rows have **no spectral or
YARA values** (the source CSVs predate those features). We zero-fill
those columns so the schema is uniform across rows. XGBoost will simply
not split on a column whose distribution is dominated by zeros — but
when synthetic flows arrive (or when the prod inference pipeline
attaches real spectral/YARA features), those splits become available.

The trained artefacts live in ``results/combined_v2/`` — **never**
overwriting ``results/cicids2017/`` (the production deploy reads from
the latter). Switching prod is a deliberate Day 11 decision, not a
side-effect of training.

Usage:
    # Default sample sizes (~1M total rows, fits in 16GB RAM, ~30 min)
    python scripts/train_combined.py

    # Quick smoke test with tiny samples
    python scripts/train_combined.py --cic2017-sample 50000 \\
        --cic2018-sample 50000 --hulk-cap 5000

    # Full CIC-2017 (no sampling), still cap CIC-2018 + Hulk
    python scripts/train_combined.py --cic2017-sample 0
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import CIC_FEATURE_COLUMNS  # noqa: E402
from threatlens.network.spectral_features import SPECTRAL_FEATURE_COLUMNS  # noqa: E402
from threatlens.network.payload_yara import YARA_FEATURE_COLUMNS  # noqa: E402
from threatlens.ml.dataset import _clean_column_names, _map_labels  # noqa: E402
from threatlens.ml.features import FeaturePipeline  # noqa: E402
from threatlens.ml.models import build_random_forest, build_xgboost  # noqa: E402
from threatlens.ml.evaluate import evaluate_model, print_comparison  # noqa: E402

# Reuse the schema mapping from the cross-dataset eval — DRY.
from scripts.eval_cross_dataset import (  # noqa: E402
    COL_MAP_2018_TO_2017,
    LABEL_MAP_2018_TO_2017,
)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("train_combined")

CIC2017_DIR = ROOT / "data" / "cicids2017"
CIC2018_DIR = ROOT / "data" / "cicids2018"
SYNTHETIC_CSV = ROOT / "data" / "synthetic" / "synthetic_flows.csv"
OUT_DIR = ROOT / "results" / "combined_v2"

# All 81 feature columns the combined model expects (in order).
ALL_FEATURE_COLUMNS = (
    list(CIC_FEATURE_COLUMNS) + list(SPECTRAL_FEATURE_COLUMNS) + list(YARA_FEATURE_COLUMNS)
)


def _stratified_sample(df: pd.DataFrame, n: int, label_col: str = "Label",
                       random_state: int = 42) -> pd.DataFrame:
    """Random sample preserving class distribution. Manual loop because
    pandas 2.x groupby().apply() drops the group column."""
    if n <= 0 or n >= len(df):
        return df
    parts = []
    total = len(df)
    for _, group in df.groupby(label_col):
        n_take = max(1, int(round(n * len(group) / total)))
        n_take = min(n_take, len(group))
        parts.append(group.sample(n=n_take, random_state=random_state))
    return pd.concat(parts, ignore_index=True)


def _zero_fill_missing_features(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure every column in ALL_FEATURE_COLUMNS exists (zero if missing).

    CIC-2017 and CIC-2018 rows have no spectral/YARA columns; this
    fills them in so the combined DataFrame is rectangular.
    """
    for col in ALL_FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0
    return df


def load_cic2017(sample_size: int, random_state: int) -> pd.DataFrame:
    files = sorted(CIC2017_DIR.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CIC-IDS2017 CSVs in {CIC2017_DIR}")

    logger.info("[CIC-2017] reading %d files", len(files))
    parts = []
    for f in files:
        try:
            chunk = pd.read_csv(f, low_memory=False, encoding="utf-8")
        except UnicodeDecodeError:
            chunk = pd.read_csv(f, low_memory=False, encoding="latin-1")
        parts.append(_clean_column_names(chunk))
    df = pd.concat(parts, ignore_index=True)

    df = df.replace([np.inf, -np.inf], np.nan)
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    initial = len(df)
    df = df.dropna(subset=numeric_cols)
    logger.info("[CIC-2017] %d rows after NaN/inf drop (was %d)", len(df), initial)

    df["Label"] = df["Label"].astype(str).str.strip()

    if sample_size > 0 and sample_size < len(df):
        df = _stratified_sample(df, sample_size, random_state=random_state)
        logger.info("[CIC-2017] stratified sample to %d rows", len(df))

    df["__source"] = "cic2017"
    df = _zero_fill_missing_features(df)
    return df


def load_cic2018(sample_size: int, random_state: int) -> pd.DataFrame:
    files = sorted(CIC2018_DIR.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CIC-IDS2018 CSVs in {CIC2018_DIR}")

    # CIC-2018 files are huge (200-400 MB each). Sample per-file proportionally.
    per_file = (sample_size // len(files)) if sample_size > 0 else None
    parts = []
    for f in files:
        logger.info("[CIC-2018] reading %s", f.name)
        if per_file:
            # Read full then sample (CIC-2018 has ~1M rows per file; manageable)
            chunk = pd.read_csv(f, low_memory=False)
        else:
            chunk = pd.read_csv(f, low_memory=False)

        chunk = chunk[chunk["Label"] != "Label"].copy()  # drop accidentally-inserted header rows
        if per_file and len(chunk) > per_file:
            chunk = chunk.sample(n=per_file, random_state=random_state)
        parts.append(chunk)
    df = pd.concat(parts, ignore_index=True)
    logger.info("[CIC-2018] %d rows after sampling", len(df))

    df = df.rename(columns=COL_MAP_2018_TO_2017)
    df["mapped_label"] = df["Label"].astype(str).str.strip().map(LABEL_MAP_2018_TO_2017).fillna("OTHER")
    df = df[df["mapped_label"] != "OTHER"].copy()
    df["Label"] = df["mapped_label"]
    df = df.drop(columns=["mapped_label"])
    logger.info("[CIC-2018] %d rows after label mapping (dropped OTHER)", len(df))

    df = df.replace([np.inf, -np.inf], np.nan)

    # Add CIC-2017 features that CIC-2018 lacks (e.g., "Fwd Header Length.1" duplicate)
    if "Fwd Header Length.1" not in df.columns and "Fwd Header Length" in df.columns:
        df["Fwd Header Length.1"] = df["Fwd Header Length"]
    for c in CIC_FEATURE_COLUMNS:
        if c not in df.columns:
            df[c] = 0.0
        else:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

    df["__source"] = "cic2018"
    df = _zero_fill_missing_features(df)
    return df


def load_synthetic_balanced(hulk_cap: int, random_state: int) -> pd.DataFrame:
    if not SYNTHETIC_CSV.exists():
        raise FileNotFoundError(f"Synthetic CSV missing: {SYNTHETIC_CSV}. "
                                "Run scripts/synthetic/extract_flows.py first.")

    df = pd.read_csv(SYNTHETIC_CSV, low_memory=False)
    logger.info("[synthetic] %d rows loaded", len(df))

    # DoS Hulk swamps the synthetic set (130K of 143K). Cap it.
    if hulk_cap > 0:
        hulk_mask = df["Label"] == "DoS Hulk"
        if hulk_mask.sum() > hulk_cap:
            keep = pd.concat([
                df[~hulk_mask],
                df[hulk_mask].sample(n=hulk_cap, random_state=random_state),
            ], ignore_index=True)
            logger.info("[synthetic] DoS Hulk capped %d -> %d, total %d -> %d",
                        hulk_mask.sum(), hulk_cap, len(df), len(keep))
            df = keep

    df["__source"] = "synthetic"

    # Synthetic has all 81 features; spectral/YARA already populated.
    df = _zero_fill_missing_features(df)
    return df


def main() -> int:
    parser = argparse.ArgumentParser(description="Day 5 — combined retrain")
    parser.add_argument("--cic2017-sample", type=int, default=500_000,
                        help="Stratified sample size from CIC-2017 (0 = full)")
    parser.add_argument("--cic2018-sample", type=int, default=500_000,
                        help="Per-source sample size from CIC-2018 (0 = full; very RAM heavy)")
    parser.add_argument("--hulk-cap", type=int, default=10_000,
                        help="Max DoS Hulk rows from synthetic (otherwise dominates)")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--output", default=str(OUT_DIR))
    parser.add_argument("--skip-rf", action="store_true",
                        help="Skip RandomForest (slower, mostly for comparison)")
    args = parser.parse_args()

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ---- Load all three sources ----
    t0 = time.time()
    cic17 = load_cic2017(args.cic2017_sample, args.random_state)
    cic18 = load_cic2018(args.cic2018_sample, args.random_state)
    syn = load_synthetic_balanced(args.hulk_cap, args.random_state)
    logger.info("Loaded all sources in %.1fs", time.time() - t0)

    # ---- Concat ----
    combined = pd.concat([cic17, cic18, syn], ignore_index=True, sort=False)
    logger.info("Combined: %d rows", len(combined))

    src_dist = combined["__source"].value_counts()
    label_dist = combined["Label"].value_counts()
    logger.info("Per-source rows:\n%s", src_dist.to_string())
    logger.info("Per-label rows:\n%s", label_dist.to_string())

    # ---- Drop tiny classes that can't survive stratified split ----
    # Stratified train/test needs >= 2 samples per class for the test fold;
    # XGBoost also dislikes singletons.
    keep_labels = label_dist[label_dist >= 10].index
    dropped = set(label_dist.index) - set(keep_labels)
    if dropped:
        logger.warning("Dropping %d labels with <10 samples: %s", len(dropped), sorted(dropped))
        combined = combined[combined["Label"].isin(keep_labels)].reset_index(drop=True)

    # ---- Build X/y ----
    # Coerce every feature column to float, fill NaN/inf with zero.
    for c in ALL_FEATURE_COLUMNS:
        combined[c] = pd.to_numeric(combined[c], errors="coerce")
    combined[ALL_FEATURE_COLUMNS] = (combined[ALL_FEATURE_COLUMNS]
                                     .replace([np.inf, -np.inf], np.nan)
                                     .fillna(0.0))

    X = combined[ALL_FEATURE_COLUMNS].copy()
    y = combined["Label"].astype(str)
    src = combined["__source"].copy()
    logger.info("Feature matrix: %s (%d MB)", X.shape, X.memory_usage(deep=True).sum() // 1_000_000)

    # ---- Stratified split ----
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test, src_train, src_test = train_test_split(
        X, y, src,
        test_size=args.test_size, random_state=args.random_state, stratify=y,
    )
    logger.info("Train: %d, Test: %d", len(X_train), len(X_test))

    # ---- Preprocess ----
    pipeline = FeaturePipeline()
    X_train_p, y_train_e = pipeline.fit_transform(X_train, y_train)
    X_test_p, y_test_e = pipeline.transform(X_test, y_test)
    logger.info("Pipeline kept %d features after variance filter", len(pipeline.feature_names))

    # ---- Train models ----
    all_metrics = []

    logger.info("=== XGBoost (combined) ===")
    xgb = build_xgboost(random_state=args.random_state)
    xgb_metrics = evaluate_model(
        xgb, X_train_p, y_train_e, X_test_p, y_test_e,
        model_name="XGBoost-combined", feature_names=pipeline.feature_names,
    )
    all_metrics.append(xgb_metrics)
    joblib.dump(xgb, out_dir / "xgboost.joblib")

    if not args.skip_rf:
        logger.info("=== RandomForest (combined) ===")
        rf = build_random_forest(random_state=args.random_state)
        rf_metrics = evaluate_model(
            rf, X_train_p, y_train_e, X_test_p, y_test_e,
            model_name="RandomForest-combined", feature_names=pipeline.feature_names,
        )
        all_metrics.append(rf_metrics)
        joblib.dump(rf, out_dir / "random_forest.joblib")

    joblib.dump(pipeline, out_dir / "feature_pipeline.joblib")

    # ---- Per-source breakdown of test performance (the headline result) ----
    from sklearn.metrics import f1_score, classification_report
    y_test_arr = y_test.values
    y_pred_str = pipeline.label_encoder.inverse_transform(xgb.predict(X_test_p))

    per_source = {}
    for source_name in ["cic2017", "cic2018", "synthetic"]:
        mask = src_test.values == source_name
        if mask.sum() == 0:
            continue
        per_source[source_name] = {
            "n_test": int(mask.sum()),
            "f1_weighted": float(f1_score(y_test_arr[mask], y_pred_str[mask],
                                          average="weighted", zero_division=0)),
            "f1_macro": float(f1_score(y_test_arr[mask], y_pred_str[mask],
                                       average="macro", zero_division=0)),
            "report": classification_report(y_test_arr[mask], y_pred_str[mask],
                                            output_dict=True, zero_division=0),
        }
        logger.info("[XGB on %s] n=%d, F1 weighted=%.4f, F1 macro=%.4f",
                    source_name, per_source[source_name]["n_test"],
                    per_source[source_name]["f1_weighted"],
                    per_source[source_name]["f1_macro"])

    # ---- Save ----
    print_comparison(all_metrics, out_file=str(out_dir / "comparison.csv"))

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
            "top_features": [[name, float(imp)] for name, imp in m.feature_importance[:30]],
        })

    summary = {
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "n_features_input": int(len(ALL_FEATURE_COLUMNS)),
        "n_features_kept": int(len(pipeline.feature_names)),
        "per_source_train": src_train.value_counts().to_dict(),
        "per_source_test": src_test.value_counts().to_dict(),
        "per_label_train": y_train.value_counts().to_dict(),
        "per_label_test": y_test.value_counts().to_dict(),
        "models": metrics_json,
        "per_source_test_performance": per_source,
        "args": vars(args),
        "feature_order": ALL_FEATURE_COLUMNS,
    }
    (out_dir / "metrics.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )

    logger.info("Saved combined model + metrics to %s", out_dir)
    logger.info("Total wall time: %.1f min", (time.time() - t0) / 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
