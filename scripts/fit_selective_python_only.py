"""Day 9c — fit the Mahalanobis abstainer on the python_only model.

Day 9 / 9b result: python_only model has 91.6 % real-world ATTACK recall
but predicts everything in benign DNS/TLS captures as 'Bot'. Adding
diverse synthetic benign + class weighting only fixed 2 of 91 false
positives.

The Day 8 selective-prediction work (MahalanobisAbstainer) was built
exactly for this: when a flow lives outside the training distribution
it gets abstained on rather than mislabelled as the nearest class.

This script fits a fresh abstainer on the python_only training set
(synthetic + CTU-train + diverse benign), tunes per-class thresholds
on an internal val split, and saves it next to the model. It is then
applied at eval time by the existing eval_python_only.py path that
loads it.

Usage:
    python scripts/fit_selective_python_only.py
    python scripts/fit_selective_python_only.py --target-coverage 0.90
"""
from __future__ import annotations

import argparse
import json
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
from threatlens.ml.selective import MahalanobisAbstainer  # noqa: E402

ALL_FEATURES = (list(CIC_FEATURE_COLUMNS) + list(SPECTRAL_FEATURE_COLUMNS)
                + list(YARA_FEATURE_COLUMNS))

MODEL_DIR = ROOT / "results" / "python_only"
SYNTHETIC_CSV = ROOT / "data" / "synthetic" / "synthetic_flows.csv"
DIVERSE_BENIGN_PARQUET = MODEL_DIR / "diverse_benign_flows.parquet"
ATTACK_VOLUME_PARQUET = MODEL_DIR / "attack_volume_flows.parquet"
CTU_HOLDOUT_PARQUET = MODEL_DIR / "ctu_test_holdout.parquet"
CACHE_PARQUET = ROOT / "results" / "real_world_flows_cache.parquet"


def load_train_set() -> pd.DataFrame:
    """Reconstruct the same train pool used by train_python_only.py."""
    syn = pd.read_csv(SYNTHETIC_CSV, low_memory=False)
    syn["Label"] = syn["Label"].astype(str).str.strip()
    # Same hulk cap = 10000 default
    hulk = syn["Label"] == "DoS Hulk"
    if hulk.sum() > 10_000:
        syn = pd.concat([syn[~hulk], syn[hulk].sample(n=10_000, random_state=42)],
                         ignore_index=True)

    cache = pd.read_parquet(CACHE_PARQUET)
    ctu_all = cache[cache["__source"].str.startswith("botnet-")].copy()
    ctu_all["Label"] = "Bot"
    # Take same 70 % per-source split as training
    rng = np.random.default_rng(42)
    train_parts = []
    for src, g in ctu_all.groupby("__source"):
        idx = np.arange(len(g))
        rng.shuffle(idx)
        n_tr = int(len(g) * 0.70)
        train_parts.append(g.iloc[idx[:n_tr]])
    ctu_train = pd.concat(train_parts, ignore_index=True)

    diverse = pd.DataFrame()
    if DIVERSE_BENIGN_PARQUET.exists():
        diverse = pd.read_parquet(DIVERSE_BENIGN_PARQUET)
        diverse["Label"] = "BENIGN"

    attack_vol = pd.DataFrame()
    if ATTACK_VOLUME_PARQUET.exists():
        attack_vol = pd.read_parquet(ATTACK_VOLUME_PARQUET)

    parts = [syn, ctu_train]
    if not diverse.empty:
        parts.append(diverse)
    if not attack_vol.empty:
        parts.append(attack_vol)
    train = pd.concat(parts, ignore_index=True, sort=False)
    return train


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser()
    parser.add_argument("--target-coverage", type=float, default=0.95,
                        help="Fraction of correctly-classified training "
                             "flows to retain (default 0.95)")
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    t0 = time.time()
    print(f"[1/4] Loading python_only model")
    clf = joblib.load(MODEL_DIR / "xgboost.joblib")
    pipeline = joblib.load(MODEL_DIR / "feature_pipeline.joblib")
    print(f"  features: {len(pipeline.feature_names)}")
    print(f"  classes:  {list(pipeline.label_encoder.classes_)}")

    print(f"\n[2/4] Reconstructing training pool")
    train = load_train_set()
    counts = train["Label"].value_counts()
    keep = counts[counts >= 5].index
    train = train[train["Label"].isin(keep)].reset_index(drop=True)
    print(f"  train rows: {len(train):,}")
    print(f"  per label: {train['Label'].value_counts().to_dict()}")

    # Align columns and clean
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
        X_scaled, y, test_size=0.30, random_state=args.random_state,
        stratify=y,
    )
    print(f"  fit: {len(X_fit):,}, val: {len(X_val):,}")

    print(f"\n[3/4] Fitting Mahalanobis abstainer")
    abstainer = MahalanobisAbstainer().fit(
        X_fit, y_fit,
        classes=list(range(len(pipeline.label_encoder.classes_))),
    )
    y_val_pred = clf.predict(X_val)
    tune = abstainer.tune_thresholds(X_val, y_val, y_val_pred,
                                      target_coverage=args.target_coverage)
    print(f"  per-class thresholds: {abstainer.thresholds}")
    print(f"  global fallback:      {abstainer._global_fallback:.4f}")
    print(f"  achieved coverage:    {tune.get('achieved_coverage', 'n/a')}")

    print(f"\n[4/4] Saving abstainer + summary")
    out_path = MODEL_DIR / "mahalanobis_abstainer.joblib"
    joblib.dump(abstainer, out_path)
    summary = {
        "target_coverage": args.target_coverage,
        "achieved_coverage": tune.get("achieved_coverage"),
        "n_train": int(len(X_fit)),
        "n_val": int(len(X_val)),
        "thresholds": {str(k): float(v) for k, v in abstainer.thresholds.items()},
        "global_fallback": float(abstainer._global_fallback),
        "wall_time_s": round(time.time() - t0, 2),
    }
    (MODEL_DIR / "mahalanobis_abstainer_summary.json").write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(f"  saved: {out_path}")
    print(f"  wall time: {time.time()-t0:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
