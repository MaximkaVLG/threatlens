"""Sanity check: train XGBoost on synthetic flows, test on synthetic flows.

If F1 weighted < 0.95, the generator is producing flows the model cannot
distinguish — investigate before relying on synthetic data for retraining.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler
import xgboost as xgb

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import CIC_FEATURE_COLUMNS  # noqa: E402

CSV = ROOT / "data" / "synthetic" / "synthetic_flows.csv"
OUT = ROOT / "results" / "synthetic_sanity.json"


def main() -> int:
    if not CSV.exists():
        print(f"Run extract_flows.py first; missing {CSV}", file=sys.stderr)
        return 1

    df = pd.read_csv(CSV)
    print(f"Loaded {len(df):,} flows across {df['Label'].nunique()} labels")
    print(df["Label"].value_counts())

    # Drop labels with too few samples for stratified CV
    counts = df["Label"].value_counts()
    keep = counts[counts >= 5].index
    df = df[df["Label"].isin(keep)].reset_index(drop=True)
    print(f"After min-5 filter: {len(df):,} flows, {df['Label'].nunique()} labels")

    feature_cols = [c for c in CIC_FEATURE_COLUMNS if c in df.columns]
    print(f"Features available: {len(feature_cols)} / {len(CIC_FEATURE_COLUMNS)}")
    if "Fwd Header Length.1" not in df.columns and "Fwd Header Length" in df.columns:
        df["Fwd Header Length.1"] = df["Fwd Header Length"]
        feature_cols.append("Fwd Header Length.1")

    X = df[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0).values.astype(float)
    y_str = df["Label"].values
    le = LabelEncoder()
    y = le.fit_transform(y_str)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    n_splits = min(5, int(counts.min()))
    print(f"\nRunning {n_splits}-fold stratified CV...")
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    fold_f1 = []
    for fold, (tr, te) in enumerate(cv.split(X_scaled, y), 1):
        clf = xgb.XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            random_state=42, n_jobs=-1, tree_method="hist",
            verbosity=0,
        )
        clf.fit(X_scaled[tr], y[tr])
        pred = clf.predict(X_scaled[te])
        f1 = f1_score(y[te], pred, average="weighted", zero_division=0)
        fold_f1.append(float(f1))
        print(f"  fold {fold}: F1 = {f1:.4f}")

    mean_f1 = float(np.mean(fold_f1))
    std_f1 = float(np.std(fold_f1))
    print(f"\n{n_splits}-fold F1 weighted: {mean_f1:.4f} ± {std_f1:.4f}")

    # Final fit on all data, print per-class report (informational only)
    clf = xgb.XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        random_state=42, n_jobs=-1, tree_method="hist", verbosity=0,
    )
    clf.fit(X_scaled, y)
    pred_all = clf.predict(X_scaled)
    report = classification_report(le.inverse_transform(y),
                                    le.inverse_transform(pred_all),
                                    output_dict=True, zero_division=0)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "n_flows": int(len(df)),
        "n_classes": int(df["Label"].nunique()),
        "labels": sorted(df["Label"].unique().tolist()),
        "cv_folds": n_splits,
        "cv_f1_weighted_mean": mean_f1,
        "cv_f1_weighted_std": std_f1,
        "cv_f1_per_fold": fold_f1,
        "in_sample_classification_report": report,
    }, indent=2))

    verdict = "PASS" if mean_f1 >= 0.95 else "INVESTIGATE"
    print(f"\nVerdict: {verdict} (threshold 0.95 from improvement_plan.md)")
    print(f"Written: {OUT}")
    return 0 if mean_f1 >= 0.95 else 2


if __name__ == "__main__":
    sys.exit(main())
