"""Diploma defense demo: evaluate the trained detector on a real CIC-IDS2017 slice.

Load a few thousand rows from every attack class present in the 8 CSV files
and run them through the FlowDetector exactly as the web API does. Prints a
per-class confusion summary plus overall accuracy/precision/recall/F1 so the
numbers reported in the thesis are reproducible with one command.

Usage:
    python scripts/demo_benchmark.py
    python scripts/demo_benchmark.py --per-class 2000 --model xgboost
"""

from __future__ import annotations

import argparse
import glob
import os
import sys
import time
from collections import Counter

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, classification_report,
)

# Make `threatlens` importable whether script is run from repo root or scripts/.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..")))

from threatlens.network import FlowDetector


def load_balanced_slice(csv_dir: str, per_class: int) -> pd.DataFrame:
    """Read every CIC-IDS2017 CSV, cap each Label to `per_class` rows."""
    files = sorted(glob.glob(os.path.join(csv_dir, "*.csv")))
    if not files:
        print(f"No CSVs in {csv_dir!r} — download CIC-IDS2017 first.", file=sys.stderr)
        sys.exit(1)

    parts: list[pd.DataFrame] = []
    for path in files:
        try:
            df = pd.read_csv(path, low_memory=False, encoding="utf-8")
        except UnicodeDecodeError:
            df = pd.read_csv(path, low_memory=False, encoding="latin-1")
        df.columns = [c.strip() for c in df.columns]
        if "Label" not in df.columns:
            continue
        df["Label"] = df["Label"].astype(str).str.strip()
        for label, group in df.groupby("Label"):
            parts.append(group.head(per_class))

    full = pd.concat(parts, ignore_index=True)
    full = full.replace([np.inf, -np.inf], np.nan).dropna(
        subset=full.select_dtypes(include=[np.number]).columns
    )
    return full


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default="data/cicids2017")
    parser.add_argument("--results-dir", default="results/cicids2017")
    parser.add_argument("--per-class", type=int, default=1000,
                        help="Max rows sampled per attack class (default: 1000)")
    parser.add_argument("--model", choices=["xgboost", "random_forest"], default="xgboost")
    args = parser.parse_args()

    print(f"Loading CIC-IDS2017 slice from {args.data_dir!r} "
          f"({args.per_class} per class)...")
    t0 = time.perf_counter()
    df = load_balanced_slice(args.data_dir, args.per_class)
    print(f"  {len(df)} rows, {df['Label'].nunique()} classes, "
          f"loaded in {time.perf_counter() - t0:.1f}s")
    print(f"  class distribution: {dict(Counter(df['Label']))}")

    print(f"\nLoading detector from {args.results_dir!r}...")
    detector = FlowDetector.from_results_dir(args.results_dir)

    print(f"Running {args.model} on {len(df)} flows...")
    t0 = time.perf_counter()
    preds = detector.predict(df, model=args.model)
    pred_time = time.perf_counter() - t0
    print(f"  predicted in {pred_time:.2f}s "
          f"({len(df) / pred_time:.0f} flows/sec)")

    y_true = df["Label"].values
    y_pred = preds["label"].values

    print("\n" + "=" * 60)
    print(f"OVERALL METRICS ({args.model})")
    print("=" * 60)
    print(f"  accuracy : {accuracy_score(y_true, y_pred):.4f}")
    print(f"  precision: {precision_score(y_true, y_pred, average='weighted', zero_division=0):.4f}")
    print(f"  recall   : {recall_score(y_true, y_pred, average='weighted', zero_division=0):.4f}")
    print(f"  f1       : {f1_score(y_true, y_pred, average='weighted', zero_division=0):.4f}")
    print()

    print("PER-CLASS REPORT")
    print("=" * 60)
    print(classification_report(y_true, y_pred, zero_division=0, digits=4))

    # Simple confusion count: how many rows of each true label got the right prediction
    hits = (y_true == y_pred).astype(int)
    by_label = (
        pd.DataFrame({"label": y_true, "hit": hits})
        .groupby("label")["hit"].agg(["sum", "count"])
        .assign(accuracy=lambda d: d["sum"] / d["count"])
        .sort_values("accuracy", ascending=False)
    )
    print("\nPER-CLASS ACCURACY")
    print("=" * 60)
    for label, row in by_label.iterrows():
        bar = "#" * int(row["accuracy"] * 40)
        print(f"  {label:35s}  {row['sum']:>5}/{row['count']:<5}  {row['accuracy']*100:5.1f}%  {bar}")


if __name__ == "__main__":
    main()
