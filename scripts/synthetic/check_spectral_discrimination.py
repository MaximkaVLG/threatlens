"""Quick check: do the 8 spectral features actually differ across attack classes?

Reads synthetic_flows.csv, prints per-class median + IQR for each spectral
feature, plus a Kruskal-Wallis p-value. If p > 0.05 across ALL features, the
feature is uninformative; if p < 0.001, it discriminates.

Run: python scripts/synthetic/check_spectral_discrimination.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import kruskal

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.spectral_features import SPECTRAL_FEATURE_COLUMNS  # noqa: E402

CSV = ROOT / "data" / "synthetic" / "synthetic_flows.csv"


def main() -> int:
    if not CSV.exists():
        print(f"Run extract_flows.py first; missing {CSV}", file=sys.stderr)
        return 1

    df = pd.read_csv(CSV)
    labels = sorted(df["Label"].unique())
    print(f"Loaded {len(df):,} flows, {len(labels)} classes: {labels}\n")

    # Cap each class at 5000 flows for fair statistical comparison (DoS Hulk
    # has 130K which would dominate KW test).
    pieces = []
    for lbl, g in df.groupby("Label"):
        pieces.append(g.sample(min(len(g), 5000), random_state=42))
    capped = pd.concat(pieces, ignore_index=True)
    print(f"Capped to {len(capped):,} flows for statistics:")
    print(capped["Label"].value_counts().to_string())
    print()

    print(f"{'Feature':<28} {'KW p-value':>12} {'Verdict':<14}")
    print("-" * 80)
    informative = 0
    for feat in SPECTRAL_FEATURE_COLUMNS:
        groups = [capped.loc[capped["Label"] == lbl, feat].dropna().values
                  for lbl in labels]
        groups = [g for g in groups if len(g) > 1]
        if len(groups) < 2:
            print(f"{feat:<28} {'-':>12} {'too few groups':<14}")
            continue
        try:
            stat, p = kruskal(*groups)
        except ValueError as e:
            print(f"{feat:<28} {'-':>12} {str(e)[:14]}")
            continue
        verdict = "DISCRIMINATES" if p < 0.001 else ("weak" if p < 0.05 else "uninformative")
        if p < 0.001:
            informative += 1
        print(f"{feat:<28} {p:>12.2e} {verdict:<14}")

    print()
    print(f"=> {informative} / {len(SPECTRAL_FEATURE_COLUMNS)} spectral features discriminate at p<0.001")
    print()

    # Show medians per class for the most discriminating feature
    print("Per-class median ± IQR for each spectral feature:")
    for feat in SPECTRAL_FEATURE_COLUMNS:
        print(f"\n  {feat}:")
        for lbl in labels:
            v = capped.loc[capped["Label"] == lbl, feat].dropna()
            if len(v) == 0:
                continue
            q25, q50, q75 = np.percentile(v, [25, 50, 75])
            nonzero = (v != 0).mean() * 100
            print(f"    {lbl:18s}  median={q50:>10.4g}  IQR=[{q25:>10.4g}, {q75:>10.4g}]  nonzero={nonzero:5.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
