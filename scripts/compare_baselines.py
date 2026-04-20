"""Baseline comparison for the diploma defense.

Runs five classifiers on the same 50K stratified slice of CIC-IDS2017 that
was used to train the production models:

    - Logistic Regression  (linear baseline, fastest)
    - Linear SVM           (linear-margin baseline)
    - Decision Tree        (non-linear non-ensemble baseline)
    - Random Forest        (ensemble baseline, identical hyper-params to prod)
    - XGBoost              (production champion)

Evaluation: 5-fold stratified cross-validation with identical preprocessing
(StandardScaler + LabelEncoder + VarianceThreshold), same random_state.
Reports weighted accuracy / precision / recall / F1 as `mean +/- std` plus
a 95% confidence interval. Also saves a bar chart to
docs/screenshots/baseline_comparison.png.

Usage:
    python scripts/compare_baselines.py
    python scripts/compare_baselines.py --sample-size 30000 --cv 3
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..")))

from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

from threatlens.ml.dataset import load_cicids2017, split_features_labels
from threatlens.ml.features import FeaturePipeline
from threatlens.ml.models import build_random_forest, build_xgboost
from threatlens.ml.evaluate import cross_validate_model, print_cv_comparison

RESULTS_DIR = os.path.join(_HERE, "..", "results", "cicids2017")
SCREENSHOTS_DIR = os.path.join(_HERE, "..", "docs", "screenshots")

DARK_BG = "#111111"
FG = "#e0e0e0"
ACCENT = "#00d4ff"
BASELINE_COLOUR = "#9c27b0"
CHAMPION_COLOUR = "#4caf50"


def baseline_factories(random_state: int) -> list[tuple[str, callable, str]]:
    """Return [(name, zero-arg factory, colour)] — lexicographic defense order."""
    return [
        (
            "LogisticRegression",
            lambda rs=random_state: LogisticRegression(
                solver="lbfgs", max_iter=1000,
                n_jobs=-1, random_state=rs,
            ),
            BASELINE_COLOUR,
        ),
        (
            "LinearSVC",
            lambda rs=random_state: LinearSVC(
                C=1.0, max_iter=2000, dual="auto", random_state=rs,
            ),
            BASELINE_COLOUR,
        ),
        (
            "DecisionTree",
            lambda rs=random_state: DecisionTreeClassifier(
                max_depth=None, class_weight="balanced", random_state=rs,
            ),
            BASELINE_COLOUR,
        ),
        (
            "RandomForest",
            lambda rs=random_state: build_random_forest(random_state=rs),
            CHAMPION_COLOUR,
        ),
        (
            "XGBoost",
            lambda rs=random_state: build_xgboost(random_state=rs),
            CHAMPION_COLOUR,
        ),
    ]


def plot_comparison(results, colours, out_path: str):
    """Horizontal grouped bar chart: F1 mean ± std per model."""
    names = [r.model_name for r in results]
    f1_means = [np.mean(r.f1) for r in results]
    f1_stds = [np.std(r.f1, ddof=1) if len(r.f1) > 1 else 0 for r in results]
    train_means = [np.mean(r.train_time) for r in results]

    fig, (ax1, ax2) = plt.subplots(
        1, 2, figsize=(13, 5), facecolor=DARK_BG,
        gridspec_kw={"width_ratios": [2, 1]},
    )

    # F1 bar chart with error bars
    y = np.arange(len(names))
    ax1.barh(y, f1_means, xerr=f1_stds, color=colours,
             edgecolor="#222", error_kw=dict(ecolor=FG, capsize=4))
    for i, (m, s) in enumerate(zip(f1_means, f1_stds)):
        ax1.text(m + 0.005, i, f"{m:.4f} ±{s:.4f}",
                 color=FG, fontsize=10, va="center")
    ax1.set_yticks(y)
    ax1.set_yticklabels(names, fontsize=11)
    ax1.set_xlim(0.5, 1.02)
    ax1.set_xlabel("weighted F1 (5-fold CV)", color=FG, fontsize=11)
    ax1.set_title("Модели — качество", color=ACCENT, fontsize=13, pad=12)
    _style_axis(ax1)

    # Train time bar chart (log scale)
    ax2.barh(y, train_means, color=colours, edgecolor="#222")
    for i, t in enumerate(train_means):
        ax2.text(t * 1.05, i, f"{t:.1f}s", color=FG, fontsize=10, va="center")
    ax2.set_yticks(y)
    ax2.set_yticklabels([])
    ax2.set_xscale("log")
    ax2.set_xlabel("avg fold train time, seconds (log)", color=FG, fontsize=11)
    ax2.set_title("Модели — скорость", color=ACCENT, fontsize=13, pad=12)
    _style_axis(ax2)

    fig.suptitle(
        "Baselines vs production на CIC-IDS2017 (50K stratified, 5-fold CV)",
        color=ACCENT, fontsize=14, y=0.98,
    )
    fig.tight_layout()
    fig.savefig(out_path, dpi=130, facecolor=DARK_BG, bbox_inches="tight")
    plt.close(fig)


def _style_axis(ax):
    ax.set_facecolor(DARK_BG)
    for s in ax.spines.values():
        s.set_color("#333")
    ax.tick_params(colors=FG)
    ax.grid(axis="x", color="#222", linestyle="-", linewidth=0.5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default="data/cicids2017")
    parser.add_argument("--sample-size", type=int, default=50000)
    parser.add_argument("--cv", type=int, default=5)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

    print(f"Loading CIC-IDS2017 ({args.sample_size} samples)...")
    df = load_cicids2017(
        args.data_dir, sample_size=args.sample_size, random_state=args.random_state,
    )
    print(f"  {len(df)} rows, {df['Label'].nunique()} classes")

    X, y_multi, _ = split_features_labels(df)
    pipeline = FeaturePipeline()
    X_proc, y_enc = pipeline.fit_transform(X, y_multi)
    print(f"  preprocessed: {X_proc.shape}, {len(pipeline.label_encoder.classes_)} classes")

    factories = baseline_factories(args.random_state)

    results = []
    colours = []
    for name, factory, colour in factories:
        print(f"\n=== {name} — 5-fold CV ===")
        t0 = time.perf_counter()
        try:
            res = cross_validate_model(
                factory, X_proc, y_enc,
                n_splits=args.cv, random_state=args.random_state,
                model_name=name,
            )
            print(f"  done in {time.perf_counter() - t0:.1f}s")
            results.append(res)
            colours.append(colour)
        except Exception as e:
            print(f"  FAILED: {e}")

    out_csv = os.path.join(RESULTS_DIR, "baseline_comparison.csv")
    print_cv_comparison(results, out_file=out_csv)
    print(f"\nNumeric results saved to {out_csv}")

    out_png = os.path.join(SCREENSHOTS_DIR, "baseline_comparison.png")
    plot_comparison(results, colours, out_png)
    print(f"Chart saved to {out_png}")


if __name__ == "__main__":
    main()
