"""Diploma-defense plots: confusion matrix and top feature importances.

Runs the trained XGBoost detector on a balanced slice of real CIC-IDS2017
rows, then saves:
    docs/screenshots/confusion_matrix.png   — 15x15 heatmap, normalised per row
    docs/screenshots/feature_importance.png — horizontal bar top-20 features

Intended to be regenerated on demand; it reads the same joblib artefacts
that the web app uses.
"""

from __future__ import annotations

import glob
import os
import sys

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
from sklearn.metrics import confusion_matrix

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..")))

from threatlens.network import FlowDetector

DATA_DIR = os.path.join(_HERE, "..", "data", "cicids2017")
RESULTS_DIR = os.path.join(_HERE, "..", "results", "cicids2017")
OUT_DIR = os.path.join(_HERE, "..", "docs", "screenshots")

DARK_BG = "#111111"
FG = "#e0e0e0"
ACCENT = "#00d4ff"


def _dark_fig(w: float = 10, h: float = 8):
    fig, ax = plt.subplots(figsize=(w, h), facecolor=DARK_BG)
    ax.set_facecolor(DARK_BG)
    for spine in ax.spines.values():
        spine.set_color("#333")
    ax.tick_params(colors=FG)
    ax.xaxis.label.set_color(FG)
    ax.yaxis.label.set_color(FG)
    ax.title.set_color(ACCENT)
    return fig, ax


def load_balanced_slice(per_class: int = 1000) -> pd.DataFrame:
    files = sorted(glob.glob(os.path.join(DATA_DIR, "*.csv")))
    if not files:
        print(f"No CSVs in {DATA_DIR}", file=sys.stderr)
        sys.exit(1)
    parts = []
    for path in files:
        try:
            df = pd.read_csv(path, low_memory=False, encoding="utf-8")
        except UnicodeDecodeError:
            df = pd.read_csv(path, low_memory=False, encoding="latin-1")
        df.columns = [c.strip() for c in df.columns]
        if "Label" not in df.columns:
            continue
        df["Label"] = df["Label"].astype(str).str.strip()
        for _, group in df.groupby("Label"):
            parts.append(group.head(per_class))
    full = pd.concat(parts, ignore_index=True)
    full = full.replace([np.inf, -np.inf], np.nan).dropna(
        subset=full.select_dtypes(include=[np.number]).columns
    )
    return full


def plot_confusion_matrix(y_true, y_pred, labels, out_path: str):
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    # Row-normalise so per-class recall shows on the diagonal.
    with np.errstate(invalid="ignore", divide="ignore"):
        cm_norm = cm / cm.sum(axis=1, keepdims=True)
        cm_norm = np.nan_to_num(cm_norm)

    cmap = LinearSegmentedColormap.from_list(
        "threatlens", ["#111111", "#0a3a52", "#00d4ff"], N=256,
    )

    fig, ax = _dark_fig(11, 9)
    im = ax.imshow(cm_norm, interpolation="nearest", cmap=cmap, vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=9)
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xlabel("Predicted", fontsize=11)
    ax.set_ylabel("True", fontsize=11)
    ax.set_title(
        "Confusion matrix (row-normalised) — XGBoost on real CIC-IDS2017",
        fontsize=12, pad=14,
    )

    # Print recall values inside cells that have at least one sample
    thresh = 0.5
    for i in range(len(labels)):
        for j in range(len(labels)):
            val = cm_norm[i, j]
            if cm[i, j] == 0 and i != j:
                continue
            colour = "#000000" if val > thresh else FG
            ax.text(j, i, f"{val*100:.0f}", ha="center", va="center",
                    color=colour, fontsize=8)

    cbar = fig.colorbar(im, ax=ax, fraction=0.035, pad=0.02)
    cbar.ax.yaxis.set_tick_params(color=FG, labelsize=9)
    plt.setp(cbar.ax.get_yticklabels(), color=FG)
    cbar.set_label("recall", color=FG)
    cbar.outline.set_edgecolor("#333")

    fig.tight_layout()
    fig.savefig(out_path, dpi=130, facecolor=DARK_BG, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {os.path.relpath(out_path)}")


def plot_feature_importance(detector: FlowDetector, top_n: int, out_path: str):
    xgb = detector._models["xgboost"]
    names = detector._pipeline.feature_names
    importances = xgb.feature_importances_
    order = np.argsort(importances)[-top_n:]  # ascending so largest at top
    top_names = [names[i] for i in order]
    top_vals = importances[order]

    fig, ax = _dark_fig(10, 7)
    bars = ax.barh(range(top_n), top_vals, color=ACCENT, edgecolor="#006080")
    ax.set_yticks(range(top_n))
    ax.set_yticklabels(top_names, fontsize=10)
    ax.set_xlabel("Gain-based importance (XGBoost)", fontsize=11)
    ax.set_title(
        f"Top-{top_n} most predictive flow features",
        fontsize=12, pad=14,
    )
    for bar, val in zip(bars, top_vals):
        ax.text(val + top_vals.max() * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:.3f}", va="center", color=FG, fontsize=9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(out_path, dpi=130, facecolor=DARK_BG, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {os.path.relpath(out_path)}")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    print("Loading detector...")
    detector = FlowDetector.from_results_dir(RESULTS_DIR)

    print("Loading balanced CIC-IDS2017 slice...")
    df = load_balanced_slice(per_class=500)
    print(f"  {len(df)} rows, {df['Label'].nunique()} classes")

    print("Predicting with XGBoost...")
    preds = detector.predict(df, model="xgboost")
    y_true = df["Label"].values
    y_pred = preds["label"].values

    # Use the label_encoder's own class order for consistent axes
    labels_sorted = sorted(
        set(y_true) | set(y_pred),
        key=lambda s: ("BENIGN" != s, s.lower()),  # BENIGN first, then alpha
    )

    print("Plotting confusion matrix...")
    plot_confusion_matrix(y_true, y_pred, labels_sorted,
                          os.path.join(OUT_DIR, "confusion_matrix.png"))

    print("Plotting feature importance...")
    plot_feature_importance(
        detector, 20, os.path.join(OUT_DIR, "feature_importance.png")
    )

    print("\nDone.")


if __name__ == "__main__":
    main()
