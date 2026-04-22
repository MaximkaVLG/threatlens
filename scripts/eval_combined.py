"""Head-to-head: old CIC-2017-only model vs new combined model.

Runs both models on three hold-out sets:

1. **CIC-IDS2017 test slice** — in-distribution baseline. The new model
   should not lose much here (maybe drops 0.1-0.5 F1 points because we
   added rows from other distributions that compete for tree splits).
2. **CIC-IDS2018 sample** — cross-dataset. This is where the new model
   should shine; the old model scored F1=0.50-0.60.
3. **Synthetic hold-out** — out-of-distribution generator. Both models
   will see the *same* feature matrix but the new one has exposure to
   spectral + YARA signals at training time.

Output:
- Per-benchmark, per-class F1 / precision / recall
- Delta table: new - old (positive = improvement)
- JSON at ``results/combined_v2/head_to_head.json``

Usage:
    python scripts/eval_combined.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, f1_score, accuracy_score

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import CIC_FEATURE_COLUMNS  # noqa: E402
from threatlens.network.spectral_features import SPECTRAL_FEATURE_COLUMNS  # noqa: E402
from threatlens.network.payload_yara import YARA_FEATURE_COLUMNS  # noqa: E402
from scripts.eval_cross_dataset import (  # noqa: E402
    COL_MAP_2018_TO_2017, LABEL_MAP_2018_TO_2017,
)

OLD_MODEL_DIR = ROOT / "results" / "cicids2017"
NEW_MODEL_DIR = ROOT / "results" / "combined_v2"
OUT_JSON = NEW_MODEL_DIR / "head_to_head.json"

ALL_FEATURE_COLUMNS = (
    list(CIC_FEATURE_COLUMNS) + list(SPECTRAL_FEATURE_COLUMNS) + list(YARA_FEATURE_COLUMNS)
)


def _load_model(model_dir: Path, name: str = "xgboost"):
    """Load a joblib model + its feature pipeline."""
    model = joblib.load(model_dir / f"{name}.joblib")
    pipeline = joblib.load(model_dir / "feature_pipeline.joblib")
    return model, pipeline


def _predict_with_pipeline(model, pipeline, df: pd.DataFrame) -> np.ndarray:
    """Transform rows through pipeline, predict, return string labels."""
    # Align columns — the pipeline's feature_names might be a subset
    expected = pipeline.feature_names
    missing = [c for c in expected if c not in df.columns]
    for c in missing:
        df[c] = 0.0
    X = df[expected].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X_scaled = pipeline.scaler.transform(X.values)
    y_pred_int = model.predict(X_scaled)
    return pipeline.label_encoder.inverse_transform(y_pred_int)


def _metrics_report(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    return {
        "n": int(len(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "per_class": classification_report(y_true, y_pred, output_dict=True, zero_division=0),
    }


def eval_on_cic2017_sample(sample_size: int = 200_000) -> pd.DataFrame:
    """Load a stratified sample from CIC-2017 full CSV set for in-dist eval."""
    files = sorted((ROOT / "data" / "cicids2017").glob("*.csv"))
    parts = []
    for f in files:
        try:
            parts.append(pd.read_csv(f, low_memory=False, encoding="utf-8"))
        except UnicodeDecodeError:
            parts.append(pd.read_csv(f, low_memory=False, encoding="latin-1"))
    df = pd.concat(parts, ignore_index=True)
    df.columns = [c.strip() for c in df.columns]
    df["Label"] = df["Label"].astype(str).str.strip()
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=df.select_dtypes(include=[np.number]).columns)

    if len(df) > sample_size:
        # Stratified sample preserving label distribution
        parts = []
        for _, g in df.groupby("Label"):
            n = max(1, min(len(g), int(sample_size * len(g) / len(df))))
            parts.append(g.sample(n=n, random_state=1234))
        df = pd.concat(parts, ignore_index=True)
    return df


def eval_on_cic2018_sample(sample_size: int = 200_000) -> pd.DataFrame:
    files = sorted((ROOT / "data" / "cicids2018").glob("*.csv"))
    parts = []
    per_file = sample_size // len(files)
    for f in files:
        chunk = pd.read_csv(f, low_memory=False)
        chunk = chunk[chunk["Label"] != "Label"].copy()
        if len(chunk) > per_file:
            chunk = chunk.sample(n=per_file, random_state=1234)
        parts.append(chunk)
    df = pd.concat(parts, ignore_index=True)

    df = df.rename(columns=COL_MAP_2018_TO_2017)
    df["mapped_label"] = df["Label"].astype(str).str.strip().map(LABEL_MAP_2018_TO_2017).fillna("OTHER")
    df = df[df["mapped_label"] != "OTHER"].copy()
    df["Label"] = df["mapped_label"]
    df = df.drop(columns=["mapped_label"])

    if "Fwd Header Length.1" not in df.columns and "Fwd Header Length" in df.columns:
        df["Fwd Header Length.1"] = df["Fwd Header Length"]
    for c in CIC_FEATURE_COLUMNS:
        if c not in df.columns:
            df[c] = 0.0
        else:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
    return df


def eval_on_synthetic() -> pd.DataFrame:
    csv = ROOT / "data" / "synthetic" / "synthetic_flows.csv"
    df = pd.read_csv(csv, low_memory=False)
    # Cap DoS Hulk so one class doesn't drown the macro F1
    hulk_mask = df["Label"] == "DoS Hulk"
    if hulk_mask.sum() > 10_000:
        kept = pd.concat([
            df[~hulk_mask],
            df[hulk_mask].sample(n=10_000, random_state=1234),
        ], ignore_index=True)
        df = kept
    return df


def main() -> int:
    print("[1/4] Loading models")
    old_model, old_pipe = _load_model(OLD_MODEL_DIR, "xgboost")
    new_model, new_pipe = _load_model(NEW_MODEL_DIR, "xgboost")
    print(f"  Old pipeline: {len(old_pipe.feature_names)} features, {len(old_pipe.label_encoder.classes_)} classes")
    print(f"  New pipeline: {len(new_pipe.feature_names)} features, {len(new_pipe.label_encoder.classes_)} classes")

    benchmarks = {}

    for bench_name, loader in [
        ("cic2017_sample", eval_on_cic2017_sample),
        ("cic2018_sample", eval_on_cic2018_sample),
        ("synthetic", eval_on_synthetic),
    ]:
        print(f"\n[{bench_name}] loading")
        t0 = time.time()
        df = loader()
        print(f"  {len(df):,} rows in {time.time() - t0:.1f}s")

        y_true = df["Label"].values

        t0 = time.time()
        y_pred_old = _predict_with_pipeline(old_model, old_pipe, df.copy())
        print(f"  old predict: {time.time() - t0:.1f}s")

        t0 = time.time()
        y_pred_new = _predict_with_pipeline(new_model, new_pipe, df.copy())
        print(f"  new predict: {time.time() - t0:.1f}s")

        old_metrics = _metrics_report(y_true, y_pred_old)
        new_metrics = _metrics_report(y_true, y_pred_new)

        delta = {
            "accuracy": new_metrics["accuracy"] - old_metrics["accuracy"],
            "f1_weighted": new_metrics["f1_weighted"] - old_metrics["f1_weighted"],
            "f1_macro": new_metrics["f1_macro"] - old_metrics["f1_macro"],
        }

        print(f"  old: acc={old_metrics['accuracy']:.4f} "
              f"F1w={old_metrics['f1_weighted']:.4f} F1m={old_metrics['f1_macro']:.4f}")
        print(f"  new: acc={new_metrics['accuracy']:.4f} "
              f"F1w={new_metrics['f1_weighted']:.4f} F1m={new_metrics['f1_macro']:.4f}")
        print(f"  delta: F1w {delta['f1_weighted']:+.4f}  F1m {delta['f1_macro']:+.4f}")

        benchmarks[bench_name] = {
            "old": old_metrics,
            "new": new_metrics,
            "delta": delta,
        }

    # Summary table for console (ASCII only — Windows console is cp1251)
    print("\n" + "=" * 72)
    print(f"{'Benchmark':<22}{'Old F1w':>10}{'New F1w':>10}{'Delta':>10}  | "
          f"{'Old F1m':>10}{'New F1m':>10}{'Delta':>10}")
    print("-" * 72)
    for name, b in benchmarks.items():
        print(f"{name:<22}"
              f"{b['old']['f1_weighted']:>10.4f}"
              f"{b['new']['f1_weighted']:>10.4f}"
              f"{b['delta']['f1_weighted']:>+10.4f}  | "
              f"{b['old']['f1_macro']:>10.4f}"
              f"{b['new']['f1_macro']:>10.4f}"
              f"{b['delta']['f1_macro']:>+10.4f}")
    print("=" * 72)

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(benchmarks, indent=2, ensure_ascii=False, default=str),
                        encoding="utf-8")
    print(f"\nSaved: {OUT_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
