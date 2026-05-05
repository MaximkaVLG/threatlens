"""Day 13.1 — evaluate the python_only model on the live-ingested sandbox PCAPs.

These are PCAPs the model has NEVER seen — neither in training nor in our
8-PCAP "real_pcap" test set. They are 2024-2026 malware captures pulled
on the day this evaluation runs. The point is to answer: does the model
generalise to threats that didn't exist when CTU-13 was assembled?

Differences from `eval_python_only.py`:

  - Uses `results/python_only/sandbox_malware_flows.parquet` produced by
    `extract_sandbox_pcaps.py`, not the cached real_pcap parquet.
  - All sandbox samples are labelled `Bot` (modern C2/stealer/RAT
    families collapsed to the closest existing class). So precision
    can't be computed against a benign baseline — we report:
        * recall_attack    = fraction of Bot flows predicted as ANY attack class
        * recall_exact_bot = fraction predicted as `Bot` specifically
        * abstain_rate     = fraction the Mahalanobis abstainer would defer
  - Per-capture and per-family breakdowns so a reviewer can see WHICH
    modern families work and which don't.

Usage:
    python scripts/eval_sandbox.py
    python scripts/eval_sandbox.py --in results/python_only/sandbox_malware_flows.parquet
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import CIC_FEATURE_COLUMNS  # noqa: E402
from threatlens.network.spectral_features import SPECTRAL_FEATURE_COLUMNS  # noqa: E402
from threatlens.network.payload_yara import YARA_FEATURE_COLUMNS  # noqa: E402

ALL_FEATURES = (list(CIC_FEATURE_COLUMNS) + list(SPECTRAL_FEATURE_COLUMNS)
                + list(YARA_FEATURE_COLUMNS))

MODEL_DIR = ROOT / "results" / "python_only"
DEFAULT_PARQUET = MODEL_DIR / "sandbox_malware_flows.parquet"
DEFAULT_OUT_JSON = MODEL_DIR / "sandbox_eval.json"


def to_binary(label: str) -> str:
    return "BENIGN" if label == "BENIGN" else "ATTACK"


def main(argv=None) -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser()
    parser.add_argument("--in-parquet", type=Path, default=DEFAULT_PARQUET,
                         help="Parquet of sandbox flows. Default = full file. "
                              "Use sandbox_holdout_flows.parquet for the "
                              "Phase 1 holdout-only eval.")
    parser.add_argument("--out-json", type=Path, default=None,
                         help="Output JSON. Default = "
                              "<model-dir>/sandbox_eval.json.")
    parser.add_argument("--model-dir", type=Path, default=MODEL_DIR,
                         help="Model bundle directory. Default "
                              "results/python_only/. Use results/v2/ for the "
                              "Phase 1 v2 retrain candidate.")
    args = parser.parse_args(argv)

    model_dir = args.model_dir
    out_json = args.out_json or (model_dir / "sandbox_eval.json")

    if not args.in_parquet.exists():
        print(f"ERROR: {args.in_parquet} not found.")
        print("Run: python scripts/ingest_sandbox_pcaps.py --source all --limit 20")
        print("     python scripts/extract_sandbox_pcaps.py")
        return 1

    print(f"[1/4] Loading sandbox flows from {args.in_parquet.name}  "
          f"(model dir: {model_dir.name})")
    df = pd.read_parquet(args.in_parquet)
    print(f"  total flows: {len(df)}")
    print(f"  per-label:    {dict(df['Label'].value_counts())}")
    print(f"  per-source:   {dict(df['__sandbox_source'].value_counts())}")
    print(f"  unique PCAPs: {df['__source_pcap'].nunique()}")
    print(f"  date range:   {sorted(df['__captured_date'].dropna().unique())[:1]} "
          f"... {sorted(df['__captured_date'].dropna().unique())[-1:] if df['__captured_date'].notna().any() else '?'}")

    print("\n[2/4] Loading model + pipeline + abstainer")
    clf = joblib.load(model_dir / "xgboost.joblib")
    pipeline = joblib.load(model_dir / "feature_pipeline.joblib")
    abstainer_path = model_dir / "mahalanobis_abstainer.joblib"
    abstainer = joblib.load(abstainer_path) if abstainer_path.exists() else None

    expected = pipeline.feature_names
    for c in expected:
        if c not in df.columns:
            df[c] = 0.0
    X_raw = df[expected].apply(lambda s: pd.to_numeric(s, errors="coerce")) \
                        .replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X_scaled = pipeline.scaler.transform(X_raw.values.astype(np.float64))

    print("\n[3/4] Predicting")
    t0 = time.time()
    y_int = clf.predict(X_scaled)
    y_pred = pipeline.label_encoder.inverse_transform(y_int)
    y_proba = clf.predict_proba(X_scaled).max(axis=1)
    print(f"  predict wall time: {time.time() - t0:.2f}s "
          f"({len(df)/(time.time()-t0):.0f} flows/s)")

    abstain_mask = None
    if abstainer is not None:
        abstain_mask, _ = abstainer.should_abstain(X_scaled, y_int)
        print(f"  abstainer: {int(abstain_mask.sum())}/{len(df)} "
              f"({abstain_mask.mean()*100:.1f}%) flagged for review")

    df = df.copy()
    df["pred_label"] = y_pred
    df["pred_confidence"] = y_proba
    df["pred_is_attack"] = df["pred_label"] != "BENIGN"
    df["pred_is_bot"] = df["pred_label"] == "Bot"
    if abstain_mask is not None:
        df["abstained"] = abstain_mask
    else:
        df["abstained"] = False

    print("\n[4/4] Aggregating results")
    print("=" * 90)

    # Headline numbers — only for ATTACK ground truth (all sandbox flows are
    # labelled "Bot", but be defensive for future BENIGN samples).
    attack_df = df[df["Label"] != "BENIGN"]
    n_attack = len(attack_df)
    if n_attack == 0:
        print("ERROR: No attack-labelled flows in sandbox dataset.")
        return 1

    n_detected = int(attack_df["pred_is_attack"].sum())
    n_exact_bot = int(attack_df["pred_is_bot"].sum())
    n_abstained_attack = int(attack_df["abstained"].sum())
    recall_attack = n_detected / n_attack
    recall_exact_bot = n_exact_bot / n_attack

    print(f"HEADLINE: live-ingested 2024-2026 sandbox PCAPs")
    print(f"  total attack flows:     {n_attack:>5d}")
    print(f"  detected (any attack):  {n_detected:>5d}    recall={recall_attack:.4f}")
    print(f"  exact 'Bot' label:      {n_exact_bot:>5d}    recall={recall_exact_bot:.4f}")
    if abstainer is not None:
        print(f"  abstained (review):     {n_abstained_attack:>5d}    "
              f"({n_abstained_attack/max(n_attack,1)*100:.1f}%)")
    print(f"  mean confidence:        {attack_df['pred_confidence'].mean():.4f}")

    # Per-capture breakdown
    per_capture = []
    print("\nPer-capture (sorted by recall ascending — worst first):")
    print(f"{'capture':<55}{'flows':>7}{'detected':>10}{'recall':>9}{'family':>15}")
    print("-" * 96)
    for cap, g in attack_df.groupby("__source_pcap"):
        n = len(g)
        det = int(g["pred_is_attack"].sum())
        rec = det / n if n > 0 else 0.0
        family = g["__family"].iloc[0] if "__family" in g.columns else ""
        date = g["__captured_date"].iloc[0] if "__captured_date" in g.columns else ""
        per_capture.append({
            "source_pcap": cap, "n_flows": n, "n_detected": det,
            "recall": rec, "family": str(family), "captured_date": str(date),
            "label_distribution": dict(Counter(g["pred_label"].tolist())),
        })
    per_capture.sort(key=lambda r: r["recall"])
    for r in per_capture:
        cap_short = r["source_pcap"][:54]
        print(f"  {cap_short:<53}{r['n_flows']:>7d}{r['n_detected']:>10d}"
              f"{r['recall']:>9.3f}{r['family'][:14]:>15}")

    # Per-family aggregate
    per_family = []
    if "__family" in attack_df.columns:
        print("\nPer-family aggregate:")
        for fam, g in attack_df.groupby("__family"):
            n = len(g)
            det = int(g["pred_is_attack"].sum())
            per_family.append({
                "family": str(fam), "n_flows": n, "n_detected": det,
                "recall": det / n if n > 0 else 0.0,
            })
        per_family.sort(key=lambda r: r["recall"])
        for r in per_family:
            print(f"  {r['family']:<25}  {r['n_flows']:>5d} flows  "
                  f"detected={r['n_detected']:>5d}  recall={r['recall']:.3f}")

    # Per-source aggregate
    per_source = []
    print("\nPer-source aggregate (stratosphere vs mta):")
    for src, g in attack_df.groupby("__sandbox_source"):
        n = len(g)
        det = int(g["pred_is_attack"].sum())
        per_source.append({
            "source": str(src), "n_flows": n, "n_detected": det,
            "recall": det / n if n > 0 else 0.0,
        })
    for r in per_source:
        print(f"  {r['source']:<20}  {r['n_flows']:>5d} flows  "
              f"detected={r['n_detected']:>5d}  recall={r['recall']:.3f}")

    print("=" * 90)

    out = {
        "n_pcaps": int(df["__source_pcap"].nunique()),
        "n_flows_total": int(len(df)),
        "n_attack_flows": int(n_attack),
        "headline": {
            "recall_attack": float(recall_attack),
            "recall_exact_bot": float(recall_exact_bot),
            "n_detected_any_attack": int(n_detected),
            "n_exact_bot": int(n_exact_bot),
            "abstain_rate": float(n_abstained_attack / max(n_attack, 1))
                             if abstainer is not None else None,
            "mean_confidence": float(attack_df["pred_confidence"].mean()),
        },
        "per_capture": per_capture,
        "per_family": per_family,
        "per_source": per_source,
    }
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(out, indent=2, default=str),
                              encoding="utf-8")
    print(f"\nSaved: {out_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
