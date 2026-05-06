"""Phase 3 — adversarial baseline against the v2 model.

For each (perturbation, strength) pair we:
  1. Apply the perturbation to each holdout PCAP via perturb_pcap.py
  2. Re-extract flows from the perturbed PCAP
  3. Run them through the v2 model + abstainer
  4. Record recall_attack (and how flow boundaries shifted)

The grid is 4 perturbations × 4 strengths × 9 holdout PCAPs = 144 cells,
runs in ~10-20 minutes on a laptop. Output:

    results/v2/adversarial_eval.json   per-cell raw counts
    results/v2/adversarial_eval.md     reviewer-facing table

What we expect to find (and what would surprise us):

  Expected:  IAT-jitter aggressive → recall drops 20-40 pp (model relies
             on Flow IAT features per Day 9e feature importance).
  Expected:  Padding → recall stable; payload-length features dominated
             by max/mean/min-bounded numbers, padding shifts mean only.
  Expected:  TTL randomisation → no measurable effect (model doesn't
             use TTL).
  Expected:  RST inject → small recall drop, RST injection changes flag
             counts which v2 does use moderately.

If any of these don't match, we report it as an unexpected finding and
investigate. The point isn't to pass an evasion test (no honest detector
does), it's to publish the floor.

Usage:
    python scripts/adversarial_eval.py
    python scripts/adversarial_eval.py --model-dir results/python_only
    python scripts/adversarial_eval.py --perturbations iat_jitter,packet_padding
"""
from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
import time
from pathlib import Path
from typing import Dict, List

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="scapy")

from threatlens.network.flow_extractor import FlowExtractor  # noqa: E402
from scripts.perturb_pcap import (  # noqa: E402
    perturb, PERTURBATIONS, STRENGTH_LEVELS,
)

logger = logging.getLogger("adversarial_eval")

DEFAULT_MODEL_DIR = ROOT / "results" / "v2"
SANDBOX_DIR = ROOT / "data" / "sandbox_malware"
SPLIT_JSON = ROOT / "results" / "python_only" / "sandbox_split.json"


def predict_attack(model, pipeline, df: pd.DataFrame) -> np.ndarray:
    """Returns a boolean array: True where pred != BENIGN."""
    expected = pipeline.feature_names
    for c in expected:
        if c not in df.columns:
            df[c] = 0.0
    X = (df[expected].apply(lambda s: pd.to_numeric(s, errors="coerce"))
                       .replace([np.inf, -np.inf], np.nan).fillna(0.0)
                       .values.astype(np.float64))
    Xs = pipeline.scaler.transform(X)
    y_int = model.predict(Xs)
    y_label = pipeline.label_encoder.inverse_transform(y_int)
    return (y_label != "BENIGN")


def find_pcap_on_disk(basename: str) -> Path:
    """Resolve sandbox holdout PCAP basename to its absolute path."""
    candidates = [
        SANDBOX_DIR / "stratosphere" / basename,
        SANDBOX_DIR / "mta" / basename,
    ]
    for c in candidates:
        if c.exists():
            return c
    raise FileNotFoundError(f"Holdout PCAP not on disk: {basename}")


def main(argv=None) -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    p = argparse.ArgumentParser()
    p.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    p.add_argument("--perturbations", default=",".join(PERTURBATIONS),
                    help="Comma-separated perturbation names. Default = all 4.")
    p.add_argument("--strengths", default=",".join(STRENGTH_LEVELS),
                    help="Comma-separated strength levels. Default = all 4.")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--keep-perturbed", action="store_true",
                    help="Keep the per-cell perturbed PCAPs after eval. "
                          "Default deletes (they're huge). Useful for repro.")
    p.add_argument("--verbose", "-v", action="count", default=0)
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(message)s")

    perturbations = [s.strip() for s in args.perturbations.split(",")
                      if s.strip()]
    strengths = [s.strip() for s in args.strengths.split(",")
                  if s.strip()]
    bad = (set(perturbations) - set(PERTURBATIONS)) | \
          (set(strengths) - set(STRENGTH_LEVELS))
    if bad:
        print(f"ERROR: unknown perturbation/strength: {bad}", file=sys.stderr)
        return 1

    model_dir = args.model_dir.resolve()
    print(f"=== Adversarial baseline on {model_dir.name} ===\n")

    print("[1/5] Loading model + pipeline + abstainer")
    clf = joblib.load(model_dir / "xgboost.joblib")
    pipeline = joblib.load(model_dir / "feature_pipeline.joblib")
    abstainer_path = model_dir / "mahalanobis_abstainer.joblib"
    abstainer = joblib.load(abstainer_path) if abstainer_path.exists() else None
    print(f"  abstainer: {'loaded' if abstainer else 'not present'}")

    print("\n[2/5] Loading holdout split")
    split = json.loads(SPLIT_JSON.read_text(encoding="utf-8"))
    holdout_pcaps = [meta["pcap"] for meta in split["holdout"]["pcaps"]]
    print(f"  holdout PCAPs: {len(holdout_pcaps)}")

    print("\n[3/5] Computing baseline (no perturbation)")
    extractor = FlowExtractor()
    baseline_results = []
    for basename in holdout_pcaps:
        pcap_path = find_pcap_on_disk(basename)
        df = extractor.extract(str(pcap_path))
        if df.empty:
            baseline_results.append({"pcap": basename, "n_flows": 0,
                                       "n_detected": 0, "recall": 0.0})
            continue
        is_attack = predict_attack(clf, pipeline, df)
        baseline_results.append({
            "pcap": basename, "n_flows": int(len(df)),
            "n_detected": int(is_attack.sum()),
            "recall": float(is_attack.mean()),
        })
    baseline_total_flows = sum(r["n_flows"] for r in baseline_results)
    baseline_total_detected = sum(r["n_detected"] for r in baseline_results)
    baseline_recall = (baseline_total_detected / baseline_total_flows
                        if baseline_total_flows else 0.0)
    print(f"  baseline: {baseline_total_detected}/{baseline_total_flows} "
          f"flows detected = {baseline_recall*100:.2f}%")

    print(f"\n[4/5] Running adversarial grid: "
          f"{len(perturbations)} perturbations × {len(strengths)} strengths "
          f"× {len(holdout_pcaps)} PCAPs = {len(perturbations)*len(strengths)*len(holdout_pcaps)} cells")

    # Per-cell results
    cells: List[Dict] = []
    work_dir = model_dir / ".adversarial_work"
    work_dir.mkdir(parents=True, exist_ok=True)

    grand_total_cells = (len(perturbations) * len(strengths) * len(holdout_pcaps))
    cell_idx = 0
    for pert in perturbations:
        for strength in strengths:
            cell_t0 = time.time()
            cell_total_flows = 0
            cell_total_detected = 0
            per_pcap = []
            for basename in holdout_pcaps:
                cell_idx += 1
                pcap_path = find_pcap_on_disk(basename)
                if strength == "none":
                    # Reuse baseline numbers; no need to perturb a passthrough
                    base_match = next(r for r in baseline_results
                                       if r["pcap"] == basename)
                    per_pcap.append({
                        "pcap": basename,
                        "n_flows": base_match["n_flows"],
                        "n_detected": base_match["n_detected"],
                        "recall": base_match["recall"],
                    })
                    cell_total_flows += base_match["n_flows"]
                    cell_total_detected += base_match["n_detected"]
                    continue

                # Perturb
                pert_path = work_dir / f"{pert}_{strength}_{basename}"
                try:
                    perturb(pcap_path, pert_path, pert, strength,
                             seed=args.seed)
                except Exception as exc:
                    logger.error("[%d/%d] %s @ %s on %s: perturb failed: %s",
                                  cell_idx, grand_total_cells, pert, strength,
                                  basename, exc)
                    per_pcap.append({"pcap": basename, "n_flows": 0,
                                       "n_detected": 0, "recall": 0.0,
                                       "error": str(exc)})
                    continue

                # Extract + predict
                try:
                    df = FlowExtractor().extract(str(pert_path))
                except Exception as exc:
                    logger.error("[%d/%d] %s @ %s on %s: extract failed: %s",
                                  cell_idx, grand_total_cells, pert, strength,
                                  basename, exc)
                    per_pcap.append({"pcap": basename, "n_flows": 0,
                                       "n_detected": 0, "recall": 0.0,
                                       "error": str(exc)})
                    if not args.keep_perturbed:
                        pert_path.unlink(missing_ok=True)
                    continue

                if df.empty:
                    per_pcap.append({"pcap": basename, "n_flows": 0,
                                       "n_detected": 0, "recall": 0.0})
                else:
                    is_attack = predict_attack(clf, pipeline, df)
                    n_flows = int(len(df))
                    n_det = int(is_attack.sum())
                    per_pcap.append({"pcap": basename, "n_flows": n_flows,
                                       "n_detected": n_det,
                                       "recall": float(n_det / n_flows)})
                    cell_total_flows += n_flows
                    cell_total_detected += n_det

                if not args.keep_perturbed:
                    pert_path.unlink(missing_ok=True)

            cell_recall = (cell_total_detected / cell_total_flows
                            if cell_total_flows else 0.0)
            cell_dt = time.time() - cell_t0
            cells.append({
                "perturbation": pert,
                "strength": strength,
                "n_total_flows": cell_total_flows,
                "n_total_detected": cell_total_detected,
                "recall": cell_recall,
                "delta_pp_vs_baseline": (cell_recall - baseline_recall) * 100,
                "wall_time_s": round(cell_dt, 1),
                "per_pcap": per_pcap,
            })
            print(f"  {pert:<16} {strength:<11} "
                  f"flows={cell_total_flows:>6} det={cell_total_detected:>6} "
                  f"recall={cell_recall*100:6.2f}%  "
                  f"Δ{(cell_recall-baseline_recall)*100:+6.2f} pp  "
                  f"({cell_dt:.0f}s)")

    if not args.keep_perturbed:
        try:
            shutil.rmtree(work_dir)
        except Exception:
            pass

    print("\n[5/5] Building report")

    out = {
        "model_dir": str(model_dir.relative_to(ROOT)),
        "baseline": {
            "n_total_flows": baseline_total_flows,
            "n_total_detected": baseline_total_detected,
            "recall": baseline_recall,
            "per_pcap": baseline_results,
        },
        "perturbations_tested": perturbations,
        "strengths_tested": strengths,
        "cells": cells,
        "seed": args.seed,
    }
    out_json = model_dir / "adversarial_eval.json"
    out_json.write_text(json.dumps(out, indent=2, default=str),
                          encoding="utf-8")
    print(f"  Saved JSON: {out_json}")

    # Markdown matrix
    md = [f"# Adversarial baseline ({model_dir.name})", "",
          f"Model: `{model_dir.name}`. Test set: 9-PCAP sandbox holdout "
          f"(N_baseline_flows={baseline_total_flows}). Each cell is the "
          "recall on the perturbed re-extraction. Δ pp = absolute change vs "
          f"baseline recall {baseline_recall*100:.2f} %.", "",
          "Caveats:",
          "- IAT-jitter changes packet timing, which changes how the cicflowmeter "
          "  session-izer aggregates packets into flows. Aggressive jitter "
          "  often produces *fewer* flows than baseline because flow timeouts "
          "  fire differently. We report recall on the resulting flows; if a "
          "  flow's identity changes, the model still has to classify it.",
          "- Recall here is `predicted_attack / total_flows_after_perturb` "
          "  (not against ground truth — sandbox PCAPs are 100 % Bot, so "
          "  any non-attack prediction is a miss).",
          "- N_flows column shows whether perturbation collapsed or expanded "
          "  the flow count. A drop from baseline_flows → 50 % means half "
          "  the flows merged together — feature distributions shift even "
          "  before classification runs.", "",
          "## Recall matrix", "",
          "| Perturbation | none | mild | moderate | aggressive |",
          "|---|---:|---:|---:|---:|"]
    by_pert = {}
    for c in cells:
        by_pert.setdefault(c["perturbation"], {})[c["strength"]] = c
    for pert in perturbations:
        row = [f"| **{pert}**"]
        for st in strengths:
            cell = by_pert.get(pert, {}).get(st)
            if cell:
                row.append(f"{cell['recall']*100:.1f} %  "
                            f"(Δ{cell['delta_pp_vs_baseline']:+.1f} pp, "
                            f"n={cell['n_total_flows']})")
            else:
                row.append("—")
        md.append(" | ".join(row) + " |")

    md += ["", "## Flow-count matrix (how perturbation changed aggregation)", "",
           "| Perturbation | none | mild | moderate | aggressive |",
           "|---|---:|---:|---:|---:|"]
    for pert in perturbations:
        row = [f"| **{pert}**"]
        for st in strengths:
            cell = by_pert.get(pert, {}).get(st)
            if cell:
                pct = (cell["n_total_flows"] / baseline_total_flows * 100
                        if baseline_total_flows else 0)
                row.append(f"{cell['n_total_flows']} ({pct:.0f} %)")
            else:
                row.append("—")
        md.append(" | ".join(row) + " |")

    md += ["",
           "## Reading",
           "",
           "- Baseline (no perturbation): "
           f"recall = {baseline_recall*100:.2f} %, n_flows = {baseline_total_flows}.",
           "- Cells with negative Δ pp = recall degradation (worse).",
           "- Cells with substantially fewer flows than baseline = the "
           "  perturbation changed cicflowmeter's flow boundaries; the "
           "  resulting flows have different feature values, which is *part* "
           "  of the adversarial impact, not separate from it.",
           "- This is a *floor* measurement. A motivated adversary doing "
           "  pattern-aware mimicry would shift recall lower; this is what "
           "  random-noise evasion costs by itself."]

    out_md = model_dir / "adversarial_eval.md"
    out_md.write_text("\n".join(md), encoding="utf-8")
    print(f"  Saved MD:   {out_md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
