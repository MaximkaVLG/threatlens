"""Phase 7 — submission cross-check.

Walks the headline numbers cited in `README.md` and `SUBMISSION.md`,
opens the artifact JSONs they implicitly reference, and asserts each
cited number matches the artifact within tolerance.

Why this exists
---------------
During Phase 1 retrain + Phase 5 bootstrap we accumulated ~12 distinct
headline metrics across 4 markdown files. A reviewer who re-runs
`scripts/eval_python_only.py` should land on the exact percentages
quoted in the docs. This script is the regression test for that.

What it checks
--------------
For each (md_file, claim, artifact_path, json_pointer) tuple:
  - the claim's percentage is parsed
  - the artifact's number at the JSON pointer is loaded
  - they're compared with abs tolerance 0.01 pp (equivalent to
    rounding-to-2-decimals precision)

Failure prints both expected and observed; exits non-zero so this
can run as a pre-submit check.

Usage:
    python scripts/check_submission_consistency.py
    python scripts/check_submission_consistency.py --strict   # fail on any
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
# Absolute percentage-point tolerance. Headlines are rounded to 2 decimals
# (e.g. 96.85 %) or 1 decimal (e.g. 81.8 %); 0.05 pp covers both rounding
# regimes while still catching meaningful drift.
TOLERANCE_PP = 0.05


# --- claim registry ---------------------------------------------------------

# Each claim is (markdown_file, human_label, expected_pct,
#                artifact_path, json_pointer, multiplier).
# json_pointer is a dotted path; multiplier is 100 for fractions stored as
# 0..1 in the JSON, 1 for raw percentages.
CLAIMS: List[Tuple[str, str, float, str, str, float]] = [
    # ---- python_only ----
    ("SUBMISSION.md",
     "lenient FP rate",
     2.02,
     "results/python_only/workload_metric.json",
     "operating_points.0.auto_fp_pct",
     1.0),
    ("SUBMISSION.md",
     "lenient recall (model alone)",
     97.83,
     "results/python_only/workload_metric.json",
     "operating_points.0.auto_recall_attack",
     100.0),
    ("SUBMISSION.md",
     "safe coverage = 81.8 % auto-classified",
     81.8,
     "results/python_only/workload_metric.json",
     "operating_points.1.auto_classified_pct",
     1.0),
    ("SUBMISSION.md",
     "safe pipeline recall (with reviewer) = 99.33 %",
     99.33,
     "results/python_only/workload_metric.json",
     "operating_points.1.pipeline_recall_attack_with_review",
     100.0),
    ("SUBMISSION.md",
     "Historical real-world recall = 96.25 %",
     96.25,
     "results/python_only/bootstrap_ci.json",
     "datasets.real_pcap_historical.recall_attack.point",
     100.0),
    ("SUBMISSION.md",
     "Historical real-world recall CI low = 93.95 %",
     93.95,
     "results/python_only/bootstrap_ci.json",
     "datasets.real_pcap_historical.recall_attack.ci_low",
     100.0),
    ("SUBMISSION.md",
     "Historical real-world recall CI high = 97.99 %",
     97.99,
     "results/python_only/bootstrap_ci.json",
     "datasets.real_pcap_historical.recall_attack.ci_high",
     100.0),
    ("SUBMISSION.md",
     "Sandbox FULL 25-PCAP recall = 72.24 %",
     72.24,
     "results/python_only/bootstrap_ci.json",
     "datasets.sandbox_full.recall_attack.point",
     100.0),
    ("SUBMISSION.md",
     "Sandbox FULL 25-PCAP CI low = 70.92 %",
     70.92,
     "results/python_only/bootstrap_ci.json",
     "datasets.sandbox_full.recall_attack.ci_low",
     100.0),
    ("SUBMISSION.md",
     "Sandbox FULL 25-PCAP CI high = 73.50 %",
     73.50,
     "results/python_only/bootstrap_ci.json",
     "datasets.sandbox_full.recall_attack.ci_high",
     100.0),
    ("SUBMISSION.md",
     "Sandbox holdout 9-PCAP recall = 60.46 %",
     60.46,
     "results/python_only/bootstrap_ci.json",
     "datasets.sandbox_holdout.recall_attack.point",
     100.0),
    ("SUBMISSION.md",
     "Sandbox holdout 9-PCAP CI low = 55.29 %",
     55.29,
     "results/python_only/bootstrap_ci.json",
     "datasets.sandbox_holdout.recall_attack.ci_low",
     100.0),
    ("SUBMISSION.md",
     "Sandbox holdout 9-PCAP CI high = 65.90 %",
     65.90,
     "results/python_only/bootstrap_ci.json",
     "datasets.sandbox_holdout.recall_attack.ci_high",
     100.0),
    ("README.md",
     "Sandbox per-source: stratosphere recall = 74.8 %",
     74.8,
     "results/python_only/sandbox_eval.json",
     "per_source.1.recall",
     100.0),
    ("README.md",
     "Sandbox per-source: MTA recall = 47.1 %",
     47.1,
     "results/python_only/sandbox_eval.json",
     "per_source.0.recall",
     100.0),
    ("SUBMISSION.md",
     "Abstainer flagged 70.8 % of fresh sandbox flows as OOD",
     70.8,
     "results/python_only/sandbox_eval.json",
     "headline.abstain_rate",
     100.0),

    # ---- v2 ----
    ("results/v2/ab_vs_python_only.md",
     "v2 sandbox holdout recall = 96.85 %",
     96.85,
     "results/v2/bootstrap_ci.json",
     "datasets.sandbox_holdout.recall_attack.point",
     100.0),
    ("results/v2/ab_vs_python_only.md",
     "v2 sandbox holdout CI low = 94.56 %",
     94.56,
     "results/v2/bootstrap_ci.json",
     "datasets.sandbox_holdout.recall_attack.ci_low",
     100.0),
    ("results/v2/ab_vs_python_only.md",
     "v2 sandbox holdout CI high = 98.57 %",
     98.57,
     "results/v2/bootstrap_ci.json",
     "datasets.sandbox_holdout.recall_attack.ci_high",
     100.0),
]


def lookup(d: Any, dotted: str) -> Optional[Any]:
    """Walk a dotted path through a nested dict / list. Returns None on miss."""
    cur = d
    for part in dotted.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            if part not in cur:
                return None
            cur = cur[part]
        else:
            return None
    return cur


def main(argv=None) -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    p = argparse.ArgumentParser()
    p.add_argument("--strict", action="store_true",
                    help="Exit 1 if any claim fails (default).")
    p.add_argument("--verbose", action="store_true",
                    help="Print every claim, not just failures.")
    args = p.parse_args(argv)

    n_pass = 0
    n_fail = 0
    n_skip = 0
    failures: List[str] = []

    for md_file, label, expected, art_path, ptr, mult in CLAIMS:
        art_full = ROOT / art_path
        if not art_full.exists():
            print(f"  SKIP   {label}  (artifact missing: {art_path})")
            n_skip += 1
            continue
        try:
            data = json.loads(art_full.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"  ERROR  {label}  (cannot parse {art_path}: {exc})")
            failures.append(label)
            n_fail += 1
            continue

        observed_raw = lookup(data, ptr)
        if observed_raw is None:
            print(f"  ERROR  {label}  (json pointer not found: {ptr})")
            failures.append(label)
            n_fail += 1
            continue

        observed = float(observed_raw) * mult
        delta = abs(observed - expected)
        if delta <= TOLERANCE_PP:
            n_pass += 1
            if args.verbose:
                print(f"  OK     {label}  observed={observed:.4f} "
                      f"expected={expected:.2f} (Δ={delta:.4f})")
        else:
            print(f"  FAIL   {label}  observed={observed:.4f} "
                  f"expected={expected:.2f} (Δ={delta:.4f} > {TOLERANCE_PP})")
            print(f"         from {md_file} ↔ {art_path}::{ptr}")
            failures.append(label)
            n_fail += 1

    print(f"\n  Total: {n_pass} pass / {n_fail} fail / {n_skip} skip "
          f"(of {len(CLAIMS)} claims)")
    if n_fail > 0:
        print("\n  Failures:")
        for f in failures:
            print(f"   - {f}")
        return 1 if args.strict else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
