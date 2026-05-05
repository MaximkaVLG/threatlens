"""Phase 3.3 — head-to-head comparison of two adversarial_eval.json files.

Reads `results/<modelA>/adversarial_eval.json` and
`results/<modelB>/adversarial_eval.json`, prints + writes a side-by-side
recall matrix that goes into `docs/adversarial_baseline.md`.

The comparison answers: "for each (perturbation, strength) cell, which
model degrades less?". Useful as the deciding piece for an operator
choosing between A and B — if one is consistently more robust to
naive evasion, that's a tie-breaker even when baseline recall is
similar.

Usage:
    python scripts/adversarial_compare.py
    python scripts/adversarial_compare.py --model-a results/python_only --model-b results/v2
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent

DEFAULT_A = ROOT / "results" / "python_only"
DEFAULT_B = ROOT / "results" / "v2"


def load_eval(model_dir: Path) -> Dict:
    p = model_dir / "adversarial_eval.json"
    if not p.exists():
        raise FileNotFoundError(f"adversarial_eval.json missing at {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def cells_by_pert(eval_data: Dict) -> Dict:
    out: Dict = {}
    for c in eval_data["cells"]:
        out.setdefault(c["perturbation"], {})[c["strength"]] = c
    return out


def main(argv=None) -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    p = argparse.ArgumentParser()
    p.add_argument("--model-a", type=Path, default=DEFAULT_A,
                    help="First model dir (label A in output table)")
    p.add_argument("--model-b", type=Path, default=DEFAULT_B,
                    help="Second model dir (label B in output table)")
    p.add_argument("--out-md", type=Path,
                    default=ROOT / "docs" / "adversarial_compare.md",
                    help="Where to write the side-by-side table")
    args = p.parse_args(argv)

    a = load_eval(args.model_a.resolve())
    b = load_eval(args.model_b.resolve())
    name_a = args.model_a.name
    name_b = args.model_b.name

    a_cells = cells_by_pert(a)
    b_cells = cells_by_pert(b)

    perturbations = a["perturbations_tested"]
    strengths = a["strengths_tested"]

    md: List[str] = [
        f"# Adversarial baseline — head-to-head ({name_a} vs {name_b})",
        "",
        f"Auto-generated from `results/{name_a}/adversarial_eval.json` and "
        f"`results/{name_b}/adversarial_eval.json`. Each cell shows recall "
        "for both models on the same perturbed test set, plus the "
        "robustness delta (B - A in pp).",
        "",
        f"Baselines (no perturbation):",
        f"- **{name_a}**: recall = {a['baseline']['recall']*100:.2f} % "
        f"(n_flows = {a['baseline']['n_total_flows']})",
        f"- **{name_b}**: recall = {b['baseline']['recall']*100:.2f} % "
        f"(n_flows = {b['baseline']['n_total_flows']})",
        "",
        f"## Recall under perturbation",
        "",
    ]

    for pert in perturbations:
        md += [f"### {pert}", "",
                f"| Strength | {name_a} recall | {name_b} recall | "
                f"Δ ({name_b} − {name_a}) | {name_a} flows / {name_b} flows |",
                "|---|---:|---:|---:|---|"]
        for st in strengths:
            ca = a_cells.get(pert, {}).get(st)
            cb = b_cells.get(pert, {}).get(st)
            if ca is None or cb is None:
                md.append(f"| {st} | — | — | — | — |")
                continue
            delta_pp = (cb["recall"] - ca["recall"]) * 100
            md.append(
                f"| {st} | "
                f"{ca['recall']*100:.1f} % "
                f"(Δ vs base {ca['delta_pp_vs_baseline']:+.1f}) | "
                f"{cb['recall']*100:.1f} % "
                f"(Δ vs base {cb['delta_pp_vs_baseline']:+.1f}) | "
                f"**{delta_pp:+.1f} pp** | "
                f"{ca['n_total_flows']} / {cb['n_total_flows']} |")
        md.append("")

    # Aggregate robustness summary
    a_under_pert = []
    b_under_pert = []
    for pert in perturbations:
        for st in strengths:
            if st == "none":
                continue
            ca = a_cells.get(pert, {}).get(st)
            cb = b_cells.get(pert, {}).get(st)
            if ca and cb:
                a_under_pert.append(ca["recall"])
                b_under_pert.append(cb["recall"])
    if a_under_pert:
        a_avg = sum(a_under_pert) / len(a_under_pert)
        b_avg = sum(b_under_pert) / len(b_under_pert)
        md += ["## Aggregate robustness",
                "",
                f"Mean recall across **{len(a_under_pert)}** perturbed cells "
                f"(non-trivial strengths only):",
                "",
                f"- **{name_a}**: {a_avg*100:.2f} %",
                f"- **{name_b}**: {b_avg*100:.2f} %",
                f"- **Δ**: {(b_avg-a_avg)*100:+.2f} pp "
                f"({'B more robust' if b_avg > a_avg else 'A more robust' if a_avg > b_avg else 'tie'})",
                "",
                "Note: this is a coarse aggregate — a cell with 50 % recall "
                "drop and a cell with 5 % recall drop count equally. The "
                "per-perturbation tables above show where the meaningful "
                "differences are.",
                ""]

    md += ["## Reading", "",
            "- `Δ vs base` columns: each model's drop relative to its own "
            "baseline. Useful to compare *robustness* even when absolute "
            "recall numbers differ.",
            "- `Δ (B − A)` column: the head-to-head — positive means B did "
            "better on that cell, negative means A did better.",
            "- `flows` column: how many flows survived re-extraction. A "
            "drop here means the perturbation collapsed cicflowmeter's "
            "flow boundaries; the resulting flows have shifted feature "
            "values, which is part of the adversarial impact.",
            "- The strength=none row is a sanity check (should equal "
            "baseline). Non-zero Δ pp on `none` indicates a bug."]

    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text("\n".join(md), encoding="utf-8")
    print(f"Wrote {args.out_md.relative_to(ROOT)}")

    # Also print to stdout so the operator can paste into PR descriptions
    print()
    print("\n".join(md[:60]))  # First few sections
    return 0


if __name__ == "__main__":
    sys.exit(main())
