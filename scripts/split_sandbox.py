"""Phase 1.1 — Stratified train/holdout split of sandbox-ingested malware PCAPs.

Reads `data/sandbox_malware/metadata.frozen.jsonl` (the snapshot frozen at
Phase 0 — do NOT regenerate from `metadata.jsonl` mid-experiment, or
holdout stops being holdout) and the `sandbox_malware_flows.parquet`
produced by `extract_sandbox_pcaps.py`. Writes:

    results/python_only/sandbox_split.json        — explicit train/holdout
                                                    PCAP filename lists +
                                                    summary statistics
    results/python_only/sandbox_train_flows.parquet
    results/python_only/sandbox_holdout_flows.parquet

The split is **hardcoded by hand**, not random — small N per family means
random splits get unstable family coverage. Design rationale per family
in `SPLIT_DESIGN` below.

Once `sandbox_split.json` exists this script reads it and re-emits the
two parquets (idempotent). Pass `--regenerate` to overwrite the JSON
from the in-source design (e.g. after adding new PCAPs).

Usage:
    python scripts/split_sandbox.py
    python scripts/split_sandbox.py --regenerate
    python scripts/split_sandbox.py --in-parquet results/python_only/sandbox_malware_flows.parquet
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Dict, List

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEFAULT_FROZEN_META = ROOT / "data" / "sandbox_malware" / "metadata.frozen.jsonl"
DEFAULT_IN_PARQUET = ROOT / "results" / "python_only" / "sandbox_malware_flows.parquet"
DEFAULT_SPLIT_JSON = ROOT / "results" / "python_only" / "sandbox_split.json"
DEFAULT_TRAIN_PARQUET = ROOT / "results" / "python_only" / "sandbox_train_flows.parquet"
DEFAULT_HOLDOUT_PARQUET = ROOT / "results" / "python_only" / "sandbox_holdout_flows.parquet"


# -----------------------------------------------------------------------------
# Hand-designed split. Substring matching on __source_pcap so we don't have
# to track the full family__Bot.pcap suffix everywhere.
# -----------------------------------------------------------------------------
SPLIT_DESIGN = {
    "rationale": (
        "Stratified by source AND family. Holdout selected to be "
        "medium-recall (not cherry-picked best or worst) where family "
        "has >=2 PCAPs. Single-PCAP families with no train representation "
        "(netsupport, rhadamanthys) go to holdout — model has zero sandbox "
        "signal for them, holdout measures cold-start generalisation. "
        "Single-PCAP families that ARE represented elsewhere (formbook, "
        "kongtuke, macsync) go to train — model learns the new family "
        "without a holdout signal for it specifically (acceptable cost: "
        "we know per-family cold-start = ~0%, no need to re-measure)."
    ),
    "holdout_pcaps": [
        # Stratosphere (2): medium recall (60% / 73%)
        "CTU-Malware-Capture-Botnet-83-1__bot__Bot.pcap",
        "CTU-Mixed-Capture-6__bot__Bot.pcap",
        # MTA lumma (3): mix of recalls (100% / 50% / 50%)
        "2025-08-15_2025-08-15-Lumma-Stealer-infection-with-Sectop-RAT.pcap__lumma__Bot.pcap",
        "2025-09-03_2025-09-03-Kongtuke-ClickFix-leading-to-Lumma-Stealer.pcap__lumma__Bot.pcap",
        "2025-09-24_2025-09-24-traffic-from-running-Setup.exe.pcap__lumma__Bot.pcap",
        # MTA clickfix (1): medium recall (67%)
        "2025-10-08_2025-10-08-initial-infection-traffic-from-Kongtuke-ClickFix-page.pcap__clickfix__Bot.pcap",
        # MTA stealc (1): small-N flag
        "2025-05-22_2025-05-22-StealCv2-infection.pcap__stealc__Bot.pcap",
        # MTA single-PCAP families with no train representation
        "2025-12-29_2025-12-29-ClickFix-page-sends-NetSupportRAT.pcap__netsupport__Bot.pcap",
        "2025-10-01_2025-10-01-possible-Rhadamanthys-post-infection-traffic.pcap__rhadamanthys__Bot.pcap",
    ],
    # Everything else in metadata becomes train.
}


def _file_md5(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def load_frozen_pcap_universe(meta_path: Path) -> List[str]:
    """Return list of PCAP filenames (basenames) from frozen metadata."""
    if not meta_path.exists():
        raise FileNotFoundError(
            f"Frozen metadata not found: {meta_path}. Run Phase 0:\n"
            f"  cp data/sandbox_malware/metadata.jsonl "
            f"data/sandbox_malware/metadata.frozen.jsonl"
        )
    pcaps = []
    seen = set()
    with meta_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            j = json.loads(line)
            rel = j.get("pcap_path") or ""
            basename = Path(rel).name
            if basename and basename not in seen:
                pcaps.append(basename)
                seen.add(basename)
    return pcaps


def build_split_design(in_parquet: Path,
                        frozen_meta: Path) -> dict:
    """Realise SPLIT_DESIGN against the actual parquet contents."""
    df = pd.read_parquet(in_parquet)
    available = set(df["__source_pcap"].unique())
    universe = set(load_frozen_pcap_universe(frozen_meta))

    # Defensive: every holdout PCAP must exist in the parquet AND in the
    # frozen metadata.
    missing_from_parquet = []
    missing_from_meta = []
    for h in SPLIT_DESIGN["holdout_pcaps"]:
        if h not in available:
            missing_from_parquet.append(h)
        if h not in universe:
            missing_from_meta.append(h)
    if missing_from_parquet or missing_from_meta:
        raise ValueError(
            "SPLIT_DESIGN references PCAPs that don't match runtime data:\n"
            f"  missing from parquet ({len(missing_from_parquet)}): "
            f"{missing_from_parquet}\n"
            f"  missing from metadata ({len(missing_from_meta)}): "
            f"{missing_from_meta}\n"
            "Fix the SPLIT_DESIGN list or re-extract the parquet."
        )

    holdout_set = set(SPLIT_DESIGN["holdout_pcaps"])
    train_pcaps = sorted(available - holdout_set)
    holdout_pcaps = sorted(holdout_set)

    def summary(pcaps_subset):
        sub = df[df["__source_pcap"].isin(pcaps_subset)]
        per_pcap = []
        for cap, g in sub.groupby("__source_pcap"):
            per_pcap.append({
                "pcap": cap,
                "source": g["__sandbox_source"].iloc[0],
                "family": g["__family"].iloc[0],
                "captured_date": str(g["__captured_date"].iloc[0]),
                "n_flows": int(len(g)),
            })
        per_pcap.sort(key=lambda r: (r["source"], r["family"], r["pcap"]))
        return {
            "n_pcaps": len(pcaps_subset),
            "n_flows": int(len(sub)),
            "by_source": dict(Counter(p["source"] for p in per_pcap)),
            "by_family": dict(Counter(p["family"] for p in per_pcap)),
            "by_source_flow_count": {
                src: int(sub[sub["__sandbox_source"] == src].shape[0])
                for src in sub["__sandbox_source"].unique()
            },
            "by_family_flow_count": {
                fam: int(sub[sub["__family"] == fam].shape[0])
                for fam in sub["__family"].unique()
            },
            "pcaps": per_pcap,
        }

    return {
        "version": 1,
        "generated_at": date.today().isoformat(),
        "frozen_metadata_path": str(frozen_meta.relative_to(ROOT)),
        "frozen_metadata_md5": _file_md5(frozen_meta),
        "in_parquet_path": str(in_parquet.relative_to(ROOT)),
        "rationale": SPLIT_DESIGN["rationale"],
        "train": summary(train_pcaps),
        "holdout": summary(holdout_pcaps),
    }


def write_parquets(in_parquet: Path,
                    split: dict,
                    train_path: Path,
                    holdout_path: Path) -> None:
    df = pd.read_parquet(in_parquet)
    train_set = {p["pcap"] for p in split["train"]["pcaps"]}
    holdout_set = {p["pcap"] for p in split["holdout"]["pcaps"]}
    train_df = df[df["__source_pcap"].isin(train_set)].reset_index(drop=True)
    holdout_df = df[df["__source_pcap"].isin(holdout_set)].reset_index(drop=True)
    train_path.parent.mkdir(parents=True, exist_ok=True)
    train_df.to_parquet(train_path, index=False)
    holdout_df.to_parquet(holdout_path, index=False)
    print(f"  Wrote: {train_path.name} ({len(train_df)} rows, "
          f"{train_path.stat().st_size / 1024:.0f} KB)")
    print(f"  Wrote: {holdout_path.name} ({len(holdout_df)} rows, "
          f"{holdout_path.stat().st_size / 1024:.0f} KB)")


def print_summary(split: dict) -> None:
    print()
    print("=" * 70)
    print("SPLIT SUMMARY")
    print("=" * 70)
    for name in ("train", "holdout"):
        s = split[name]
        print(f"\n{name.upper():>7s}: {s['n_pcaps']} PCAPs, {s['n_flows']} flows")
        print(f"  By source: {s['by_source_flow_count']}")
        print(f"  By family: {s['by_family_flow_count']}")
    print()
    train_total = split["train"]["n_flows"]
    holdout_total = split["holdout"]["n_flows"]
    overall = train_total + holdout_total
    print(f"Train share: {train_total/overall*100:.1f} % "
          f"({train_total}/{overall})")
    print(f"Holdout share: {holdout_total/overall*100:.1f} % "
          f"({holdout_total}/{overall})")
    print()


def main(argv=None) -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    p = argparse.ArgumentParser()
    p.add_argument("--frozen-meta", type=Path, default=DEFAULT_FROZEN_META)
    p.add_argument("--in-parquet", type=Path, default=DEFAULT_IN_PARQUET)
    p.add_argument("--split-json", type=Path, default=DEFAULT_SPLIT_JSON)
    p.add_argument("--train-parquet", type=Path, default=DEFAULT_TRAIN_PARQUET)
    p.add_argument("--holdout-parquet", type=Path, default=DEFAULT_HOLDOUT_PARQUET)
    p.add_argument("--regenerate", action="store_true",
                    help="Overwrite split_json from in-source SPLIT_DESIGN even "
                          "if it exists (use after adding new PCAPs to metadata).")
    args = p.parse_args(argv)

    if args.split_json.exists() and not args.regenerate:
        print(f"[1/2] Loading existing split: {args.split_json.name}")
        split = json.loads(args.split_json.read_text(encoding="utf-8"))
        # Sanity: frozen metadata md5 must still match
        actual_md5 = _file_md5(args.frozen_meta)
        if actual_md5 != split.get("frozen_metadata_md5"):
            print(f"  WARNING: frozen metadata md5 changed!")
            print(f"  expected: {split.get('frozen_metadata_md5')}")
            print(f"  actual:   {actual_md5}")
            print(f"  Re-run with --regenerate if intentional.")
            return 1
    else:
        action = "Regenerating" if args.regenerate else "Building"
        print(f"[1/2] {action} split design from SPLIT_DESIGN")
        split = build_split_design(args.in_parquet, args.frozen_meta)
        args.split_json.parent.mkdir(parents=True, exist_ok=True)
        args.split_json.write_text(
            json.dumps(split, indent=2, default=str), encoding="utf-8")
        print(f"  Wrote: {args.split_json.name} "
              f"({args.split_json.stat().st_size / 1024:.1f} KB)")

    print(f"\n[2/2] Writing per-split parquets")
    write_parquets(args.in_parquet, split,
                    args.train_parquet, args.holdout_parquet)

    print_summary(split)
    print("Next: update train_python_only.py to load --sandbox-train-parquet,")
    print("then retrain into results/v2/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
