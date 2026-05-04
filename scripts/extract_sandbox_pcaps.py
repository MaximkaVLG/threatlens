"""Day 13 — extract flows from sandbox PCAPs ingested by ingest_sandbox_pcaps.py.

Reads PCAPs under data/sandbox_malware/<source>/ and the metadata.jsonl
sidecar, runs them through the same FlowExtractor used at inference,
and writes a parquet that train_python_only.py picks up automatically
(analogously to diverse_benign_flows.parquet and attack_volume_flows.parquet).

Output:
    results/python_only/sandbox_malware_flows.parquet

Each row is one flow with the usual 70 CIC + 8 spectral + 3 YARA
columns, plus:
    Label               — 7-class label (Bot/BENIGN/...) mapped at ingest
    __source_pcap       — filename of the PCAP this flow came from
    __split_source      — "sandbox_malware"
    __sandbox_source    — "stratosphere" | "mta" | ...
    __captured_date     — ISO YYYY-MM-DD if known, else ""
    __family            — best-guess family tag ("lumma", "cobalt-strike", ...)

Usage:
    python scripts/extract_sandbox_pcaps.py
    python scripts/extract_sandbox_pcaps.py --in data/sandbox_malware
    python scripts/extract_sandbox_pcaps.py --limit 10
    python scripts/extract_sandbox_pcaps.py --max-flows-per-pcap 50000

Memory model:
    Each PCAP is extracted, capped at --max-flows-per-pcap (default 100k —
    pathological scan-heavy captures like Stratosphere Botnet-61-1 produce
    1.5M flows that blow up RAM if kept in full), then written immediately
    to a per-PCAP parquet under a temp directory. At the end we stream-concat
    those parquets into the final file via pyarrow.dataset, so memory peak
    is bounded by the largest *single* per-PCAP parquet, not the sum.
"""
from __future__ import annotations

import argparse
import gc
import json
import logging
import shutil
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd
import pyarrow as pa
import pyarrow.dataset as ds
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import FlowExtractor  # noqa: E402

DEFAULT_IN_DIR = ROOT / "data" / "sandbox_malware"
DEFAULT_OUT_PARQUET = ROOT / "results" / "python_only" / "sandbox_malware_flows.parquet"
METADATA_FILENAME = "metadata.jsonl"
DEFAULT_MAX_FLOWS_PER_PCAP = 100_000
SAMPLE_SEED = 42

logger = logging.getLogger("extract_sandbox")


@dataclass
class MetaRow:
    """Subset of ingest metadata.jsonl we need to label flows."""
    source: str
    sample_id: str
    label: str
    family: str
    captured_date: str
    pcap_path: Path    # absolute


def load_metadata(meta_path: Path) -> Dict[str, MetaRow]:
    """Return {absolute_pcap_path_str: MetaRow} keyed by resolved path."""
    if not meta_path.exists():
        raise FileNotFoundError(
            f"Metadata file not found: {meta_path}. Run "
            f"scripts/ingest_sandbox_pcaps.py first to create it."
        )
    out: Dict[str, MetaRow] = {}
    base = meta_path.parent
    with meta_path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("metadata line %d: skipping malformed (%s)",
                               line_no, exc)
                continue
            rel = j.get("pcap_path")
            if not rel:
                continue
            abs_path = (base / rel).resolve()
            out[str(abs_path)] = MetaRow(
                source=j.get("source", ""),
                sample_id=j.get("sample_id", ""),
                label=j.get("label", ""),
                family=j.get("family", ""),
                captured_date=j.get("captured_date") or "",
                pcap_path=abs_path,
            )
    return out


def _safe_parquet_name(meta: MetaRow, idx: int) -> str:
    """Path-safe per-PCAP parquet basename (collision-free via idx)."""
    stem = meta.pcap_path.stem
    # Cap to ~80 chars, keep it readable
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in stem)[:80]
    return f"{idx:03d}_{safe}.parquet"


def main(argv: Optional[List[str]] = None) -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description=(
            "Extract flows from sandbox-ingested PCAPs into a parquet "
            "that train_python_only.py auto-merges into training."
        )
    )
    parser.add_argument("--in-dir", type=Path, default=DEFAULT_IN_DIR,
                         help=f"Sandbox data directory (default {DEFAULT_IN_DIR}).")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT_PARQUET,
                         help=f"Output parquet (default {DEFAULT_OUT_PARQUET}).")
    parser.add_argument("--limit", type=int, default=0,
                         help="Max PCAPs to extract (0 = no limit).")
    parser.add_argument("--max-flows-per-pcap", type=int,
                         default=DEFAULT_MAX_FLOWS_PER_PCAP,
                         help=f"Cap flows per PCAP (default {DEFAULT_MAX_FLOWS_PER_PCAP}; "
                              "stratified random sample if exceeded). 0 = no cap.")
    parser.add_argument("--keep-parts", action="store_true",
                         help="Keep per-PCAP parquet temp files after merge "
                              "(useful for debugging / partial recovery).")
    parser.add_argument("--skip-pcaps", type=str, default="",
                         help="Comma-separated PCAP filenames (basenames) to "
                              "skip entirely. Use to drop pathological captures "
                              "(e.g. CTU-Malware-Capture-Botnet-61-1__bot__Bot.pcap "
                              "produces 1.5M flows from a port-scan workload "
                              "that OOMs FlowExtractor before our sample step).")
    parser.add_argument("--resume", action="store_true",
                         help="Skip PCAPs whose per-PCAP parquet already exists "
                              "in the parts dir. Lets a re-run pick up where a "
                              "crashed run left off without redoing finished work.")
    parser.add_argument("--verbose", "-v", action="count", default=0,
                         help="Increase log verbosity.")
    args = parser.parse_args(argv)

    level = {0: logging.INFO, 1: logging.DEBUG}.get(args.verbose, logging.DEBUG)
    logging.basicConfig(level=level,
                        format="%(asctime)s %(levelname)-7s %(message)s")
    logger.setLevel(level)

    meta_path = args.in_dir / METADATA_FILENAME
    metadata = load_metadata(meta_path)
    if not metadata:
        logger.error("No metadata entries in %s — nothing to extract.",
                     meta_path)
        return 1

    # Iterate in deterministic order (sorted by captured_date, then sample_id)
    rows = sorted(metadata.values(),
                  key=lambda r: (r.captured_date or "", r.sample_id))
    if args.limit and args.limit > 0:
        rows = rows[:args.limit]

    skip_set = {s.strip() for s in args.skip_pcaps.split(",") if s.strip()}
    if skip_set:
        before = len(rows)
        rows = [r for r in rows if r.pcap_path.name not in skip_set]
        logger.info("--skip-pcaps removed %d / %d entries: %s",
                    before - len(rows), before, sorted(skip_set))

    extractor = FlowExtractor()

    # Per-PCAP parquets land in a temp dir alongside the final output so OneDrive
    # doesn't try to sync them (the .pytest-tmp / data dirs are gitignored).
    parts_dir = args.out.parent / ".sandbox_extract_parts"
    parts_dir.mkdir(parents=True, exist_ok=True)

    n_total_flows = 0
    n_pcaps_ok = 0
    skipped = 0
    label_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    written_parts: List[Path] = []

    for idx, row in enumerate(rows):
        if not row.pcap_path.exists():
            logger.warning("  missing on disk, skipping: %s",
                           row.pcap_path.name)
            skipped += 1
            continue

        part_path_preview = parts_dir / _safe_parquet_name(row, idx)
        if args.resume and part_path_preview.exists():
            # Resume mode: skip the heavy extraction, just register the existing
            # part for the final merge.
            try:
                # Cheap row-count read for accurate stats
                import pyarrow.parquet as _pq
                n_kept = _pq.ParquetFile(part_path_preview).metadata.num_rows
            except Exception:
                n_kept = 0
            logger.info("  %-60s [resume: part exists, %d rows]",
                        row.pcap_path.name, n_kept)
            written_parts.append(part_path_preview)
            n_total_flows += n_kept
            n_pcaps_ok += 1
            label_counts[row.label] += n_kept
            source_counts[row.source] += n_kept
            continue

        t0 = time.time()
        try:
            df = extractor.extract(str(row.pcap_path))
        except Exception as exc:
            logger.error("  extraction failed for %s: %s",
                         row.pcap_path.name, exc)
            skipped += 1
            continue
        dt = time.time() - t0

        n_raw = len(df)
        if df.empty:
            logger.info("  %-60s %5d flows (%.1fs) [empty, skipping]",
                        row.pcap_path.name, n_raw, dt)
            del df
            gc.collect()
            continue

        # Cap per-PCAP flows to keep memory bounded. Botnet-61-1 produces 1.5M
        # flows from what looks like a port-scan workload; that single PCAP
        # would OOM the process. A 100k stratified sample preserves enough
        # signal for evaluation.
        if args.max_flows_per_pcap > 0 and n_raw > args.max_flows_per_pcap:
            logger.warning("  %s has %d flows — sampling %d (seed=%d) for memory",
                           row.pcap_path.name, n_raw,
                           args.max_flows_per_pcap, SAMPLE_SEED)
            df = (df.sample(n=args.max_flows_per_pcap, random_state=SAMPLE_SEED)
                    .reset_index(drop=True))

        df["Label"] = row.label
        df["__source_pcap"] = row.pcap_path.name
        df["__split_source"] = "sandbox_malware"
        df["__sandbox_source"] = row.source
        df["__captured_date"] = row.captured_date
        df["__family"] = row.family

        part_path = parts_dir / _safe_parquet_name(row, idx)
        try:
            df.to_parquet(part_path, index=False)
        except Exception as exc:
            logger.error("  write failed for %s: %s", part_path.name, exc)
            skipped += 1
            del df
            gc.collect()
            continue

        n_kept = len(df)
        n_total_flows += n_kept
        n_pcaps_ok += 1
        label_counts[row.label] += n_kept
        source_counts[row.source] += n_kept
        written_parts.append(part_path)

        logger.info("  %-60s raw=%-6d kept=%-6d (%.1fs) label=%s family=%s",
                    row.pcap_path.name, n_raw, n_kept, dt,
                    row.label, row.family)

        del df
        gc.collect()

    if not written_parts:
        logger.error("No flows extracted (skipped=%d). Aborting.", skipped)
        return 1

    logger.info("")
    logger.info("Per-PCAP extraction done: %d pcaps OK, %d skipped, %d total flows",
                n_pcaps_ok, skipped, n_total_flows)
    logger.info("Per-label: %s", dict(label_counts))
    logger.info("Per-source: %s", dict(source_counts))

    # Stream-concat per-PCAP parquets into the single output. pyarrow.dataset
    # handles schema evolution if any PCAP had a slightly different dtype
    # (e.g. all-zero numeric inferred as int64 vs float64).
    logger.info("Merging %d per-PCAP parquets via pyarrow.dataset stream",
                len(written_parts))
    args.out.parent.mkdir(parents=True, exist_ok=True)

    dataset = ds.dataset([str(p) for p in written_parts], format="parquet")
    unified_schema = pa.unify_schemas([pq.read_schema(p) for p in written_parts])
    writer: Optional[pq.ParquetWriter] = None
    try:
        for batch in dataset.to_batches(batch_size=50_000):
            # Cast to unified schema so writer accepts every chunk
            casted = pa.Table.from_batches([batch]).cast(unified_schema,
                                                         safe=False)
            if writer is None:
                writer = pq.ParquetWriter(args.out, unified_schema,
                                          compression="snappy")
            writer.write_table(casted)
    finally:
        if writer is not None:
            writer.close()

    final_size = args.out.stat().st_size / (1024 * 1024)
    logger.info("Saved: %s  (%.1f MB)", args.out, final_size)

    if args.keep_parts:
        logger.info("Keeping parts dir: %s", parts_dir)
    else:
        try:
            shutil.rmtree(parts_dir)
        except Exception as exc:
            logger.warning("Could not clean parts dir %s: %s", parts_dir, exc)

    logger.info("Next: python scripts/eval_sandbox.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
