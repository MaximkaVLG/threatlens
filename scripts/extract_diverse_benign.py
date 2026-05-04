"""Day 9b helper — extract the diverse-benign PCAPs through FlowExtractor.

Output: results/python_only/diverse_benign_flows.parquet, then merged into
the training set by an updated train_python_only.py call.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import FlowExtractor  # noqa: E402

SRC_DIR = ROOT / "data" / "synthetic" / "diverse_benign"
OUT_PARQUET = ROOT / "results" / "python_only" / "diverse_benign_flows.parquet"


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    extractor = FlowExtractor()
    frames = []
    for p in sorted(SRC_DIR.glob("*.pcap")):
        t0 = time.time()
        df = extractor.extract(str(p))
        print(f"  {p.name:<48}  {len(df):>5} flows  ({time.time()-t0:.1f}s)")
        if df.empty:
            continue
        df["Label"] = "BENIGN"
        df["__source_pcap"] = p.name
        df["__split_source"] = "diverse_benign"
        frames.append(df)
    if not frames:
        print("No flows extracted!")
        return 1
    combined = pd.concat(frames, ignore_index=True, sort=False)
    print(f"\nTotal diverse-benign flows: {len(combined)}")
    OUT_PARQUET.parent.mkdir(parents=True, exist_ok=True)
    combined.to_parquet(OUT_PARQUET, index=False)
    print(f"Saved: {OUT_PARQUET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
