"""Day 9d helper — extract high-volume attack PCAPs through FlowExtractor.

Output: results/python_only/attack_volume_flows.parquet, then merged
into the training set by train_python_only.py.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import FlowExtractor  # noqa: E402

SRC_DIR = ROOT / "data" / "synthetic" / "attack_volume"
OUT_PARQUET = ROOT / "results" / "python_only" / "attack_volume_flows.parquet"


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    extractor = FlowExtractor()
    frames = []
    for p in sorted(SRC_DIR.glob("*.pcap")):
        # Filename: <profile>__<Label>.pcap (label might contain '_' from
        # SSH-Patator -> SSH_Patator). Convert back.
        stem = p.stem
        label_part = stem.split("__")[-1]
        label = label_part.replace("_", "-")  # SSH_Patator -> SSH-Patator
        t0 = time.time()
        df = extractor.extract(str(p))
        print(f"  {p.name:<70}  {len(df):>5} flows ({time.time()-t0:.1f}s) "
              f"label={label}")
        if df.empty:
            continue
        df["Label"] = label
        df["__source_pcap"] = p.name
        df["__split_source"] = "attack_volume"
        frames.append(df)
    if not frames:
        print("No flows extracted!")
        return 1
    combined = pd.concat(frames, ignore_index=True, sort=False)
    print(f"\nTotal attack-volume flows: {len(combined)}")
    print(f"Per-label: {combined['Label'].value_counts().to_dict()}")
    OUT_PARQUET.parent.mkdir(parents=True, exist_ok=True)
    combined.to_parquet(OUT_PARQUET, index=False)
    print(f"Saved: {OUT_PARQUET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
