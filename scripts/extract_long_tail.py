"""Day 9e helper — extract long-tail PCAPs and merge with existing parquets.

Splits flows into BENIGN (merged into diverse_benign_flows.parquet) and
non-BENIGN (merged into attack_volume_flows.parquet) so train_python_only.py
picks them up automatically without code changes.

Filename convention from generate_long_tail.py:
    <profile_name>__<Label>__<group>.pcap
where group is 'diverse_benign' or 'attack_volume'.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import FlowExtractor  # noqa: E402

SRC_DIR = ROOT / "data" / "synthetic" / "long_tail"
DIVERSE_PARQUET = ROOT / "results" / "python_only" / "diverse_benign_flows.parquet"
ATTACK_VOL_PARQUET = ROOT / "results" / "python_only" / "attack_volume_flows.parquet"


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    extractor = FlowExtractor()

    benign_frames = []
    attack_frames = []
    for p in sorted(SRC_DIR.glob("*.pcap")):
        # filename: <profile>__<Label>__<group>.pcap
        parts = p.stem.split("__")
        if len(parts) < 3:
            print(f"  SKIP {p.name} — malformed name")
            continue
        label_part, group = parts[-2], parts[-1]
        label = label_part.replace("_", "-")
        t0 = time.time()
        df = extractor.extract(str(p))
        print(f"  {p.name:<70}  {len(df):>5} flows ({time.time()-t0:.1f}s) "
              f"label={label} group={group}")
        if df.empty:
            continue
        df["Label"] = label
        df["__source_pcap"] = p.name
        df["__split_source"] = "long_tail"
        if group == "diverse_benign":
            benign_frames.append(df)
        else:
            attack_frames.append(df)

    if benign_frames:
        new_benign = pd.concat(benign_frames, ignore_index=True, sort=False)
        existing = (pd.read_parquet(DIVERSE_PARQUET)
                     if DIVERSE_PARQUET.exists() else pd.DataFrame())
        merged = pd.concat([existing, new_benign], ignore_index=True, sort=False)
        merged.to_parquet(DIVERSE_PARQUET, index=False)
        print(f"\nDiverse benign now: {len(merged)} flows "
              f"(+{len(new_benign)} from long_tail)")

    if attack_frames:
        new_attack = pd.concat(attack_frames, ignore_index=True, sort=False)
        existing = (pd.read_parquet(ATTACK_VOL_PARQUET)
                     if ATTACK_VOL_PARQUET.exists() else pd.DataFrame())
        merged = pd.concat([existing, new_attack], ignore_index=True, sort=False)
        merged.to_parquet(ATTACK_VOL_PARQUET, index=False)
        print(f"Attack volume now: {len(merged)} flows "
              f"(+{len(new_attack)} from long_tail) "
              f"per-label: {merged['Label'].value_counts().to_dict()}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
