"""Extract CIC-IDS2017 flow features from synthetic PCAPs.

Reads every PCAP in data/synthetic/, runs threatlens.network.FlowExtractor,
attaches the label from the sidecar `<pcap>.meta.json`, and writes a single
labeled CSV ready for combined-dataset training.

Output: data/synthetic/synthetic_flows.csv
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import FlowExtractor  # noqa: E402

PCAP_DIR = ROOT / "data" / "synthetic"
OUT_CSV = PCAP_DIR / "synthetic_flows.csv"
SUMMARY_JSON = PCAP_DIR / "_extraction_summary.json"


def main() -> int:
    pcaps = sorted([p for p in PCAP_DIR.glob("*.pcap")
                    if not p.name.startswith("_")])  # skip log/summary files
    if not pcaps:
        print(f"No PCAPs in {PCAP_DIR}", file=sys.stderr)
        return 1

    extractor = FlowExtractor()
    all_dfs = []
    summary = {"per_pcap": [], "labels": {}, "total_flows": 0}

    for pcap in pcaps:
        meta_path = pcap.with_suffix(".meta.json")
        if not meta_path.exists():
            print(f"  SKIP {pcap.name} (no sidecar metadata)")
            continue

        meta = json.loads(meta_path.read_text())
        label = meta["label"]

        t0 = time.time()
        try:
            df = extractor.extract(str(pcap))
        except Exception as e:
            print(f"  ERROR {pcap.name}: {e}")
            summary["per_pcap"].append({
                "pcap": pcap.name, "error": str(e), "flows": 0,
            })
            continue

        if df.empty:
            print(f"  EMPTY {pcap.name} (no flows extracted)")
            summary["per_pcap"].append({
                "pcap": pcap.name, "flows": 0, "label": label, "extract_seconds": round(time.time() - t0, 2),
            })
            continue

        df["Label"] = label
        df["__source_pcap"] = pcap.name
        df["__netem_profile"] = meta.get("netem_profile", "clean")
        all_dfs.append(df)

        n = len(df)
        summary["per_pcap"].append({
            "pcap": pcap.name,
            "flows": n,
            "label": label,
            "netem_profile": meta.get("netem_profile"),
            "extract_seconds": round(time.time() - t0, 2),
        })
        summary["labels"][label] = summary["labels"].get(label, 0) + n
        summary["total_flows"] += n
        print(f"  {pcap.name:55s}  {label:18s}  {n:>5} flows ({time.time() - t0:.1f}s)")

    if not all_dfs:
        print("No flows extracted from any PCAP", file=sys.stderr)
        return 1

    combined = pd.concat(all_dfs, ignore_index=True)
    combined.to_csv(OUT_CSV, index=False)
    SUMMARY_JSON.write_text(json.dumps(summary, indent=2))

    print()
    print(f"Total flows: {summary['total_flows']:,}")
    print(f"Per-label counts:")
    for label, n in sorted(summary["labels"].items(), key=lambda x: -x[1]):
        print(f"  {label:18s} {n:>6}")
    print(f"\nWritten: {OUT_CSV} ({combined.shape})")
    print(f"Written: {SUMMARY_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
