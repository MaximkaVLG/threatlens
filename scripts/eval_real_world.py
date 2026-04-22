"""Evaluate the trained CIC-IDS2017 models on real-world PCAPs.

Reads PCAPs from `data/real_pcap/`, extracts flows, runs the FlowDetector,
and compares predictions against capture-level ground-truth labels declared
in this script. Writes per-PCAP and aggregate metrics to
`results/real_world_eval.json` and prints a human-readable summary.

Usage:
    python scripts/eval_real_world.py
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)

# Resolve repo root from this script's location
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import FlowExtractor  # noqa: E402
from threatlens.network.detector import FlowDetector  # noqa: E402

PCAP_DIR = ROOT / "data" / "real_pcap"
MODELS_DIR = ROOT / "results" / "cicids2017"
OUT_JSON = ROOT / "results" / "real_world_eval.json"

# Capture-level ground truth. For mixed captures we record `expected_class`
# loosely; per-flow labels do not exist in these public datasets, so we
# evaluate at the binary attack/benign level for those PCAPs and skip them
# from the per-class confusion matrix.
PCAP_LABELS = {
    "slips_ssh-bruteforce.pcap":              {"binary": "ATTACK",  "class": "SSH-Patator", "strict": True},
    "slips_test12_icmp-portscan.pcap":        {"binary": "ATTACK",  "class": "PortScan",    "strict": False},  # ICMP-based, model trained on TCP scans
    "slips_test7_malicious.pcap":             {"binary": "ATTACK",  "class": None,          "strict": False},  # mixed
    "slips_test8_malicious.pcap":             {"binary": "ATTACK",  "class": None,          "strict": False},  # UDP-only C2
    "wireshark_dns-mdns.pcap":                {"binary": "BENIGN",  "class": "BENIGN",      "strict": True},
    "wireshark_http2-data-reassembly.pcap":   {"binary": "BENIGN",  "class": "BENIGN",      "strict": True},
    "wireshark_http2_follow_multistream.pcapng": {"binary": "BENIGN", "class": "BENIGN",   "strict": True},
    "wireshark_tls-renegotiation.pcap":       {"binary": "BENIGN",  "class": "BENIGN",      "strict": True},
    "wireshark_tls12-chacha20.pcap":          {"binary": "BENIGN",  "class": "BENIGN",      "strict": True},
}


def to_binary(label: str) -> str:
    return "BENIGN" if label == "BENIGN" else "ATTACK"


def main() -> int:
    print(f"[1/3] Loading FlowDetector from {MODELS_DIR}")
    detector = FlowDetector.from_results_dir(str(MODELS_DIR))

    extractor = FlowExtractor()
    per_pcap = []
    all_y_true_binary, all_y_pred_binary = [], []
    all_y_true_class, all_y_pred_class = [], []

    pcap_files = sorted([f for f in os.listdir(PCAP_DIR) if f.endswith((".pcap", ".pcapng", ".cap"))])
    if not pcap_files:
        print(f"ERROR: no PCAPs found in {PCAP_DIR}", file=sys.stderr)
        return 1

    print(f"[2/3] Found {len(pcap_files)} PCAPs. Running inference...")

    for fname in pcap_files:
        path = PCAP_DIR / fname
        meta = PCAP_LABELS.get(fname)
        if meta is None:
            print(f"  SKIP {fname} (no ground-truth declared)")
            continue

        t0 = time.time()
        flows = extractor.extract(str(path))
        if flows.empty:
            print(f"  {fname:50s}  SKIP (no flows extracted)")
            per_pcap.append({
                "pcap": fname, "flows": 0, "extract_seconds": round(time.time() - t0, 2),
                "expected_binary": meta["binary"], "expected_class": meta["class"],
                "strict": meta["strict"], "predicted_labels": {}, "binary_correct_pct": None,
            })
            continue

        preds = detector.predict(flows)
        pred_labels = preds["label"].tolist()
        pred_binary = [to_binary(l) for l in pred_labels]

        binary_correct = sum(1 for b in pred_binary if b == meta["binary"])
        binary_pct = round(100.0 * binary_correct / len(pred_binary), 1)

        label_counts = preds["label"].value_counts().to_dict()
        label_counts_str = {str(k): int(v) for k, v in label_counts.items()}

        per_pcap.append({
            "pcap": fname,
            "flows": int(len(preds)),
            "extract_seconds": round(time.time() - t0, 2),
            "expected_binary": meta["binary"],
            "expected_class": meta["class"],
            "strict": meta["strict"],
            "predicted_labels": label_counts_str,
            "binary_correct_pct": binary_pct,
            "mean_confidence": round(float(preds["confidence"].mean()), 4),
            "anomaly_flag_pct": round(100.0 * float(preds["anomaly_flag"].mean()), 1),
        })

        # Aggregate for binary metrics — every PCAP contributes
        all_y_true_binary.extend([meta["binary"]] * len(pred_binary))
        all_y_pred_binary.extend(pred_binary)

        # Aggregate for per-class metrics — only strict PCAPs (clean ground truth)
        if meta["strict"] and meta["class"] is not None:
            all_y_true_class.extend([meta["class"]] * len(pred_labels))
            all_y_pred_class.extend(pred_labels)

        print(f"  {fname:50s}  flows={len(preds):>4} | "
              f"binary={binary_pct:>5.1f}% match | "
              f"top-pred={max(label_counts, key=label_counts.get)}")

    print("[3/3] Computing aggregate metrics...")

    # Binary metrics
    binary_acc = accuracy_score(all_y_true_binary, all_y_pred_binary) if all_y_true_binary else 0.0
    binary_f1 = f1_score(all_y_true_binary, all_y_pred_binary, pos_label="ATTACK", average="binary") if all_y_true_binary else 0.0
    binary_cm = confusion_matrix(all_y_true_binary, all_y_pred_binary, labels=["BENIGN", "ATTACK"]).tolist() if all_y_true_binary else []

    # Per-class metrics on strict PCAPs only
    if all_y_true_class:
        per_class_report = classification_report(all_y_true_class, all_y_pred_class, output_dict=True, zero_division=0)
        per_class_f1_weighted = f1_score(all_y_true_class, all_y_pred_class, average="weighted", zero_division=0)
    else:
        per_class_report = {}
        per_class_f1_weighted = None

    summary = {
        "n_pcaps": len(per_pcap),
        "n_flows_total": int(sum(p["flows"] for p in per_pcap)),
        "binary_accuracy": round(float(binary_acc), 4),
        "binary_f1_attack": round(float(binary_f1), 4),
        "binary_confusion_matrix": {
            "labels": ["BENIGN", "ATTACK"],
            "matrix": binary_cm,
            "format": "rows=true, cols=predicted",
        },
        "per_class_f1_weighted_strict_only": (
            round(float(per_class_f1_weighted), 4) if per_class_f1_weighted is not None else None
        ),
        "per_class_report_strict_only": per_class_report,
    }

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps({"summary": summary, "per_pcap": per_pcap}, indent=2))
    print(f"\nWritten: {OUT_JSON}")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
