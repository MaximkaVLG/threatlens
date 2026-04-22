"""Day 6 — A/B real-world evaluation: old (CIC-2017-only) vs new (combined) model.

Runs both models on TWO real-world test sets in a single pass:

  1. **real_pcap/** — 9 small captures (Stratosphere SSH/portscan/malicious +
     Wireshark benign DNS/HTTP/TLS). Capture-level labels are hardcoded.
     Old model F1 binary on this set was 0.0000 (zero true positives).

  2. **ctu_malware/** — 3 CTU-13 botnet captures (Neris x2, Sogou x1).
     Per CTU-13 README, the ``botnet-capture-*.pcap`` files contain
     **only the botnet traffic** (the full mixed PCAPs are private,
     not in the repo). Capture-level label is "Bot" for every flow.

Single extraction pass → two predict calls. Side-by-side metrics.
Output: ``results/real_world_eval_ab.json`` + console table.

Crucially, **NEITHER model is loaded twice** and PCAP extraction
(slow on CTU's 56 MB files) runs only once per file.

Usage:
    python scripts/eval_real_world_ab.py
    python scripts/eval_real_world_ab.py --skip-ctu  # quick re-run on small captures only
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, classification_report,
    confusion_matrix, f1_score,
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import (  # noqa: E402
    FlowExtractor, CIC_FEATURE_COLUMNS,
)
from threatlens.network.spectral_features import SPECTRAL_FEATURE_COLUMNS  # noqa: E402
from threatlens.network.payload_yara import YARA_FEATURE_COLUMNS  # noqa: E402

OLD_MODEL_DIR = ROOT / "results" / "cicids2017"
NEW_MODEL_DIR = ROOT / "results" / "combined_v2"
REAL_PCAP_DIR = ROOT / "data" / "real_pcap"
CTU_DIR = ROOT / "data" / "ctu_malware"
OUT_JSON = ROOT / "results" / "real_world_eval_ab.json"

# Stratosphere/Wireshark capture-level labels (copied verbatim from
# the original eval_real_world.py to keep results comparable).
REAL_PCAP_LABELS: Dict[str, dict] = {
    "slips_ssh-bruteforce.pcap":              {"binary": "ATTACK", "class": "SSH-Patator", "strict": True},
    "slips_test12_icmp-portscan.pcap":        {"binary": "ATTACK", "class": "PortScan",    "strict": False},
    "slips_test7_malicious.pcap":             {"binary": "ATTACK", "class": None,          "strict": False},
    "slips_test8_malicious.pcap":             {"binary": "ATTACK", "class": None,          "strict": False},
    "wireshark_dns-mdns.pcap":                {"binary": "BENIGN", "class": "BENIGN",      "strict": True},
    "wireshark_http2-data-reassembly.pcap":   {"binary": "BENIGN", "class": "BENIGN",      "strict": True},
    "wireshark_http2_follow_multistream.pcapng": {"binary": "BENIGN", "class": "BENIGN",   "strict": True},
    "wireshark_tls-renegotiation.pcap":       {"binary": "BENIGN", "class": "BENIGN",      "strict": True},
    "wireshark_tls12-chacha20.pcap":          {"binary": "BENIGN", "class": "BENIGN",      "strict": True},
}


def discover_ctu_pcaps() -> List[Dict]:
    """CTU-13 directory layout: ctu_malware/botnet-N/botnet-capture-*.pcap.

    Per the README in each subdir, those PCAPs contain only botnet
    traffic — every flow is labelled "Bot" / "ATTACK".
    """
    out = []
    if not CTU_DIR.exists():
        return out
    for sub in sorted(CTU_DIR.iterdir()):
        if not sub.is_dir():
            continue
        for pcap in sorted(sub.glob("botnet-capture-*.pcap")):
            out.append({
                "path": pcap,
                "label_binary": "ATTACK",
                "label_class": "Bot",
                "scenario": sub.name,
            })
    return out


def to_binary(label: str) -> str:
    return "BENIGN" if label == "BENIGN" else "ATTACK"


def predict_with_pipeline(model, pipeline, df: pd.DataFrame) -> np.ndarray:
    """Same as scripts/eval_combined.py — align columns then transform+predict."""
    expected = pipeline.feature_names
    for c in expected:
        if c not in df.columns:
            df[c] = 0.0
    X = df[expected].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X_scaled = pipeline.scaler.transform(X.values)
    y_int = model.predict(X_scaled)
    return pipeline.label_encoder.inverse_transform(y_int)


def evaluate_capture(name: str, df: pd.DataFrame, label_binary: str, label_class,
                     old_model, old_pipe, new_model, new_pipe) -> Dict:
    """Run BOTH models on the same flow DataFrame, return per-capture metrics."""
    n_flows = len(df)
    if n_flows == 0:
        return {"name": name, "n_flows": 0, "label_binary": label_binary,
                "label_class": label_class}

    # Predict
    old_preds = predict_with_pipeline(old_model, old_pipe, df.copy())
    new_preds = predict_with_pipeline(new_model, new_pipe, df.copy())

    old_bin = np.array([to_binary(l) for l in old_preds])
    new_bin = np.array([to_binary(l) for l in new_preds])

    return {
        "name": name,
        "n_flows": int(n_flows),
        "label_binary": label_binary,
        "label_class": label_class,
        "old": {
            "binary_correct_pct": float((old_bin == label_binary).mean() * 100),
            "label_counts": {str(k): int(v) for k, v in pd.Series(old_preds).value_counts().items()},
        },
        "new": {
            "binary_correct_pct": float((new_bin == label_binary).mean() * 100),
            "label_counts": {str(k): int(v) for k, v in pd.Series(new_preds).value_counts().items()},
        },
        "_y_true_binary": [label_binary] * n_flows,
        "_y_pred_old_binary": old_bin.tolist(),
        "_y_pred_new_binary": new_bin.tolist(),
        "_y_true_class": ([label_class] * n_flows) if label_class else None,
        "_y_pred_old_class": old_preds.tolist() if label_class else None,
        "_y_pred_new_class": new_preds.tolist() if label_class else None,
    }


def aggregate(per_cap: List[Dict], scope: str) -> Dict:
    """Aggregate binary + per-class metrics across captures matching ``scope``."""
    chosen = [p for p in per_cap if p.get("_y_true_binary")]
    if not chosen:
        return {}

    y_true_bin = sum((p["_y_true_binary"] for p in chosen), [])
    y_old_bin = sum((p["_y_pred_old_binary"] for p in chosen), [])
    y_new_bin = sum((p["_y_pred_new_binary"] for p in chosen), [])

    # Per-class is class-strict only — captures with label_class None are skipped
    strict = [p for p in chosen if p.get("_y_true_class")]
    y_true_cls = sum((p["_y_true_class"] for p in strict), []) if strict else []
    y_old_cls = sum((p["_y_pred_old_class"] for p in strict), []) if strict else []
    y_new_cls = sum((p["_y_pred_new_class"] for p in strict), []) if strict else []

    def _bin_stats(y_true, y_pred):
        return {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "f1_attack": float(f1_score(y_true, y_pred, pos_label="ATTACK",
                                        average="binary", zero_division=0)),
            "confusion_matrix": confusion_matrix(y_true, y_pred,
                                                 labels=["BENIGN", "ATTACK"]).tolist(),
        }

    summary = {
        "scope": scope,
        "n_captures": len(chosen),
        "n_flows": int(sum(p["n_flows"] for p in chosen)),
        "binary_old": _bin_stats(y_true_bin, y_old_bin),
        "binary_new": _bin_stats(y_true_bin, y_new_bin),
    }

    if y_true_cls:
        summary["per_class"] = {
            "n_strict_flows": len(y_true_cls),
            "old_f1_weighted": float(f1_score(y_true_cls, y_old_cls,
                                              average="weighted", zero_division=0)),
            "new_f1_weighted": float(f1_score(y_true_cls, y_new_cls,
                                              average="weighted", zero_division=0)),
            "old_report": classification_report(y_true_cls, y_old_cls,
                                                output_dict=True, zero_division=0),
            "new_report": classification_report(y_true_cls, y_new_cls,
                                                output_dict=True, zero_division=0),
        }

    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-ctu", action="store_true",
                        help="Skip the slow CTU-13 botnet PCAPs (small captures only)")
    parser.add_argument("--out", default=str(OUT_JSON))
    args = parser.parse_args()

    # Force UTF-8 stdout on Windows so class names containing replacement
    # chars (CIC-2017 "Web Attack \ufffd ...") don't crash cp1251.
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    import joblib
    print(f"[1/5] Loading models")
    old_model = joblib.load(OLD_MODEL_DIR / "xgboost.joblib")
    old_pipe = joblib.load(OLD_MODEL_DIR / "feature_pipeline.joblib")
    new_model = joblib.load(NEW_MODEL_DIR / "xgboost.joblib")
    new_pipe = joblib.load(NEW_MODEL_DIR / "feature_pipeline.joblib")
    print(f"  old: {len(old_pipe.feature_names)} features, "
          f"{len(old_pipe.label_encoder.classes_)} classes")
    print(f"  new: {len(new_pipe.feature_names)} features, "
          f"{len(new_pipe.label_encoder.classes_)} classes")

    extractor = FlowExtractor()

    # ---- 2. real_pcap captures ----
    print(f"\n[2/5] Real-world Stratosphere/Wireshark captures")
    per_cap_real = []
    for fname in sorted(REAL_PCAP_LABELS.keys()):
        path = REAL_PCAP_DIR / fname
        if not path.exists():
            print(f"  SKIP {fname} (not on disk)")
            continue
        meta = REAL_PCAP_LABELS[fname]
        t0 = time.time()
        df = extractor.extract(str(path))
        extract_s = time.time() - t0
        result = evaluate_capture(
            fname, df, meta["binary"], meta["class"],
            old_model, old_pipe, new_model, new_pipe,
        )
        result["extract_seconds"] = round(extract_s, 2)
        result["scope"] = "real_pcap"
        per_cap_real.append(result)
        if df.empty:
            print(f"  {fname:50s}  no flows ({extract_s:.1f}s)")
            continue
        print(f"  {fname:50s}  flows={result['n_flows']:>4} | "
              f"old binary {result['old']['binary_correct_pct']:>5.1f}% | "
              f"new binary {result['new']['binary_correct_pct']:>5.1f}%")

    # ---- 3. CTU-13 captures ----
    per_cap_ctu = []
    if not args.skip_ctu:
        ctu_pcaps = discover_ctu_pcaps()
        print(f"\n[3/5] CTU-13 botnet captures ({len(ctu_pcaps)} files, "
              f"{sum(p['path'].stat().st_size for p in ctu_pcaps) // 1_000_000} MB total)")
        for spec in ctu_pcaps:
            print(f"  extracting {spec['scenario']}/{spec['path'].name} ({spec['path'].stat().st_size // 1_000_000} MB)...")
            t0 = time.time()
            df = extractor.extract(str(spec["path"]))
            extract_s = time.time() - t0
            result = evaluate_capture(
                f"{spec['scenario']}/{spec['path'].name}", df,
                spec["label_binary"], spec["label_class"],
                old_model, old_pipe, new_model, new_pipe,
            )
            result["extract_seconds"] = round(extract_s, 2)
            result["scope"] = "ctu13"
            per_cap_ctu.append(result)
            print(f"    flows={result['n_flows']:>5} ({extract_s:.1f}s) | "
                  f"old ATTACK {result['old']['binary_correct_pct']:>5.1f}% | "
                  f"new ATTACK {result['new']['binary_correct_pct']:>5.1f}%")
    else:
        print(f"\n[3/5] Skipping CTU-13 (--skip-ctu set)")

    # ---- 4. Aggregate ----
    print(f"\n[4/5] Aggregating")
    summary = {
        "real_pcap": aggregate(per_cap_real, "real_pcap"),
        "ctu13": aggregate(per_cap_ctu, "ctu13") if per_cap_ctu else {},
        "combined": aggregate(per_cap_real + per_cap_ctu, "combined") if per_cap_ctu else {},
    }

    # ---- 5. Persist + console table ----
    OUT_JSON_path = Path(args.out)
    OUT_JSON_path.parent.mkdir(parents=True, exist_ok=True)

    # Strip the per-flow arrays before writing — they bloat the JSON.
    def _strip(p):
        out = {k: v for k, v in p.items() if not k.startswith("_")}
        return out
    persisted = {
        "summary": summary,
        "per_capture_real_pcap": [_strip(p) for p in per_cap_real],
        "per_capture_ctu13": [_strip(p) for p in per_cap_ctu],
    }
    OUT_JSON_path.write_text(json.dumps(persisted, indent=2, default=str),
                              encoding="utf-8")

    print(f"\n[5/5] Results")
    print("=" * 78)
    print(f"{'Scope':<15} {'Captures':>9} {'Flows':>8} {'Old F1 ATK':>12} {'New F1 ATK':>12} {'Delta':>10}")
    print("-" * 78)
    for scope_name in ["real_pcap", "ctu13", "combined"]:
        s = summary.get(scope_name)
        if not s:
            continue
        old_f1 = s["binary_old"]["f1_attack"]
        new_f1 = s["binary_new"]["f1_attack"]
        print(f"{scope_name:<15} {s['n_captures']:>9} {s['n_flows']:>8} "
              f"{old_f1:>12.4f} {new_f1:>12.4f} {new_f1 - old_f1:>+10.4f}")
    print("=" * 78)

    # Per-class for real_pcap (only one with strict per-class labels)
    if "per_class" in summary.get("real_pcap", {}):
        pc = summary["real_pcap"]["per_class"]
        print(f"\nReal-world per-class F1 weighted (strict captures only, n_flows={pc['n_strict_flows']}):")
        print(f"  old: {pc['old_f1_weighted']:.4f}    new: {pc['new_f1_weighted']:.4f}    "
              f"delta: {pc['new_f1_weighted'] - pc['old_f1_weighted']:+.4f}")

    print(f"\nWritten: {OUT_JSON_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
