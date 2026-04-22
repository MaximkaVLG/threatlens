"""Day 8 — evaluate SelectiveFlowDetector against four hold-out sets.

Reports three metrics per set:

1. **All-flows F1 ATK** — what the old (no-abstention) combined model
   produces. Same as the "new" column of ``results/real_world_eval_ab.json``.
2. **Accepted-flows F1 ATK** — F1 computed only on flows the Mahalanobis
   abstainer allowed through. If the abstainer is doing its job, this
   should be noticeably higher than #1.
3. **Abstention rate** — fraction of flows refused. The product-facing
   metric: "how many flows did the IDS refuse to guess on?"

Four hold-out sets:

- CIC-2017 test-size slice (in-distribution) — abstention rate should
  be close to the tuning target (~1 %).
- CIC-2018 test-size slice (sister dataset) — abstention moderate.
- real_pcap + CTU-13 combined — real-world torture test.
- Synthetic (sanity check) — abstention rate should also be ~1 %.

This is the Day 8 evidence for "selective prediction works because
OUR model is confidently wrong on OOD, and Mahalanobis distance
catches OOD even when softmax confidence doesn't".

Usage:
    python scripts/eval_selective.py
    python scripts/eval_selective.py --skip-ctu   # fast iteration
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import FlowExtractor  # noqa: E402
from threatlens.ml.selective import SelectiveFlowDetector, MahalanobisAbstainer, ABSTAIN_LABEL  # noqa: E402

from scripts.eval_cross_dataset import COL_MAP_2018_TO_2017, LABEL_MAP_2018_TO_2017  # noqa: E402
from scripts.train_combined import ALL_FEATURE_COLUMNS, _stratified_sample  # noqa: E402

MODEL_DIR = ROOT / "results" / "combined_v2"
REAL_PCAP_DIR = ROOT / "data" / "real_pcap"
CTU_DIR = ROOT / "data" / "ctu_malware"
SYNTHETIC_CSV = ROOT / "data" / "synthetic" / "synthetic_flows.csv"
OUT_JSON = ROOT / "results" / "selective_eval.json"

# Hardcoded real-world labels, copied from eval_real_world_ab.py
REAL_PCAP_LABELS = {
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


def to_binary(label: str) -> str:
    if label == ABSTAIN_LABEL:
        return ABSTAIN_LABEL
    return "BENIGN" if label == "BENIGN" else "ATTACK"


def compute_three_metrics(y_true_bin: np.ndarray, y_pred_bin: np.ndarray,
                           abstained: np.ndarray) -> Dict:
    """Compute the three headline metrics (all-flows F1, accepted F1, abstention rate)."""
    n = len(y_true_bin)
    if n == 0:
        return {"n": 0}

    # All-flows F1: treat abstentions as BENIGN (silent miss) — this is
    # the baseline "what if we didn't have abstention" for comparison.
    y_pred_silent = np.where(abstained, "BENIGN", y_pred_bin)

    # Accepted-only F1: drop abstained rows.
    accepted = ~abstained
    y_true_acc = y_true_bin[accepted]
    y_pred_acc = y_pred_bin[accepted]

    all_f1 = f1_score(y_true_bin, y_pred_silent, pos_label="ATTACK",
                      average="binary", zero_division=0)
    accepted_f1 = (f1_score(y_true_acc, y_pred_acc, pos_label="ATTACK",
                            average="binary", zero_division=0)
                   if len(y_true_acc) > 0 else None)

    return {
        "n": int(n),
        "n_accepted": int(accepted.sum()),
        "abstention_rate": float(abstained.mean()),
        "all_flows_f1_attack": float(all_f1),
        "accepted_f1_attack": float(accepted_f1) if accepted_f1 is not None else None,
        "accepted_accuracy": (float(accuracy_score(y_true_acc, y_pred_acc))
                              if len(y_true_acc) > 0 else None),
        "confusion_matrix_accepted": (
            confusion_matrix(y_true_acc, y_pred_acc, labels=["BENIGN", "ATTACK"]).tolist()
            if len(y_true_acc) > 0 else []
        ),
    }


def run_on_dataframe(detector: SelectiveFlowDetector, df: pd.DataFrame,
                     label_binary_per_row: np.ndarray) -> Dict:
    preds = detector.predict_with_abstention(df)
    abstained = preds["abstained"].values.astype(bool)
    pred_bin = np.array([to_binary(l) for l in preds["raw_label"].values])
    return compute_three_metrics(label_binary_per_row, pred_bin, abstained), preds


def load_cic2017_slice(sample_size: int, random_state: int) -> pd.DataFrame:
    """Stratified sample from the raw CIC-2017 CSVs (same as cross-dataset eval)."""
    files = sorted((ROOT / "data" / "cicids2017").glob("*.csv"))
    parts = []
    for f in files:
        try:
            chunk = pd.read_csv(f, low_memory=False, encoding="utf-8")
        except UnicodeDecodeError:
            chunk = pd.read_csv(f, low_memory=False, encoding="latin-1")
        parts.append(chunk)
    df = pd.concat(parts, ignore_index=True)
    df.columns = [c.strip() for c in df.columns]
    df["Label"] = df["Label"].astype(str).str.strip()
    df = df.replace([np.inf, -np.inf], np.nan).dropna(
        subset=df.select_dtypes(include=[np.number]).columns)
    return _stratified_sample(df, sample_size, random_state=random_state)


def load_cic2018_slice(sample_size: int, random_state: int) -> pd.DataFrame:
    files = sorted((ROOT / "data" / "cicids2018").glob("*.csv"))
    per_file = sample_size // len(files)
    parts = []
    for f in files:
        chunk = pd.read_csv(f, low_memory=False)
        chunk = chunk[chunk["Label"] != "Label"].copy()
        if len(chunk) > per_file:
            chunk = chunk.sample(n=per_file, random_state=random_state)
        parts.append(chunk)
    df = pd.concat(parts, ignore_index=True)
    df = df.rename(columns=COL_MAP_2018_TO_2017)
    df["mapped_label"] = df["Label"].astype(str).str.strip().map(LABEL_MAP_2018_TO_2017).fillna("OTHER")
    df = df[df["mapped_label"] != "OTHER"].copy()
    df["Label"] = df["mapped_label"]
    df = df.drop(columns=["mapped_label"])
    if "Fwd Header Length.1" not in df.columns and "Fwd Header Length" in df.columns:
        df["Fwd Header Length.1"] = df["Fwd Header Length"]
    # Defensive: CIC-2018 CSVs occasionally have string "Infinity" or NaN in
    # numeric columns. Scaler->classifier won't tolerate that, and our
    # feature columns overlap with CIC_FEATURE_COLUMNS.
    from threatlens.network.flow_extractor import CIC_FEATURE_COLUMNS
    for c in CIC_FEATURE_COLUMNS:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    numeric = df.select_dtypes(include=[np.number]).columns
    df[numeric] = df[numeric].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return df


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-ctu", action="store_true")
    parser.add_argument("--cic-sample", type=int, default=100_000)
    parser.add_argument("--out", default=str(OUT_JSON))
    args = parser.parse_args()

    print(f"[1/6] Loading combined model + Mahalanobis abstainer")
    clf = joblib.load(MODEL_DIR / "xgboost.joblib")
    pipeline = joblib.load(MODEL_DIR / "feature_pipeline.joblib")
    abstainer = MahalanobisAbstainer.load(str(MODEL_DIR / "mahalanobis_abstainer.joblib"))
    detector = SelectiveFlowDetector(pipeline=pipeline, classifier=clf, abstainer=abstainer)
    print(f"  pipeline: {len(pipeline.feature_names)} features")
    print(f"  abstainer thresholds: {len(abstainer.thresholds)} classes, "
          f"global tau fallback = {abstainer._global_fallback:.3f}")

    results = {}

    print(f"\n[2/6] CIC-2017 hold-out sample (in-distribution control)")
    t0 = time.time()
    cic17 = load_cic2017_slice(args.cic_sample, random_state=111)
    print(f"  loaded {len(cic17):,} rows in {time.time()-t0:.1f}s")
    y_bin = np.array(["BENIGN" if l == "BENIGN" else "ATTACK" for l in cic17["Label"]])
    m, _ = run_on_dataframe(detector, cic17, y_bin)
    results["cic2017"] = m
    print(f"  abstention={m['abstention_rate']:.3f}  all_F1={m['all_flows_f1_attack']:.4f}  "
          f"accepted_F1={m['accepted_f1_attack']:.4f}")

    print(f"\n[3/6] CIC-2018 hold-out sample (cross-dataset)")
    t0 = time.time()
    cic18 = load_cic2018_slice(args.cic_sample, random_state=111)
    print(f"  loaded {len(cic18):,} rows in {time.time()-t0:.1f}s")
    y_bin = np.array(["BENIGN" if l == "BENIGN" else "ATTACK" for l in cic18["Label"]])
    m, _ = run_on_dataframe(detector, cic18, y_bin)
    results["cic2018"] = m
    print(f"  abstention={m['abstention_rate']:.3f}  all_F1={m['all_flows_f1_attack']:.4f}  "
          f"accepted_F1={m['accepted_f1_attack']:.4f}")

    print(f"\n[4/6] Synthetic hold-out")
    syn = pd.read_csv(SYNTHETIC_CSV, low_memory=False)
    hulk_mask = syn["Label"] == "DoS Hulk"
    if hulk_mask.sum() > 10_000:
        syn = pd.concat([syn[~hulk_mask], syn[hulk_mask].sample(n=10_000, random_state=111)],
                        ignore_index=True)
    y_bin = np.array(["BENIGN" if l == "BENIGN" else "ATTACK" for l in syn["Label"]])
    m, _ = run_on_dataframe(detector, syn, y_bin)
    results["synthetic"] = m
    print(f"  abstention={m['abstention_rate']:.3f}  all_F1={m['all_flows_f1_attack']:.4f}  "
          f"accepted_F1={m['accepted_f1_attack']:.4f}")

    print(f"\n[5/6] Real-world PCAPs (Stratosphere + {'CTU-13' if not args.skip_ctu else 'skip CTU'})")
    extractor = FlowExtractor()
    real_frames: List[Tuple[pd.DataFrame, str]] = []
    # Stratosphere / Wireshark
    for fname, meta in REAL_PCAP_LABELS.items():
        p = REAL_PCAP_DIR / fname
        if not p.exists():
            continue
        print(f"  extracting {fname}...")
        df = extractor.extract(str(p))
        if df.empty:
            continue
        real_frames.append((df, meta["binary"]))
    if not args.skip_ctu:
        for sub in sorted(CTU_DIR.iterdir()):
            if not sub.is_dir():
                continue
            for p in sorted(sub.glob("botnet-capture-*.pcap")):
                print(f"  extracting {sub.name}/{p.name} ({p.stat().st_size // 1_000_000} MB)...")
                df = extractor.extract(str(p))
                if df.empty:
                    continue
                real_frames.append((df, "ATTACK"))
    if real_frames:
        combined_df = pd.concat([f for f, _ in real_frames], ignore_index=True)
        y_bin = np.concatenate([[lbl] * len(f) for f, lbl in real_frames])
        m, preds = run_on_dataframe(detector, combined_df, y_bin)
        results["real_world"] = m
        print(f"  abstention={m['abstention_rate']:.3f}  all_F1={m['all_flows_f1_attack']:.4f}  "
              f"accepted_F1={m['accepted_f1_attack']:.4f}")
        # Extra stats useful for doc: distance histogram per true label
        results["real_world"]["distance_stats"] = {
            "median_all": float(np.median(preds["mahalanobis_distance"])),
            "p95_all": float(np.percentile(preds["mahalanobis_distance"], 95)),
            "max_all": float(preds["mahalanobis_distance"].max()),
        }

    # ---- Summary table ----
    print(f"\n[6/6] Summary")
    print("=" * 84)
    print(f"{'Scope':<14}{'Flows':>8}{'Abstention':>12}{'All-flows F1 ATK':>18}"
          f"{'Accepted F1 ATK':>18}{'Lift':>10}")
    print("-" * 84)
    for scope in ["cic2017", "cic2018", "synthetic", "real_world"]:
        m = results.get(scope)
        if not m:
            continue
        lift = ((m["accepted_f1_attack"] or 0) - m["all_flows_f1_attack"])
        print(f"{scope:<14}{m['n']:>8}{m['abstention_rate']:>12.3f}"
              f"{m['all_flows_f1_attack']:>18.4f}"
              f"{(m['accepted_f1_attack'] or 0):>18.4f}"
              f"{lift:>+10.4f}")
    print("=" * 84)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(results, indent=2, default=str),
                               encoding="utf-8")
    print(f"\nSaved: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
