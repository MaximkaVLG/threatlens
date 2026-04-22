"""Day 7 — diagnose whether the real-world generalization gap is
explainable as feature distribution drift between training and inference.

Two independent diagnostics:

A) **Within-project distribution comparison.** For three labels that
   exist in BOTH the CIC-IDS2017 CSVs (Java CICFlowMeter +
   Argus-labeled, our training distribution) AND in the synthetic
   flows CSV (Python cicflowmeter + scapy, our inference distribution),
   compare per-feature value distributions:

     - Kolmogorov-Smirnov D-statistic + p-value
     - Wasserstein distance (1-D earth-mover)
     - Mean and std ratio

   If the overlap classes look statistically identical, distribution
   drift is unlikely to be the bottleneck. If most features differ at
   p<0.001 with large Wasserstein distances, drift is the leading
   suspect for Day 6's poor real-world transfer.

   Caveat (acknowledged in docs/day7): same-class still differs by
   *traffic generator* (curl vs lab humans), not just *extractor*. So
   this is a *necessary* but not *sufficient* test for drift. If
   distributions match here, drift is exonerated; if they don't,
   drift is a candidate but not yet proven without a Java extractor.

B) **Confidence-collapse signature.** Run the old (CIC-2017-only)
   model on three slices:
   - CIC-2017 test split (in-distribution control)
   - Synthetic flows (Python extractor, lab traffic)
   - real_pcap + CTU-13 (Python extractor, wild traffic)

   Compare predict_proba max distributions. If the model is
   *confident* on real-world flows (just confidently wrong), the
   problem is generalization. If the model is *uncertain* on
   real-world flows but the threshold logic still picks a class, the
   problem is calibration / decision threshold.

Output: results/feature_drift_diag.json + console summary.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd
from scipy.stats import ks_2samp, wasserstein_distance

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import (  # noqa: E402
    FlowExtractor, CIC_FEATURE_COLUMNS,
)

CIC_DIR = ROOT / "data" / "cicids2017"
SYNTHETIC_CSV = ROOT / "data" / "synthetic" / "synthetic_flows.csv"
REAL_PCAP_DIR = ROOT / "data" / "real_pcap"
CTU_DIR = ROOT / "data" / "ctu_malware"
OLD_MODEL_DIR = ROOT / "results" / "cicids2017"
OUT_JSON = ROOT / "results" / "feature_drift_diag.json"

# Labels present in both CIC-2017 and our synthetic generator.
# CIC-2017 lacks the messy unicode label issues we see in CIC-2018, but
# we still strip whitespace.
SHARED_LABELS = ["BENIGN", "PortScan", "FTP-Patator", "SSH-Patator", "DoS slowloris"]


def _stratified_sample_per_label(df: pd.DataFrame, labels: List[str],
                                 n_per_label: int = 5000,
                                 random_state: int = 42) -> pd.DataFrame:
    out = []
    for lbl in labels:
        slice_ = df[df["Label"] == lbl]
        if len(slice_) == 0:
            continue
        n = min(len(slice_), n_per_label)
        out.append(slice_.sample(n=n, random_state=random_state))
    return pd.concat(out, ignore_index=True) if out else pd.DataFrame()


def load_cic_filtered(labels: List[str], n_per_label: int = 5000) -> pd.DataFrame:
    files = sorted(CIC_DIR.glob("*.csv"))
    parts = []
    for f in files:
        try:
            chunk = pd.read_csv(f, low_memory=False, encoding="utf-8")
        except UnicodeDecodeError:
            chunk = pd.read_csv(f, low_memory=False, encoding="latin-1")
        chunk.columns = [c.strip() for c in chunk.columns]
        chunk["Label"] = chunk["Label"].astype(str).str.strip()
        chunk = chunk[chunk["Label"].isin(labels)]
        if not chunk.empty:
            parts.append(chunk)
    df = pd.concat(parts, ignore_index=True)
    df = df.replace([np.inf, -np.inf], np.nan).dropna(
        subset=df.select_dtypes(include=[np.number]).columns)
    return _stratified_sample_per_label(df, labels, n_per_label)


def load_synthetic_filtered(labels: List[str], n_per_label: int = 5000) -> pd.DataFrame:
    df = pd.read_csv(SYNTHETIC_CSV, low_memory=False)
    df["Label"] = df["Label"].astype(str).str.strip()
    df = df[df["Label"].isin(labels)]
    return _stratified_sample_per_label(df, labels, n_per_label)


def per_feature_drift(cic_df: pd.DataFrame, syn_df: pd.DataFrame,
                      label: str) -> List[Dict]:
    """For one label, compute KS + Wasserstein per CIC feature.

    Returns sorted list of dicts (most divergent first).
    """
    cic_slice = cic_df[cic_df["Label"] == label]
    syn_slice = syn_df[syn_df["Label"] == label]
    if len(cic_slice) < 30 or len(syn_slice) < 30:
        return []

    rows = []
    for col in CIC_FEATURE_COLUMNS:
        if col not in cic_slice.columns or col not in syn_slice.columns:
            continue
        a = pd.to_numeric(cic_slice[col], errors="coerce").dropna().values
        b = pd.to_numeric(syn_slice[col], errors="coerce").dropna().values
        if len(a) < 10 or len(b) < 10:
            continue

        # Skip features that are constant on either side
        if a.std() == 0 and b.std() == 0:
            continue

        try:
            ks_stat, ks_p = ks_2samp(a, b)
        except ValueError:
            continue

        # Wasserstein needs non-degenerate; normalise by combined range
        # so distances are comparable across features of different scale
        rng = max(a.max(), b.max()) - min(a.min(), b.min())
        if rng <= 0:
            wd_norm = 0.0
        else:
            wd = wasserstein_distance(a, b)
            wd_norm = float(wd / rng)

        rows.append({
            "feature": col,
            "ks_d": float(ks_stat),
            "ks_p": float(ks_p),
            "wasserstein_norm": wd_norm,
            "cic_mean": float(np.mean(a)),
            "cic_std": float(np.std(a)),
            "syn_mean": float(np.mean(b)),
            "syn_std": float(np.std(b)),
        })

    rows.sort(key=lambda r: -r["ks_d"])
    return rows


def confidence_signature(model_dir: Path) -> Dict:
    """Compare prediction confidence between in-distribution and wild flows."""
    import joblib
    model = joblib.load(model_dir / "xgboost.joblib")
    pipe = joblib.load(model_dir / "feature_pipeline.joblib")
    expected = pipe.feature_names

    def _predict_proba_max(df: pd.DataFrame) -> np.ndarray:
        for c in expected:
            if c not in df.columns:
                df[c] = 0.0
        X = df[expected].replace([np.inf, -np.inf], np.nan).fillna(0.0)
        X_scaled = pipe.scaler.transform(X.values)
        proba = model.predict_proba(X_scaled)
        return proba.max(axis=1)

    out: Dict[str, Dict] = {}

    print("[B] CIC-2017 BENIGN sample (in-distribution control)")
    cic = load_cic_filtered(["BENIGN"], n_per_label=5000)
    if not cic.empty:
        conf = _predict_proba_max(cic.copy())
        out["cic2017_benign"] = {
            "n": int(len(conf)),
            "confidence_p25": float(np.percentile(conf, 25)),
            "confidence_median": float(np.percentile(conf, 50)),
            "confidence_p75": float(np.percentile(conf, 75)),
            "confidence_low_pct": float((conf < 0.5).mean() * 100),
        }
        print(f"  median conf {out['cic2017_benign']['confidence_median']:.3f}, "
              f"low(<0.5)={out['cic2017_benign']['confidence_low_pct']:.1f}%")

    print("[B] Synthetic flows (Python extractor, lab traffic)")
    syn = pd.read_csv(SYNTHETIC_CSV, low_memory=False)
    syn = syn.sample(n=min(5000, len(syn)), random_state=42)
    conf = _predict_proba_max(syn.copy())
    out["synthetic"] = {
        "n": int(len(conf)),
        "confidence_p25": float(np.percentile(conf, 25)),
        "confidence_median": float(np.percentile(conf, 50)),
        "confidence_p75": float(np.percentile(conf, 75)),
        "confidence_low_pct": float((conf < 0.5).mean() * 100),
    }
    print(f"  median conf {out['synthetic']['confidence_median']:.3f}, "
          f"low(<0.5)={out['synthetic']['confidence_low_pct']:.1f}%")

    print("[B] Real-world PCAPs (Stratosphere + CTU-13, wild traffic)")
    extractor = FlowExtractor()
    wild_dfs = []
    pcaps = list(REAL_PCAP_DIR.glob("*.pcap")) + list(REAL_PCAP_DIR.glob("*.pcapng"))
    for sub in CTU_DIR.iterdir():
        if sub.is_dir():
            pcaps.extend(sub.glob("botnet-capture-*.pcap"))
    for p in pcaps:
        try:
            df = extractor.extract(str(p))
            if not df.empty:
                wild_dfs.append(df)
        except Exception as e:
            print(f"  WARN extract failed for {p.name}: {e}")
    if wild_dfs:
        wild = pd.concat(wild_dfs, ignore_index=True)
        conf = _predict_proba_max(wild.copy())
        out["real_world"] = {
            "n": int(len(conf)),
            "confidence_p25": float(np.percentile(conf, 25)),
            "confidence_median": float(np.percentile(conf, 50)),
            "confidence_p75": float(np.percentile(conf, 75)),
            "confidence_low_pct": float((conf < 0.5).mean() * 100),
        }
        print(f"  median conf {out['real_world']['confidence_median']:.3f}, "
              f"low(<0.5)={out['real_world']['confidence_low_pct']:.1f}%")

    return out


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print("=" * 76)
    print("Day 7 — feature drift diagnostic")
    print("=" * 76)

    print("\n[A] Within-project distribution comparison")
    print(f"  Loading CIC-2017 (Java-extracted) for: {SHARED_LABELS}")
    cic = load_cic_filtered(SHARED_LABELS, n_per_label=5000)
    print(f"  CIC-2017: {len(cic)} rows")
    print(f"  Per label:\n{cic['Label'].value_counts().to_string()}")

    print(f"\n  Loading synthetic (Python-extracted) for: {SHARED_LABELS}")
    syn = load_synthetic_filtered(SHARED_LABELS, n_per_label=5000)
    print(f"  Synthetic: {len(syn)} rows")
    print(f"  Per label:\n{syn['Label'].value_counts().to_string()}")

    drift_per_label: Dict[str, List[Dict]] = {}
    summary_per_label: Dict[str, Dict] = {}

    print("\n  Per-label per-feature drift (top 5 by KS D-stat):")
    print("  " + "-" * 70)
    for lbl in SHARED_LABELS:
        results = per_feature_drift(cic, syn, lbl)
        drift_per_label[lbl] = results
        if not results:
            print(f"\n  {lbl}: SKIP (insufficient data in either source)")
            continue

        n_significant = sum(1 for r in results if r["ks_p"] < 0.001)
        n_huge_ks = sum(1 for r in results if r["ks_d"] >= 0.5)
        summary_per_label[lbl] = {
            "n_features_compared": len(results),
            "n_p_lt_001": n_significant,
            "n_ks_d_gte_0.5": n_huge_ks,
            "pct_significant": round(100 * n_significant / len(results), 1),
            "median_ks_d": float(np.median([r["ks_d"] for r in results])),
            "median_wasserstein_norm": float(np.median([r["wasserstein_norm"] for r in results])),
        }

        print(f"\n  {lbl} ({len(results)} features compared, "
              f"{n_significant} at p<0.001, {n_huge_ks} with D>=0.5):")
        print(f"  {'feature':<36}  {'KS D':>6}  {'KS p':>10}  {'W norm':>8}  {'CIC mean':>11}  {'SYN mean':>11}")
        for r in results[:5]:
            print(f"  {r['feature']:<36}  {r['ks_d']:>6.3f}  {r['ks_p']:>10.2e}  "
                  f"{r['wasserstein_norm']:>8.4f}  {r['cic_mean']:>11.3g}  {r['syn_mean']:>11.3g}")

    print("\n[A summary]")
    for lbl, s in summary_per_label.items():
        print(f"  {lbl:<22}  {s['n_p_lt_001']:>3}/{s['n_features_compared']:>3} features at p<0.001 "
              f"({s['pct_significant']:>5.1f}%), median KS D = {s['median_ks_d']:.3f}")

    print("\n[B] Confidence collapse signature (old CIC-2017 model)")
    conf_results = confidence_signature(OLD_MODEL_DIR)

    print("\n[B summary]")
    print(f"  {'slice':<20}  {'n':>6}  {'median conf':>12}  {'low(<0.5) %':>12}")
    for k, v in conf_results.items():
        print(f"  {k:<20}  {v['n']:>6}  {v['confidence_median']:>12.4f}  {v['confidence_low_pct']:>12.1f}")

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps({
        "shared_labels": SHARED_LABELS,
        "drift_per_label_top10": {lbl: r[:10] for lbl, r in drift_per_label.items()},
        "drift_summary_per_label": summary_per_label,
        "confidence_signature": conf_results,
    }, indent=2, default=str), encoding="utf-8")
    print(f"\nSaved: {OUT_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
