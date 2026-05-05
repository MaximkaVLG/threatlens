"""Phase 5 — Bootstrap 95 % confidence intervals + small-N flagging.

Every recall headline in SUBMISSION.md / README is a point estimate from a
specific test set. The "72.24 % on fresh sandbox" or "96.85 % on holdout"
look exact, but they're samples — if we re-ran with a slightly different
PCAP set we'd get different numbers. This script answers "by how much".

Bootstraps recall_attack at 95 % CI (1000 resamples, percentile method) on:

  - real_pcap (historical 7-capture set, 347 ATTACK + 93 BENIGN)
  - CTU-13 hold-out (253 ATTACK)
  - sandbox holdout (Phase 1.1 split, 349 ATTACK across 9 PCAPs)
  - per-family on sandbox holdout (with explicit small-N (<10) flag)

Output:
  results/<model-dir>/bootstrap_ci.json    — machine-readable
  results/<model-dir>/bootstrap_ci.md      — human-readable table
  results/<model-dir>/confusion_sandbox.json — class-by-class confusion on
                                                sandbox holdout, lets a
                                                reviewer see why exact-Bot
                                                recall is what it is.

Usage:
    python scripts/bootstrap_ci.py --model-dir results/v2
    python scripts/bootstrap_ci.py --model-dir results/python_only
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatlens.network.flow_extractor import CIC_FEATURE_COLUMNS  # noqa: E402
from threatlens.network.spectral_features import SPECTRAL_FEATURE_COLUMNS  # noqa: E402
from threatlens.network.payload_yara import YARA_FEATURE_COLUMNS  # noqa: E402

ALL_FEATURES = (list(CIC_FEATURE_COLUMNS) + list(SPECTRAL_FEATURE_COLUMNS)
                + list(YARA_FEATURE_COLUMNS))

ROOT_RESULTS = ROOT / "results"
DEFAULT_MODEL_DIR = ROOT_RESULTS / "v2"
CACHE_PARQUET = ROOT_RESULTS / "real_world_flows_cache.parquet"
SANDBOX_HOLDOUT = ROOT_RESULTS / "python_only" / "sandbox_holdout_flows.parquet"
SANDBOX_FULL = ROOT_RESULTS / "python_only" / "sandbox_malware_flows.parquet"

SMALL_N_THRESHOLD = 10        # flag families / slices with N below this
N_BOOTSTRAP = 1000
SEED = 42
ALPHA = 0.05                  # 95 % CI


def predict_attack(model, pipeline, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
    """Return (y_pred_label, y_is_attack_bool) — handles missing columns."""
    expected = pipeline.feature_names
    for c in expected:
        if c not in df.columns:
            df[c] = 0.0
    X = (df[expected].apply(lambda s: pd.to_numeric(s, errors="coerce"))
                       .replace([np.inf, -np.inf], np.nan).fillna(0.0)
                       .values.astype(np.float64))
    Xs = pipeline.scaler.transform(X)
    y_int = model.predict(Xs)
    y_label = pipeline.label_encoder.inverse_transform(y_int)
    return y_label, (y_label != "BENIGN")


def bootstrap_recall(y_true_attack: np.ndarray,
                      y_pred_attack: np.ndarray,
                      n_resamples: int = N_BOOTSTRAP,
                      seed: int = SEED) -> Dict:
    """Stratified bootstrap on the ATTACK subset.

    Recall = TP / (TP + FN); we resample only the attack flows because
    that's what the denominator measures. Returns point + CI + small-N
    flag.
    """
    n_attack = int(y_true_attack.sum())
    if n_attack == 0:
        return {"n": 0, "point": None, "ci_low": None, "ci_high": None,
                "small_n": True}

    # The y_pred_attack values for the attack subset
    pred_on_attack = y_pred_attack[y_true_attack]
    point = float(pred_on_attack.mean())

    rng = np.random.default_rng(seed)
    boot = np.empty(n_resamples, dtype=np.float64)
    for i in range(n_resamples):
        idx = rng.integers(0, n_attack, n_attack)
        boot[i] = pred_on_attack[idx].mean()
    ci_low = float(np.percentile(boot, 100 * ALPHA / 2))
    ci_high = float(np.percentile(boot, 100 * (1 - ALPHA / 2)))
    return {"n": n_attack, "point": point,
            "ci_low": ci_low, "ci_high": ci_high,
            "ci_width_pp": float((ci_high - ci_low) * 100),
            "small_n": n_attack < SMALL_N_THRESHOLD}


def bootstrap_fp_rate(y_true_benign: np.ndarray,
                       y_pred_attack: np.ndarray,
                       n_resamples: int = N_BOOTSTRAP,
                       seed: int = SEED) -> Dict:
    """FP rate = FP / (FP + TN), bootstrap on BENIGN subset."""
    n_benign = int(y_true_benign.sum())
    if n_benign == 0:
        return {"n": 0, "point": None, "ci_low": None, "ci_high": None,
                "small_n": True}
    pred_on_benign = y_pred_attack[y_true_benign]
    point = float(pred_on_benign.mean())

    rng = np.random.default_rng(seed)
    boot = np.empty(n_resamples, dtype=np.float64)
    for i in range(n_resamples):
        idx = rng.integers(0, n_benign, n_benign)
        boot[i] = pred_on_benign[idx].mean()
    ci_low = float(np.percentile(boot, 100 * ALPHA / 2))
    ci_high = float(np.percentile(boot, 100 * (1 - ALPHA / 2)))
    return {"n": n_benign, "point": point,
            "ci_low": ci_low, "ci_high": ci_high,
            "ci_width_pp": float((ci_high - ci_low) * 100),
            "small_n": n_benign < SMALL_N_THRESHOLD}


def fmt_recall(r: Dict) -> str:
    if r["point"] is None:
        return "n/a (N=0)"
    flag = " ⚠SMALL-N" if r["small_n"] else ""
    return (f"{r['point']*100:.2f} % [{r['ci_low']*100:.2f}, "
            f"{r['ci_high']*100:.2f}] (N={r['n']}, ±{r['ci_width_pp']/2:.1f} pp){flag}")


def main(argv=None) -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    p = argparse.ArgumentParser()
    p.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    p.add_argument("--n-resamples", type=int, default=N_BOOTSTRAP)
    p.add_argument("--seed", type=int, default=SEED)
    args = p.parse_args(argv)

    model_dir = args.model_dir.resolve()
    print(f"=== Bootstrap CI on {model_dir.name} "
          f"(B={args.n_resamples}, seed={args.seed}) ===\n")

    print("[1/4] Loading model + pipeline")
    clf = joblib.load(model_dir / "xgboost.joblib")
    pipeline = joblib.load(model_dir / "feature_pipeline.joblib")

    out: Dict = {
        "model_dir": str(model_dir.relative_to(ROOT)),
        "n_resamples": args.n_resamples,
        "alpha": ALPHA,
        "small_n_threshold": SMALL_N_THRESHOLD,
        "datasets": {},
    }

    # ---------- 2. Historical real_pcap ----------
    print("\n[2/4] Historical real-world (real_pcap cache)")
    cache = pd.read_parquet(CACHE_PARQUET)
    real_df = cache[~cache["__source"].str.startswith("botnet-")].copy()
    real_df.reset_index(drop=True, inplace=True)
    real_y_true_attack = (real_df["__label_binary"].values == "ATTACK")
    _, real_pred_attack = predict_attack(clf, pipeline, real_df)
    real_recall = bootstrap_recall(real_y_true_attack, real_pred_attack,
                                     args.n_resamples, args.seed)
    real_fp = bootstrap_fp_rate(~real_y_true_attack, real_pred_attack,
                                 args.n_resamples, args.seed)
    print(f"  recall ATK: {fmt_recall(real_recall)}")
    print(f"  FP rate (model alone): {fmt_recall(real_fp)}")
    out["datasets"]["real_pcap_historical"] = {
        "recall_attack": real_recall, "fp_rate": real_fp,
    }

    # ---------- 3. CTU holdout ----------
    print("\n[3/4] CTU-13 holdout")
    ctu_path = model_dir / "ctu_test_holdout.parquet"
    if ctu_path.exists():
        ctu_df = pd.read_parquet(ctu_path)
        ctu_df.reset_index(drop=True, inplace=True)
        ctu_y_true_attack = np.ones(len(ctu_df), dtype=bool)  # all ATTACK
        _, ctu_pred_attack = predict_attack(clf, pipeline, ctu_df)
        ctu_recall = bootstrap_recall(ctu_y_true_attack, ctu_pred_attack,
                                        args.n_resamples, args.seed)
        print(f"  recall ATK: {fmt_recall(ctu_recall)}")
        out["datasets"]["ctu_holdout"] = {"recall_attack": ctu_recall}
    else:
        print(f"  SKIP: {ctu_path.name} not found")

    # ---------- 4a. Sandbox FULL set (25 PCAPs, only if no leakage) ----------
    # Only fair for python_only — v2 trained on 16 of these 25 PCAPs, so
    # evaluating it on the full set inflates recall via train leakage.
    # Detect leakage by `sandbox_malware_size` key in metrics.json
    # (set by train_python_only.py when --sandbox-train-parquet is used).
    metrics_path = model_dir / "metrics.json"
    has_sandbox_in_train = False
    if metrics_path.exists():
        try:
            mtr = json.loads(metrics_path.read_text(encoding="utf-8"))
            has_sandbox_in_train = bool(mtr.get("sandbox_malware_size", 0))
        except Exception:
            pass

    print("\n[4a/4] Sandbox FULL set (25 PCAPs, all 5011 flows)")
    if has_sandbox_in_train:
        print("  SKIP: model trained on a subset of these PCAPs "
              "(would leak into recall). Use sandbox_holdout below.")
    elif SANDBOX_FULL.exists():
        full_df = pd.read_parquet(SANDBOX_FULL)
        full_df.reset_index(drop=True, inplace=True)
        full_y_true_attack = np.ones(len(full_df), dtype=bool)  # all "Bot"
        _, full_pred_attack = predict_attack(clf, pipeline, full_df)
        full_recall = bootstrap_recall(full_y_true_attack, full_pred_attack,
                                         args.n_resamples, args.seed)
        print(f"  recall ATK: {fmt_recall(full_recall)}")
        out["datasets"]["sandbox_full"] = {"recall_attack": full_recall}
    else:
        print(f"  SKIP: {SANDBOX_FULL.name} not found")

    # ---------- 4. Sandbox holdout (per-family) ----------
    print("\n[4/4] Sandbox holdout (per-family + per-source)")
    if SANDBOX_HOLDOUT.exists():
        sand_df = pd.read_parquet(SANDBOX_HOLDOUT)
        sand_df.reset_index(drop=True, inplace=True)
        sand_y_true_attack = np.ones(len(sand_df), dtype=bool)  # all "Bot"
        sand_y_pred_label, sand_pred_attack = predict_attack(clf, pipeline, sand_df)

        overall = bootstrap_recall(sand_y_true_attack, sand_pred_attack,
                                     args.n_resamples, args.seed)
        print(f"\n  OVERALL recall ATK: {fmt_recall(overall)}")

        # Per-source
        per_source = {}
        for src in sorted(sand_df["__sandbox_source"].unique()):
            mask = (sand_df["__sandbox_source"].values == src)
            sub_recall = bootstrap_recall(np.ones(int(mask.sum()), dtype=bool),
                                            sand_pred_attack[mask],
                                            args.n_resamples, args.seed)
            per_source[src] = sub_recall
            print(f"  per-source {src:<14}: {fmt_recall(sub_recall)}")

        # Per-family
        per_family = {}
        print()
        for fam in sorted(sand_df["__family"].unique()):
            mask = (sand_df["__family"].values == fam)
            sub_recall = bootstrap_recall(np.ones(int(mask.sum()), dtype=bool),
                                            sand_pred_attack[mask],
                                            args.n_resamples, args.seed)
            per_family[fam] = sub_recall
            print(f"  per-family {fam:<14}: {fmt_recall(sub_recall)}")

        # Per-class confusion
        from collections import Counter
        per_pred_label_counter = Counter(sand_y_pred_label.tolist())
        confusion_sandbox = {
            "n_total": int(len(sand_df)),
            "ground_truth": "Bot (all flows)",
            "predicted_label_distribution": dict(per_pred_label_counter),
        }
        print(f"\n  Predicted-label distribution on holdout (true=Bot):")
        for k, v in sorted(per_pred_label_counter.items(), key=lambda kv: -kv[1]):
            print(f"    {k:<18}: {v:>4d}  ({v/len(sand_df)*100:5.2f} %)")

        out["datasets"]["sandbox_holdout"] = {
            "recall_attack": overall,
            "per_source": per_source,
            "per_family": per_family,
            "confusion_against_Bot": confusion_sandbox,
        }
    else:
        print(f"  SKIP: {SANDBOX_HOLDOUT} not found "
              "(run scripts/split_sandbox.py first)")

    # ---------- Save ----------
    out_json = model_dir / "bootstrap_ci.json"
    out_json.write_text(json.dumps(out, indent=2, default=str),
                          encoding="utf-8")
    print(f"\nSaved: {out_json}")

    # ---------- Markdown summary ----------
    md_lines = [
        f"# Bootstrap 95 % CI on {model_dir.name}",
        "",
        f"Method: percentile bootstrap on the ATTACK subset for recall, on "
        f"the BENIGN subset for FP rate. {args.n_resamples} resamples per "
        f"slice, seed {args.seed}. Slices with N < {SMALL_N_THRESHOLD} are "
        "flagged ⚠SMALL-N — their CI is wide enough that the point estimate "
        "is directional only, not a statistic to act on.",
        "",
        "## Headline test sets",
        "",
        "| Test set | N | Point | 95 % CI | ±pp |",
        "|---|---:|---:|---|---:|",
    ]
    for slice_name, label in [
        ("real_pcap_historical", "Historical real-world recall"),
        ("ctu_holdout", "CTU-13 holdout recall"),
        ("sandbox_full", "Sandbox FULL recall (25 PCAPs)"),
        ("sandbox_holdout", "Sandbox holdout recall (9 PCAPs)"),
    ]:
        if slice_name not in out["datasets"]:
            continue
        r = out["datasets"][slice_name].get("recall_attack")
        if r is None:
            continue
        flag = " ⚠SMALL-N" if r["small_n"] else ""
        md_lines.append(f"| {label}{flag} | {r['n']} | "
                         f"{r['point']*100:.2f} % | "
                         f"[{r['ci_low']*100:.2f}, {r['ci_high']*100:.2f}] | "
                         f"±{r['ci_width_pp']/2:.1f} |")

    if "real_pcap_historical" in out["datasets"]:
        fp = out["datasets"]["real_pcap_historical"]["fp_rate"]
        md_lines += ["",
                      "| FP rate (model alone, BENIGN only) | "
                      f"{fp['n']} | {fp['point']*100:.2f} % | "
                      f"[{fp['ci_low']*100:.2f}, {fp['ci_high']*100:.2f}] | "
                      f"±{fp['ci_width_pp']/2:.1f} |",]

    if "sandbox_holdout" in out["datasets"]:
        md_lines += ["", "## Sandbox holdout — per-source breakdown", "",
                      "| Source | N | Point | 95 % CI | ±pp |",
                      "|---|---:|---:|---|---:|"]
        for src, r in out["datasets"]["sandbox_holdout"]["per_source"].items():
            flag = " ⚠SMALL-N" if r["small_n"] else ""
            md_lines.append(f"| {src}{flag} | {r['n']} | "
                             f"{r['point']*100:.2f} % | "
                             f"[{r['ci_low']*100:.2f}, {r['ci_high']*100:.2f}] | "
                             f"±{r['ci_width_pp']/2:.1f} |")

        md_lines += ["", "## Sandbox holdout — per-family breakdown", "",
                      "| Family | N | Point | 95 % CI | ±pp | Note |",
                      "|---|---:|---:|---|---:|---|"]
        for fam, r in sorted(out["datasets"]["sandbox_holdout"]["per_family"].items(),
                              key=lambda kv: kv[1]["n"]):
            flag = " ⚠SMALL-N" if r["small_n"] else ""
            note = "Wide CI, treat as directional" if r["small_n"] else ""
            md_lines.append(f"| {fam}{flag} | {r['n']} | "
                             f"{r['point']*100:.2f} % | "
                             f"[{r['ci_low']*100:.2f}, {r['ci_high']*100:.2f}] | "
                             f"±{r['ci_width_pp']/2:.1f} | {note} |")

        md_lines += ["", "## Confusion against ground-truth Bot (sandbox holdout)",
                      "",
                      "All 349 holdout flows are labelled `Bot` at ingest. "
                      "The model classifies them as:", ""]
        confusion = out["datasets"]["sandbox_holdout"]["confusion_against_Bot"]
        for k, v in sorted(confusion["predicted_label_distribution"].items(),
                            key=lambda kv: -kv[1]):
            md_lines.append(f"- `{k}`: {v} flows ({v/confusion['n_total']*100:.2f} %)")

        md_lines += ["", "Reading: high `Bot` count = correct exact-class recall. "
                      "Significant `DoS slowloris` / `PortScan` / `SSH-Patator` "
                      "counts mean the timing patterns of modern stealer C2 land "
                      "in those classes' decision regions instead — limit of the "
                      "inherited 7-class taxonomy from CIC-IDS2017."]

    out_md = model_dir / "bootstrap_ci.md"
    out_md.write_text("\n".join(md_lines), encoding="utf-8")
    print(f"Saved: {out_md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
