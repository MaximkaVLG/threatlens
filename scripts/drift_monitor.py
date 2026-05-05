"""Phase 6 — drift monitor for production predictions.

Reads the `prediction_summary` table populated by the FastAPI handler
(`threatlens/web/app.py::_record_prediction_summary_safe`), computes
Population Stability Index (PSI) against the training-distribution
baseline, and writes a daily JSON + Markdown report.

The training-distribution baseline is built from the model's metrics.json
(per-class counts at training time). PSI is computed on the rolling
7-day production class distribution, with a "warm-up" flag while the
window is incomplete.

Output:
  results/drift_monitor/<YYYY-MM-DD>.json   — raw PSI numbers
  results/drift_monitor/log.md              — human-readable rolling log
  results/drift_monitor/ALERT.txt           — only if PSI ≥ 0.25 (for
                                               external watchdog)

Conventional PSI thresholds:
  < 0.10  no meaningful drift
  0.10-0.25  slight drift, monitor
  >= 0.25  significant drift, retrain candidate

Usage:
    python scripts/drift_monitor.py
    python scripts/drift_monitor.py --window-days 7
    python scripts/drift_monitor.py --model-dir results/v2

Designed to be cron-safe — exits 0 even on warm-up; writes ALERT.txt
only when an external watcher should escalate.
"""
from __future__ import annotations

import argparse
import json
import math
import sqlite3
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PSI_BIN_FLOOR = 0.001       # Avoid log(0) blowups for empty bins
WARNING_THRESHOLD = 0.10
ALERT_THRESHOLD = 0.25
DEFAULT_WINDOW_DAYS = 7
DEFAULT_MODEL_DIR = ROOT / "results" / "v2"
OUTPUT_DIR = ROOT / "results" / "drift_monitor"


def compute_psi(reference: Dict[str, float],
                 observed: Dict[str, float]) -> Dict[str, float]:
    """Population Stability Index between two normalized class distributions.

    PSI = Σ_classes ((p_obs - p_ref) × ln(p_obs / p_ref))

    Both inputs should sum to ~1.0; we re-normalize defensively.
    Classes seen in only one distribution still contribute (with the
    other side floored to PSI_BIN_FLOOR so log() doesn't blow up).

    Returns:
        {"psi": <float>, "per_class": {<class>: <psi_contrib>, ...}}
    """
    classes = set(reference.keys()) | set(observed.keys())
    if not classes:
        return {"psi": 0.0, "per_class": {}}

    ref_total = sum(reference.values()) or 1.0
    obs_total = sum(observed.values()) or 1.0
    ref_norm = {c: max(reference.get(c, 0) / ref_total, PSI_BIN_FLOOR)
                 for c in classes}
    obs_norm = {c: max(observed.get(c, 0) / obs_total, PSI_BIN_FLOOR)
                 for c in classes}
    per_class = {}
    psi = 0.0
    for c in classes:
        contrib = (obs_norm[c] - ref_norm[c]) * math.log(obs_norm[c] / ref_norm[c])
        per_class[c] = contrib
        psi += contrib
    return {"psi": psi, "per_class": per_class}


def load_training_baseline(model_dir: Path) -> Dict[str, float]:
    """Read per-class training counts from metrics.json.

    Returns a dict like {"BENIGN": 35000, "Bot": 800, ...} normalized
    to relative frequencies. If metrics.json doesn't expose per-class
    counts directly, falls back to val_per_class_report support counts.
    """
    metrics_path = model_dir / "metrics.json"
    if not metrics_path.exists():
        raise FileNotFoundError(f"metrics.json not found at {metrics_path}")
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))

    # Try the val_per_class_report block first (sklearn classification_report
    # with output_dict=True). Two formats are possible:
    #   - keys are class names ("BENIGN", "Bot", ...)
    #   - keys are encoded label indices ("0", "1", ...) when the report was
    #     called with the integer y_pred — in which case we map back via
    #     metrics["classes"].
    SKLEARN_META = {"accuracy", "macro avg", "weighted avg"}
    classes_list = metrics.get("classes", [])
    report = metrics.get("val_per_class_report", {})
    counts: Dict[str, float] = {}
    for k, v in report.items():
        if k in SKLEARN_META:
            continue
        if not isinstance(v, dict) or "support" not in v:
            continue
        # Translate "0", "1", ... back to "BENIGN", "Bot", ...
        if isinstance(k, str) and k.isdigit() and classes_list:
            idx = int(k)
            if 0 <= idx < len(classes_list):
                counts[classes_list[idx]] = float(v["support"])
                continue
        counts[k] = float(v["support"])
    if counts:
        return counts

    # Fallback: use the global class totals if exposed
    classes = metrics.get("classes", [])
    if classes:
        # Equal weights — least informative but better than crashing
        return {c: 1.0 for c in classes}
    raise RuntimeError(f"metrics.json at {metrics_path} doesn't expose "
                        "val_per_class_report or classes")


def load_cache_window(window_seconds: int,
                       model_dir_filter: Optional[str] = None) -> Counter:
    """Aggregate class_distribution_json from the last `window_seconds`."""
    from threatlens.cache import get_cache
    cache = get_cache()
    cutoff = int(time.time()) - window_seconds
    sql = ("SELECT class_distribution_json FROM prediction_summary "
            "WHERE timestamp >= ?")
    params = [cutoff]
    if model_dir_filter:
        sql += " AND model_dir = ?"
        params.append(model_dir_filter)
    counts: Counter = Counter()
    n_scans = 0
    with sqlite3.connect(cache.db_path) as conn:
        for (json_str,) in conn.execute(sql, params).fetchall():
            try:
                d = json.loads(json_str or "{}")
            except json.JSONDecodeError:
                continue
            counts.update(d)
            n_scans += 1
    counts["_n_scans"] = n_scans  # smuggle scan count for the report
    return counts


def main(argv=None) -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    p = argparse.ArgumentParser()
    p.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR,
                    help="Production model dir; used for training baseline + filter.")
    p.add_argument("--window-days", type=int, default=DEFAULT_WINDOW_DAYS)
    p.add_argument("--no-write", action="store_true",
                    help="Compute and print, but don't write any output files.")
    args = p.parse_args(argv)

    model_dir = args.model_dir.resolve()
    model_id = str(model_dir.relative_to(ROOT)).replace("\\", "/")
    print(f"=== Drift monitor on {model_id}, window={args.window_days}d ===\n")

    print("[1/3] Training-distribution baseline")
    try:
        ref = load_training_baseline(model_dir)
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"  ERROR: {exc}")
        return 1
    ref_total = sum(ref.values())
    print(f"  {len(ref)} classes, total support N={ref_total:.0f}")

    print(f"\n[2/3] Production window (last {args.window_days} days)")
    obs_counter = load_cache_window(window_seconds=args.window_days * 86400,
                                      model_dir_filter=model_id)
    n_scans = obs_counter.pop("_n_scans", 0)
    obs_total = sum(obs_counter.values())
    print(f"  {n_scans} scans -> {obs_total} flows -> {len(obs_counter)} distinct classes")

    if n_scans == 0:
        print("  WARM-UP: no production scans in window. PSI not computable.")
        out = {
            "model_dir": model_id,
            "window_days": args.window_days,
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "warm_up": True,
            "n_scans": 0,
            "n_flows_observed": 0,
            "psi": None,
            "per_class": {},
            "alert": False,
        }
    else:
        print(f"\n[3/3] Population Stability Index")
        psi_result = compute_psi(reference=ref, observed=dict(obs_counter))
        psi = psi_result["psi"]
        if psi < WARNING_THRESHOLD:
            verdict = f"OK (PSI={psi:.3f} < {WARNING_THRESHOLD})"
        elif psi < ALERT_THRESHOLD:
            verdict = (f"WARN (PSI={psi:.3f} in [{WARNING_THRESHOLD}, "
                        f"{ALERT_THRESHOLD})) — slight drift, monitor")
        else:
            verdict = (f"ALERT (PSI={psi:.3f} ≥ {ALERT_THRESHOLD}) — "
                        "significant drift, retrain candidate")
        print(f"  {verdict}")
        per_class_sorted = sorted(
            psi_result["per_class"].items(),
            key=lambda kv: -abs(kv[1]))
        print(f"  Top 5 contributing classes (|contrib| descending):")
        for cls, contrib in per_class_sorted[:5]:
            ref_pct = (ref.get(cls, 0) / ref_total * 100) if ref_total else 0
            obs_pct = (obs_counter.get(cls, 0) / obs_total * 100) if obs_total else 0
            print(f"    {cls:<18}  ref={ref_pct:5.2f} %  obs={obs_pct:5.2f} %  "
                  f"contrib={contrib:+.4f}")
        out = {
            "model_dir": model_id,
            "window_days": args.window_days,
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "warm_up": False,
            "n_scans": n_scans,
            "n_flows_observed": obs_total,
            "psi": psi,
            "verdict": verdict,
            "per_class": dict(per_class_sorted),
            "reference_distribution": {c: ref.get(c, 0) / ref_total
                                          for c in ref},
            "observed_distribution": {c: obs_counter.get(c, 0) / obs_total
                                         for c in obs_counter},
            "alert": psi >= ALERT_THRESHOLD,
        }

    if not args.no_write:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        out_json = OUTPUT_DIR / f"{date_str}.json"
        out_json.write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"\n  Saved {out_json.relative_to(ROOT)}")

        # Append a one-line summary to log.md for the operator
        log_md = OUTPUT_DIR / "log.md"
        line = (f"| {date_str} | {model_id} | {n_scans} | "
                 f"{out.get('psi') if out.get('psi') is not None else 'warm-up'} | "
                 f"{out.get('verdict', 'warm-up')} |")
        if not log_md.exists():
            log_md.write_text(
                "# Drift monitor — daily log\n\n"
                "Run nightly via cron. PSI < 0.10 = OK, "
                "0.10-0.25 = WARN (monitor), ≥ 0.25 = ALERT (retrain).\n\n"
                "| Date | Model | N_scans | PSI | Verdict |\n"
                "|---|---|---:|---:|---|\n"
                + line + "\n",
                encoding="utf-8")
        else:
            with log_md.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        print(f"  Appended to {log_md.relative_to(ROOT)}")

        # Alert file for external watchdog
        alert_file = OUTPUT_DIR / "ALERT.txt"
        if out.get("alert"):
            alert_file.write_text(
                f"{date_str}: {out['verdict']} on {model_id}\n"
                f"Top contributing class: {next(iter(out['per_class']))}\n",
                encoding="utf-8")
            print(f"  WROTE ALERT: {alert_file.relative_to(ROOT)}")
        elif alert_file.exists():
            # Clear stale alert if drift recovered
            alert_file.unlink()
            print(f"  Cleared stale {alert_file.relative_to(ROOT)} "
                  "(drift recovered)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
