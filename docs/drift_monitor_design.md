# Drift monitor — design (Phase 6)

**Status:** design only. Not implemented as of this commit. The
infrastructure description below is the plan we'd ship if the project
runs long enough on threatlens.tech to accumulate meaningful inference
traffic.

## Why this is a "design" doc, not an implemented feature

A drift monitor needs **production data** to be meaningful. We can ship
the logging schema and the analysis script today, but the resulting
charts would say "no data yet" for the first several weeks. Reporting
"the drift monitor is implemented" without actual drift signal would be
the kind of theatre this project tries to avoid.

The plan below is concrete enough that turning it on takes ~2 days of
code work; the value lands ~14 days later when production logs
accumulate.

## What we'd monitor

The model can degrade in two distinct ways, and they need different
detectors:

1. **Feature drift.** The mix of traffic the model sees in production
   diverges from the training distribution. Symptoms: median packet
   sizes shift, flow durations change, the abstainer rate climbs.

2. **Class drift.** The mix of *predictions* the model emits changes.
   Could be benign (more user uploads) or malicious (a wave of one
   attack family). Symptoms: a class that was 1 % of predictions
   yesterday is 30 % today.

Each is separately actionable. Feature drift triggers retraining;
class drift triggers triage by the operator.

## Logging schema

Add to `threatlens/cache.py` next to the existing `scan_events` table:

```sql
CREATE TABLE IF NOT EXISTS prediction_summary (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,                     -- unix seconds
    scan_id INTEGER NOT NULL REFERENCES scan_events(id),
    model_dir TEXT NOT NULL,                        -- e.g. "results/v2"

    -- Per-scan aggregate stats (one row per /api/network/analyze-pcap)
    n_flows INTEGER NOT NULL,
    n_attack INTEGER NOT NULL,
    n_benign INTEGER NOT NULL,
    n_abstain INTEGER NOT NULL,
    mean_confidence REAL NOT NULL,

    -- Compact per-class histogram as JSON
    -- e.g. {"BENIGN": 12, "Bot": 3, "DoS Hulk": 0, ...}
    class_distribution_json TEXT NOT NULL,

    -- Compact per-feature mean / std / pct snapshot, as JSON
    -- (subset: 8 features the variance filter kept first; full feature
    -- vectors would explode storage)
    feature_summary_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_pred_summary_ts
    ON prediction_summary(timestamp);
CREATE INDEX IF NOT EXISTS idx_pred_summary_model
    ON prediction_summary(model_dir);
```

Storage cost: ~500 bytes per scan. At 1 scan/min that's ~3 KB/hour,
~70 KB/day, ~25 MB/year. Negligible for our scale.

Sampling: an env var `THREATLENS_DRIFT_LOG_RATE` controls the fraction
of scans that get logged here (default 1.0 = log all). Knob exists for
when traffic outgrows storage budget.

## Analysis: PSI on the rolling window

Population Stability Index is the standard drift metric:

  PSI = Σ ((p_obs - p_ref) × ln(p_obs / p_ref))

where `p_ref` is the training distribution (frozen) and `p_obs` is the
last 7-day rolling production distribution. Conventional thresholds:

| PSI | Interpretation |
|---|---|
| < 0.1 | No meaningful drift |
| 0.1 – 0.25 | Slight drift, monitor |
| ≥ 0.25 | Significant drift, retrain candidate |

We compute PSI for two slices:

1. **Class-distribution PSI.** Compares per-class prediction frequency
   in production vs the validation-set class frequency the model was
   tuned on.
2. **Feature-summary PSI.** For each of 8 anchor features (the ones
   with highest XGBoost importance), bin into 10 quantiles based on
   the training distribution, compute PSI on the bin frequencies.

## Trigger / report

`scripts/drift_monitor.py` runs daily on a cron, reads the last
~28 days of `prediction_summary`, emits:

- `results/drift_monitor/<YYYY-MM-DD>.json` — raw PSI numbers, the
  current week's class histogram, top 3 features whose distribution
  shifted the most.
- A markdown summary appended to `results/drift_monitor/log.md` that
  the operator can read on threatlens.tech.

If PSI ≥ 0.25 on either slice, the script also writes a one-line
summary to `results/drift_monitor/ALERT.txt` so an external watchdog
(systemd timer + email) can pick it up.

## Why we don't ship learned-from-history retrain

A naive auto-retrain on production traffic is dangerous: a single
miscaltegorised batch poisons the next model. The plan is **alert
only**. The operator triages the drift report, decides whether the
production data is actually labellable (rarely is), and runs
`scripts/train_python_only.py` manually with curated additions.

This is the same conservative posture as the active-learning demo
([`docs/day12_buffer_and_submission.md`](day12_buffer_and_submission.md))
— the analyst is the source of truth, not the prediction stream.

## Reproduce the schema today (without traffic)

The schema migration is a one-shot script:

```bash
python -c "from threatlens.cache import get_cache; get_cache()"
```

The first call adds the new table without touching `scan_cache` or
`scan_events`. Drift monitor would then start populating it as scans
arrive.

## Open questions / known gaps

- **Feature snapshot subset selection.** Which 8 features? The Day 9
  XGBoost importance list points to Flow IAT mean, Flow Duration,
  Total Fwd Packets, etc. — but importance changes with each retrain.
  Best practice: pin the 8 to whatever the *production* model thinks
  is most important at the time of its build, not retrain-by-retrain.
- **Class-imbalance distortion.** PSI on a class with 0.1 % training
  frequency is noisy; we'd cap minimum-frequency bins at 1 % to keep
  the metric stable. Same approach as the variance filter handles
  near-zero features.
- **Cold start.** First 7 days of production have no rolling window
  to compute PSI against. We'd back-fill with the validation-set
  distribution for the reference and emit a "warm-up" flag in the
  output until 7 days of history accumulates.
