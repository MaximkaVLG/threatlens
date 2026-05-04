# Documentation map

This directory has 17 markdown files. They are organised by **time
budget** rather than chronology — pick a row that matches how long you
have, and the rest is optional depth.

## 5 minutes (just want the headline)

| File | Why |
|---|---|
| [`/SUBMISSION.md`](../SUBMISSION.md) (in repo root) | One-page summary: 97.83 % recall @ 2.02 % FP, before/after table, 5 reproduction commands, honest limits |
| [`/README.md`](../README.md) | Project overview + screenshots + quick-start |

That's it. If the headline number checks out and the repro-commands
look sane, everything else is supporting material.

## 30 minutes (technical reviewer wants to verify)

| File | Why |
|---|---|
| [`architecture.md`](architecture.md) | 5-layer Defense-in-Depth pipeline, ASCII diagram, per-layer module + test mapping, operating-mode trade-off table |
| [`day9_python_only_retrain.md`](day9_python_only_retrain.md) | Why the model went from 0.86 % → 96.25 % real-world recall. Includes per-iteration recall trajectory v1→v7 |
| [`day12_buffer_and_submission.md`](day12_buffer_and_submission.md) | Success-criteria audit (3/5 literally met + 1 stronger replacement + 1 deferred) + active-learning mini-demo (5 labels → -6 FPs, -0.29 pt recall) |
| [`test_report_2026-04-23.md`](test_report_2026-04-23.md) | 188 / 2 / 0 test results, per-module breakdown, cross-check between published metrics and live re-runs |

After these 4 files you can defend any number on the title page.

## Deep dive (full process — academic / Practicum reviewer)

The 12-day improvement plan from broken baseline → submission-ready
model. Each day-doc is self-contained with its own setup, results,
honest limits, and reproduction commands.

| Day | File | What changed |
|---:|---|---|
| 0 | [`improvement_plan.md`](improvement_plan.md) | The 12-day plan itself with go/no-go criteria |
| 4 | [`day4_yara_synergy.md`](day4_yara_synergy.md) | YARA-on-payload features added (3 cols, dormant in current model — see day12 for honest note) |
| 5 | [`day5_combined_retrain.md`](day5_combined_retrain.md) | Combined CIC-2017+CIC-2018 retrain — failed to fix real-world recall, motivated Day 7 diagnostic |
| 6 | [`day6_real_world_reeval.md`](day6_real_world_reeval.md) | Re-eval on Stratosphere PCAPs revealed 0.86 % recall — the real problem |
| 7 | [`day7_drift_diagnostic.md`](day7_drift_diagnostic.md) | KS-test on Java vs Python CICFlowMeter: 91-98 % features have p<0.001 — found the root cause |
| 8 | [`day8_selective_prediction.md`](day8_selective_prediction.md) | Mahalanobis abstainer as a stop-gap (treat OOD as "unknown") |
| 9 | [`day9_python_only_retrain.md`](day9_python_only_retrain.md) | The architectural fix — drop Java CSVs, train on Python-extracted only. v1→v7 iterations |
| 10 | [`day10_web_app_integration.md`](day10_web_app_integration.md) | Wire python_only into FastAPI + UI, optional-artefact loader, env-var rollback path |
| 11 | [`day11_metrics_and_docs.md`](day11_metrics_and_docs.md) | Honest-metric reframe (0.998 in-distribution out, 0.96 real-world in), workload-reduction sweep |
| 12 | [`day12_buffer_and_submission.md`](day12_buffer_and_submission.md) | Success audit, active-learning demo, SUBMISSION.md |
| 13 | [`day13_sandbox_ingestion.md`](day13_sandbox_ingestion.md) | Modern (2024-2026) malware PCAP ingest pipeline + 39 unit tests |

## Reference docs (not part of the 12-day narrative)

| File | What it is |
|---|---|
| [`real_world_eval.md`](real_world_eval.md) | Original real-world PCAP evaluation methodology — covers test-set composition |
| [`cross_dataset_eval.md`](cross_dataset_eval.md) | The CIC-IDS2017 → CIC-IDS2018 generalisation experiment that motivated Day 7 |
| [`synthetic_eval.md`](synthetic_eval.md) | Synthetic data sanity checks — show the model isn't overfitting to scapy artefacts |
| [`diploma.md`](diploma.md) | Russian-language diploma defence text. Separate audience from the prize submission |

## What's deliberately NOT here

- **No tutorial / "getting started" walk-through.** The 5-command repro
  in `SUBMISSION.md` is the tutorial. We don't have the cycles for a
  full onboarding doc and a reviewer doesn't need one.
- **No API reference.** FastAPI auto-generates one at
  `http://localhost:8888/docs` when the app is running. Linking to a
  static copy would drift.
- **No "future work" essay.** What's planned vs what's done is in
  `improvement_plan.md`; honest limits per layer are in
  `architecture.md` and `SUBMISSION.md`.
