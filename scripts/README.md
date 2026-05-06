# Scripts directory map

35 Python scripts. Most are referenced from `docs/day*.md` reproduction
sections (and `docs/adversarial_baseline.md` / `docs/drift_monitor_design.md`
for the Phase 3/6 work). Categorised here by purpose so a reviewer can
find what's critical vs what's historical without grep-ing.

## Headline / submission-critical (5 scripts)

These produce the numbers in `SUBMISSION.md` and the README. If only
one of these breaks, the rest of the submission can't be reproduced —
treat as load-bearing.

| Script | Wall time | Output |
|---|---:|---|
| [`train_python_only.py`](train_python_only.py) | ~10 s | `results/python_only/{xgboost,feature_pipeline}.joblib` — the production model |
| [`fit_selective_python_only.py`](fit_selective_python_only.py) | ~2 s | `results/python_only/mahalanobis_abstainer.joblib` — Day 8 abstainer |
| [`eval_python_only.py`](eval_python_only.py) | ~1 s | `results/python_only/real_world_eval.json` — the **F1 = 0.961, recall = 96.25 %** headline |
| [`workload_metric.py`](workload_metric.py) | ~5 s | `results/python_only/workload_metric.json` — the lenient/safe/strict/paranoid trade-off |
| [`active_learning_demo.py`](active_learning_demo.py) | ~7 s | `results/python_only/active_learning_demo.json` — Day 12 "5 labels → -6 FPs" demo |

## Reproducible training-data generation (6 scripts, run as 3 pairs)

Each pair: `generate_*` crafts PCAPs with scapy under various network
conditions, `extract_*` runs `FlowExtractor` over them and saves a
parquet. Re-run only if you need to regenerate the training data from
scratch (otherwise the parquets in `results/python_only/` are sufficient).

| Pair | What it makes | Day |
|---|---|---:|
| `generate_diverse_benign.py` + `extract_diverse_benign.py` | DNS / TLS / HTTP / SSH / SMTP / mDNS / DHCP / NTP / SSDP benign flows | 9b/d |
| `generate_attack_volume.py` + `extract_attack_volume.py` | Port-diverse SSH / FTP brute-force at hydra-class volumes | 9d |
| `generate_long_tail.py` + `extract_long_tail.py` | TLS quick-fetch + HTTP/2 stream + HTTP/2 idle + TCP-micro brute-force | 9e |

## Sandbox ingest (Day 13, 2 scripts)

| Script | What it does |
|---|---|
| [`ingest_sandbox_pcaps.py`](ingest_sandbox_pcaps.py) | Downloads modern (2024-2026) malware PCAPs from Stratosphere CTU + malware-traffic-analysis.net |
| [`extract_sandbox_pcaps.py`](extract_sandbox_pcaps.py) | Runs `FlowExtractor` over downloaded PCAPs and saves parquet for re-eval / re-train |

39 unit tests in `tests/test_sandbox_ingest.py` cover this pipeline.

## Setup / one-time (1 script)

| Script | When to run |
|---|---|
| [`download_yara_rules.py`](download_yara_rules.py) | Once after `pip install` — fetches ~1500 community YARA rules into `threatlens/rules/yara_community/`. The Dockerfile runs this in the build stage |

## Plot / screenshot generators (2 scripts)

| Script | Output |
|---|---|
| [`make_analysis_plots.py`](make_analysis_plots.py) | `docs/figures/*.png` (feature importance, confusion matrix, etc.) |
| [`make_screenshots.py`](make_screenshots.py) | `docs/screenshots/*.png` (UI captures used in README) |

Re-run only when refreshing the docs/.

## Historical / superseded by python_only path (11 scripts)

These scripts produced the intermediate `combined_v2/` model bundle
and its evaluations. They still work and are referenced from
`docs/day{4,5,6,7,8}_*.md`, but they are **not part of the current
production pipeline**. Kept so the day-by-day docs reproduce.

| Script | Source day | What it was for |
|---|---:|---|
| [`compare_baselines.py`](compare_baselines.py) | Day 2 | Compare classical ML baselines vs initial XGBoost |
| [`demo_benchmark.py`](demo_benchmark.py) | Day 2 | Latency benchmark of analyze-pcap endpoint |
| [`diag_feature_drift.py`](diag_feature_drift.py) | Day 7 | KS-test of Java vs Python CICFlowMeter feature distributions |
| [`eval_combined.py`](eval_combined.py) | Day 5 | combined_v2 vs cicids2017 head-to-head |
| [`eval_cross_dataset.py`](eval_cross_dataset.py) | Day 5 | CIC-IDS2017 → CIC-IDS2018 generalisation test |
| [`eval_real_world.py`](eval_real_world.py) | Day 6 | Stratosphere PCAP eval (the one that revealed 0.86 % recall) |
| [`eval_real_world_ab.py`](eval_real_world_ab.py) | Day 6 | A/B comparison of cicids2017 vs combined_v2 on real PCAPs |
| [`eval_selective.py`](eval_selective.py) | Day 8 | Selective-prediction one-shot eval at default coverage |
| [`eval_selective_sweep.py`](eval_selective_sweep.py) | Day 8 | Selective-prediction coverage-vs-F1 sweep |
| [`fit_selective.py`](fit_selective.py) | Day 8 | Mahalanobis abstainer fit on combined_v2 |
| [`train_combined.py`](train_combined.py) | Day 5 | Train combined_v2 (CIC-2017 + CIC-2018 + synthetic) |

If you are evaluating the **current** model only, you can ignore all
11 — `train_python_only.py` + `eval_python_only.py` cover the full
production path.

## Sandbox holdout split + per-PCAP eval (Day 13 + Phase 1, 2 scripts)

| Script | What it does |
|---|---|
| [`split_sandbox.py`](split_sandbox.py) | Stratified split of 25 sandbox PCAPs into 16 train / 9 holdout. Hand-designed to keep family + source diversity in both halves. Emits `results/python_only/sandbox_{split.json,train_flows.parquet,holdout_flows.parquet}` |
| [`eval_sandbox.py`](eval_sandbox.py) | Per-PCAP eval against any model dir. Adds `--full` for the 25-PCAP set or default 9-PCAP holdout |

## Statistical + adversarial + drift (Phase 3 / 5 / 6 / 7, 6 scripts)

These don't change the model — they make the headline number defensible.

| Script | Phase | Output |
|---|---:|---|
| [`bootstrap_ci.py`](bootstrap_ci.py) | 5 | `results/<model>/bootstrap_ci.{json,md}` — 95 % percentile bootstrap CI on every test set, with small-N flagging and per-source / per-family breakdown |
| [`perturb_pcap.py`](perturb_pcap.py) | 3 | one perturbed PCAP — primitives for the adversarial grid (4 perturbations × 4 strengths) |
| [`adversarial_eval.py`](adversarial_eval.py) | 3 | `results/<model>/adversarial_eval.{json,md}` — full 4 × 4 grid of recall under perturbation per holdout PCAP |
| [`adversarial_compare.py`](adversarial_compare.py) | 3 | `docs/adversarial_compare.md` — head-to-head recall matrix between two models on the same grid |
| [`drift_monitor.py`](drift_monitor.py) | 6 | `results/drift_monitor/<date>.json` + `log.md` + `ALERT.txt` — nightly PSI on production class distribution vs training baseline |
| [`check_submission_consistency.py`](check_submission_consistency.py) | 7 | exit 0/1 — regression test across 26 headline numbers cited in `SUBMISSION.md` / `README.md` / `ab_vs_python_only.md`. Run before tagging a release |
