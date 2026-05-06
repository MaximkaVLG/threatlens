# ThreatLens — Defense-in-Depth IDS architecture

**Updated:** 2026-04-23 (Day 11)
**Status:** Production architecture as of the Day 9e python-only retrain.

This document describes the full pipeline a PCAP file goes through
once an analyst uploads it. It's organised as a **five-layer
defense-in-depth design**: each layer can stand on its own, but the
combination is what gives ThreatLens its real-world detection numbers.

```
   ┌─────────────────────────────────────────────────────────────┐
   │  Layer 1 — Python flow extractor (zero cross-stack drift)   │
   │  Layer 2 — 81-feature engineering (CIC + spectral + YARA)   │
   │  Layer 3 — XGBoost classifier (python-only retrain)          │
   │  Layer 4 — Mahalanobis abstainer (selective prediction)      │
   │  Layer 5 — SHAP + YandexGPT explainability                   │
   └─────────────────────────────────────────────────────────────┘
```

The ASCII pipeline:

```
        PCAP file
            │
            ▼
   ┌──────────────────┐
   │ Layer 1          │  threatlens.network.flow_extractor
   │ FlowExtractor    │  (Python cicflowmeter wrapper —
   │                  │   same code path used at training time)
   └────────┬─────────┘
            │  flows DataFrame: 5-tuple + 70 CIC base features
            ▼
   ┌──────────────────┐
   │ Layer 2          │  threatlens.network.spectral_features
   │ Spectral + YARA  │  threatlens.network.payload_yara
   │ feature builder  │  + 8 spectral + 3 YARA features
   └────────┬─────────┘
            │  flows DataFrame: 5-tuple + 81 features
            ▼
   ┌──────────────────┐
   │ Layer 3          │  threatlens.network.detector.FlowDetector
   │ XGBoost          │  loads results/python_only/xgboost.joblib
   │ (7-class)        │  predicts label + per-class probability
   └────────┬─────────┘
            │  predictions: label, confidence
            ▼
   ┌──────────────────┐
   │ Layer 4          │  threatlens.ml.selective.MahalanobisAbstainer
   │ OOD abstainer    │  computes distance-to-class-centroid
   │ (optional)       │  flags is_uncertain when above tuned threshold
   └────────┬─────────┘
            │  predictions + is_uncertain + distance_to_centroid
            ▼
   ┌──────────────────┐
   │ Layer 5          │  threatlens.ml.shap_explainer (per-flow click)
   │ Explainability   │  + threatlens.ai.yandex_gpt (natural language)
   └────────┬─────────┘
            │  per-flow JSON: SHAP top-K features + AI explanation
            ▼
   FastAPI JSON  →  web UI (table + charts + per-flow drill-down)
```

## Layer 1 — Python flow extractor

`threatlens/network/flow_extractor.py` wraps the `cicflowmeter` Python
package. Critically, the SAME extractor runs at training time AND at
inference time — eliminating the Java-vs-Python feature-drift gap that
crippled the previous CIC-IDS2017-only model (Day 7 diagnostic showed
91-98 % of features had p<0.001 between the two extractor implementations).

**Why it matters:** Day 6 measured 0.86 % attack recall on the same
real-world PCAPs Day 9 hits 96.25 % on. The single biggest factor was
extractor consistency, not classifier sophistication.

## Layer 2 — Feature engineering

Three feature groups are stitched together per flow:

| Group | # features | After variance filter | What it captures |
|---|---:|---:|---|
| CIC-2017 base | 70 | 57 | Flow duration, packet counts, byte totals, IAT statistics, TCP flag counts, bidirectional asymmetry |
| Spectral (Day 5) | 8 | 8 | FFT-based: peak frequency + magnitude, entropy, centroid, bandwidth, low-freq energy ratio, IAT periodicity (botnet-beacon detector), zero-crossing rate |
| YARA payload (Day 4) | 3 | 0 | Per-flow YARA hit count, max severity, has-match flag |
| **Total** | **81** | **65** | |

The `FeaturePipeline` (`threatlens/ml/features.py`) standard-scales
the 81 raw features and drops zero-variance columns, leaving 65
for the final model.

**Honest note on YARA features.** All 3 YARA features get dropped by
the variance filter on the python_only training corpus. The reason:
`yara-python` does not install on Python 3.14 (no wheel; source build
needs MSVC + libyara), so during training those columns are constant
zero. The infrastructure (`threatlens/network/payload_yara.py`,
`compute_yara_features()`, integration into `CicFlowExtractor.extract`)
exists end-to-end and the unit tests cover the plumbing with mocked
yara, but **the python_only model in `results/python_only/` makes its
predictions from CIC + spectral features alone**. The YARA layer is
real architecturally but presently dormant in production. Re-enabling
it requires (a) installing yara-python on the training machine,
(b) re-extracting training data with YARA actually firing, and
(c) re-fitting the variance filter so the YARA columns survive. This
is documented as a deferred Day 12 item in `docs/day12_buffer_and_submission.md`.

All 8 spectral features survive variance filtering and the model uses
them — `Spectral Entropy` and `IAT Periodicity Score` are among the
top-importance features by XGBoost gain.

## Layer 3 — XGBoost classifier

`results/python_only/xgboost.joblib` — the Day 9e candidate.

| | Value |
|---|---|
| Model | XGBoost, 200 estimators, max_depth 8 |
| Training rows | 30 743 (synthetic + 70 % CTU-13 + diverse benign + attack-volume + long-tail) |
| Classes | 7 — `BENIGN`, `Bot`, `DoS Hulk`, `DoS slowloris`, `FTP-Patator`, `PortScan`, `SSH-Patator` |
| Class balancing | Inverse-frequency `sample_weight` |
| Internal val F1 weighted | 0.9958 |
| **Real-world F1 (real_pcap)** | **0.961** |
| **Real-world recall ATTACK** | **96.25 %** (334 / 347) |
| **CTU-13 hold-out recall** | **100 %** (253 / 253) |

A `random_forest.joblib` is shipped alongside in legacy bundles
(`results/cicids2017/`, `results/combined_v2/`) but not in the python_only
bundle — the additional model wasn't worth the load time given XGBoost
is uniformly better on this feature set.

## Layer 4 — Mahalanobis abstainer (selective prediction)

`results/python_only/mahalanobis_abstainer.joblib` — Day 8 work, refit
on the python_only training distribution at coverage 0.99 by default.

For each prediction, the abstainer:

1. Computes Mahalanobis distance from the input vector to the centroid
   of the predicted class (in the standardised feature space, using a
   pooled covariance matrix with ridge regularisation).
2. Compares to a per-class threshold tuned on a held-out validation
   split so that 99 % of correctly-classified training flows lie
   under it.
3. Sets `is_uncertain=1` for flows above the threshold.

Two operating modes:

- **Lenient (default):** `is_uncertain` is just a flag. Original label
  preserved. UI shows a yellow "review" marker on the row but doesn't
  hide the prediction. Operators see the model's best guess + a
  confidence-degradation hint.
- **Strict (`THREATLENS_STRICT_MODE=1`):** Abstained predictions get
  rewritten to the `UNCERTAIN` label (yellow in the class distribution
  bar). Useful for high-stakes environments where false alerts are
  extra-expensive.

The Day 9e measurement showed the abstainer no longer offers a Pareto
improvement at any coverage — the model is well-enough calibrated on
its own. The abstainer is kept as a configurable operator control,
not a default workflow blocker.

## Layer 5 — Explainability

Two complementary tools, both available per-flow on click:

- **SHAP** (`threatlens/ml/shap_explainer.py`): TreeSHAP on the XGBoost
  model. Returns top-K features by `|SHAP value|` for the predicted
  class, with each feature's actual value. Cached per `(model, label)`
  so the explainer doesn't re-initialise on every request.
- **YandexGPT** (`threatlens/ai/yandex_gpt_*.py`): natural-language
  rationale for the prediction, in Russian. Receives the flow's
  features + label + confidence and produces a 2-3 sentence summary
  for analysts who don't read raw feature tables.

## Operating-mode summary

| Mode | Auto-classified | Review queue | False positive rate (auto pile) | Real-world recall (model alone) | Recall (with reviewer) |
|---|---:|---:|---:|---:|---:|
| **lenient** (default) | **100.0 %** | 0.0 % | **2.02 %** | **97.83 %** | 97.83 % |
| safe (cov 0.95) | 81.8 % | 18.2 % | 2.47 % | 80.17 % | 99.33 % |
| strict (cov 0.80) | 67.5 % | 32.5 % | 2.35 % | 64.50 % | 99.67 % |
| paranoid (cov 0.50) | 30.4 % | 69.6 % | 0.47 % | 23.50 % | 99.83 % |

Measured on `real_pcap/*.pcap` + 30 % CTU-13 hold-out (693 flows total,
600 ATTACK + 93 BENIGN). Reproduce with `python scripts/workload_metric.py`.

## How the layers compound

| Failure mode | Layer that catches it |
|---|---|
| Java-vs-Python feature drift | L1 (same extractor at train and inference) |
| Botnet beaconing (regular IAT) | L2 (`IAT Periodicity Score` feature) |
| File transfer with known-bad payload | L2 (YARA features force ATTACK label) |
| Routine attack with known signature | L3 (XGBoost direct prediction) |
| Out-of-distribution flow (zero-day-shaped) | L4 (abstainer flags for review) |
| Analyst doesn't know why a flow was flagged | L5 (SHAP + AI explanation) |

Every layer is independently testable; every layer has at least one
unit test in `tests/`. None of the layers is silent: a failure at any
layer surfaces in the UI as a different visual signal (red label,
yellow border, anomaly indicator, missing explanation banner).

## Production deployment

threatlens.tech runs systemd + venv (no Docker) on timeweb 109.68.215.9.

- Repo at `/opt/threatlens`, redeploy via SSH + `git pull` + `systemctl restart threatlens`.
- Default model: `results/python_only/` (Day 9e candidate).
- Roll back: set `THREATLENS_ML_DIR=/opt/threatlens/results/cicids2017` in the systemd drop-in.
- Strict abstention: set `THREATLENS_STRICT_MODE=1`.
- Secrets (YandexGPT OAuth, STATS_SALT, etc.) live in the systemd drop-in `Environment=` lines, not in `.env` on disk.

## Reproduce the entire pipeline from scratch

```bash
# Optional: regenerate synthetic training data (adds ~5 min)
python scripts/generate_diverse_benign.py --flows-per-profile 400
python scripts/generate_attack_volume.py --attempts-per-profile 400
python scripts/generate_long_tail.py --flows-per-profile 500
python scripts/extract_diverse_benign.py
python scripts/extract_attack_volume.py
python scripts/extract_long_tail.py

# Train the model (10 sec on a laptop)
python scripts/train_python_only.py

# Fit the abstainer (2 sec)
python scripts/fit_selective_python_only.py --target-coverage 0.99

# Honest evaluation on real-world PCAPs
python scripts/eval_python_only.py
python scripts/workload_metric.py

# Run the web app locally
python -m threatlens.web
# → http://localhost:8000
```

For a single-paragraph submission summary, see `README.md`. For the
full Day 9 retrain narrative (why we threw out Java-extracted CSVs
and what each iteration fixed), see `docs/day9_python_only_retrain.md`.

## Beyond the headline — supporting analyses

The 5-layer pipeline is the core of the system; these documents cover
the work that turns "the model has high recall on a test set" into
"the system can be operated honestly":

- [`results/v2/bootstrap_ci.md`](../results/v2/bootstrap_ci.md) +
  [`results/python_only/bootstrap_ci.md`](../results/python_only/bootstrap_ci.md)
  — 95 % bootstrap CIs on every headline number, 1000 resamples per
  slice, seed 42. Small-N families (<10 flows) flagged as directional.
- [`results/v2/ab_vs_python_only.md`](../results/v2/ab_vs_python_only.md)
  — apples-to-apples A/B between the previous prod model and the v2
  candidate. Same 9-PCAP holdout, both models, non-overlapping CIs
  on the +36.4 pp lift.
- [`adversarial_baseline.md`](adversarial_baseline.md) — Phase 3
  recall-under-perturbation grid (4 perturbations × 4 strengths). v2
  is robust to 3 of 4 naive evasion techniques; the floor is 86.53 %
  recall under the one perturbation that actually moves the boundary
  (mild packet padding).
- [`drift_monitor_design.md`](drift_monitor_design.md) — Phase 6
  production logging schema + nightly PSI script. Infrastructure is
  shipped (`scripts/drift_monitor.py`); meaningful PSI signal lands
  ~14 days after the model sees production traffic.
- `scripts/check_submission_consistency.py` — regression test across
  26 headline numbers cited in `SUBMISSION.md`, `README.md`, and
  `results/v2/ab_vs_python_only.md`. Each is paired with a JSON
  pointer into an artefact; tolerance 0.05 pp catches real drift while
  ignoring rounding-level differences. Run as a pre-submit check.
