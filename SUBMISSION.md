# ThreatLens — Yandex Practicum Award 2026 submission summary

**One-page reference for reviewers.** Full architecture in
[`docs/architecture.md`](docs/architecture.md); full day-by-day story
starting at [`docs/improvement_plan.md`](docs/improvement_plan.md).

## Headline metric

**97.83 % recall on real-world attack flows at 2.02 % false-positive
rate — on PCAPs the model never saw during training.**

Measured on 693 flows: 600 ATTACK + 93 BENIGN, aggregated from
Stratosphere SLIPS test captures, 30 % CTU-13 botnet hold-out, and
Wireshark sample PCAPs for modern benign protocols (TLS 1.2 ChaCha20,
HTTP/2, mDNS / DHCP / NTP multicast).

Same test set, same extractor, previous production model:
**0.86 % recall** (3 / 347 real-world attack flows).

That's the gap the 12-day improvement plan closed. Reproducible with
`python scripts/workload_metric.py`.

## Why this is interesting

The original `results/cicids2017/` model advertised **99.83 % F1** on a
CIC-IDS2017 test split. On PCAPs from any other network, it detected
**3 of 347 attacks**. We traced this to a Java-vs-Python CICFlowMeter
feature-distribution mismatch (91-98 % of features had p<0.001 between
the two extractor implementations on the same PCAP — see
[`docs/day7_drift_diagnostic.md`](docs/day7_drift_diagnostic.md)).

The fix was architectural, not a hyperparameter tweak: **retrain on
flows extracted by the exact same Python code path that runs at
inference**, with synthetic + CTU-13 + diverse-benign + long-tail
traffic covering the feature-space corners real-world captures occupy.

| Model | Real-world recall | Real-world F1 | CTU-13 hold-out recall |
|---|---:|---:|---:|
| Previous prod (`results/cicids2017/`, Java-extracted train) | 0.86 % | 0.017 | 5.93 % |
| **Current prod (`results/python_only/`, Day 9e)** | **96.25 %** | **0.961** | **100 %** |

## Time-validation: fresh 2024-2025 malware

The 96.25 % above is measured on PCAPs from ≤2018 captures. To check whether
the model has gone quietly stale on threats that didn't exist when CTU-13
was assembled, we live-ingest modern malware captures on the day this
evaluation runs:

```bash
python scripts/ingest_sandbox_pcaps.py --source all --limit 100
python scripts/extract_sandbox_pcaps.py --skip-pcaps "CTU-Malware-Capture-Botnet-61-1__bot__Bot.pcap"
python scripts/eval_sandbox.py
```

| Test set | Year | N PCAPs | N attack flows | Recall (any-attack) |
|---|---:|---:|---:|---:|
| Historical real-world (above) | ≤2018 | 7 | 600 | **96.25 %** |
| Fresh sandbox ingest | 2024-2025 | 25 | 5011 | **72.24 %** |

The drop is **honest, not hidden**. Three things to read from the breakdown
in [`results/python_only/sandbox_eval.json`](results/python_only/sandbox_eval.json):

1. **Per-source split:** Stratosphere CTU 2024 captures hit 74.8 % recall;
   malware-traffic-analysis.net 2025 daily posts hit only **47.1 %**. The
   model is weaker on the freshest channel — the reverse of what a
   benchmark-fitted model would show.
2. **Per-family:** the model handles infrastructure-shaped C2 traffic well
   (NetSupport 100 %, StealC 82 %, ClickFix 78 %, Kongtuke 75 %) but
   struggles on short-lived stealer infection traffic (Lumma 40 %, Formbook
   27 %, Rhadamanthys 25 %). Several PCAPs only contain 1–3 flows of
   "initial check-in" traffic that look more like normal HTTPS than C2.
3. **Abstainer flagged 70.8 % of these flows as out-of-distribution.** The
   Mahalanobis layer correctly recognised most of these modern captures
   as outside its training manifold — exactly what selective prediction
   is supposed to do. Without the abstainer the operator would not know
   the model is uncertain on this slice.

The sandbox PCAPs are 100 % labeled `Bot` (closest existing class for
modern stealers/RATs/loaders), so we can compute recall but **not**
precision against a benign baseline — there is no benign traffic in this
set. Read this as a *generalisation* signal, not a replacement for the
F1 = 0.961 above. Full per-PCAP breakdown reproducible via `eval_sandbox.py`.

## Architecture (5 layers, defense-in-depth)

```
PCAP
  └─► L1: Python FlowExtractor         — same extractor train & inference
       └─► L2: 81 features              — 70 CIC + 8 spectral + 3 YARA
            └─► L3: XGBoost (7-class)   — 65 features after variance filter
                 └─► L4: Mahalanobis abstainer   — selective prediction
                      └─► L5: SHAP + YandexGPT   — per-flow explanation
```

- **L1** (training/inference consistency) is the single biggest reason
  real-world recall jumped 112× — not model sophistication.
- **L2** spectral features (`IAT Periodicity Score`, `Spectral Entropy`)
  are in the top XGBoost importance list — they catch botnet beaconing
  the CIC feature set alone can't see.
- **L3** uses inverse-frequency sample weights so rare classes (FTP-
  Patator ~800 samples vs PortScan ~13 000) get fair gradient share.
- **L4** is the abstainer. At its default lenient mode it only *flags*
  OOD flows; strict mode (`THREATLENS_STRICT_MODE=1`) rewrites them to
  `UNCERTAIN`. Operator choice, not a default blocker.
- **L5** runs on per-flow click in the UI — TreeSHAP for feature
  contributions, YandexGPT for natural-language summary.

Full write-up: [`docs/architecture.md`](docs/architecture.md).

## Operating-mode trade-off

The Mahalanobis abstainer lets the operator tune coverage without
retraining. Same 693-flow test set as above:

| Mode | Auto-classified | Review queue | FP rate | Recall (model alone) | Recall (with reviewer) |
|---|---:|---:|---:|---:|---:|
| **lenient** (default) | **100 %** | 0 % | 2.02 % | **97.83 %** | 97.83 % |
| safe (cov 0.95) | 81.8 % | 18.2 % | 2.47 % | 80.17 % | 99.33 % |
| strict (cov 0.80) | 67.5 % | 32.5 % | 2.35 % | 64.50 % | 99.67 % |
| paranoid (cov 0.50) | 30.4 % | 69.6 % | 0.47 % | 23.50 % | 99.83 % |

Reproduce: `python scripts/workload_metric.py`.

## Active-learning demo (5 labels, measurable improvement)

One 30-second analyst task — labeling 5 mDNS false positives as BENIGN
— transfers to 6 of 9 similar held-out flows:

| Slice | Baseline | After 5 labels | Delta |
|---|---|---|---|
| Held-out mDNS (9 flows) | 9/9 FPs | 3/9 FPs | **-6 FPs (-66.7 pt)** |
| Attack captures (347 flows) | 340/347 TPs | 339/347 TPs | -1 TP (-0.29 pt) |
| Other benign captures (10 flows) | 0/10 FPs | 0/10 FPs | unchanged |

Reproduce: `python scripts/active_learning_demo.py`.
Full write-up in [`docs/day12_buffer_and_submission.md`](docs/day12_buffer_and_submission.md).

## Five commands to reproduce everything

```bash
# 1. Install deps (uses Python 3.10+; cicflowmeter pure-Python port)
pip install -r requirements.txt

# 2. Train the production model (~10 sec on a laptop)
python scripts/train_python_only.py

# 3. Fit the Mahalanobis abstainer (~2 sec)
python scripts/fit_selective_python_only.py --target-coverage 0.99

# 4. Headline evaluation on real-world PCAPs (~1 sec)
python scripts/eval_python_only.py
# → real_pcap F1 = 0.961, CTU hold-out F1 = 1.0

# 5. Operating-point sweep for the submission table (~5 sec)
python scripts/workload_metric.py
# → lenient row: 100 % auto / 2.02 % FP / 97.83 % recall
```

All five complete in under 30 seconds total on a 2023 laptop with no
GPU. The full regeneration pipeline (including synthetic attack PCAP
crafting) is under 10 minutes — documented in
[`docs/architecture.md`](docs/architecture.md#reproduce-the-entire-pipeline-from-scratch).

## Live deployment

- [https://threatlens.tech](https://threatlens.tech) runs the python_only
  model by default (see `docs/day10_web_app_integration.md`).
- systemd + venv on timeweb 109.68.215.9, repo at `/opt/threatlens`.
- Roll-back / model-swap is one env var: `THREATLENS_ML_DIR=/opt/threatlens/results/cicids2017`.
- Strict abstention toggle: `THREATLENS_STRICT_MODE=1`.

## Honest limits

The headline metric is measured on a **specific test set** and does
NOT generalise to:

- Adversarial flows crafted to land near benign centroids — no
  robustness numbers against active attackers.
- Modern encrypted protocols not in the training corpus (QUIC, DoH,
  encrypted SNI, IPv6-only). These land in the review queue or get
  misclassified.
- Drift over time — no temporal-stability numbers, no online learning.
- Attack types outside the 7-class taxonomy (BENIGN / Bot / DoS Hulk /
  DoS slowloris / FTP-Patator / PortScan / SSH-Patator). Heartbleed /
  Web-Attack / DDoS / Infiltration flows from the legacy 14-class set
  are either misclassified or flagged uncertain.
- YARA-on-payload layer — infrastructure complete, but yara-python
  doesn't install on Python 3.14, so the 3 YARA features are currently
  dropped by the variance filter. Re-enable path documented in
  `docs/day12_buffer_and_submission.md`.

These limits are repeated verbatim in `docs/architecture.md` so no
reviewer has to hunt for them.

## Key documents

- [`README.md`](README.md) — project overview and feature list
- [`docs/architecture.md`](docs/architecture.md) — 5-layer pipeline detail
- [`docs/improvement_plan.md`](docs/improvement_plan.md) — 12-day plan that produced this
- [`docs/day9_python_only_retrain.md`](docs/day9_python_only_retrain.md) — how we closed the drift gap
- [`docs/day10_web_app_integration.md`](docs/day10_web_app_integration.md) — production model swap
- [`docs/day11_metrics_and_docs.md`](docs/day11_metrics_and_docs.md) — honest-metric reframe
- [`docs/day12_buffer_and_submission.md`](docs/day12_buffer_and_submission.md) — success-criteria audit + active-learning demo

## Authors / contact

Single-author project by Maksim ["masya"](https://github.com/masya).
Questions, repro issues, or test failures: open a GitHub issue.
