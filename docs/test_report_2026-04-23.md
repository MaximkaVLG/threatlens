# ThreatLens — Test report

**Date:** 2026-04-23
**Environment:** Windows, Python 3.14.2, pytest 9.0.2, pytest-cov 7.1.0, pytest-timeout 2.4.0
**Repo head:** branch `main`, Day 12 work committed
**Model under test:** `results/python_only/` (Day 9e candidate)

## TL;DR

| Suite | Result | Wall time |
|---|---|---:|
| `pytest tests/` (190 collected) | **188 passed, 2 skipped, 0 failed, 0 errors** | 7.52 s |
| `scripts/eval_python_only.py` | ✅ numbers match published (F1=0.9612 / recall=96.25 %) | 0.4 s |
| `scripts/workload_metric.py` | ✅ 4 operating points match Day 11 table | ~5 s |
| `scripts/active_learning_demo.py` | ✅ Verdict: WIN (−6 FPs, −0.29 pt recall) | 6.9 s |

**Zero regressions.** Every number in `README.md`, `docs/architecture.md`,
and `SUBMISSION.md` reproduces from a clean re-run.

## 1. Unit / integration tests

### 1.1 Headline

```
$ python -m pytest tests/ -q
............................................................................
.................................................................ss........
............
188 passed, 2 skipped in 7.52s
```

No failures. **No errors.** No xfail-turned-pass.

### 1.1.1 Fixed environment regression

The test report's first revision (151 collected, 149 passed, 2 skipped) was
captured before Day 13 added `tests/test_sandbox_ingest.py` (39 tests). After
Day 13, the suite went to 190 collected — but one of those tests
(`test_is_valid_pcap_file_handles_missing_and_good`) failed at fixture-setup
time with `PermissionError [WinError 5]` on
`C:\Users\masya\AppData\Local\Temp\pytest-of-masya`.

Root cause: NOT a test bug. Pytest's default `tmp_path_factory` basetemp is
`{system_temp}/pytest-of-{user}/`. On this dev machine that directory has
been left in a denied-ACL state by some earlier crashed pytest run, so
`os.scandir(basetemp)` (called by pytest itself before any test code runs)
fails. Even `takeown` and `cmd /c rmdir` cannot remove it without admin.

Fix: `tests/conftest.py:pytest_configure` now redirects `option.basetemp`
to `<repo>/.pytest-tmp` (a directory the running user definitely can list).
Honoured exception: an explicit `--basetemp <path>` on the command line
still wins. The fix is environment-defensive — it would also catch the
same failure on a CI worker with stale temp.

After the fix: 188 passed / 2 skipped / **0 errors**. `.pytest-tmp/` added
to `.gitignore` and `.dockerignore` so the repo + image stay clean.

### 1.2 Per-module breakdown

| Module | Tests | Pass | Skip | What it covers |
|---|---:|---:|---:|---|
| `test_analyzers.py` | 14 | 14 | 0 | Generic file analyzer (PE, scripts, entropy, URL extraction) |
| `test_archives_pytest.py` | 5 | 5 | 0 | ZIP / tar.gz / 7z extraction + per-file YARA scan |
| `test_cache.py` | 15 | 15 | 0 | SQLite scan cache, scan-event aggregation, IP-hash salt |
| `test_core.py` | 10 | 10 | 0 | `analyze_file` orchestration, explanations, recommendations |
| `test_detector.py` | 14 | 14 | 0 | Legacy + python_only FlowDetector, SHAP top-K, abstainer |
| `test_explanations.py` | 7 | 7 | 0 | Rule-based explanation templates (RU + EN) |
| `test_flow_extractor.py` | 10 | 10 | 0 | `CicFlowExtractor` column contract + μs rescaling |
| `test_heuristic.py` | 5 | 5 | 0 | Heuristic engine (stealer / dropper / keylogger) |
| `test_payload_yara.py` | 14 | 12 | 2 | YARA-on-payload plumbing (2 skips need `yara-python`) |
| `test_repo_analyzer.py` | 20 | 20 | 0 | GitHub repo URL validation + SSRF guards |
| `test_sandbox_ingest.py` | 39 | 39 | 0 | Day 13 — sandbox PCAP ingest pipeline (download / extract / parquet) |
| `test_selective.py` | 9 | 9 | 0 | `MahalanobisAbstainer` fit / threshold / save-load |
| `test_spectral_features.py` | 9 | 9 | 0 | FFT features (periodicity, entropy, zero-crossing) |
| `test_web_api.py` | 19 | 19 | 0 | FastAPI endpoints + rate limiting + security headers |
| **Total** | **190** | **188** | **2** | |

### 1.3 Skipped tests (both expected)

Both skips are in `test_payload_yara.py`:

- `test_scan_payloads_eicar_triggers_match` — needs `yara-python` to
  match the EICAR payload
- `test_scan_payloads_benign_text_no_match` — same

`yara-python` has no Python 3.14 wheel and source-building needs MSVC
+ libyara. Documented in `docs/day4_yara_synergy.md` and
`docs/day12_buffer_and_submission.md`. The plumbing tests around these
(5-tuple alignment, merge into flow dataframe, default zeros when no
matches) still run with mocked yara and all pass.

### 1.4 Slowest tests (top 15)

| Test | Duration |
|---|---:|
| `test_detector.py::test_shap_explanation_returns_topk_features` (call) | 2.23 s |
| `test_detector.py::test_detector_recognises_portscan_rows_above_threshold` (setup) | 1.39 s |
| `test_flow_extractor.py::test_cic_flow_extractor_produces_required_columns` (setup) | 0.71 s |
| `test_detector.py::test_detector_loads_all_artefacts` (setup) | 0.26 s |
| `test_detector.py::test_python_only_shap_uses_full_feature_set` (call) | 0.16 s |
| Remaining 10 | ≤ 0.10 s each |

Setup time dominates for the detector fixtures (loading joblib
artefacts). No test is slow enough to warrant parallelisation; the
full suite runs under 9 seconds on a 2023 laptop without a GPU.

### 1.5 Regression assertions

The detector tests explicitly assert on numeric thresholds, which is
the strongest defence against silent regression:

- `test_detector_recognises_portscan_rows_above_threshold`:
  `flagged >= len(attacks) * 0.5` on real CIC-IDS2017 PortScan rows
- `test_python_only_loads_optional_artefacts`: `info["n_classes"] == 7`
  and `"BENIGN" in info["classes"]`
- `test_python_only_predict_includes_uncertainty_columns`: all 7
  output columns present, anomaly columns zero-filled when no
  IsolationForest loaded
- `test_python_only_available_models_only_xgboost`:
  `py_detector.available_models == ["xgboost"]`
- `test_shap_top_k_is_clamped`: `1 <= len(contributions) <= 30`

These catch common breakage patterns: accidental reordering of output
columns, a future model swap that changes class count, a hardcoded
feature-list leak in the predict path.

## 2. Reproduction scripts

### 2.1 `scripts/eval_python_only.py` — headline numbers

**Wall time:** 0.4 s
**Output:** `results/python_only/real_world_eval.json`

```
Test set              Model               TP    FN    FP    TN  Recall ATK   Prec ATK    F1 ATK
------------------------------------------------------------------------------------------------
real_pcap (n=440)     combined_v2          3   344     2    91      0.0086     0.6000    0.0170
                      python_only        334    13    14    79      0.9625     0.9598    0.9612
ctu_holdout (n=253)   combined_v2         15   238     0     0      0.0593     1.0000    0.1119
                      python_only        253     0     0     0      1.0000     1.0000    1.0000
```

**Status:** ✅ Matches the numbers in `README.md` (lines 126-130) and
`docs/day9_python_only_retrain.md` exactly.

Per-capture recall on `real_pcap`:

```
slips_ssh-bruteforce.pcap       67 flows  60/67 detected  89.6%
slips_test7_malicious.pcap     279 flows  273/279 detected 97.8%
slips_test8_malicious.pcap       1 flow    1/1 detected  100 %
wireshark_dns-mdns.pcap         83 flows  14 FP (documented)
wireshark_http2-*.pcap(ng)       2 flows   0 FP ✓
wireshark_tls-renegotiation.pcap 1 flow    0 FP ✓
wireshark_tls12-chacha20.pcap    7 flows   0 FP ✓
```

### 2.2 `scripts/workload_metric.py` — operating-point sweep

**Wall time:** ~5 s (dominated by re-fitting abstainer at 3 coverages)
**Output:** `results/python_only/workload_metric.json`

```
Mode         Cov    Auto %   Review %   FP %   Specif   Recall ATK   +Review
----------------------------------------------------------------------------
lenient       -     100.0      0.0      2.02   84.9      97.8         97.8
safe        0.95     81.8     18.2      2.47   82.9      80.2         99.3
strict      0.80     67.5     32.5      2.35   86.1      64.5         99.7
paranoid    0.50     30.4     69.6      0.47   98.6      23.5         99.8
```

**Status:** ✅ Matches the table in `README.md` (lines 148-153),
`SUBMISSION.md` and `docs/architecture.md` exactly.

Accepted-pile F1 (success criterion #3 from `improvement_plan.md`,
"selective F1 ≥ 0.90 at coverage ≥ 50 %"):

| Mode | Accepted TP | Accepted FP | Accepted FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| safe (cov 0.95) | 481 | 14 | 4 | 0.972 | 0.992 | **0.982** |
| strict (cov 0.80) | 387 | 11 | 2 | 0.972 | 0.995 | **0.983** |
| paranoid (cov 0.50) | 141 | 1 | 1 | 0.993 | 0.993 | **0.993** |

All three points clear the 0.90 threshold.

### 2.3 `scripts/active_learning_demo.py` — Day 12 demo

**Wall time:** 6.92 s (two XGBoost fits on 33 243 rows)
**Output:** `results/python_only/active_learning_demo.json`

```
Slice                              Truth     BASELINE          CORRECTED         Delta
--------------------------------------------------------------------------------------
Held-out mDNS (9 flows)            BENIGN    FP=9/9            FP=3/9            -6 FPs
Attack captures (347 flows)        ATTACK    TP=340/347        TP=339/347        -1 TPs
Other benign captures (10 flows)   BENIGN    FP=0/10           FP=0/10           +0 FPs

Recall delta on attack captures:  -0.29 pt  (acceptable if |delta| <= 1 pt)
FP delta on held-out mDNS:        -66.7 pt  (target: strongly negative)

Verdict: WIN — 5 labels reduced FPs on similar flows without recall loss
```

**Status:** ✅ Verdict = WIN. 5 analyst labels transferred to 6 of 9
held-out similar flows with <1 pt recall cost. JSON machine-record
saved.

Determinism note: `random_state=42` seeds both the label-selection
permutation (`np.random.default_rng(42).permutation(fp_indices)`) and
the XGBoost fit. Re-runs produce identical output.

## 3. Environment sanity checks

### 3.1 Package versions observed

From the pytest header:

- Python **3.14.2**
- pytest **9.0.2**, plugins: cov 7.1.0, timeout 2.4.0, anyio 4.12.1

Other relevant versions (from imports during script runs): xgboost
(ships joblib artefact produced with compatible version), scikit-learn
(Mahalanobis abstainer loads cleanly), pandas + numpy + pyarrow
(parquet reads work without PyArrow/numpy dtype collision).

### 3.2 Artefact presence

```
$ ls results/python_only/
attack_volume_flows.parquet      feature_pipeline.joblib        metrics.json
ctu_test_holdout.parquet         mahalanobis_abstainer.joblib   real_world_eval.json
diverse_benign_flows.parquet     mahalanobis_abstainer_summary.json  workload_metric.json
                                                                xgboost.joblib
                                                                active_learning_demo.json
```

All 10 required artefacts present. No stale paths referenced.

### 3.3 Known environmental limits

| Limit | Impact | Workaround |
|---|---|---|
| `yara-python` missing (no Python 3.14 wheel) | 2 tests skip; YARA features dropped by variance filter during training | Re-enable on prod timeweb box where MSVC is available; see `docs/day12_buffer_and_submission.md` |
| Windows cp1251 console default encoding | Would crash on CIC-IDS2017 Web-Attack class names with Unicode | All CLI scripts reconfigure stdout to utf-8 on boot |
| Python 3.14 PyArrow dtype backend | Pandas → numpy conversion needed before XGBoost fit | `.astype("float64")` in train_python_only + workload_metric |

All three are handled in code; none cause test failures.

## 4. Cross-check against published metrics

| Location | Metric claimed | Metric reproduced | Match |
|---|---|---|---|
| `README.md:127` | python_only F1 = 0.961, recall = 96.25 %, precision = 95.98 % | 0.9612 / 0.9625 / 0.9598 | ✅ |
| `README.md:150` | lenient: 100 % auto @ 2.02 % FP @ 97.83 % recall | 100.0 / 2.02 / 97.8 | ✅ |
| `README.md:130` | CTU-13 hold-out python_only: 100 % recall | 253/253 = 100 % | ✅ |
| `SUBMISSION.md:15` | 97.83 % recall @ 2.02 % FP on 693 flows | Matches | ✅ |
| `docs/architecture.md:159` | lenient row values | Matches | ✅ |
| `docs/day12_*.md` | active learning: -6 FPs, -0.29 pt recall | Exact match | ✅ |
| `docs/day9_python_only_retrain.md:78` | python_only TP=334, FN=13, FP=14, TN=79 | Exact match | ✅ |

Seven independent cross-checks, zero drift between docs and actual
measurements.

## 5. What this report does NOT cover

Honest bounds on the test coverage:

- **No end-to-end PCAP upload test in CI.** The `test_web_api.py` suite
  exercises the FastAPI plumbing but does not push a real PCAP through
  `POST /api/network/analyze-pcap`. Day 10 did a manual smoke via
  `fastapi.testclient.TestClient`; not in the automated suite.
- **No GPU tests.** XGBoost runs on CPU. Whether `tree_method=hist`
  on a CUDA build produces identical decisions is untested.
- **No live production tests.** `threatlens.tech` is not polled by the
  suite. A separate smoke is needed post-deploy.
- **No adversarial tests.** Flows crafted to land near benign centroids
  aren't in the test corpus.
- **No drift tests.** Capturing traffic a year from now and re-running
  is the only real measure of drift resilience; we don't have that.
- **YARA matching itself.** The 2 skipped tests are the actual-match
  cases. Plumbing is covered, content-matching is not (until
  yara-python is installable).

These are also listed in `SUBMISSION.md` → "Honest limits" and
`docs/architecture.md` → "What this does NOT cover".

## 6. Conclusion

Everything the submission packet depends on is green and reproducible
from a clean shell:

```bash
pytest tests/                  # 149 pass, 2 skip
python scripts/eval_python_only.py        # F1=0.961
python scripts/workload_metric.py          # lenient 100%/2.02%/97.8%
python scripts/active_learning_demo.py     # Verdict: WIN
```

No action items from this test run. Ready to proceed to post-plan
work (presentation, landing page refresh, submission form) per
`docs/improvement_plan.md` days 13–23.
