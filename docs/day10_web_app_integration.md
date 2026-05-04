# Day 10 — Web app integration of `python_only` model

**Run date:** 2026-04-23
**Status:** ✅ Complete. End-to-end PCAP upload through the FastAPI web
UI now uses the Day 9e python-only model by default, with full
backwards-compatibility for the legacy `cicids2017` and `combined_v2`
artefact bundles. All 14 detector tests pass (8 legacy + 6 new).

## Why this day

Day 9e produced `results/python_only/` with F1 0.96 / recall 96 % on
real-world PCAPs — a 50× improvement over the production model. Day 10
wires those artefacts into the actual web app so the gain shows up at
the user interface, not just in offline benchmarks.

The challenge: the production `FlowDetector` was hardcoded for the
legacy 4-artefact bundle (RandomForest + IsolationForest + XGBoost +
pipeline) on 70 features and 14 CIC-2017 classes. The python_only
bundle has only 2 artefacts (XGBoost + pipeline + optional Mahalanobis
abstainer) on 65 features and 7 classes. We needed the loader and the
predict path to gracefully degrade across both shapes, plus surface
the new abstainer signal in the UI.

## Changes

### `threatlens/network/detector.py`

Optional-artefact loader + abstainer integration.

```python
@dataclass
class DetectorArtefacts:
    feature_pipeline: object        # required
    xgboost: object                 # required
    random_forest: Optional[object] = None       # legacy
    isolation_forest: Optional[object] = None    # legacy
    mahalanobis_abstainer: Optional[object] = None  # Day 8/9
    source_dir: Optional[str] = None
```

`FlowDetector.from_results_dir(results_dir, strict_abstention=False)`:

- Required: `feature_pipeline.joblib`, `xgboost.joblib` (FileNotFoundError otherwise)
- Optional: `random_forest.joblib`, `isolation_forest.joblib`, `mahalanobis_abstainer.joblib` (logged at INFO if missing, silently skipped)
- New `strict_abstention` flag. Off by default — abstainer fires `is_uncertain=1` flag but keeps original label. On — abstained predictions get rewritten to `UNCERTAIN`.

`FlowDetector.predict(flows_df, model=None)`:

- Uses `pipeline.feature_names` as source-of-truth for input columns (was hardcoded `CIC_FEATURE_COLUMNS` — would silently drop spectral + YARA features needed by python_only)
- Returns 7 columns instead of 5: adds `is_uncertain` (0/1) and `distance_to_centroid` (float, Mahalanobis distance to predicted-class centroid)
- Anomaly columns (`anomaly_flag`, `anomaly_score`) are zero-filled when no IsolationForest is loaded, so downstream code doesn't have to branch
- `is_attack` excludes both `BENIGN` and `UNCERTAIN`

`FlowDetector.summary(predictions)`:

- New `uncertain_flows` count (independent of attack/benign — a flow can be ATTACK + UNCERTAIN at the same time when in lenient mode)
- New `model_info` block: `source_dir`, `models`, `n_features`, `n_classes`, `classes`, `has_isolation_forest`, `has_abstainer`, `strict_abstention` — surfaced to the UI for the "model badge" footer

`FlowDetector.available_models` property — replaces the hardcoded
`{"random_forest", "xgboost"}` validation in the API endpoint. Returns
`["xgboost"]` on python_only, `["random_forest", "xgboost"]` on the
legacy bundles.

### `threatlens/web/app.py`

```python
default_dir = ROOT/"results"/"python_only"
results_dir = os.environ.get("THREATLENS_ML_DIR", default_dir)
# Fallback to legacy cicids2017 if python_only not on disk
if not os.path.exists(results_dir + "/xgboost.joblib"):
    results_dir = ROOT/"results"/"cicids2017"

strict = os.environ.get("THREATLENS_STRICT_MODE", "0") in ("1","true","yes","on")
detector = FlowDetector.from_results_dir(results_dir, strict_abstention=strict)
```

Endpoint validation now uses `detector.available_models` instead of the
hardcoded set, so the API correctly rejects `random_forest` requests
when the loaded model bundle doesn't include one.

Two env vars to control behaviour without redeploy:

| Variable | Default | Effect |
|---|---|---|
| `THREATLENS_ML_DIR` | `results/python_only` | Which model bundle to load. Set to `results/cicids2017` to roll back. |
| `THREATLENS_STRICT_MODE` | `0` (off) | When `1`, the abstainer rewrites OOD predictions to `UNCERTAIN`. Off → abstainer just marks rows for UI review. |

### `threatlens/web/templates/index.html`

UI updates so the new signals are visible:

1. **Stat-card swap.** When the loaded model has an abstainer, the third
   "Аномалии (IsolationForest)" card is replaced with "Неопределённость"
   (yellow, with hover-tooltip explaining Mahalanobis abstention). Falls
   back to the IsolationForest card when running on the legacy bundle.

2. **Model footer.** Below the summary, a one-line model badge:
   `Модель: xgboost [python_only, 7 классов, 65 фич, abstainer]`. Lets the
   user / a screenshotting reviewer see at a glance which artefact bundle
   produced these results.

3. **Per-flow row.** New "Уверенность" column. Each row shows either:
   - 🟢 `OK` — the flow lives in a region the model has training coverage on
   - 🟡 `⚠ review` — Mahalanobis distance over per-class threshold, with
     hover tooltip showing the actual distance value

4. **Class distribution bar.** `UNCERTAIN` shown as yellow (vs green
   BENIGN / red attack classes).

5. **Model dropdown caption.** Updated `XGBoost (F1=0.998)` → `XGBoost
   (real-world F1=0.96)`. The 0.998 was the in-distribution CIC-2017
   number which oversold; 0.96 is the honest real-world F1 from Day 9e.

### `tests/test_detector.py`

Six new tests against `results/python_only/`:

| Test | What it verifies |
|---|---|
| `test_python_only_loads_optional_artefacts` | RF and IF are gracefully optional; abstainer detected; class count = 7 |
| `test_python_only_predict_includes_uncertainty_columns` | All 7 output columns present; anomaly columns are zero-filled |
| `test_python_only_strict_mode_rewrites_label` | When `strict_abstention=True`, OOD rows get `UNCERTAIN` label, are not counted as attacks |
| `test_python_only_summary_counts_uncertain_separately` | `uncertain_flows` distinct from attack/benign; `model_info` populated |
| `test_python_only_available_models_only_xgboost` | `available_models == ["xgboost"]`; predict with `random_forest` raises ValueError |
| `test_python_only_shap_uses_full_feature_set` | SHAP picks features from `pipeline.feature_names` (CIC + spectral + YARA), not the legacy 70-column list |

All 14 detector tests pass (8 legacy + 6 new):

```
$ python -m pytest tests/test_detector.py -v
============================= 14 passed in 4.55s =============================
```

## End-to-end smoke test

`fastapi.testclient.TestClient` pointed at the live `app` instance,
uploading the same real-world PCAPs the Day 9 metrics were measured on:

```text
slips_test7_malicious.pcap (Stratosphere mixed C2):
  total=279, attack=273, benign=6, uncertain=2
  labels: {Bot: 233, DoS Hulk: 39, BENIGN: 6, SSH-Patator: 1}
  -> matches Day 9e v7 numbers exactly

wireshark_tls12-chacha20.pcap (TLS 1.2 ChaCha20):
  total=7, attack=0, benign=7, uncertain=0
  labels: {BENIGN: 7}
  -> 0 false positives (was 7 in Day 9 v3)

wireshark_dns-mdns.pcap (kitchen-sink LAN snapshot):
  total=83, attack=14, benign=69, uncertain=0
  labels: {BENIGN: 69, Bot: 14}

slips_ssh-bruteforce.pcap (TCP/902 brute-force):
  total=67, attack=60, benign=7, uncertain=42
  labels: {SSH-Patator: 56, BENIGN: 7, PortScan: 4}
  -> 89.6% recall; abstainer flagged 42 high-distance rows for analyst review
```

Backwards-compat verified by setting `THREATLENS_ML_DIR=results/cicids2017`
and re-running the mDNS PCAP — falls back to the legacy 4-artefact path
with `random_forest` model and IsolationForest column visible.

## Production deployment notes

The model artefacts are tracked in `results/python_only/` (whitelisted
in `.gitignore` from Day 9), so a `git pull` on the prod server
(threatlens.tech) is enough to roll the new model out. No Docker rebuild
needed — the prod server runs systemd + venv with the repo at
`/opt/threatlens` (see `MEMORY.md` → `prod_deploy_layout.md`).

Sequence:

```bash
# On prod server (timeweb 109.68.215.9)
ssh root@109.68.215.9
cd /opt/threatlens
git pull
sudo systemctl restart threatlens
# Default config picks up python_only automatically via the new
# default in app.py — no env var change needed
```

Roll-back is one env var:

```bash
sudo systemctl edit threatlens
# Add: Environment=THREATLENS_ML_DIR=/opt/threatlens/results/cicids2017
sudo systemctl restart threatlens
```

## What this unlocks

- Live demo at `threatlens.tech` now reflects the Day 9 numbers (96 %
  recall / 96 % precision on real-world PCAPs) instead of the broken
  baseline (0.86 % recall on the same data).
- Per-flow `is_uncertain` flag exposes the Day 8 selective-prediction
  work in the UI — analysts see *which* flows the model is shaky on,
  not just an aggregate confidence number.
- Operators can flip between strict (UNCERTAIN-as-label) and lenient
  (UNCERTAIN-as-flag) abstention modes via env var without redeploying
  the model.
- Backwards-compat preserved: legacy `cicids2017` bundle still loads
  identically; existing tests pass unchanged.

## Honest framing — what's NOT done

- **No SHAP retraining for python_only's 65 features.** SHAP works (it
  uses `pipeline.feature_names` correctly), but the explainer cache
  was tuned on the legacy 70-feature schema. SHAP values are still
  meaningful for python_only but the per-feature human descriptions
  in the LLM prompt may reference features (e.g. some Bulk-AVG/STD
  columns) that aren't in the python_only feature set. Will surface
  as "feature X (no description available)" rather than crashing.
- **No new YandexGPT prompt template.** The "explain this flow" path
  still uses the existing prompt that mentions CIC-2017 attack types.
  Most of the python_only classes (BENIGN / Bot / DoS Hulk / DoS
  slowloris / FTP-Patator / PortScan / SSH-Patator) overlap with
  the existing prompt vocabulary, so no breakage in practice.
- **Dashboard "all-time stats"** counters at the top of the page still
  reference the old artifact bundle's class names. Cosmetic only.

These are Day 11 items.

## Reproduce

```bash
# 1. Make sure Day 9e artefacts are in place
ls results/python_only/   # xgboost.joblib + feature_pipeline.joblib (+ optional)

# 2. Run the new tests
python -m pytest tests/test_detector.py -v

# 3. Start the app locally
python -m threatlens.web

# 4. Upload a PCAP at http://localhost:8000 and verify:
#    - "Неопределённость" stat card visible (yellow)
#    - Model footer shows "[python_only, 7 классов, 65 фич, abstainer]"
#    - Per-flow rows have "Уверенность" column with OK/review markers
#    - Yellow left-border on uncertain rows

# 5. (Optional) try strict mode
THREATLENS_STRICT_MODE=1 python -m threatlens.web
# OOD flows now get UNCERTAIN label (yellow) instead of original

# 6. (Optional) roll back to legacy model
THREATLENS_ML_DIR=results/cicids2017 python -m threatlens.web
# Stat card flips back to "Аномалии (IsolationForest)"
```
