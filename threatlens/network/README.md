# ThreatLens Network

Extracts bidirectional network flows from PCAP files and classifies them as
benign or attack traffic using the ML models trained by `threatlens.ml`.

The default production model bundle is `results/python_only/` (Day 9e
retrain — XGBoost on a 65-feature schema, F1 0.96 / recall 96 % on
real-world PCAPs). The legacy `results/cicids2017/` bundle still loads
unchanged through the same loader (set `THREATLENS_ML_DIR=results/cicids2017`).

## Pipeline

```
  PCAP file              scapy              FlowExtractor
      |           ---> packets --->      bidirectional flows
      v                                          |
  100-1000 MB                            70 CIC base + 8 spectral
                                         + 3 YARA = 81 features
                                         (65 retained after variance filter)
                                                 |
                                                 v
                                         FlowDetector
                              +------------------+------------------+
                              |                  |                  |
                          XGBoost          Mahalanobis        IsolationForest
                       (labeled attacks)    abstainer          (legacy bundle
                                          (is_uncertain)        only)
```

## Usage

```python
from threatlens.network import FlowExtractor, FlowDetector

extractor = FlowExtractor()
flows_df = extractor.extract("capture.pcap")

detector = FlowDetector.from_results_dir("results/python_only")
predictions = detector.predict(flows_df, model="xgboost")

print(detector.summary(predictions))
```

`predictions` is a DataFrame with columns: `src_ip`, `dst_ip`, `src_port`,
`protocol`, `dst_port`, `label`, `is_attack`, `confidence`,
`is_uncertain`, `distance_to_centroid`, `anomaly_score`, `anomaly_flag`.

When the loaded bundle has no IsolationForest (e.g. `python_only`), the
`anomaly_*` columns are zero-filled so downstream code does not have to
branch. When the bundle has no Mahalanobis abstainer (e.g. legacy
`cicids2017`), `is_uncertain` and `distance_to_centroid` are zero-filled.

## HTTP endpoint

`POST /api/network/analyze-pcap` accepts a `multipart/form-data` upload with:
- `file`: PCAP / PCAPNG / CAP (up to 200MB)
- `model`: must be one of `detector.available_models` — `xgboost` for
  python_only, `xgboost` or `random_forest` for the legacy bundle
- `max_flows`: how many ranked flows to return (default 200)

## Feature computation

Three feature groups are stitched together per flow:

| Group | # features | What it captures |
|---|---:|---|
| CIC-2017 base | 70 | Flow duration, packet counts, byte totals, IAT statistics, TCP flag counts, bidirectional asymmetry |
| Spectral | 8 | FFT-based: peak frequency, entropy, centroid, bandwidth, low-freq energy ratio, IAT periodicity (botnet beaconing), zero-crossing rate |
| YARA payload | 3 | Per-flow YARA hit count, max severity, has-match flag |

The 70 CIC base columns follow CICFlowMeter conventions:

- `Flow Duration` and all IAT values are in microseconds.
- Forward direction is defined by the first packet seen for the 5-tuple.
- Active/idle periods are split by a 5-second inactivity threshold.
- `CWE Flag Count` corresponds to TCP CWR (CIC-IDS2017 column typo).
- Flow timeout is 120 seconds by default.

After standard scaling and zero-variance dropping in `FeaturePipeline`, the
final model sees 65 features (57 CIC + 8 spectral). All 3 YARA features
are dropped because `yara-python` does not install on the Python 3.14
training machine (no wheel; source build needs MSVC + libyara) — the
columns are constant zero and don't survive the variance filter. The
YARA-on-payload infrastructure exists end-to-end and is exercised by
unit tests with mocked yara; re-enabling it in production requires
installing yara-python on the training machine and re-fitting the
pipeline. See `docs/day12_buffer_and_submission.md` for the deferred
re-enable steps.

## Implementation: two extractors

Two extractors are available:

- `CicFlowExtractor` *(default, exported as `FlowExtractor`)* — delegates
  flow reconstruction and feature computation to the `cicflowmeter` Python
  library, which is a direct port of the original Java CICFlowMeter used to
  produce CIC-IDS2017. Field names and time units are remapped to match the
  CIC-IDS2017 CSV schema (e.g. cicflowmeter emits durations in seconds while
  CIC-IDS2017 uses microseconds).
- `LegacyFlowExtractor` — independent re-implementation kept for reference.
  Spec-faithful but produces features that drift from CICFlowMeter on
  idiosyncratic details, which was observed to degrade predictions.

## Java-vs-Python feature drift — resolved by Day 9e

**Historical context.** The original ThreatLens model (`results/cicids2017/`)
was trained on CSVs produced by the Java CICFlowMeter (Maven distribution),
but inference at deployment used the Python `cicflowmeter` port — a
training/serving feature distribution mismatch. The Day 7 diagnostic
measured 91-98 % of features had p<0.001 between the two extractors, and
the production system bottomed out at 0.86 % attack recall on real-world
PCAPs (Day 6 measurement).

**The fix (Day 9e).** Re-extracted ALL training data with the same Python
`cicflowmeter` that runs at inference time, plus added synthetic + CTU-13 +
diverse-benign + attack-volume + long-tail traffic to fill out the feature
space. New model: `results/python_only/xgboost.joblib`. Same extractor
runs at training and inference, so the gap closes.

**Result.** On the same real-world PCAPs Day 6 measured 0.86 % recall on,
Day 9e measures **96.25 % recall** (334 / 347 attacks caught) and 96.0 %
precision. See `docs/day9_python_only_retrain.md` for the iteration history
and `docs/architecture.md` for the full 5-layer pipeline.

The legacy `cicids2017` bundle is still shipped (and still has the residual
drift gap on real-world PCAPs), but the default loader now points at
`python_only` and the legacy bundle is only loaded when explicitly
requested via `THREATLENS_ML_DIR`.
