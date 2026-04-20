# ThreatLens Network

Extracts bidirectional network flows from PCAP files and classifies them as
benign or attack traffic using the ML models trained on CIC-IDS2017
(`threatlens.ml`).

## Pipeline

```
  PCAP file              scapy              FlowExtractor
      |           ---> packets --->      bidirectional flows
      v                                          |
  100-1000 MB                            70 CIC-IDS2017 features
                                                 |
                                                 v
                                         FlowDetector
                                    +-------------+--------------+
                                    |                            |
                              XGBoost / RF               IsolationForest
                              (labeled attacks)          (anomaly score)
```

## Usage

```python
from threatlens.network import FlowExtractor, FlowDetector

extractor = FlowExtractor()
flows_df = extractor.extract("capture.pcap")

detector = FlowDetector.from_results_dir("results/cicids2017")
predictions = detector.predict(flows_df, model="xgboost")

print(detector.summary(predictions))
```

`predictions` is a DataFrame with columns: `src_ip`, `dst_ip`, `src_port`,
`protocol`, `dst_port`, `label`, `is_attack`, `confidence`, `anomaly_score`,
`anomaly_flag`.

## HTTP endpoint

`POST /api/network/analyze-pcap` accepts a `multipart/form-data` upload with:
- `file`: PCAP / PCAPNG / CAP (up to 200MB)
- `model`: `xgboost` (default) or `random_forest`
- `max_flows`: how many ranked flows to return (default 200)

## Feature computation

Features follow the CIC-IDS2017 CSV schema (70 columns after variance
filtering — see `CIC_FEATURE_COLUMNS`). The extractor mirrors CICFlowMeter
conventions:

- `Flow Duration` and all IAT values are in microseconds.
- Forward direction is defined by the first packet seen for the 5-tuple.
- Active/idle periods are split by a 5-second inactivity threshold.
- `CWE Flag Count` corresponds to TCP CWR (the CIC-IDS2017 column is a typo
  from the original dataset).
- Flow timeout is 120 seconds by default (CICFlowMeter default).

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
  idiosyncratic details (flag counting, segment-size), which was observed
  to degrade predictions.

## Residual feature drift

Even with the cicflowmeter port, small behavioural differences between the
Java and Python implementations mean features extracted from real-world
PCAPs will not perfectly match a re-run of the original Java CICFlowMeter.
The most visible difference is flag counting: CIC-IDS2017 frequently shows
`SYN Flag Count = 0` even for flows that started with a SYN, which is not
the behaviour of the Python port.

Consequence: predictions on third-party PCAPs will not hit the 99.8% F1
reported on the CIC-IDS2017 test split. Real-world deployment should either
retrain the models on outputs of this extractor, or run the original Java
CICFlowMeter as a preprocessing step.
