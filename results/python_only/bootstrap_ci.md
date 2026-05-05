# Bootstrap 95 % CI on python_only

Method: percentile bootstrap on the ATTACK subset for recall, on the BENIGN subset for FP rate. 1000 resamples per slice, seed 42. Slices with N < 10 are flagged ⚠SMALL-N — their CI is wide enough that the point estimate is directional only, not a statistic to act on.

## Headline test sets

| Test set | N | Point | 95 % CI | ±pp |
|---|---:|---:|---|---:|
| Historical real-world recall | 347 | 96.25 % | [93.95, 97.99] | ±2.0 |
| CTU-13 holdout recall | 253 | 100.00 % | [100.00, 100.00] | ±0.0 |
| Sandbox holdout recall | 349 | 60.46 % | [55.29, 65.90] | ±5.3 |

| FP rate (model alone, BENIGN only) | 93 | 15.05 % | [7.53, 22.58] | ±7.5 |

## Sandbox holdout — per-source breakdown

| Source | N | Point | 95 % CI | ±pp |
|---|---:|---:|---|---:|
| mta | 103 | 55.34 % | [45.63, 64.10] | ±9.2 |
| stratosphere | 246 | 62.60 % | [56.91, 68.70] | ±5.9 |

## Sandbox holdout — per-family breakdown

| Family | N | Point | 95 % CI | ±pp | Note |
|---|---:|---:|---|---:|---|
| stealc ⚠SMALL-N | 2 | 100.00 % | [100.00, 100.00] | ±0.0 | Wide CI, treat as directional |
| rhadamanthys ⚠SMALL-N | 4 | 25.00 % | [0.00, 75.00] | ±37.5 | Wide CI, treat as directional |
| netsupport ⚠SMALL-N | 7 | 100.00 % | [100.00, 100.00] | ±0.0 | Wide CI, treat as directional |
| clickfix ⚠SMALL-N | 9 | 66.67 % | [33.33, 100.00] | ±33.3 | Wide CI, treat as directional |
| lumma | 81 | 50.62 % | [40.74, 61.73] | ±10.5 |  |
| bot | 246 | 62.60 % | [56.91, 68.70] | ±5.9 |  |

## Confusion against ground-truth Bot (sandbox holdout)

All 349 holdout flows are labelled `Bot` at ingest. The model classifies them as:

- `BENIGN`: 138 flows (39.54 %)
- `Bot`: 87 flows (24.93 %)
- `DoS slowloris`: 79 flows (22.64 %)
- `PortScan`: 21 flows (6.02 %)
- `SSH-Patator`: 13 flows (3.72 %)
- `DoS Hulk`: 9 flows (2.58 %)
- `FTP-Patator`: 2 flows (0.57 %)

Reading: high `Bot` count = correct exact-class recall. Significant `DoS slowloris` / `PortScan` / `SSH-Patator` counts mean the timing patterns of modern stealer C2 land in those classes' decision regions instead — limit of the inherited 7-class taxonomy from CIC-IDS2017.