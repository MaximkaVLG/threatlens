# Bootstrap 95 % CI on v2

Method: percentile bootstrap on the ATTACK subset for recall, on the BENIGN subset for FP rate. 1000 resamples per slice, seed 42. Slices with N < 10 are flagged ⚠SMALL-N — their CI is wide enough that the point estimate is directional only, not a statistic to act on.

## Headline test sets

| Test set | N | Point | 95 % CI | ±pp |
|---|---:|---:|---|---:|
| Historical real-world recall | 347 | 99.42 % | [98.56, 100.00] | ±0.7 |
| CTU-13 holdout recall | 253 | 100.00 % | [100.00, 100.00] | ±0.0 |
| Sandbox holdout recall (9 PCAPs) | 349 | 96.85 % | [94.56, 98.57] | ±2.0 |

| FP rate (model alone, BENIGN only) | 93 | 19.35 % | [10.75, 27.96] | ±8.6 |

## Sandbox holdout — per-source breakdown

| Source | N | Point | 95 % CI | ±pp |
|---|---:|---:|---|---:|
| mta | 103 | 96.12 % | [92.23, 99.03] | ±3.4 |
| stratosphere | 246 | 97.15 % | [94.72, 99.19] | ±2.2 |

## Sandbox holdout — per-family breakdown

| Family | N | Point | 95 % CI | ±pp | Note |
|---|---:|---:|---|---:|---|
| stealc ⚠SMALL-N | 2 | 100.00 % | [100.00, 100.00] | ±0.0 | Wide CI, treat as directional |
| rhadamanthys ⚠SMALL-N | 4 | 100.00 % | [100.00, 100.00] | ±0.0 | Wide CI, treat as directional |
| netsupport ⚠SMALL-N | 7 | 100.00 % | [100.00, 100.00] | ±0.0 | Wide CI, treat as directional |
| clickfix ⚠SMALL-N | 9 | 100.00 % | [100.00, 100.00] | ±0.0 | Wide CI, treat as directional |
| lumma | 81 | 95.06 % | [90.12, 98.77] | ±4.3 |  |
| bot | 246 | 97.15 % | [94.72, 99.19] | ±2.2 |  |

## Confusion against ground-truth Bot (sandbox holdout)

All 349 holdout flows are labelled `Bot` at ingest. The model classifies them as:

- `Bot`: 338 flows (96.85 %)
- `BENIGN`: 11 flows (3.15 %)

Reading: high `Bot` count = correct exact-class recall. Significant `DoS slowloris` / `PortScan` / `SSH-Patator` counts mean the timing patterns of modern stealer C2 land in those classes' decision regions instead — limit of the inherited 7-class taxonomy from CIC-IDS2017.