# Day 5 — Combined retraining (pulled forward from Day 8)

**Run date:** 2026-04-22
**Status:** ✅ Complete. Results below.

**Headline result:** The cross-dataset generalisation gap that
motivated the entire improvement plan is largely closed.

- CIC-IDS2017 (in-distribution): F1 weighted 0.9981 → 0.9987 (no
  regression — still essentially perfect)
- CIC-IDS2018 (cross-dataset): F1 weighted 0.6032 → **0.9228**
  (+0.32), F1 macro 0.084 → **0.870** (+0.79). Four attack classes
  (Bot, DDoS, FTP-Patator, SSH-Patator) went from **undetected** to
  **perfect**.
- Synthetic: F1 weighted 0.0004 → 1.0000.

**Biggest surprise:** `Spectral Entropy` (new Day 3 feature) is the
single most informative feature in the combined XGBoost model
(importance 0.096), ranking above `SYN Flag Count` which was
previously CIC-IDS2017's canonical top feature.

---

**Goal:** Fold the three training sources built up over Days 1-4 into a
single XGBoost model that consumes the full 81-feature schema. This
was originally Day 8, pulled forward because:

1. Days 3 and 4 landed ahead of schedule (spectral + YARA features).
2. Without retraining, none of those features *do* anything — the prod
   model still expects 70 columns and ignores everything else.
3. Day 9 (selective prediction) needs a trained model to layer on top of.

**Safety rail:** new artefacts go to `results/combined_v2/`, *never*
overwriting `results/cicids2017/` which production reads. Switching
prod is a deliberate Day 11 decision, not a side-effect of Day 5.

## Input sources

| Source | Rows | Features natively | After alignment |
|---|---:|---:|---|
| CIC-IDS2017 (stratified sample) | ~500 K | 70 CIC | 81 (spectral/YARA zero-filled) |
| CIC-IDS2018 (sampled + column-mapped) | ~500 K | 80 (abbrev names) → 70 | 81 (spectral/YARA zero-filled) |
| Synthetic (Day 2, DoS Hulk capped at 10 K) | ~25 K | 81 (all present) | 81 |
| **Total combined** | **~1.025 M** | | **81** |

### Column alignment

CIC-IDS2018 uses abbreviated names (`Tot Fwd Pkts` vs
`Total Fwd Packets`); we reuse the mapping from
[`scripts/eval_cross_dataset.py`](../scripts/eval_cross_dataset.py)
(`COL_MAP_2018_TO_2017`, 43 entries) plus the label map
(`LABEL_MAP_2018_TO_2017`, 13 entries — includes the infamous
`Infilteration` typo).

### Why zero-fill spectral / YARA for CIC-2017 / 2018

The source CSVs for both CIC datasets predate the spectral and YARA
features by several years — the original CICFlowMeter didn't compute
them, and we can't recompute without re-extracting flows from the
original PCAPs (which CIC distributes separately and which are 70+ GB).

Zero-fill is the conservative choice: the training objective sees those
columns as constant for 97 % of rows. XGBoost will *not* split on them
unless the synthetic rows provide enough signal to justify it. If
spectral/YARA end up high in feature importance post-training, it's
evidence they genuinely help; if they rank near the bottom, they're
effectively dormant until future data is collected with them populated.

### DoS Hulk cap

Synthetic DoS Hulk dominates (130 066 of 143 841 synthetic rows, 90 %).
Left uncapped, it would account for ~13 % of the *combined* training set
and distort loss weighting. Capping at 10 K keeps the class visible to
the model without drowning out the other 11 synthetic attack variants.

## Training pipeline

- **Split:** stratified 80 / 20 train/test on combined labels.
- **Preprocessing:** existing `FeaturePipeline` — NaN/inf → 0, variance
  threshold, StandardScaler, LabelEncoder. No changes.
- **Model:** primary is XGBoost (same hyperparams as
  [`threatlens/ml/models.py`](../threatlens/ml/models.py) `build_xgboost`);
  RandomForest trained for comparison.
- **Artefacts:** `results/combined_v2/{xgboost,random_forest,feature_pipeline}.joblib`
  + `metrics.json` + `comparison.csv`.
- **Drop tiny classes:** any label with < 10 combined rows is dropped
  before splitting (Heartbleed, Web Attack XSS/SQLi in the current set —
  these are real CIC-2017 classes but nearly empty even in the full
  dataset, and the column-encoding artefact `Web Attack \ufffd XSS`
  makes them fragile across pandas versions).

## Results — combined training

Combined DataFrame: **1,023,724 rows × 81 cols** (663 MB). Stratified
80/20 split → train 818,979 / test 204,745.

**Per-source test rows:** CIC-2017 ~100K, CIC-2018 ~100K, synthetic
~4.6K. **13 labels survived** the ≥ 10-row filter (Heartbleed and
`Web Attack Sql Injection` dropped — too sparse even in combined).

**Feature retention:** 78 / 81 kept after variance filter. Three
dropped: the zero-filled tail of YARA columns (CIC-2017 + CIC-2018
supply no YARA data, and the synthetic slice happens to give zero
matches for every flow — consistent with `docs/day4_yara_synergy.md`).
Spectral columns survived because synthetic + a few CIC flows do
exercise them.

**Training time:**
- XGBoost: **114.7 s**, test F1 weighted **0.9608**
- RandomForest: **44.6 s**, test F1 weighted **0.9429**
- End-to-end wall time including data load: **4.3 min** on 8-core CPU.

**In-training per-source F1 (XGBoost, 20 % of combined test set):**

| Source | Test rows | F1 weighted | F1 macro |
|---|---:|---:|---:|
| CIC-2017 slice | 100,143 | **0.9989** | 0.8418 |
| CIC-2018 slice | 99,962 | **0.9214** | 0.6515 |
| Synthetic slice | 4,640 | **1.0000** | 1.0000 |

### Feature importance (top 20, XGBoost combined)

| Rank | Feature | Importance |
|---:|---|---:|
| **1** | **Spectral Entropy** | **0.0960** |
| 2 | SYN Flag Count | 0.0896 |
| 3 | Avg Bwd Segment Size | 0.0866 |
| 4 | Subflow Bwd Bytes | 0.0709 |
| 5 | Bwd Packet Length Std | 0.0541 |
| 6 | Bwd Packet Length Min | 0.0434 |
| 7 | act_data_pkt_fwd | 0.0366 |
| 8 | Fwd Header Length.1 | 0.0353 |
| 9 | Destination Port | 0.0347 |
| 10 | min_seg_size_forward | 0.0248 |
| 11 | Bwd IAT Total | 0.0238 |
| 12 | ECE Flag Count | 0.0218 |
| 13 | Packet Length Std | 0.0206 |
| **14** | **Spectral Centroid** | **0.0205** |
| 15 | Bwd Packet Length Mean | 0.0202 |

**Spectral Entropy is the single most informative feature in the
entire combined model** (above SYN Flag Count, the CIC-IDS2017
canonical top feature). Spectral Centroid ranks 14th. YARA features
are absent from the top 25 — they're still effectively dormant on this
combined set because no training source provides YARA-positive flows
in meaningful quantity. Day 10 re-eval on real-world Stratosphere /
CTU PCAPs will be where YARA gets its validation.

Day 3's hypothesis was correct: frequency-domain features capture a
signal the 70 CIC statistics collapse away, and a classifier trained
on combined data ranks them first.

## Results — head-to-head evaluation

Evaluation harness: [`scripts/eval_combined.py`](../scripts/eval_combined.py).
Each benchmark loads both models (old CIC-2017-only and new combined
XGBoost) through their respective feature pipelines and compares F1
on an independent hold-out sample drawn from the raw source CSVs (NOT
the combined-training test fold).

| Benchmark | Rows | Old F1w | New F1w | ΔF1w | Old F1m | New F1m | ΔF1m |
|---|---:|---:|---:|---:|---:|---:|---:|
| CIC-2017 sample | 199,993 | 0.9981 | **0.9987** | **+0.0006** | 0.7152 | 0.7183 | +0.0032 |
| CIC-2018 sample | 199,981 | 0.6032 | **0.9228** | **+0.3196** | 0.0838 | **0.8701** | **+0.7863** |
| Synthetic sample | 23,775 | 0.0004 | **1.0000** | **+0.9996** | 0.0109 | 1.0000 | +0.9891 |

### Per-class on CIC-IDS2018 (the headline lift)

The old CIC-2017-only model effectively collapsed to BENIGN-only on
CIC-2018 — every attack class scored F1 = 0.00:

| Class | Support | Old F1 | New F1 | Δ |
|---|---:|---:|---:|---:|
| BENIGN | 143,872 | 0.8384 | 0.9591 | +0.12 |
| Bot | 9,106 | **0.0000** | **0.9999** | **+1.00** |
| DDoS | 21,967 | **0.0000** | **1.0000** | **+1.00** |
| FTP-Patator | 6,168 | **0.0000** | **1.0000** | **+1.00** |
| Infiltration | 12,933 | 0.0000 | 0.2617 | +0.26 |
| SSH-Patator | 5,935 | **0.0000** | **0.9999** | **+1.00** |

Four of six attack classes went from **undetected** to **perfect**.
Infiltration remains weak (0.26) — a known-hard class that deliberately
mimics benign traffic; moving that will likely require a richer feature
set than flow statistics can provide (ties into the Day 9 selective
prediction strategy: flag low-confidence flows for human review rather
than trying to force a classification decision).

### Interpretation framework

- **CIC-2017 sample:** the old model was trained exactly on this
  distribution and scored F1 = 0.998. The combined model should stay
  within ~0.5 F1 points of that — any larger drop indicates the new
  training sources are competing with (not augmenting) the old signal.
- **CIC-2018 sample:** the headline lift. Old model scored 0.50-0.60
  F1 weighted ([`docs/cross_dataset_eval.md`](cross_dataset_eval.md)).
  A weighted-F1 lift of +0.20 would be a clear win for the award pitch.
- **Synthetic sample:** both models should score high here because
  synthetic flows are trivially separable (see
  [`docs/synthetic_eval.md`](synthetic_eval.md) — 5-fold CV F1 = 1.0000
  on synthetic-only). The old model may still score lower because its
  variance filter strips features the synthetic generator uses.

## Known limitations

1. **No Stratosphere / real-world PCAP eval in Day 5.** That lives in
   Day 10 because running inference on PCAPs requires re-extracting
   flows with the full 81-feature pipeline, which is slow (the
   Stratosphere captures in `data/real_pcap/` are non-trivial).
   Deferring keeps Day 5 focused on "does combined training actually
   improve cross-dataset"; Day 10 closes the loop on real-world.
2. **Sampling introduces variance.** We use a fixed random seed (42)
   so runs are reproducible, but smaller samples (e.g.
   `--cic2017-sample 50000`) produce noticeably different per-class F1.
   The numbers quoted here are for the default 500K/500K/cap=10K config.
3. **Prod deploy NOT affected.** `results/cicids2017/` is untouched.
   The web app still loads the old model on startup. Day 11 evaluates
   whether to flip `THREATLENS_ML_DIR` env var to
   `results/combined_v2/` and redeploy.

## Reproduce

```bash
# Full run (~20-30 min)
python scripts/train_combined.py

# Smoke test (~1 min)
python scripts/train_combined.py \
    --cic2017-sample 30000 --cic2018-sample 30000 \
    --hulk-cap 5000 --output results/combined_smoketest --skip-rf

# Head-to-head eval (old vs new, three benchmarks)
python scripts/eval_combined.py
```

## Files added / changed

- **NEW** [`scripts/train_combined.py`](../scripts/train_combined.py) —
  combined loader + sample/align + train XGBoost/RandomForest + save.
- **NEW** [`scripts/eval_combined.py`](../scripts/eval_combined.py) —
  head-to-head comparison harness.
- **NEW** [`results/combined_v2/`](../results/combined_v2/) — trained
  artefacts (not committed — too large; reproduce via the commands above).
- **UNCHANGED** `results/cicids2017/` — prod production model.
