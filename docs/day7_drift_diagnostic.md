# Day 7 — Feature drift diagnostic

**Run date:** 2026-04-22
**Status:** ✅ Complete. Two independent signals both point to severe
distribution shift between training and inference, with the critical
complication that **the model is confident everywhere** — including
when it's confidently wrong.

## Why diagnose before pivoting

Day 6 proved the combined model still misses most real-world attacks
(F1 ATK 0.10 on CTU-13 + Stratosphere). There are two broad causes:

1. **Distribution drift** — training data and inference data have the
   same *column names* but not the same *value distributions*.
   Plausibly caused by Java CICFlowMeter (training) vs Python
   cicflowmeter (inference) computing slightly-different numbers
   from identical packet sequences.

2. **Generalisation gap** — even with identical extractors, 2011
   CTU-13 botnets and 2017 CIC lab attacks may differ fundamentally
   in what "malicious" looks like.

Picking a Day 8 strategy without knowing which cause dominates risks
wasted work: if the problem is drift, retraining on even more CIC
data doesn't help; if it's generalisation, swapping extractors
doesn't help either. So Day 7 gathers two independent diagnostic
signals.

## Diagnostic A — within-project distribution comparison

For five attack classes that exist in both our training data
(CIC-IDS2017 CSVs, produced by Java CICFlowMeter on lab PCAPs) and
our Python-extracted synthetic flows (Day 2 generator), compute
per-feature:

- **Kolmogorov-Smirnov D-statistic + p-value** (are the two samples
  drawn from the same distribution?)
- **Normalised Wasserstein distance** (how far apart are the two
  distributions, in units of the combined value range?)

Sample size: 5,000 per class from CIC-2017, up to 5,000 per class
from synthetic (some synthetic classes have fewer rows — see
[`docs/synthetic_eval.md`](synthetic_eval.md) for the class imbalance).

### Results — fraction of features that differ significantly

| Class | Features compared | p < 0.001 | KS D ≥ 0.5 | % significant | Median KS D |
|---|---:|---:|---:|---:|---:|
| BENIGN | 68 | 62 | 39 | **91.2 %** | 0.62 |
| PortScan | 66 | 42 | 35 | 63.6 % | 0.56 |
| FTP-Patator | 58 | 56 | 54 | **96.6 %** | 0.89 |
| DoS slowloris | 65 | 64 | 61 | **98.5 %** | 0.66 |
| SSH-Patator | — | — | — | (skipped — only 27 synthetic rows) | — |

KS D = 1.0 means "no overlap at all between the two empirical CDFs".
KS D = 0.5 is already a dramatic distribution shift. Median D values
of 0.6-0.9 across 90+ % of features is **extreme distribution
mismatch**. 39 / 68 features for BENIGN and 54 / 58 for FTP-Patator
have D ≥ 0.5, meaning half or more of the training signal looks
like a different population from inference-time traffic.

### Top 5 most-divergent features per class

**BENIGN** — CIC lab benign traffic vs curl-based synthetic benign:

| Feature | KS D | Wasserstein (norm) | CIC mean | Synthetic mean |
|---|---:|---:|---:|---:|
| FIN Flag Count | 1.00 | 0.50 | 0.016 | 2.01 |
| SYN Flag Count | 1.00 | 0.74 | 0.049 | 3.01 |
| ACK Flag Count | 1.00 | 0.37 | 0.282 | 12.2 |
| Init_Win_bytes_backward | 0.99 | 0.96 | 2,470 | 65,200 |
| Fwd Packet Length Min | 0.98 | 0.03 | 21.1 | 66 |

**FTP-Patator** — hydra brute-force in CIC lab vs hydra in our Docker lab:

| Feature | KS D | Wasserstein (norm) | CIC mean | Synthetic mean |
|---|---:|---:|---:|---:|
| Total Length of Fwd Packets | 1.00 | 0.84 | 60 | 1,220 |
| Total Length of Bwd Packets | 1.00 | 0.75 | 93.8 | 1,150 |
| Fwd Packet Length Max | 1.00 | 0.74 | 19 | 81.3 |
| Fwd Packet Length Min | 1.00 | 0.98 | 0.014 | 65 |
| Fwd Packet Length Mean | 1.00 | 0.86 | 9.39 | 71.9 |

The packet length pattern is revealing: CIC-2017 FTP-Patator flows
have `Fwd Packet Length Min ≈ 0` (the flow reports a tiny minimum,
which could be a CICFlowMeter quirk for TCP segments with no
payload), while our synthetic FTP-Patator flows have ≈ 65. This is
exactly the kind of 2-5-order-of-magnitude shift that will cause
tree-model decision boundaries to activate on the wrong side.

### What Diagnostic A rules in and out

- **Rules in:** massive distribution shift between our training data
  and our inference pipeline's output exists. The shift affects the
  majority of features in every class we can compare.
- **Does not rule in (honest caveat):** whether the shift is
  extractor-caused (Java vs Python cicflowmeter) or generator-caused
  (lab humans vs curl+nginx). To cleanly separate those, we'd need to
  feed identical PCAPs through both extractors — deferred to a future
  "drift-isolation" exercise (requires installing Java + downloading
  CICFlowMeter.jar; see
  [`docs/day6_real_world_reeval.md`](day6_real_world_reeval.md) for
  why we deferred).

Even with the extractor-vs-generator ambiguity, the finding alone is
decisive for the Day 8 plan: any strategy that tries to close the
real-world gap by adding **more CIC-style training data** will hit
the same distribution ceiling. The gap is not "we have not seen enough
attacks"; the gap is "we have not seen attacks with these values".

## Diagnostic B — confidence-collapse signature

Run the current CIC-2017-only XGBoost on three slices, measure
`predict_proba.max(axis=1)` (i.e. confidence in the winning class):

| Slice | n | Median confidence | Low (< 0.5) % |
|---|---:|---:|---:|
| CIC-2017 BENIGN (in-distribution control) | 5,000 | **1.0000** | 0.0 % |
| Synthetic (Python extractor, lab traffic) | 5,000 | **0.9997** | 0.0 % |
| Real-world PCAPs (Stratosphere + CTU-13) | 1,282 | **0.9998** | 0.1 % |

**This is the most important single finding of the diagnostic.**

The model is **uniformly 99.9 %-confident across all three slices.**
Its confidence distribution on 1,282 real-world flows is
indistinguishable from its confidence distribution on 5,000
in-distribution CIC-2017 BENIGN flows. And yet:

- On CIC-2017 BENIGN it scores F1 ≈ 1.00.
- On real-world captures it scores F1 ATK = 0.00 (old model) /
  0.096 (new model).

A confidence-based abstention mechanism (naive "if max(proba) < 0.5,
refuse to classify") would be **completely inert**. The model is not
uncertain on the flows it gets wrong; it is certain and wrong.

This has two direct consequences for the remaining days:

1. **Day 8 cannot be "just use confidence threshold for selective
   prediction."** That was the original Day 9 plan's simplest
   version; Diagnostic B kills it.
2. **Distribution-aware abstention is necessary.** Mahalanobis
   distance in feature space (or something equivalent like energy
   score, KNN distance to training set, deep-ensemble disagreement)
   is the only defence that can flag flows whose *features* are out
   of training distribution *even when the classifier is confident*
   about labelling them.

## Verdict and Day 8 plan

**Drift is real, severe, and hidden behind uniform confidence.** The
simplest selective-prediction idea (threshold on softmax) won't work.

**Day 8 plan (revised from the original Day 9):**

1. Fit a Mahalanobis distance model on the training feature matrix:
   - Per-class mean vector and shared covariance matrix (or per-class
     covariance — tune)
   - Save the distance parameters alongside the trained model
2. Wrap `FlowDetector` with a `SelectiveFlowDetector`:
   - For each inference flow, compute Mahalanobis distance to the
     predicted class centroid
   - If distance > threshold tau, return "UNKNOWN" / abstain
3. Tune tau on a validation split to hit a target *accepted-prediction
   precision* (e.g. 0.95 precision, accept whatever coverage the
   tau implies)
4. Re-run Day 6 A/B on real-world PCAPs with abstention:
   - Old metric: F1 ATK = 0.096 on all flows
   - New metric: F1 ATK on accepted flows AND abstention rate —
     expected tradeoff: high abstention rate, high precision on what
     we do predict

**Day 9 plan (what used to be Day 10):** real-world re-eval is
already done (Day 6 + Day 7). Day 9 becomes the polish pass — add an
EICAR-over-HTTP scenario to the synthetic generator, re-run the full
81-feature pipeline end-to-end, confirm YARA features fire for that
one case (closes the "YARA is dormant" gap from Day 4).

## Reframing for the award pitch

This finding actually *helps* the pitch framing, not hurts it:

- **Old pitch** (pre-Day 6): "Our IDS achieves F1 = 0.998." — dishonest,
  in-distribution-only, and gets shredded by a competent judge.
- **New pitch** (post-Day 8): "Our IDS achieves F1 = 0.998 on
  in-distribution traffic, refuses to predict on out-of-distribution
  traffic (~X % of real-world flows), and surfaces those as
  'uncertain, please review' rather than miscategorising them as
  BENIGN. Here is the Mahalanobis-distance evidence for why refusing
  is the right response." — honest, principled, defensible, and
  directly addresses the "but does it work in real life" objection.

Selective prediction is not a consolation prize when accuracy is
poor. It's a first-class feature of an IDS deployed in a high-stakes
setting where silent misses (which the old model produces at scale)
are categorically worse than explicit "I don't know"s.

## Files added

- **NEW** [`scripts/diag_feature_drift.py`](../scripts/diag_feature_drift.py)
  — two-part diagnostic harness.
- **NEW** [`results/feature_drift_diag.json`](../results/feature_drift_diag.json)
  — per-label drift stats + confidence histograms.

## Reproduce

```bash
python scripts/diag_feature_drift.py
# Outputs: results/feature_drift_diag.json and console tables
```
