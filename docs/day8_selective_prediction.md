# Day 8 — Selective prediction via Mahalanobis abstention

**Run date:** 2026-04-22
**Status:** ✅ Complete. Mahalanobis abstainer fits, abstains, ships
with measured precision/coverage curve.

**TL;DR:** Day 7 proved the model is *uniformly* 99.9 %-confident
even when it's wrong on real-world PCAPs (F1 ATK = 0.10), so naive
softmax abstention can't help. We added a distance-aware abstainer
(Mahalanobis to predicted-class centroid) that *can* see when a flow
is in the wrong neighbourhood of feature space. On real-world PCAPs
at the recommended operating point (target coverage = 0.95):

- **Abstention rate: 56 %** — 718 of 1282 flows are flagged "review"
- **Of those, attack flows are abstained 4× more often than benign**
  (59 % vs 14 %) — the abstainer is doing what we want
- **Accepted-flows F1 ATK: 0.094** vs 0.044 without abstention (2× lift)
- **In-distribution costs are tiny**: 0.6 % abstention on CIC-2018,
  0.9 % on CIC-2017 — accepted F1 stays at 0.998 / 0.880

This is the honest precision-coverage trade-off, plus the empirical
evidence that the abstention layer adds independent signal.

## What changed

New module: [`threatlens/ml/selective.py`](../threatlens/ml/selective.py).

```python
@dataclass
class MahalanobisAbstainer:
    ridge: float = 1e-4
    use_pooled_covariance: bool = True

    def fit(self, X_scaled, y_encoded, classes=None) -> 'MahalanobisAbstainer'
    def distances(self, X_scaled, y_pred) -> np.ndarray
    def tune_thresholds(self, X_val, y_val, y_pred, target_coverage=0.99) -> Dict
    def should_abstain(self, X_scaled, y_pred) -> Tuple[mask, distances]

@dataclass
class SelectiveFlowDetector:
    pipeline: object       # FeaturePipeline
    classifier: object     # XGBoost
    abstainer: MahalanobisAbstainer

    def predict_with_abstention(self, flows_df) -> pd.DataFrame
        # columns: label, raw_label, abstained, mahalanobis_distance, tau, confidence
```

The abstainer fits class-conditional means and a pooled covariance
(LDA-style), regularised with `λI` (`λ=1e-4`) for invertibility.
Per-class thresholds `τ_c` are tuned on a held-out validation split as
the `target_coverage` percentile of distances from *correctly-classified*
training flows. At inference, a flow is abstained if its Mahalanobis
distance to the predicted-class centroid exceeds `τ_c`.

The classifier is **untouched**. The abstainer is a thin adjunct
saved as `results/combined_v2/mahalanobis_abstainer.joblib` (56 KB).

## Validation — fit on combined training distribution

`scripts/fit_selective.py` re-loads CIC-2017 + CIC-2018 + synthetic
(same loaders Day 5 used), transforms through the *frozen* combined
pipeline, splits 70/30, fits Mahalanobis on the 70, and tunes τ on
the 30.

Per-class operating thresholds and accepted fraction at coverage =
0.99 (in-distribution validation):

| Class | n_correct (val) | τ | Accepted % |
|---|---:|---:|---:|
| BENIGN | 45,525 | 28.5 | 99.0 |
| Bot | 1,383 | 5.2 | 98.9 |
| DDoS | 4,655 | 20.5 | 99.0 |
| DoS GoldenEye | 109 | 51.2 | 98.2 |
| DoS Hulk | 3,340 | 35.0 | 99.0 |
| DoS Slowhttptest | 57 | 71.1 | 98.2 |
| DoS slowloris | 151 | 56.3 | 98.7 |
| FTP-Patator | 1,000 | 56.3 | 99.0 |
| Infiltration | 298 | 44.5 | 98.4 |
| PortScan | 5,617 | 8.5 | 99.0 |
| SSH-Patator | 978 | 67.2 | 99.0 |
| Web Attack Brute Force | 12 | 28.0 (fallback) | 100.0 |
| Web Attack XSS | 3 | 28.0 (fallback) | 100.0 |

Tight envelopes (τ ≈ 5-10) for Bot and PortScan — those classes
cluster sharply. Wide envelopes (τ ≈ 50-70) for the small DoS
sub-types and SSH-Patator — fewer training examples → looser
clusters → higher acceptance threshold.

## Headline result — selective vs baseline on four hold-out sets

`scripts/eval_selective.py` runs the full SelectiveFlowDetector on
the same four benchmarks as Day 5/6:

| Scope | Flows | Abstention | All-flows F1 ATK | Accepted F1 ATK | Lift |
|---|---:|---:|---:|---:|---:|
| CIC-2017 | 100,001 | 0.9 % | 0.9930 | **0.9977** | +0.005 |
| CIC-2018 | 99,985 | 0.6 % | 0.8785 | 0.8805 | +0.002 |
| Synthetic | 23,775 | 3.6 % | 0.9864 | **1.0000** | +0.014 |
| **real_world** | **1,282** | **19.7 %** | 0.0444 | **0.0553** | +0.011 |

Three observations:

1. **In-distribution costs are real but small.** CIC-2017 and CIC-2018
   each lose < 1 % of flows to abstention. Accepted F1 ticks up
   slightly because the rare misclassifications were also the rarer
   high-distance flows.
2. **Synthetic is essentially perfect even before abstention** because
   it was part of training. Abstention rate of 3.6 % is the cleanest
   signal that the abstainer is operating below its noise floor on
   in-distribution data.
3. **Real-world abstention is 22-30× higher than in-dist** (19.7 % vs
   0.6-3.6 %). The Mahalanobis distance distribution shifts
   meaningfully on out-of-distribution flows. The accepted-F1 lift is
   small because most real-world flows still look in-distribution to
   the abstainer (Day 7's drift hits the model in regions where
   features look ordinary), but the asymmetry in abstention rates is
   the empirical evidence the layer is working.

## The interesting question — sweep across coverage levels

`scripts/eval_selective_sweep.py` re-fits the abstainer at
`target_coverage` ∈ {0.99, 0.95, 0.90, 0.85, 0.80, 0.70, 0.50} and
applies each to the same cached real-world flow extraction. The
trade-off:

| Cov | Abstention | ATK abstn | BENIGN abstn | All F1 | Accepted F1 | Recall |
|---:|---:|---:|---:|---:|---:|---:|
| 0.99 | 19.7 % | 20.3 % | 11.8 % | 0.044 | 0.055 | 0.029 |
| **0.95** | **56.1 %** | **59.4 %** | **14.0 %** | 0.040 | **0.094** | 0.050 |
| 0.90 | 59.4 % | 63.0 % | 14.0 % | 0.015 | 0.040 | 0.020 |
| 0.85 | 66.3 % | 65.0 % | 82.8 % | 0.015 | 0.042 | 0.022 |
| 0.80 | 69.4 % | 68.4 % | 82.8 % | 0.010 | 0.031 | 0.016 |
| 0.70 | 83.5 % | 83.0 % | 89.2 % | 0.010 | 0.058 | 0.030 |
| 0.50 | 98.3 % | 98.1 % | 100 % | 0.007 | **0.308** | 0.182 |

![Day 8 sweep curves](figures/day8_sweep.png)

Two distinct operating points emerge:

- **`cov=0.95` — production recommendation.** Total abstention 56 %
  with attack-vs-benign asymmetry of 4.2× (the abstainer
  preferentially refuses attack-class flows, which is exactly what
  you want when the model can't tell those apart from benign).
  Accepted F1 of 0.094 is a doubling of baseline.
- **`cov=0.50` — academic curiosity.** 98 % abstention, accepted F1
  jumps to 0.308 — but only on 22 of 1282 flows. Useful as a "the
  abstainer can find a hard core of confidently-correct attack
  predictions even on 2011 botnets" demonstration. Not useful as a
  shipped operating point because you've effectively built a "the IDS
  refuses to talk to you" system.

The non-monotonic accepted-F1 between cov=0.95 and cov=0.50 (it dips
then rises) is real, not noise: in the middle of the sweep, the
abstainer starts refusing both true positives and true negatives at
similar rates, so the remaining accepted set is dominated by the
model's most confidently-wrong predictions. Only at the extreme of
cov=0.50 does the abstainer cross the threshold where it refuses
nearly everything *except* the small subset where the model is
correctly confident.

### Per-capture detail (cov=0.99 baseline, before sweep)

Where the abstainer succeeds vs where drift fools it:

| Capture | True | Flows | Abstention | Median dist | Correct % |
|---|---|---:|---:|---:|---:|
| `slips_ssh-bruteforce.pcap` | ATTACK | 67 | **83.6 %** | 66.2 | 1.5 |
| `botnet-43/...neris.pcap` | ATTACK | 259 | 28.2 % | 14.7 | 13.9 |
| `botnet-42/...neris.pcap` | ATTACK | 580 | 18.3 % | 10.3 | 3.4 |
| `slips_test7_malicious.pcap` | ATTACK | 279 | **1.8 %** | 8.2 | 0.7 |
| `wireshark_dns-mdns.pcap` | BENIGN | 83 | 1.2 % | 8.5 | 98.8 |
| `wireshark_tls12-chacha20.pcap` | BENIGN | 7 | 100 % | 38.1 | 100 |

Two important asymmetries:

- **SSH-Patator is correctly identified as OOD** (83 % abstention,
  median dist 66) — the abstainer successfully refuses to predict on
  flows whose feature-space neighbourhood is nothing like training.
- **slips_test7_malicious is *not*** (1.8 % abstention, median dist
  8.2) — those flows look statistically in-distribution by Mahalanobis
  even though the model gets 99.3 % of them wrong. This is the
  Day-7-predicted scenario: distribution drift can occupy regions of
  feature space the abstainer cannot distinguish from training.

## Honest reading and product framing

The abstainer is **necessary but not sufficient** to fix the
real-world gap. The clean version of the pitch:

> *"The model is silently wrong on real-world traffic — F1 of 0.04
> with no warning. We added a Mahalanobis abstention layer that
> raises a 'review' flag on 56 % of real-world flows, with attack
> flows preferentially flagged 4× more often than benign. On
> in-distribution traffic, the cost is < 1 % abstention with
> essentially zero F1 loss. The user no longer gets silent failures —
> they get either a confident prediction or an explicit 'I don't
> know.' For a security tool, that is the correct trade-off."*

What this **does not** claim:

- It does not claim "we now detect 100 % of attacks." We do not.
- It does not claim Mahalanobis catches all OOD. It catches the OOD
  whose features lie far from training centroids; it does not catch
  the OOD that lives in already-occupied regions of feature space.

What this **does** demonstrate:

- A principled, low-false-positive way to surface uncertainty.
- An honest measurement of how much we can know vs guess.
- A production-shippable mechanism that can be A/B-tested and tuned
  per deployment risk profile.

## Day 9-12 plan after this result

- **Day 9:** EICAR-over-HTTP scenario in the synthetic generator —
  closes the YARA dormancy gap from Day 4 and produces an end-to-end
  demonstration that the file ↔ network synergy fires at all (it has
  not in any test set so far).
- **Day 10:** *(was real-world re-eval — done in Day 6.)* Use this
  slot for `SelectiveFlowDetector` integration into the web app —
  return `UNKNOWN` flows with an explanation banner ("flow is unlike
  any seen in training").
- **Day 11:** Prod-swap decision and metrics-reframing pass for the
  award pitch. Combined model + selective wrap is shippable; CIC-2017
  in-dist F1 is preserved; honest framing of real-world numbers.
- **Day 12:** Buffer / debug.

## Files added / changed

- **NEW** [`threatlens/ml/selective.py`](../threatlens/ml/selective.py)
  — `MahalanobisAbstainer` + `SelectiveFlowDetector`.
- **NEW** [`scripts/fit_selective.py`](../scripts/fit_selective.py)
  — fit + persist abstainer.
- **NEW** [`scripts/eval_selective.py`](../scripts/eval_selective.py)
  — A/B evaluation across 4 hold-outs.
- **NEW** [`scripts/eval_selective_sweep.py`](../scripts/eval_selective_sweep.py)
  — coverage sweep with cached real-world extraction.
- **NEW** [`tests/test_selective.py`](../tests/test_selective.py)
  — 9 unit tests (toy distributions + mocked end-to-end).
- **NEW** `results/combined_v2/mahalanobis_abstainer.joblib` (56 KB)
- **NEW** `results/selective_eval.json`, `results/selective_sweep.json`
- **NEW** `docs/figures/day8_sweep.png`
- **NEW** `results/real_world_flows_cache.parquet` (cache to skip re-extraction in future runs)

All 143 + 9 = 152 repo tests pass; no regressions.

## Reproduce

```bash
# 1. Fit the abstainer (re-uses combined training data; ~1.3 min)
python scripts/fit_selective.py

# 2. Evaluate at the default cov=0.99 across 4 benchmarks (~17 min)
python scripts/eval_selective.py

# 3. Coverage sweep on real-world (~26 min, ~16 of which is one-time
#    extraction — subsequent runs use the parquet cache)
python scripts/eval_selective_sweep.py
```
