# Adversarial baseline — recall under naive evasion

**Status:** v2 results in. python_only results pending (grid in progress;
this doc updates with the head-to-head once the grid completes).

The numbers below are populated by `scripts/adversarial_eval.py` on the
9-PCAP sandbox holdout (the same holdout used for the apples-to-apples
A/B in [`results/v2/ab_vs_python_only.md`](../results/v2/ab_vs_python_only.md)).

## Why this exists

The headline 96.85 % sandbox-holdout recall reported in
[`SUBMISSION.md`](../SUBMISSION.md) is measured on **unmodified PCAPs**.
Reviewers reasonably ask: "what happens when an attacker actively tries
to evade the model?". This document publishes the answer for four naive
evasion techniques at four strength levels — a **floor** measurement.
A motivated adversary doing pattern-aware mimicry will push recall
lower; the numbers here are what generic random-noise evasion costs
*by itself*, with no attacker knowledge of the model.

## What we test

Four perturbations, each preserving wire-level PCAP validity and the
flow's 5-tuple identity (so the comparison stays apples-to-apples with
the baseline):

| Perturbation | What it does | Strength range |
|---|---|---|
| `iat_jitter` | Gaussian noise on per-packet timestamps (preserves order) | sigma ∈ {1 ms, 10 ms, 100 ms} |
| `packet_padding` | Append random bytes to TCP / UDP payload | uniform random ∈ {[10, 50], [50, 200], [200, 500]} bytes |
| `ttl_random` | Add ±N to IP TTL per packet | N ∈ {5, 20, 50} |
| `rst_inject` | Insert spurious TCP RST after a fraction of ACK packets | rate ∈ {1 %, 5 %, 20 %} |

Strengths labelled `mild` / `moderate` / `aggressive` plus a passthrough
`none` sanity row. Strength tables and exact numeric values live in
[`scripts/perturb_pcap.py`](../scripts/perturb_pcap.py).

Excluded by design (would break the apples-to-apples comparison):

- TLS handshake reorder — confounds extraction failure with detection
- IP fragmentation — frequently dropped at NIC offload, would change
  packet-count semantics across the holdout

## Methodology

1. For each (PCAP, perturbation, strength) cell, apply the perturbation
   to the original PCAP via `scripts/perturb_pcap.py`.
2. Re-extract flows from the perturbed PCAP using the **same**
   `FlowExtractor` that runs in production (`threatlens.network`).
3. Run the v2 model on the resulting flows, record `recall_attack`.
4. Repeat the entire grid for `results/python_only/` to compare how
   the previous production candidate degrades vs the v2 candidate.

Total: 4 perturbations × 4 strengths × 9 PCAPs = 144 cells per model,
288 cells total. Wall time on a 2023 laptop: ~2.5 h per model.

A note on flow counts: jitter and padding can change cicflowmeter's
flow-boundary decisions (flow timeouts fire differently when packet
arrival times shift). When the perturbed re-extraction produces
**fewer** flows, that is itself part of the adversarial impact, not a
separate confound — the resulting flows have different feature values
than the originals, which is what the model has to classify.

For all v2 cells the flow count stays at 349 ± 1 (within rounding noise),
so flow-aggregation drift is not the dominant effect here. We report
recall on whatever flows survive perturbation.

## Results — v2 (current production candidate)

Baseline (no perturbation): **96.85 %** (n=349). Source:
[`results/v2/adversarial_eval.json`](../results/v2/adversarial_eval.json),
[`results/v2/adversarial_eval.md`](../results/v2/adversarial_eval.md).

| Perturbation | none | mild | moderate | aggressive |
|---|---:|---:|---:|---:|
| **iat_jitter**     | 96.85 % (Δ +0.00) | 96.86 % (Δ +0.01) | 96.85 % (Δ +0.00) | 97.13 % (Δ +0.29) |
| **packet_padding** | 96.85 % (Δ +0.00) | **86.53 % (Δ −10.32)** | 99.43 % (Δ +2.58) | 100.00 % (Δ +3.15) |
| **ttl_random**     | 96.85 % (Δ +0.00) | 96.85 % (Δ +0.00) | 96.85 % (Δ +0.00) | 96.85 % (Δ +0.00) |
| **rst_inject**     | 96.85 % (Δ +0.00) | 96.85 % (Δ +0.00) | 96.85 % (Δ +0.00) | 96.85 % (Δ +0.00) |

### v2 — what the four rows tell us

**`ttl_random` (sanity check, all strengths flat).** The v2 feature set
includes 67 features after the variance filter, none of which is IP
TTL — the variance filter dropped it as constant within training. So
randomising TTL is invisible to the model, which is the *correct*
behaviour for this control. If TTL had moved recall, we would have a
bug in the variance filter or the predict path.

**`rst_inject` (all strengths flat, even at 20 %).** This was the
biggest surprise. We expected `RST Flag Count` (feature 42 in the kept
list) to move recall when 20 % of ACK packets get spurious RSTs after
them — that's a 200× increase in RST count for a 1000-packet flow. The
flat result tells us the 349 holdout flows sit deep in the model's
"Bot" decision region, not on the BENIGN/Bot edge — the RST count
feature would have to be the *dominant* signal to flip a verdict, and
it's clearly not. This is good news for v2: a real adversary can't
flip recall just by injecting RST traffic from the network edge, where
they typically can.

**`iat_jitter` (≤ 0.3 pp drift even at sigma = 100 ms).** Same effect,
different reason. Flow IAT mean / std features average over hundreds
of packets; ±100 ms Gaussian noise on the per-packet timestamps shifts
those means by `100 ms / sqrt(n_packets)`, which is sub-millisecond
for typical flow sizes. The 16 timing-related features are kept by the
variance filter but the perturbation lands inside the model's noise
tolerance for them. This was *not* obvious before running the
experiment — we expected timing-fragility on the order of 5-10 pp at
aggressive strength.

**`packet_padding` (the actual finding — non-monotonic).** Mild padding
(uniform random 10-50 bytes per packet) drops recall by **−10.32 pp**.
Moderate (50-200 bytes) and aggressive (200-500 bytes) both *improve*
recall above baseline (+2.58, +3.15 pp). Reading this:

  - The v2 decision boundary at the BENIGN ↔ Bot edge is shape-sensitive
    on payload-length features (`Avg Fwd Segment Size`,
    `Packet Length Mean`, `Average Packet Size`, `Bwd Packet Length Mean`).
  - Mild padding shifts those features just enough to push borderline
    Bot flows into the BENIGN region. The 11 baseline silent-misses get
    company.
  - Larger padding pushes flows *firmly* outside the BENIGN payload-length
    distribution, which is itself a strong attack signal — the model has
    seen plenty of real Bot traffic with large segment sizes (file
    exfiltration, encrypted C2 channels), and it correctly lands those
    in Bot.
  - **The most adversarially effective padding is the smallest.** This
    is non-obvious; an attacker reasoning "more padding = more confusion"
    would be wrong here.

A motivated attacker who reverse-engineers this threshold could pad
uniformly to 10-50 bytes and degrade v2's recall to 86.5 %. That's the
floor we publish. Without that knowledge, random padding *helps* the
defender on average.

## Results — python_only (current production)

**TODO:** populated when python_only adversarial grid completes
(~2.5 h after v2). Current production model (`results/python_only/`)
has lower baseline recall on this same holdout (60.46 %), so the
expected absolute numbers are lower; the question for the head-to-head
is whether v2's robustness margin holds on a relative basis.

See [`results/python_only/adversarial_eval.md`](../results/python_only/adversarial_eval.md)
once it lands.

## Head-to-head (v2 vs python_only under perturbation)

**TODO:** auto-generated by `scripts/adversarial_compare.py` once both
grids are done. Output goes to
[`docs/adversarial_compare.md`](adversarial_compare.md).

The interesting question for an operator:
*for cells where both models retain attack detection, which one is
robust to a wider strength range?*

## Reading the numbers honestly

- **Δ pp = 0** at `strength=none` is a sanity check, not a result.
- **Negative Δ pp at higher strengths is expected and not a failure.**
  No deployed IDS retains 100 % recall under arbitrary perturbation —
  the question is *how much* and *which features are fragile*.
- **Surprising outcomes** (a perturbation that doesn't move recall, or
  one that moves it more than expected) are noted in the per-row
  commentary above. They identify which features the model genuinely
  depends on, versus which are decorative.
- **The abstainer is not a defence here.** Running adversarial flows
  through the Mahalanobis layer would inflate the number — those flows
  *should* land in the review queue. We report the model-alone recall
  to make the floor measurement comparable to the headline.

## What this is not

- This is **not** an evaluation against a motivated adversary. Pattern-
  aware mimicry, model-stealing attacks, and adaptive evasion will
  produce worse numbers — likely much worse for any feature-based
  detector.
- This is **not** a robustness certificate. We do not claim recall
  remains above any specific threshold; we publish the floor so an
  operator can decide whether the residual signal is worth
  triggering on for their threat model.
- This is **not** a comparison vs Suricata / Zeek under perturbation.
  That is Phase 2 work, blocked on Docker availability.

## Reproduce

```bash
# v2 grid (~2.5 h)
python scripts/adversarial_eval.py --model-dir results/v2

# python_only grid (~2.5 h)
python scripts/adversarial_eval.py --model-dir results/python_only

# Head-to-head comparison (instant once both grids are done)
python scripts/adversarial_compare.py \
    --model-a results/python_only --model-b results/v2

# Outputs:
#   results/v2/adversarial_eval.{json,md}
#   results/python_only/adversarial_eval.{json,md}
#   docs/adversarial_compare.md
```
