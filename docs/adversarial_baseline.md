# Adversarial baseline — recall under naive evasion

**Status:** in-progress, numbers populated by `scripts/adversarial_eval.py`
on the 9-PCAP sandbox holdout (the same holdout used for the
apples-to-apples A/B in [`results/v2/ab_vs_python_only.md`](../results/v2/ab_vs_python_only.md)).

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

| Perturbation | What it does | Why we expect this to hurt |
|---|---|---|
| `iat_jitter` | Gaussian noise on per-packet timestamps (preserves order) | v2 leans on Flow IAT mean / std features |
| `packet_padding` | Append random bytes to TCP / UDP payload | Shifts payload-length statistics (mean / max) |
| `ttl_random` | Add ±N to IP TTL per packet | Sanity check — model shouldn't use TTL |
| `rst_inject` | Add spurious TCP RST after a fraction of ACK packets | Changes flag counts (RST count, FIN/RST ratio) |

Four strength levels for each: `none` (passthrough, equals baseline),
`mild`, `moderate`, `aggressive`. Strength tables are in
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
288 cells total. Wall time on a 2023 laptop: ≈2.5 h per model.

A note on flow counts: jitter and padding can change cicflowmeter's
flow-boundary decisions (flow timeouts fire differently when packet
arrival times shift). When the perturbed re-extraction produces
**fewer** flows, that is itself part of the adversarial impact, not a
separate confound — the resulting flows have different feature values
than the originals, which is what the model has to classify.

## Results

### v2 model (current production candidate)

(filled by the script; matrix lives at
`results/v2/adversarial_eval.md`).

### python_only model (current production)

(filled by the script; matrix lives at
`results/python_only/adversarial_eval.md`).

### Head-to-head delta

(filled by the comparison script; raw cells side-by-side will go here.)

## Reading the numbers honestly

- **Δ pp = 0** at `strength=none` is a sanity check, not a result.
- **Negative Δ pp at higher strengths is expected and not a failure.**
  No deployed IDS retains 100 % recall under arbitrary perturbation —
  the question is *how much* and *which features are fragile*.
- **Surprising outcomes** (a perturbation that doesn't move recall, or
  one that moves it more than expected) are noted in the per-result
  files. They identify which features the model genuinely depends on,
  versus which are decorative.
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
# v2 grid (≈2.5 h)
python scripts/adversarial_eval.py --model-dir results/v2

# python_only grid (≈2.5 h)
python scripts/adversarial_eval.py --model-dir results/python_only

# Outputs:
#   results/v2/adversarial_eval.{json,md}
#   results/python_only/adversarial_eval.{json,md}
```
