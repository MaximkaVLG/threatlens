# Adversarial baseline — head-to-head (python_only vs v2)

Auto-generated from `results/python_only/adversarial_eval.json` and `results/v2/adversarial_eval.json`. Each cell shows recall for both models on the same perturbed test set, plus the robustness delta (B - A in pp).

Baselines (no perturbation):
- **python_only**: recall = 60.46 % (n_flows = 349)
- **v2**: recall = 96.85 % (n_flows = 349)

## Recall under perturbation

### iat_jitter

| Strength | python_only recall | v2 recall | Δ (v2 − python_only) | python_only flows / v2 flows |
|---|---:|---:|---:|---|
| none | 60.5 % (Δ vs base +0.0) | 96.8 % (Δ vs base +0.0) | **+36.4 pp** | 349 / 349 |
| mild | 60.3 % (Δ vs base -0.2) | 96.9 % (Δ vs base +0.0) | **+36.6 pp** | 350 / 350 |
| moderate | 60.2 % (Δ vs base -0.3) | 96.8 % (Δ vs base +0.0) | **+36.7 pp** | 349 / 349 |
| aggressive | 57.3 % (Δ vs base -3.2) | 97.1 % (Δ vs base +0.3) | **+39.8 pp** | 349 / 349 |

### packet_padding

| Strength | python_only recall | v2 recall | Δ (v2 − python_only) | python_only flows / v2 flows |
|---|---:|---:|---:|---|
| none | 60.5 % (Δ vs base +0.0) | 96.8 % (Δ vs base +0.0) | **+36.4 pp** | 349 / 349 |
| mild | 67.6 % (Δ vs base +7.2) | 86.5 % (Δ vs base -10.3) | **+18.9 pp** | 349 / 349 |
| moderate | 83.1 % (Δ vs base +22.6) | 99.4 % (Δ vs base +2.6) | **+16.3 pp** | 349 / 349 |
| aggressive | 92.6 % (Δ vs base +32.1) | 100.0 % (Δ vs base +3.2) | **+7.4 pp** | 349 / 349 |

### ttl_random

| Strength | python_only recall | v2 recall | Δ (v2 − python_only) | python_only flows / v2 flows |
|---|---:|---:|---:|---|
| none | 60.5 % (Δ vs base +0.0) | 96.8 % (Δ vs base +0.0) | **+36.4 pp** | 349 / 349 |
| mild | 60.5 % (Δ vs base +0.0) | 96.8 % (Δ vs base +0.0) | **+36.4 pp** | 349 / 349 |
| moderate | 60.5 % (Δ vs base +0.0) | 96.8 % (Δ vs base +0.0) | **+36.4 pp** | 349 / 349 |
| aggressive | 60.5 % (Δ vs base +0.0) | 96.8 % (Δ vs base +0.0) | **+36.4 pp** | 349 / 349 |

### rst_inject

| Strength | python_only recall | v2 recall | Δ (v2 − python_only) | python_only flows / v2 flows |
|---|---:|---:|---:|---|
| none | 60.5 % (Δ vs base +0.0) | 96.8 % (Δ vs base +0.0) | **+36.4 pp** | 349 / 349 |
| mild | 60.5 % (Δ vs base +0.0) | 96.8 % (Δ vs base +0.0) | **+36.4 pp** | 349 / 349 |
| moderate | 60.5 % (Δ vs base +0.0) | 96.8 % (Δ vs base +0.0) | **+36.4 pp** | 349 / 349 |
| aggressive | 60.5 % (Δ vs base +0.0) | 96.8 % (Δ vs base +0.0) | **+36.4 pp** | 349 / 349 |

## Aggregate robustness

Mean recall across **12** perturbed cells (non-trivial strengths only):

- **python_only**: 65.32 %
- **v2**: 96.49 %
- **Δ**: +31.18 pp (B more robust)

Note: this is a coarse aggregate — a cell with 50 % recall drop and a cell with 5 % recall drop count equally. The per-perturbation tables above show where the meaningful differences are.

## Reading

- `Δ vs base` columns: each model's drop relative to its own baseline. Useful to compare *robustness* even when absolute recall numbers differ.
- `Δ (B − A)` column: the head-to-head — positive means B did better on that cell, negative means A did better.
- `flows` column: how many flows survived re-extraction. A drop here means the perturbation collapsed cicflowmeter's flow boundaries; the resulting flows have shifted feature values, which is part of the adversarial impact.
- The strength=none row is a sanity check (should equal baseline). Non-zero Δ pp on `none` indicates a bug.