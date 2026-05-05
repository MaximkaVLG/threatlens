# Adversarial baseline (v2)

Model: `v2`. Test set: 9-PCAP sandbox holdout (N_baseline_flows=349). Each cell is the recall on the perturbed re-extraction. Δ pp = absolute change vs baseline recall 96.85 %.

Caveats:
- IAT-jitter changes packet timing, which changes how the cicflowmeter   session-izer aggregates packets into flows. Aggressive jitter   often produces *fewer* flows than baseline because flow timeouts   fire differently. We report recall on the resulting flows; if a   flow's identity changes, the model still has to classify it.
- Recall here is `predicted_attack / total_flows_after_perturb`   (not against ground truth — sandbox PCAPs are 100 % Bot, so   any non-attack prediction is a miss).
- N_flows column shows whether perturbation collapsed or expanded   the flow count. A drop from baseline_flows → 50 % means half   the flows merged together — feature distributions shift even   before classification runs.

## Recall matrix

| Perturbation | none | mild | moderate | aggressive |
|---|---:|---:|---:|---:|
| **iat_jitter** | 96.8 %  (Δ+0.0 pp, n=349) | 96.9 %  (Δ+0.0 pp, n=350) | 96.8 %  (Δ+0.0 pp, n=349) | 97.1 %  (Δ+0.3 pp, n=349) |
| **packet_padding** | 96.8 %  (Δ+0.0 pp, n=349) | 86.5 %  (Δ-10.3 pp, n=349) | 99.4 %  (Δ+2.6 pp, n=349) | 100.0 %  (Δ+3.2 pp, n=349) |
| **ttl_random** | 96.8 %  (Δ+0.0 pp, n=349) | 96.8 %  (Δ+0.0 pp, n=349) | 96.8 %  (Δ+0.0 pp, n=349) | 96.8 %  (Δ+0.0 pp, n=349) |
| **rst_inject** | 96.8 %  (Δ+0.0 pp, n=349) | 96.8 %  (Δ+0.0 pp, n=349) | 96.8 %  (Δ+0.0 pp, n=349) | 96.8 %  (Δ+0.0 pp, n=349) |

## Flow-count matrix (how perturbation changed aggregation)

| Perturbation | none | mild | moderate | aggressive |
|---|---:|---:|---:|---:|
| **iat_jitter** | 349 (100 %) | 350 (100 %) | 349 (100 %) | 349 (100 %) |
| **packet_padding** | 349 (100 %) | 349 (100 %) | 349 (100 %) | 349 (100 %) |
| **ttl_random** | 349 (100 %) | 349 (100 %) | 349 (100 %) | 349 (100 %) |
| **rst_inject** | 349 (100 %) | 349 (100 %) | 349 (100 %) | 349 (100 %) |

## Reading

- Baseline (no perturbation): recall = 96.85 %, n_flows = 349.
- Cells with negative Δ pp = recall degradation (worse).
- Cells with substantially fewer flows than baseline = the   perturbation changed cicflowmeter's flow boundaries; the   resulting flows have different feature values, which is *part*   of the adversarial impact, not separate from it.
- This is a *floor* measurement. A motivated adversary doing   pattern-aware mimicry would shift recall lower; this is what   random-noise evasion costs by itself.