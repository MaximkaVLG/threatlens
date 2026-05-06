# Adversarial baseline (python_only)

Model: `python_only`. Test set: 9-PCAP sandbox holdout (N_baseline_flows=349). Each cell is the recall on the perturbed re-extraction. Δ pp = absolute change vs baseline recall 60.46 %.

Caveats:
- IAT-jitter changes packet timing, which changes how the cicflowmeter   session-izer aggregates packets into flows. Aggressive jitter   often produces *fewer* flows than baseline because flow timeouts   fire differently. We report recall on the resulting flows; if a   flow's identity changes, the model still has to classify it.
- Recall here is `predicted_attack / total_flows_after_perturb`   (not against ground truth — sandbox PCAPs are 100 % Bot, so   any non-attack prediction is a miss).
- N_flows column shows whether perturbation collapsed or expanded   the flow count. A drop from baseline_flows → 50 % means half   the flows merged together — feature distributions shift even   before classification runs.

## Recall matrix

| Perturbation | none | mild | moderate | aggressive |
|---|---:|---:|---:|---:|
| **iat_jitter** | 60.5 %  (Δ+0.0 pp, n=349) | 60.3 %  (Δ-0.2 pp, n=350) | 60.2 %  (Δ-0.3 pp, n=349) | 57.3 %  (Δ-3.2 pp, n=349) |
| **packet_padding** | 60.5 %  (Δ+0.0 pp, n=349) | 67.6 %  (Δ+7.2 pp, n=349) | 83.1 %  (Δ+22.6 pp, n=349) | 92.6 %  (Δ+32.1 pp, n=349) |
| **ttl_random** | 60.5 %  (Δ+0.0 pp, n=349) | 60.5 %  (Δ+0.0 pp, n=349) | 60.5 %  (Δ+0.0 pp, n=349) | 60.5 %  (Δ+0.0 pp, n=349) |
| **rst_inject** | 60.5 %  (Δ+0.0 pp, n=349) | 60.5 %  (Δ+0.0 pp, n=349) | 60.5 %  (Δ+0.0 pp, n=349) | 60.5 %  (Δ+0.0 pp, n=349) |

## Flow-count matrix (how perturbation changed aggregation)

| Perturbation | none | mild | moderate | aggressive |
|---|---:|---:|---:|---:|
| **iat_jitter** | 349 (100 %) | 350 (100 %) | 349 (100 %) | 349 (100 %) |
| **packet_padding** | 349 (100 %) | 349 (100 %) | 349 (100 %) | 349 (100 %) |
| **ttl_random** | 349 (100 %) | 349 (100 %) | 349 (100 %) | 349 (100 %) |
| **rst_inject** | 349 (100 %) | 349 (100 %) | 349 (100 %) | 349 (100 %) |

## Reading

- Baseline (no perturbation): recall = 60.46 %, n_flows = 349.
- Cells with negative Δ pp = recall degradation (worse).
- Cells with substantially fewer flows than baseline = the   perturbation changed cicflowmeter's flow boundaries; the   resulting flows have different feature values, which is *part*   of the adversarial impact, not separate from it.
- This is a *floor* measurement. A motivated adversary doing   pattern-aware mimicry would shift recall lower; this is what   random-noise evasion costs by itself.