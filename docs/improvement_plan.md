# 12-Day Improvement Plan — Defense-in-Depth IDS

**Goal:** Push the network IDS from "F1=0.998 in-distribution / F1=0.0 real-world" to a defensible architecture with measurable gains across all three benchmarks.

**Timeline:** 12 working days, 2026-04-23 → 2026-05-04.
**Application deadline:** 2026-05-15 (leaves 11 days for presentation, application form, polish).

## Selected techniques

| # | Technique | Expected primary effect |
|---|-----------|-------------------------|
| #1 | Synthetic attack generator (real tools in WSL) | Broaden training distribution; boost real-world recall |
| #3 | FFT / spectral features | Capture botnet beacons + periodic patterns (network-invariant) |
| #4 | File↔Network synergy via YARA on extracted payloads | Deterministic high-confidence labels for flows with file transfers |
| #2 | Selective prediction (Mahalanobis + confidence) | Honest "I don't know" → high F1 on covered subset |
| #6 | Reframe metric → workload reduction | Presentation pivot; turns specificity into business win |

## Realistic targets after the plan

| Benchmark | Current | Target |
|-----------|--------:|-------:|
| CIC-IDS2017 test split (weighted F1) | 0.998 | 0.998 |
| CIC-IDS2018 cross-dataset (weighted F1) | 0.60 | **0.90–0.95** |
| Real-world Stratosphere (zero-shot, weighted F1) | 0.00 | **0.55–0.75** |
| Real-world Stratosphere (selective, on high-confidence subset) | — | **0.92–0.97** at 50–70 % coverage |
| File↔Network flows (where YARA hits a payload) | — | **F1 ≥ 0.95** (deterministic) |
| Workload reduction (% benign auto-dismissed at FP ≤ 0.1 %) | — | **80–90 %** |

These are ambitious but each is grounded in a specific mechanism, not wishful thinking. **None of them is "we will catch 347/347 attacks"** — that target was rejected as theoretically impossible on out-of-distribution data.

## Day-by-day breakdown

### Day 1 (2026-04-23) — Environment + data acquisition

**Deliverables:**
- WSL2 Ubuntu started; `apt install -y nmap hydra hping3 slowloris tcpdump python3-scapy` verified working
- Download remaining CIC-IDS2018 days (Wednesday-21, Friday-23, Wednesday-28, Friday-02-03) — ~1.4 GB total
- Download CTU-Malware-Capture-Botnet-42 (Neris): `botnet-capture-20110810-neris.pcap` (58 MB) + `Neris.exe.zip` for YARA scan
- Download 2 more CTU-Malware-Capture sets (different malware families) — ~150 MB total
- Verify: WSL can run `nmap -sS 127.0.0.1 -p 1-100` and produce a PCAP via `tcpdump -w out.pcap`

**Risks:** WSL networking might need bridging for tcpdump to capture from `nmap` running outside WSL. Mitigation: run both attacker and victim inside WSL with `lo` interface.

### Day 2–4 (2026-04-24 to 26) — Synthetic attack generator (#1)

**Deliverables:**
- `scripts/generate_synthetic_attacks.py` — orchestrates attack tools and captures PCAPs
- Generated attack PCAPs in `data/synthetic/`:
  - 5 PortScan variants (SYN, FIN, NULL, XMAS, slow) × 3 networks
  - 3 SSH/FTP brute-force variants × 3 intensities
  - 2 Slowloris variants
  - 1 hping3 SYN flood
  - 5 benign baselines (HTTP browsing, DNS, file transfer)
- Total: ~30–50 PCAPs, each 30 sec to 5 min
- Extract flows via `FlowExtractor`, label by attack type, save to `data/synthetic/synthetic_flows.csv`
- Sanity check: train XGBoost on synthetic-only, test on synthetic-only — F1 should be ≥0.95 (else generator is broken)

**Key technique:** vary network conditions per capture using `tc netem`:
- High latency (200ms ± 50ms jitter)
- Packet loss (1–5%)
- Low bandwidth (10 Mbit cap)
This forces the generator to produce diverse flow signatures, not lab-clean ones.

**Risks:**
- WSL bridging issues — mitigation: capture on `lo` instead of `eth0`
- Some attacks may produce too few flows to be useful — mitigation: extend duration

### Day 5 (2026-04-27) — FFT / spectral features (#3)

**Deliverables:**
- New module `threatlens/network/spectral_features.py`
- 8 new features per flow:
  - `spectral_peak_freq`, `spectral_peak_magnitude` (dominant frequency)
  - `spectral_entropy` (broadband vs narrow)
  - `spectral_centroid`, `spectral_bandwidth`
  - `low_freq_energy_ratio` (Slowloris signature)
  - `iat_periodicity_score` (autocorrelation of inter-arrival times — botnet beacon detector)
  - `iat_zero_crossing_rate`
- Integrate into `FlowExtractor.extract()` — feed all 78 features (70 CIC + 8 spectral) downstream
- Unit tests: synthetic periodic signal → high `iat_periodicity_score`; random signal → low

**Risks:** flows with very few packets (<10) cannot produce stable spectra. Mitigation: zero-fill spectral features when packet count is too low; let model learn this is "uninformative".

### Day 6–7 (2026-04-28 to 29) — File↔Network synergy (#4)

**Deliverables:**
- `threatlens/network/payload_extractor.py` — pulls files out of HTTP/FTP/SMB flows in a PCAP using scapy stream reassembly
- `threatlens/network/yara_flow_labeler.py` — runs the existing YARA rules over extracted payloads
- For each PCAP: outputs a list of `(flow_5tuple, file_sha256, yara_matches, ml_prediction)`
- If YARA hits → flow label is forced to ATTACK with confidence 1.0 in the final ensemble
- Validation on CTU-Botnet-42:
  - Confirm YARA detects `Neris.exe` as malicious
  - Confirm reassembly recovers the binary from the PCAP (or notes if traffic is encrypted)
  - Report: how many flows in CTU PCAP got a YARA hit?

**Honest expectation:** if PCAP is encrypted (modern HTTPS), payload extraction yields nothing usable. CTU-Botnet-42 (2011) uses unencrypted IRC C2 — should work. Encrypted modern traffic is out of scope for #4.

**Risks:** scapy reassembly is fragile on incomplete PCAPs (missing initial SYN). Mitigation: skip flows that fail reassembly, document coverage.

### Day 8 (2026-04-30) — Combined retraining

**Deliverables:**
- Build the combined training set:
  - CIC-IDS2017 (50K stratified — current baseline)
  - CIC-IDS2018 (sample 50K balanced across days/classes after column normalization)
  - Synthetic flows from Day 2–4 (~10–20K depending on generation)
  - YARA-bootstrapped labels from CTU-Botnet-42 (~5K)
- Retrain XGBoost on this combined set with 78 features (70 CIC + 8 spectral)
- Save as `results/cicids_combined/xgboost.joblib` (do **not** overwrite the original `results/cicids2017/`)
- Quick eval: 5-fold CV F1 weighted on combined training set

**Risks:** combined dataset may be class-imbalanced in weird ways (lots of synthetic SYN scans, few of some classes). Mitigation: stratified sampling + class weights.

### Day 9 (2026-05-01) — Selective prediction layer (#2)

**Deliverables:**
- Compute training-set Mahalanobis distance distribution; pick threshold at 95th percentile
- New module `threatlens/network/selective.py` exposing:
  - `predict_with_abstention(flows_df, conf_threshold=0.85, mahalanobis_threshold=...)`
  - Returns: `label`, `is_high_confidence`, `confidence`, `mahalanobis_distance`
- Integrate into `FlowDetector.predict()` as an optional flag
- Eval: compute (F1 vs coverage) curve on each test set — show that at coverage ~60 %, F1 ≥ 0.92 even on Stratosphere

### Day 10 (2026-05-02) — Full re-evaluation across all three benchmarks

**Deliverables:**
- Rerun `scripts/eval_real_world.py` and `scripts/eval_cross_dataset.py` against the new combined model
- New script `scripts/eval_selective.py` — produces F1-vs-coverage curves
- Update `docs/real_world_eval.md` and `docs/cross_dataset_eval.md` with new numbers
- New `docs/file_network_synergy.md` with results from #4

### Day 11 (2026-05-03) — Reframe metrics + final report (#6)

**Deliverables:**
- New `docs/architecture.md` — describes the 5-layer Defense-in-Depth pipeline as one coherent design (synthetic data → 78 features → combined model → selective gate → File↔Network YARA short-circuit → workload metric)
- Workload reduction calculator: given a real PCAP, report
  - flows auto-dismissed (BENIGN, high confidence)
  - flows escalated to LLM/human review
  - flows force-labeled by YARA
- Single headline number for the application: *"X % of inbound traffic auto-classified at FP rate Y %"*
- Update top-level `README.md` with the new architecture and honest 3-point comparison table

### Day 12 (2026-05-04) — Buffer / integration / failure recovery

**Reserved for:**
- Bugs that surfaced in days 9–11
- Re-running anything that failed
- If everything succeeded ahead of schedule: add a 4th comparison point — eval on Stratosphere PCAP **after** the user labels 5 flows (mini active learning demo)

## Post-plan (days 13–23): non-technical work

- Days 13–17: presentation (10–12 slides + 5-min video demo)
- Days 18–20: rewrite landing page on threatlens.tech with the new architecture
- Days 21–22: fill the application form, attach materials
- Day 23 (2026-05-15): **final submission**

## Hard rules during execution

1. **No fabricated numbers.** Every metric in the final docs must come from a script that can be re-run.
2. **No silent failures.** If a step underperforms, document it in the report (this is the "honest IDS research" angle the judges may value).
3. **Each day ends with a commit.** Easier to backtrack if a step breaks the next.
4. **Original CIC-IDS2017 model artefacts stay untouched.** New model goes to `results/cicids_combined/`.
5. **TodoWrite tracks the current day's tasks.** This file is the master plan.

## Success criteria (binary go/no-go)

The plan is a success if **at least 4 of these 5** are true at end of Day 11:

- [ ] CIC-IDS2018 weighted F1 ≥ 0.85 on the combined model
- [ ] Real-world Stratosphere binary attack F1 ≥ 0.30 zero-shot (vs current 0.0)
- [ ] Selective predictor achieves F1 ≥ 0.90 at coverage ≥ 50 % on Stratosphere
- [ ] File↔Network module recovers ≥ 1 file from CTU-Botnet-42 and YARA flags it
- [ ] All metrics reproducible by running the documented `python scripts/...` commands

If only 2–3 succeed: still a defensible application, with honest reporting of what worked and what didn't.
If 0–1 succeed: pivot to file-only application (Plan B from the previous discussion).
