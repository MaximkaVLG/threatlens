# Synthetic attack generation — Day 2-3 of improvement plan

**Run date:** 2026-04-22 to 2026-04-25 (Day 2 → Day 4)
**Goal:** Produce a labeled training set of attack + benign flows that
varies network conditions (latency, loss) so the model is forced to learn
patterns invariant to RTT / MTU / topology, not memorise CIC-IDS2017
infrastructure constants.

## Why synthetic data

The cross-dataset eval ([`cross_dataset_eval.md`](cross_dataset_eval.md))
showed that even on CIC-IDS2018 (same CICFlowMeter family, same class
names) the model trained on CIC-IDS2017 collapses to F1=0.50. The
hypothesis: training distribution is too narrow. Augmenting with
controlled synthesis broadens it cheaply.

## Lab setup

See [`scripts/synthetic/README.md`](../scripts/synthetic/README.md). The
lab is two docker containers on a private 172.28.0.0/16 bridge:

- **lab-victim** (172.28.0.10) runs `sshd`, `vsftpd`, `nginx` with one
  weak credential `testuser:password123`. Never reachable from host.
- **lab-attacker** (172.28.0.20) runs `nmap`, `hping3`, `hydra`,
  `slowloris`, `tcpdump`, `python3-scapy`, plus a `netem` helper for
  applying latency / loss / bandwidth caps.

## Attack matrix

11 attacks × 3 netem profiles = up to 33 PCAPs.

| Attack | CIC label | Tool | Notes |
|--------|-----------|------|-------|
| portscan_syn | PortScan | `nmap -sS` | top 1000 ports |
| portscan_fin | PortScan | `nmap -sF` | top 1000 ports |
| portscan_null | PortScan | `nmap -sN` | top 1000 ports |
| portscan_xmas | PortScan | `nmap -sX` | top 1000 ports |
| portscan_slow | PortScan | `nmap -sS -T1` | top 100 ports, sneaky timing |
| dos_synflood | DoS Hulk | `hping3 --flood --syn` | 10 000 packets to port 80 |
| dos_slowloris | DoS slowloris | `slowloris -p 80 -s 100` | 100 sockets, ~25 s |
| bruteforce_ssh | SSH-Patator | `hydra ssh://` | 51-entry wordlist |
| bruteforce_ftp | FTP-Patator | `hydra ftp://` | 51-entry wordlist |
| benign_http | BENIGN | `curl http://` × 60 | sequential GETs |
| benign_ftp | BENIGN | `curl ftp://` × 30 | sequential GETs |

Netem profiles applied (one per capture, not stacked):
- **clean** — no impairment
- **high-latency** — 200 ms ± 50 ms jitter (normal distribution)
- **lossy** — 3 % packet loss + 50 ms ± 10 ms latency

## Generated dataset (Day 2 run, 2026-04-22)

| Metric | Value |
|--------|------:|
| PCAPs successfully generated | **33 / 33** |
| Total flows extracted (FlowExtractor) | **143 841** |
| Total PCAP disk size | ~38 MB |
| Wall-clock generation time | ~20 min |

Per-label flow counts (synthetic only):

| Label | Flows | Share |
|-------|------:|------:|
| DoS Hulk (synflood) | **130 066** | 90.4 % |
| PortScan (5 variants) | **13 106** | 9.1 % |
| DoS slowloris | 300 | 0.2 % |
| BENIGN (HTTP + FTP) | 294 | 0.2 % |
| FTP-Patator (hydra) | 48 | 0.03 % |
| SSH-Patator (hydra) | 27 | 0.02 % |

**Class imbalance is severe.** Two issues:

1. **`hping3 --flood --syn` randomises source ports**, so every SYN packet
   becomes its own "flow" under bidirectional 5-tuple keying. 10 000
   crafted SYNs from one capture × 3 captures × ~40 % retained ≈ 130 K
   flows. This will swamp combined training unless we subsample.
2. **Hydra reuses TCP connections aggressively** for performance, so
   brute-force runs collapse 50+ login attempts into a handful of
   flows. SSH-Patator: 27 flows total, FTP-Patator: 48. These
   under-counts make brute-force a near-zero training signal in
   isolation; CIC-IDS2017's 50 K SSH-Patator + 200 K FTP-Patator flows
   will still dominate that class in the combined set.

Both issues are addressable in Day 8 (combined retraining) via
stratified subsampling and class weights.

## Sanity check (synthetic-only XGBoost CV)

Threshold from improvement plan: F1 weighted ≥ 0.95 means the generator
produces attacks that are statistically distinguishable.

| Metric | Value |
|--------|------:|
| 5-fold CV F1 weighted (mean ± std) | **1.0000 ± 0.0000** |
| Verdict | **PASS** |

A *perfect* F1 needs honest interpretation: synthetic flows are
**trivially separable** because each attack type has distinctive
flag/timing signatures and our generator does not introduce inter-class
ambiguity. This is good — it means the synthetic data is usable as
training signal — but it also means F1 on synthetic-only is **not** a
credible upper bound on real-world performance. The real test is Day 10
re-eval on Stratosphere PCAPs and CIC-IDS2018 hold-out days.

## Reproducibility

```bash
# Start lab
cd scripts/synthetic && docker compose up -d --build

# Generate full matrix
docker exec lab-attacker python3 /work/generate.py all \
    --netem-profiles clean,high-latency,lossy

# Extract flows on host
python scripts/synthetic/extract_flows.py
# -> data/synthetic/synthetic_flows.csv

# Sanity check
python scripts/synthetic/sanity_check.py
# -> results/synthetic_sanity.json

# Tear down
docker compose down
```

## Limitations (do not paper over)

1. **Flow signatures are still lab-clean.** Even with netem, all attacks
   originate from one src IP to one dst IP. Real botnets have many src
   IPs; real port scans hit many dst IPs. Graph-aware features (Day 5
   plan) partially compensate.
2. **Slowloris and brute-force success quickly.** Hydra with the actual
   password in the wordlist stops on first success, reducing attack
   duration. We use `-f -I` to make it fail-fast on success — produces
   shorter flows than CIC-IDS2017 SSH-Patator (which ran for hours).
3. **Benign baselines are sparse.** Only HTTP and FTP. No DNS, no IRC,
   no SMTP. The "BENIGN" model class will be biased toward web traffic.
4. **No application-layer payload diversity.** Curl always sends the
   same User-Agent; nginx serves the same default page. Statistical
   features capture this; sequence features (planned: Day 5) would too.
