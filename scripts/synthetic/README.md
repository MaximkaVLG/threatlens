# Synthetic attack lab

Isolated docker-compose environment used to generate labeled attack PCAPs
for the cross-dataset training pipeline (Day 2–4 of the improvement plan).

## Why this exists

Public IDS datasets (CIC-IDS2017/2018, CTU-Malware) are fixed in time and
topology. Models trained only on them do not generalise (see
[`docs/cross_dataset_eval.md`](../../docs/cross_dataset_eval.md)). The lab
lets us synthesise arbitrarily many attack variants from real tools under
varying network conditions, which broadens the training distribution.

## Components

- **`Dockerfile.attacker`** — Ubuntu 24.04 + `nmap`, `hping3`, `hydra`,
  `tcpdump`, `slowloris`, plus a `netem` helper for introducing
  latency/loss/bandwidth caps before capture.
- **`Dockerfile.victim`** — Ubuntu 24.04 running `sshd`, `vsftpd`,
  `nginx` with a deliberately weak credential (`testuser:password123`) so
  hydra brute-force runs have something to land on. Never exposed outside
  the private bridge.
- **`docker-compose.yml`** — brings both up on a private `172.28.0.0/16`
  bridge. Attacker gets `.20`, victim gets `.10`. Captured PCAPs are
  written to `../../data/synthetic/` on the host via bind mount.
- **`netem.sh`** — thin wrapper around `tc qdisc netem` to apply
  high-latency / lossy / low-bandwidth profiles to the attacker's egress.
- **`attacks/`** — per-attack bash scripts (added on Day 2–3 of the
  improvement plan). Each script starts tcpdump, runs the tool, stops
  tcpdump and writes a PCAP with a consistent name.

## Quick start

```bash
cd scripts/synthetic
docker compose up -d --build
# wait for services (sshd takes a couple of seconds)
docker exec lab-attacker ping -c 1 172.28.0.10

# run a sample attack
docker exec lab-attacker bash /work/attacks/portscan_syn.sh

# tear down
docker compose down
```

Captured PCAPs end up in `data/synthetic/` with filenames like
`portscan_syn_highlat_20260424_131900.pcap`.

## Safety notes

- Every container is on a **private** bridge. Neither `lab-victim` nor
  `lab-attacker` publishes ports to the host. Real traffic never leaves
  Docker's internal network.
- The victim runs with **throwaway, hard-coded weak credentials** that
  exist only inside the container. They are not valid anywhere else.
- YARA / heuristic samples from `data/ctu_malware/` are **network
  captures and zipped binaries** — binaries are never executed. The lab
  here only generates *fresh* traffic from our attacker container
  against our victim container. We do not replay real-world malware.
