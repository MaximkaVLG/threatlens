# External baseline — Suricata + Zeek on the same 9-PCAP sandbox holdout

**Phase 2 of the Award-2026 prep.** We took the same 9 PCAPs that the
v2 model scored 96.85 % recall on (the held-out 9 of 25 fresh
2024-2025 sandbox captures) and ran two industry-standard tools over
them: **Suricata 8.0.4 + Emerging Threats Open ruleset** and **Zeek**.
This gives reviewers a reference point for "how hard is this dataset
without ML?".

Reproduce: `python scripts/external_benchmark.py --tools suricata,zeek`.
Output JSON: [`results/external_benchmark/external_benchmark.json`](../results/external_benchmark/external_benchmark.json).

## Setup

- **Suricata** 8.0.4, official `jasonish/suricata` Docker image.
- **Ruleset:** Emerging Threats Open (free public ruleset),
  pulled fresh via `suricata-update`. **65 923 rules / 50 027 enabled.**
  This is the ruleset most defenders deploy when they don't pay for
  ET Pro / PROOFPOINT — i.e. the realistic free-tier baseline.
- **Zeek** (official `zeek/zeek` Docker image), default scripts only,
  `LogAscii::use_json=T` for machine-readable output. Zeek has **no
  signature engine** in its default policy — `notice.log` only carries
  what default policy scripts emit, and `weird.log` is protocol-anomaly
  flags. Read Zeek's column as "what would I get if I bolted a NIDS on
  later but ran Zeek today as a flow logger."
- **Holdout:** the same 9 PCAPs documented in
  [`results/python_only/sandbox_split.json`](../results/python_only/sandbox_split.json),
  used by both `results/v2/` and `results/python_only/` evaluations.

Per-tool Docker invocation lives in `scripts/external_benchmark.py`.
We pin the rule snapshot and pcap set so the comparison is reproducible
day-to-day.

## Headline

| Tool | Per-PCAP detection | Per-flow recall (any alert) | Notes |
|---|---:|---:|---|
| **v2 ML (this project)** | **9 / 9 (100 %)** | **96.85 %** | per-flow recall is the honest metric; per-PCAP is a derived ceiling |
| Suricata + ET Open | 8 / 9 (88.89 %) | ≈ 3.09 % | misses Rhadamanthys; per-flow proxy is grossly low because Suricata isn't a per-flow classifier by design |
| Zeek (default policy) | 0 / 9 detections | 0 / 28 974 flows | no malware signatures; conn.log captured 18 573 flows fine, but notice.log emitted **0** alerts and weird.log only **16** anomaly events across all 9 PCAPs |

Numbers from `results/external_benchmark/external_benchmark.json`,
section `summary.per_tool`.

## Per-PCAP breakdown (Suricata)

| PCAP | Family | n alerts | n flows w/ alert | Top signature(s) |
|---|---|---:|---:|---|
| 2025-08-15 Lumma + SecTopRAT | lumma | 78 | 44 / 149 | `ET MALWARE Arechclient2 Backdoor/SecTopRAT Related Activity M2 (GET)` ×34, `ET MALWARE Win32/Lumma Stealer Related Domain (vishneviyjazz .ru)` ×9 |
| 2025-12-29 ClickFix → NetSupport RAT | netsupport | 520 | 9 / 432 | `ET REMOTE_ACCESS NetSupport Remote Admin Checkin` ×86, `ET INFO HTTP traffic on port 443 (POST)` ×86 |
| CTU-Malware-Capture-Botnet-83-1 | bot | 334 | 155 / 10 724 | `SURICATA ICMPv4 invalid checksum` ×155, `ET INFO Possible External IP Lookup whoer.net` ×77 |
| CTU-Mixed-Capture-6 | bot | 665 | 651 / 17 348 | `SURICATA QUIC error on data` ×622, `SURICATA STREAM suspected RST injection` ×3 |
| 2025-10-08 Kongtuke ClickFix | clickfix | 53 | 28 / 194 | `ET INFO Windows Powershell User-Agent Usage` ×6, `ET INFO TLS possible TOR SSL traffic` ×4 |
| 2025-09-24 Setup.exe traffic | lumma | 5 | 1 / 11 | `ET INFO PE EXE or DLL Windows file download HTTP`, `ET HUNTING SUSPICIOUS Dotted Quad Host MZ Response` |
| 2025-05-22 StealCv2 | stealc | 17 | 3 / 15 | `SURICATA HTTP unable to match response to request` ×15, `ET INFO Observed URL Shortening Service Domain` |
| 2025-09-03 ClickFix → Lumma | lumma | 4 | 4 / 97 | `SURICATA HTTP Response excessive header repetition` ×3 (no Lumma-specific signature fired) |
| **2025-10-01 Rhadamanthys** | **rhadamanthys** | **0** | **0 / 4** | **— no signature matched. Suricata sees the 4 flows but emits zero alerts.** |

The Rhadamanthys miss is the single instructive failure: traffic is
fully encrypted TLS to a fresh C2 IP, no SNI hits any ET Open
indicator, and the post-infection beacon is short (4 flows total).
Signature-based IDS has no leverage on this. The v2 ML model **does**
flag this PCAP because the abstainer + flow-statistics features pick
up the behavioural pattern that the SNI string doesn't carry.

## Per-PCAP breakdown (Zeek)

| PCAP | conn.log | notice.log | weird.log |
|---|---:|---:|---:|
| 2025-10-08 Kongtuke ClickFix | 213 | 0 | 1 |
| 2025-08-15 Lumma + SecTopRAT | 150 | 0 | 0 |
| 2025-09-03 ClickFix → Lumma | 119 | 0 | 0 |
| 2025-09-24 Setup.exe | 11 | 0 | 0 |
| 2025-12-29 NetSupport RAT | 388 | 0 | 14 |
| 2025-10-01 Rhadamanthys | 4 | 0 | 0 |
| 2025-05-22 StealCv2 | 15 | 0 | 0 |
| CTU-Botnet-83-1 | — | — | — (truncated dump file — Zeek's pcap reader rejects mid-packet truncation that Suricata silently ignores) |
| CTU-Mixed-Capture-6 | 17 673 | 0 | 1 |

Zeek is **not failing**: it's working as documented. The default policy
ships flow logging + protocol parsing, not threat signatures. To turn
Zeek into a detector you'd typically add ZAT / Corelight / SOC Prime
content packs — not in scope for this baseline. We include Zeek to
show that "deploy a NIDS sensor" without a content pack is **0
malware detections** on this set.

## Honest reading of the comparison

1. **Per-PCAP detection is a lenient metric for Suricata.** It only
   asks "did at least one alert fire on this PCAP?" If we instead asked
   "did Suricata correctly label this as malicious?", the answer is
   harder — many of the alerts that fired are `ET INFO …` (informational,
   not a verdict), `SURICATA HTTP …` (protocol anomalies, not malware),
   or generic `ET HUNTING …` rules. A SOC that sees an `ET INFO
   Windows Powershell User-Agent Usage` does not, in 2025, treat that
   as a malware confirmation. Filter to alerts whose category is
   actually malware (`ET MALWARE`, `ET TROJAN`, `ET REMOTE_ACCESS`)
   and the per-PCAP recall drops further: only **2 of 9 PCAPs**
   (Lumma + SecTopRAT, NetSupport RAT) had a malware-class signature
   fire. That is the recall a SOC operator really sees.

2. **Per-flow recall is the apples-to-apples metric.** Suricata's
   per-flow proxy (3.09 %) is grossly low because Suricata isn't built
   to label every flow — it fires alerts where rules match, the rest
   stay silent. The v2 ML model produces a verdict for **every** flow
   (or routes to abstainer), so recall directly measures how many
   attack flows were caught. The gap on the same 9 PCAPs is **96.85 %
   vs ≈ 3 %**, two orders of magnitude. That is the structural
   advantage of behavioural ML over signature IDS on fresh,
   short-tailed malware: nobody has written a signature for it yet.

3. **Suricata + ET Open complements ML, doesn't compete with it.** The
   86 NetSupport-specific signatures and 34 Lumma C2 signatures fired
   give the SOC a *what is this* answer that ML's class probabilities
   can't. The right deployment is "Suricata + ML in parallel, alert
   union" — Suricata for known-family attribution, ML for unknown
   behavioural detection. We don't claim ML replaces signature IDS;
   we claim ML covers the gap signature IDS structurally has on
   yesterday's malware.

4. **Per-flow recall ≠ true positive rate.** Suricata's `flow_id` is
   assigned per 5-tuple session by the eve.json `flow` event type, and
   `n_flows_with_alert` counts unique `flow_id`s that have at least
   one alert event. Many alerts (e.g. `SURICATA HTTP request field
   missing colon`) are *protocol* anomalies, not malware verdicts —
   they inflate the per-flow recall in defender-friendly direction.
   The 3.09 % is already an *over-estimate* of Suricata's true malware
   per-flow recall on this set.

## What this does NOT prove

- **We didn't test paid rulesets.** ET Pro Telemetry, PROOFPOINT,
  CrowdStrike CrowdSig — all of these add coverage Suricata + ET Open
  doesn't have. A defender paying for ET Pro would likely catch
  Rhadamanthys via a fresh telemetry-fed rule that we couldn't pull.
  This is the *free-tier* baseline.
- **We didn't test ML-augmented signature engines.** Tools like
  Stamus / Selks bolt anomaly scoring on top of Suricata. They might
  close some of the gap. Out of scope here.
- **We didn't test endpoint detection.** EDR (CrowdStrike Falcon,
  SentinelOne, MS Defender for Endpoint) sees process tree, not just
  network — it would catch Rhadamanthys at the *load* stage, not at
  beacon stage. Different detection layer, different win condition.

## Reproduce

Pre-requisites: Docker Desktop running, ~3 GB disk for the
Suricata image.

```bash
# Pull images, fetch rules, run grid
python scripts/external_benchmark.py --tools suricata,zeek

# Skip rule update if you already have a snapshot:
python scripts/external_benchmark.py --tools suricata,zeek --skip-rule-update

# Single-tool run:
python scripts/external_benchmark.py --tools suricata
```

Wall-time: ~3 minutes total (Suricata is the slow part — ~20-26 s per
PCAP including container startup; Zeek is ~1-10 s per PCAP).

Output: `results/external_benchmark/external_benchmark.json`
(per-PCAP event counts + summary).
