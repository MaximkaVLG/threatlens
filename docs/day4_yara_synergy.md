# Day 4 — File ↔ Network synergy via YARA-on-payload

**Run date:** 2026-04-22
**Goal:** Give the network classifier visibility into *what* a flow
carries, not just *how* it looks. The 70 CIC features describe byte
counts, timing, and flag distributions — they cannot see whether the
flow transports an EICAR-tagged file, a webshell upload, or a Cobalt
Strike beacon. YARA already does that on the file-analyzer side; this
day wires it up to the network side.

## Why this matters for the award

The "Defense-in-Depth" architecture pitched for the spec prize argues
that ThreatLens uniquely combines a file analyzer with a network IDS.
Until today that was a UX claim — they shared a dashboard but not a
single feature space. After Day 4 a flow's row in the model's input
matrix literally contains evidence from the file-side ruleset.

## Design

The CIC flow extractor (`cicflowmeter` library) discards raw payloads
during aggregation — it tracks `payload_length` per packet but throws
away the bytes. Reconstructing them in-place would require rewriting
the cicflowmeter pipeline. Instead we do a **second pass over the
PCAP** with scapy:

1. `extract_payloads_per_flow(pcap_path)` — read every TCP/UDP packet,
   group raw L7 bytes by canonical bidirectional 5-tuple.
2. `scan_payloads(payload_map)` — for each flow with ≥ 64 B payload,
   run the existing custom YARA ruleset (community ruleset is opt-in
   via `use_community=True` because it's 5× slower).
3. Merge the result back into the flow DataFrame by canonical 5-tuple.

Three new feature columns:

| Column | Type | Range | Semantics |
|---|---|---:|---|
| `YARA Match Count` | float | 0..N | Distinct rules that fired |
| `YARA Max Severity` | float | 0/25/50/75/100 | none/low/medium/high/critical |
| `YARA Has Match` | float | {0, 1} | Cheap binary split feature for trees |

**Why include both `Match Count` and `Has Match`?** Tree models split
better on the binary indicator (low base rate, sharp boundary), but
the integer count carries useful magnitude when several rules concur.
Severity adds an ordinal axis so `Has Match=1, Severity=100` outranks
`Has Match=1, Severity=25`.

### Bidirectional canonical key

Scapy and cicflowmeter both observe the same packets but may disagree
on which endpoint is "src" — cicflowmeter assigns it to whoever
*started* the flow, while scapy reads packet-arrival order. We
canonicalise both views to the same 5-tuple by ordering endpoints
lexicographically (`(ip, port)` pair, lower-first). The
`test_flow_extractor_merges_yara_features_to_correct_row` test
verifies this on a hand-crafted PCAP with two flows and one
artificially-flagged hit.

### Performance guards

- `_MIN_PAYLOAD_BYTES = 64` — skip flows too short for credible
  signature matching (TCP keepalives, ACKs).
- `_MAX_PAYLOAD_BYTES = 1 MiB` — cap accumulated payload per flow.
  YARA rules target headers/early bytes anyway; multi-MB downloads
  don't add discriminative signal.
- `_YARA_TIMEOUT_S = 5` — per-flow scan timeout (default `signatures.scan`
  is 30 s, far too long for thousands of flows).
- Custom rules first (~5 rules); community (566 rules) only if custom
  found nothing AND caller opts in.

## Validation

### Unit + integration tests (12 / 14 pass, 2 yara-skipped)

| Test | What it verifies |
|---|---|
| `test_canonical_key_is_bidirectional` | Forward/reverse packets collapse to same key |
| `test_canonical_key_distinguishes_protocols` | TCP/80 ≠ UDP/80 |
| `test_extract_payloads_empty_pcap_returns_empty_dict` | SYN-only PCAP → no payloads |
| `test_extract_payloads_single_flow` | Both directions concatenated under one key |
| `test_extract_payloads_two_flows_distinct_endpoints` | Separate flows stay separate |
| `test_extract_payloads_skips_packets_without_raw_layer` | Control packets ignored |
| `test_extract_payloads_truncates_at_max_size` | Hard cap honoured exactly |
| `test_compute_yara_features_handles_missing_pcap_gracefully` | Bad path → `{}` |
| `test_scan_payloads_returns_empty_when_yara_unavailable` | `HAS_YARA=False` safe |
| **`test_flow_extractor_merges_yara_features_to_correct_row`** | **The critical one — fake YARA hit lands on Flow A, not Flow B; tests the cicflowmeter↔scapy 5-tuple alignment** |
| `test_flow_extractor_yara_columns_default_zero_when_no_matches` | All-zero default applied |
| `test_scan_payloads_eicar_triggers_match` (skipped — needs yara-python) | EICAR string fires custom rule |
| `test_scan_payloads_benign_text_no_match` (skipped — needs yara-python) | Benign payload → 0 matches |

The two `skipif(not HAS_YARA)` tests run on the production server
(yara-python is in `requirements.txt`); they are skipped on the dev
Windows box because yara-python has no Python 3.14 wheel and building
from source needs MSVC + libyara.

### Synthetic dataset (143,841 flows, re-extracted with 89 columns)

| Class | Flows | YARA Has Match (count) |
|---|---:|---:|
| BENIGN | 294 | 0 |
| DoS Hulk | 130,066 | 0 |
| DoS slowloris | 300 | 0 |
| FTP-Patator | 48 | 0 |
| PortScan | 13,106 | 0 |
| SSH-Patator | 27 | 0 |

**All zero is the expected result on this dataset** — by design, none
of the 11 attacks in the synthetic matrix carry an actual file:
`hping3 --flood --syn` sends empty SYNs, `nmap` sends single
flag-probes, `hydra` sends short plaintext credentials, `slowloris`
sends partial HTTP headers, curl downloads the default nginx page.
The feature is *dormant* on synthetic data and will *light up* on
real-world PCAPs that include file transfers (Stratosphere malware
traffic, CTU-13 botnet C2 with payload exfil). Day 10 re-eval is
where this signal actually pays off.

A follow-up worth doing in Day 5 buffer time: add a
`malware_http_download` scenario to the synthetic generator — serve
the EICAR test file from the lab victim, curl it from the attacker,
verify YARA Has Match = 1 on the resulting flow.

### Local validation limits (honest)

- yara-python doesn't install on Python 3.14 (no wheel; source build
  requires MSVC + libyara).
- The local re-extraction therefore exercises the *plumbing* (PCAP →
  scapy → 5-tuple merge → DataFrame) but not the *matching*. The
  matching code is exercised by mocked-yara integration tests (the
  critical "5-tuple alignment" risk) and will run for real on the
  production timeweb box and in Day 10 re-eval.
- Risk that survives: a yara-python API regression in the
  `compiled_rules.match(data=bytes, timeout=...)` call. Mitigation —
  this is the documented public API of yara-python ≥ 3.x and is what
  the project's existing `signatures.scan()` already relies on
  internally (via `rules.match(file_path, ...)`).

## Files added / changed

- **NEW** `threatlens/network/payload_yara.py` — payload extraction +
  per-flow YARA scanning + canonical 5-tuple key.
- **MODIFIED** `threatlens/network/flow_extractor.py` —
  `CicFlowExtractor.extract()` now does a YARA pass and merges 3 new
  columns into the row dict before DataFrame assembly. Backward-
  compatible: existing CIC-trained model ignores the new columns;
  combined model (Day 8) will consume them.
- **NEW** `tests/test_payload_yara.py` — 14 tests, 12 pass + 2
  yara-skipped on dev.

## Total feature count progression

| Stage | Count | What it captures |
|---|---:|---|
| CIC-IDS2017 baseline | 70 | Byte/packet/timing statistics |
| + Spectral (Day 3) | 78 | + Frequency-domain temporal structure |
| + YARA-on-payload (Day 4) | **81** | + File-side signature evidence per flow |

(89 columns total in the CSV = 81 features + 8 metadata: src_ip,
dst_ip, src_port, protocol, timestamp, Label, source_pcap, netem_profile.)
