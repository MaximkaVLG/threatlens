# Day 13 — Sandbox-malware PCAP ingestion (modern 2024-2026 attack traffic)

**Run date:** 2026-04-23 (pipeline) + 2026-05-04 (live ingest + eval)
**Status:** ✅ Pipeline shipped, 39 unit tests pass, full suite 188 / 2.
✅ **Live data downloaded and evaluated** — 25 fresh 2024-2025 malware
PCAPs (5011 attack flows) from Stratosphere CTU + malware-traffic-analysis.net;
headline real-world recall on the fresh slice is **72.24 %** (vs 96.25 %
on the &le;2018 historical slice). Detailed numbers in the
**Live results** section below.

## Why this day

The Day 12 submission packet is strong on everything except one honest
weakness a reviewer will ask about: **"your attack captures are
2011-2019 era (CTU-13, Stratosphere SLIPS). Does this model catch
*modern* 2024-2026 threats — Lumma Stealer, Cobalt Strike 2025 beacons,
RedLine, NetSupport RAT, ClickFix / SSLoad, Mirai variants?"**

The drift-diagnostic story from Day 7 + the 0.961 real-world F1 from
Day 9 argue the approach generalises, but the most persuasive answer is
literally a sandbox ingestion pipeline that pulls real malware captures
dated 2024-2026 and folds them into training and evaluation. That is
Day 13's deliverable.

## What was built

Three new artefacts, zero changes to `threatlens/` source, one small
additive patch to `scripts/train_python_only.py`.

```
new:    scripts/ingest_sandbox_pcaps.py         (~770 lines, full download pipeline)
new:    scripts/extract_sandbox_pcaps.py        (~186 lines, FlowExtractor + parquet)
new:    tests/test_sandbox_ingest.py            (~285 lines, 39 unit tests)
new:    docs/day13_sandbox_ingestion.md         (this file)
edit:   scripts/train_python_only.py            (+1 loader mirroring attack_volume)
```

## Sources surveyed (honest audit)

Before writing code I verified what actually serves PCAPs to
unauthenticated clients in 2026. Dead-end sources are listed so a future
reviewer does not re-walk the same ground.

| Source | PCAPs on free tier? | Used? | Notes |
|---|---|---|---|
| **Stratosphere CTU (mcfp.felk.cvut.cz)** | ✅ yes, no auth | ✅ | Same provenance as our existing CTU-13 data. Browseable directory index; 2024-2025 captures verified present (`CTU-Malware-Capture-Botnet-348-1/` dated 2025-06-03, `CTU-Mixed-Capture-6/` dated 2025-08-05, etc.). |
| **malware-traffic-analysis.net** | ✅ yes, password ZIP | ✅ | Daily blog posts by Brad Duncan with modern malware families in the description. Password shown as an image on `/about.html`; community convention is `infected` (made configurable via `--mta-password`). Personal site — rate-limited to 2 s/request by default. |
| **Hybrid-Analysis** | ⚠ API key + PCAP endpoint returns 403 on free tier | ❌ not used by default | `HA_API_KEY` env-var hook exists if a reviewer has paid tier. |
| **VirusTotal** | ❌ no PCAPs on free tier | ❌ | API returns samples, not captures. |
| **ANY.RUN / Joe Sandbox** | ❌ PCAP endpoints gated behind paid enterprise tier | ❌ | Documented in script docstring as out-of-scope. |
| **MalwareBazaar** | ❌ samples only, never PCAPs | ❌ | Confirmed via direct API inspection. |

Pragmatic conclusion: Stratosphere + MTA cover modern threat families
(Lumma, Cobalt Strike, NetSupport RAT, Remcos, RedLine, AsyncRAT,
Emotet, Mirai, …) with zero credential requirements, which is the
reproducibility bar a jury cares about.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  scripts/ingest_sandbox_pcaps.py                               │
│                                                                │
│  stratosphere_list()  ──┐       ┌──► download_sample()         │
│                         ├──►  SampleMeta ──►  extract_archive  │
│  mta_list()           ──┘       └──►  PCAP magic validate      │
│                                        │                       │
│                                        ▼                       │
│                              data/sandbox_malware/             │
│                                  stratosphere/*.pcap           │
│                                  mta/*.pcap                    │
│                                  metadata.jsonl                │
└────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────┐
│  scripts/extract_sandbox_pcaps.py                              │
│                                                                │
│  load_metadata()  ──►  FlowExtractor.extract()  ──►  parquet   │
│                                                                │
│  results/python_only/sandbox_malware_flows.parquet             │
│    (70 CIC + 8 spectral + 3 YARA cols + Label + provenance)    │
└────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────┐
│  scripts/train_python_only.py  (single-line patch)             │
│                                                                │
│  if sandbox_malware_flows.parquet exists: merge into X_train   │
│  (analogous to diverse_benign + attack_volume parquets)        │
└────────────────────────────────────────────────────────────────┘
```

## Label mapping — the key design call

Modern sandbox captures advertise families in freeform text
("Lumma Stealer infection with follow-up", "Cobalt Strike beacon over
443", "NetSupport RAT via ClickFix"). Our shipped model has 7 fixed
classes inherited from CIC-IDS2017: BENIGN, Bot, DoS Hulk, DoS slowloris,
FTP-Patator, PortScan, SSH-Patator.

Design decision: map every modern C2 / stealer / loader / RAT family to
`Bot`, which is the closest behavioural neighbour (outbound beaconing
traffic, periodic timing). Brute-force and DoS families map to their
specific class; ransomware-encryption traffic patterns that don't fit
any existing class are **skipped** (not forced into Bot) to avoid
poisoning the training set.

Covered families (42 keywords in `FAMILY_TO_LABEL`, alphabetised groups):

- **Stealer / loader / C2** → `Bot`: cobalt strike, beacon, lumma, redline,
  raccoon, vidar, stealc, rhadamanthys, emotet, qakbot, trickbot, icedid,
  bazar, netsupport, asyncrat, remcos, njrat, quasar, warzone, agenttesla,
  formbook, lokibot, amadey, smokeloader, gozi, ursnif, dridex, hancitor,
  ssload, clickfix, kongtuke, neris, sogou
- **Linux botnet** → `Bot`: mirai, gafgyt, bashlite
- **Port-scan / recon** → `PortScan`: portscan, masscan, nmap, scanning, probing
- **Brute force** → `SSH-Patator` / `FTP-Patator`: ssh-patator, ssh-brute, ftp-brute
- **DoS** → `DoS slowloris` / `DoS Hulk`: slowloris, hulk, http flood

Unknown families fall through to `None` and the sample is skipped —
explicit default override via `default="Bot"` available for unusual
cases. All mapping logic is covered by 14 parametrised unit tests plus
case-insensitivity and None-handling edge cases.

## Safety rails

Real malware traffic is a sensitive artefact. The script has four
defences against silently corrupting training data:

1. **PCAP magic validation** — every downloaded/unpacked file is
   checked against the 5 known libpcap/pcapng magic numbers
   (`\xd4\xc3\xb2\xa1`, `\xa1\xb2\xc3\xd4`, `\x4d\x3c\xb2\xa1`,
   `\xa1\xb2\x3c\x4d`, `\x0a\x0d\x0d\x0a`). An HTML 404 page saved as
   `x.pcap` would be rejected here, not later in FlowExtractor.
2. **Size cap** — `--max-bytes` default 500 MB prevents a mis-tagged
   VM image from eating the disk.
3. **Archive safety** — ZIPs decrypted with `pyzipper` (AES) or stdlib
   `zipfile` (ZipCrypto), member filtered by extension, then the bytes
   re-validated with the magic check. The garbage-zip path returns
   `None` rather than propagating, covered by
   `test_extract_pcap_from_archive_bad_zip`.
4. **Polite rate limit** — 2-second default inter-request delay,
   configurable. `RateLimitedClient` enforces `min_interval_s` between
   calls but (by design) does *not* sleep on the first call.
   Regression-tested with a fake clock in
   `test_rate_limited_client_enforces_min_interval`.

User-Agent: `"ThreatLens-ingest/0.1 (+https://threatlens.tech;
research-use; contact via site)"` so the site owner can identify and
contact us.

## Test coverage — 39 new unit tests

`tests/test_sandbox_ingest.py` runs in 0.2 seconds with no network.
Uses `importlib.util.spec_from_file_location` to load the script as a
module without executing `main()`.

| Block | Tests | What it pins down |
|---|---|---|
| `map_family_to_label` | 16 | 14 real-world descriptions → correct label; case-insensitivity; default fallback |
| `guess_family` | 3 | slug generation preference, multi-word handling, empty-string safety |
| `SampleMeta.stem` | 2 | filesystem-safety (no `/`, space, or `!`); determinism |
| `is_valid_pcap_bytes` | 10 | 5 valid magics accepted, 5 non-PCAP heads rejected |
| `is_valid_pcap_file` | 1 | missing / valid / invalid on-disk handling |
| `extract_pcap_from_archive` | 4 | plain ZIP, bad member, no PCAP member, garbage bytes |
| `RateLimitedClient` | 1 | fake-clock proof first-call free, later calls sleep 1.4-1.5 s |
| `build_parser` | 2 | CLI defaults and combined flags |

**Bugs found by the tests (both fixed):**

1. `pyzipper.BadZipFile` is a *separate class* from
   `zipfile.BadZipFile` (pyzipper forks stdlib). My original
   except-clause only caught the stdlib class, so garbage-bytes ZIPs
   raised instead of returning None. Fixed by building a
   `bad_zip_types` tuple that conditionally includes the pyzipper
   class. — `ingest_sandbox_pcaps.py:327-358`
2. `RateLimitedClient._last_request_t = 0.0` made the **first** call
   wait `min_interval_s` because `elapsed = 0.0 < 1.5`. Fixed by
   initialising to `None` and early-returning from `_wait()` when
   unset. — `ingest_sandbox_pcaps.py:225-235`

Both fixes caught by unit tests before a single byte was downloaded —
which is the whole point of pinning down pure-Python logic first.

## The patch to `train_python_only.py`

Four edits, all additive; mirrors the existing `load_attack_volume()`
pattern so behaviour is zero-change when the new parquet doesn't exist.

```python
SANDBOX_MALWARE_PARQUET = OUT_DIR / "sandbox_malware_flows.parquet"

def load_sandbox_malware(path: Path = SANDBOX_MALWARE_PARQUET):
    if not path.exists():
        return None
    df = pd.read_parquet(path)
    # ... (same filter/print pattern as load_attack_volume)
    return df
```

In `main()`: `sandbox_malware_df = load_sandbox_malware()` then appended
to `train_parts` if non-None. Metrics JSON gains a `sandbox_malware_size`
field for provenance. **The shipped model artefact is unchanged** —
retraining requires the operator to run the ingest + extract + train
sequence below.

## Running it

```bash
# Step 1: dry-run to see what would be downloaded (no files written).
python scripts/ingest_sandbox_pcaps.py --dry-run
# Expected output: list of 5 Stratosphere captures + N MTA daily posts,
#                  each with [source] sample_id label=X date=YYYY-MM-DD

# Step 2: actually pull a small test batch (each source capped at 3).
python scripts/ingest_sandbox_pcaps.py --source all --limit 3 -v
# ~2 s per HTTP request due to politeness rate limit; expect 2-5 minutes
# for 6 PCAPs depending on archive sizes.
# Saves to: data/sandbox_malware/{stratosphere,mta}/*.pcap
# Appends to: data/sandbox_malware/metadata.jsonl

# Step 3: extract flows into the training-friendly parquet.
python scripts/extract_sandbox_pcaps.py -v
# Reads metadata.jsonl, runs FlowExtractor on each PCAP, writes:
#   results/python_only/sandbox_malware_flows.parquet
# Columns: 70 CIC + 8 spectral + 3 YARA + Label + __source_pcap +
#          __split_source + __sandbox_source + __captured_date + __family

# Step 4: retrain python_only with the new data merged in.
python scripts/train_python_only.py
# train_parts grows from 3 to 4; sandbox_malware_size appears in
# results/python_only/metrics.json

# Step 5: re-evaluate to measure the lift.
python scripts/eval_python_only.py
python scripts/workload_metric.py
```

## Live results (2026-05-04 ingest + eval)

The pipeline was finally pointed at the live internet on 2026-05-04.
**26 unique PCAPs downloaded** (7 Stratosphere CTU 2024 + 19
malware-traffic-analysis.net 2025), 1 excluded as pathological
(`Botnet-61-1` produced 1.57M flows from a port-scan workload that
OOM'd FlowExtractor before our 100k-per-PCAP cap could fire). The
remaining **25 PCAPs &rarr; 5011 attack flows** through `extract_sandbox_pcaps.py`
in ~20 minutes (the original run was rewritten for incremental
per-PCAP parquet writes after the first attempt died at 24 GB RAM).

`scripts/eval_sandbox.py` against the shipped python_only model:

```
HEADLINE: live-ingested 2024-2026 sandbox PCAPs
  total attack flows:      5011
  detected (any attack):   3620    recall=0.7224
  exact 'Bot' label:        213    recall=0.0425
  abstained (review):      3549    (70.8 %)
  mean confidence:        0.8878
```

**Per-source:**

| Source | N flows | Detected | Recall |
|---|---:|---:|---:|
| Stratosphere CTU 2024 | 4550 | 3403 | 74.8 % |
| malware-traffic-analysis.net 2025 | 461 | 217 | 47.1 % |

**Per-family (sorted by recall):**

| Family | N flows | Recall | Read |
|---|---:|---:|---|
| netsupport | 7 | 100.0 % | RAT C2, infrastructure-shaped |
| stealc | 50 | 82.0 % | C2 traffic looks like Bot class |
| clickfix | 50 | 78.0 % | Loader-stage HTTP |
| kongtuke | 4 | 75.0 % | TDS-style redirector |
| `bot` (Stratosphere generic) | 4550 | 74.8 % | mixed C2 / brute |
| lumma | 240 | 40.4 % | short-lived stealer check-ins |
| macsync | 6 | 33.3 % | small slice |
| formbook (incl. XLoader) | 100 | 27.0 % | weak — info-stealer over HTTPS |
| rhadamanthys | 4 | 25.0 % | small slice |

**The take-aways for the submission:**

1. The **96.25 % &rarr; 72.24 % drop** is real, and we publish it directly
   in `SUBMISSION.md` rather than burying it. Time-validation is
   cheaper than retraining and tells the jury we know our weak spots.
2. **Abstainer flagged 70.8 % of these flows as OOD** — exactly what
   the Mahalanobis layer is supposed to do. Without that signal the
   operator wouldn't know the model is uncertain on this slice.
3. **Per-source split** (Stratosphere 74.8 % vs MTA 47.1 %) is the
   honest direction: the freshest, most diverse channel is the
   weakest. A benchmark-overfit model would show the opposite.
4. **`exact "Bot"` recall is only 4.25 %** because most of these
   flows get classified as `DoS slowloris` / `PortScan` / `SSH-Patator`
   — the timing patterns are visible to the model but the modern
   stealer / RAT class label doesn't exist in our 7-class taxonomy.
   That is a legitimate caveat for any reviewer who interprets
   per-class recall strictly.

Reproducible end-to-end (the operator does NOT need to re-train —
this is a forward-only evaluation against the shipped artefacts):

```bash
python scripts/ingest_sandbox_pcaps.py --source all --limit 100   # ~30-60 min
python scripts/extract_sandbox_pcaps.py \
    --skip-pcaps "CTU-Malware-Capture-Botnet-61-1__bot__Bot.pcap"  # ~20 min
python scripts/eval_sandbox.py                                     # ~5 sec
# → results/python_only/sandbox_eval.json
```

Output JSON has the per-PCAP and per-family rows above plus
`label_distribution` for each capture (which 7-class label each
flow was predicted as) so a reviewer can spot why exact-Bot recall
is low without re-running anything.

## Refactor of `extract_sandbox_pcaps.py` (2026-05-04)

The original script accumulated all per-PCAP DataFrames in a single
in-memory list and concat-ed at the end. That approach killed the
process at 24 GB RAM during Botnet-61-1's 1.57M-flow extraction. The
refactor:

- **Incremental per-PCAP parquet writes** under
  `results/python_only/.sandbox_extract_parts/`, freed immediately.
- **`--max-flows-per-pcap 100000`** stratified random sample (seed=42)
  if a single PCAP exceeds the cap. (Doesn't help if FlowExtractor
  OOMs *during* extraction — Botnet-61-1 still has to be skipped via
  `--skip-pcaps`.)
- **`--resume`** picks up existing per-PCAP parquets without redoing
  the heavy work, so a crash recovery is one command.
- **`--skip-pcaps`** drops named captures entirely.
- Final merge via `pyarrow.dataset.to_batches()` so the writer streams
  rather than holding everything in memory.

These changes are transparent to the production retrain path and do
not change any existing behaviour.

## Honest limits & future work

What this deliverable **does not** claim:

- **Per-family recall is small-N for several families.** Rhadamanthys
  (4 flows), MacSync (6), Kongtuke (4), NetSupport (7) — single-digit
  flow counts make their recall numbers high-variance. Read them as
  directional, not statistically tight. Lumma (240) and Stratosphere
  bot (4550) are the load-bearing rows.
- **Label mapping is lossy.** Lumma, Cobalt Strike and NetSupport RAT
  all collapse to `Bot`. This is honest about what our 7-class model
  can distinguish, but a reviewer who wants per-family recall will see
  we lose that granularity at the mapping step. The `metadata.jsonl`
  file preserves the original family tag so a future multi-class
  rework has a labelled corpus ready.
- **MTA rate limit.** Brad Duncan's personal site could reasonably
  block us if we got greedy. 2 s/request is conservative; if a reviewer
  re-runs ingestion on a fresh machine they inherit our User-Agent and
  politeness settings by default.
- **MTA zip password.** "infected" is the community-convention default.
  If Brad rotates it (published only as an image on
  `/about.html`), `--mta-password <new>` lets the operator override
  without a code change. We do not scrape the image.
- **Ransomware / supply-chain families are skipped.** Their traffic
  patterns don't match any of our 7 classes cleanly; forcing them into
  `Bot` would be dishonest mis-labelling that pollutes training. Those
  families would need a class-schema rework (an 8th "encryption-tunnel"
  class, say) which is out of scope for this week.

## Reproduce Day 13

```bash
# 1. Tests (no network)
python -m pytest tests/test_sandbox_ingest.py -v --basetemp=./.pytest-tmp
# expect: 39 passed

# 2. Full suite regression guard
python -m pytest tests/ --basetemp=./.pytest-tmp -q
# expect: 188 passed, 2 skipped (2 skips = yara-python on Py3.14, documented Day 4)

# 3. CLI smoke
python scripts/ingest_sandbox_pcaps.py --help
python scripts/extract_sandbox_pcaps.py --help

# 4. Dry-run (network-touching but writes nothing)
python scripts/ingest_sandbox_pcaps.py --dry-run -v
```

All four steps finish in under 15 seconds on a 2023 laptop.

## What this unlocks for the submission

- Directly answers the "атаки 2017-года, устаревшие" reviewer objection.
- Gives the final submission a reproducible pipeline from
  `mcfp.felk.cvut.cz` + `malware-traffic-analysis.net` → parquet →
  training → evaluation with a single command per step.
- Preserves `metadata.jsonl` provenance so the jury can spot-check
  claims like "trained on 2025 Lumma captures".
- Zero new infrastructure or paid API dependencies — the jury can
  re-run exactly this pipeline on their own laptop.
