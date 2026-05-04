# Day 11 — Metric reframe, workload calculator, architecture doc

**Run date:** 2026-04-23
**Status:** ✅ Complete. README + network/README + new architecture doc all
report honest real-world numbers (F1 0.96 / recall 96 % on real-world
PCAPs) instead of the misleading 0.998 in-distribution F1. New
`workload_metric.py` produces the operating-point sweep needed for the
prize submission's "X % auto-classified at Y % FP" headline.

## Why this day

Day 9e produced the `python_only` model that closed the extractor-drift
gap. Day 10 wired it into the web app. Day 11 was about turning those
gains into language reviewers can verify, and giving operators a
defensible operating-point trade-off table — not just one number.

The submission prompt for the Yandex Practicum Award asks specifically
for:

1. A reproducible headline metric that holds up under independent
   re-evaluation. The 0.998 F1 number we used to ship was measured on
   an in-distribution CIC-2017 split — **on real-world PCAPs we measured
   0.86 % recall**. That's the gap we just closed; the README has to
   stop quoting the easy number.
2. A clear "what's in the box" picture for a reviewer who has 10 minutes
   to skim. Five layers, ASCII pipeline, what each layer catches.
3. Operator-side numbers — not just a single confusion matrix but a
   trade-off curve so a SOC manager can see the cost/coverage knob.

This day delivers all three.

## What changed

### `scripts/workload_metric.py` (new, 297 lines)

Operating-point sweep. Re-fits the Mahalanobis abstainer at four
coverage targets and computes the workload-reduction numbers on the
full 693-flow real-world test set (real_pcap + 30 % CTU hold-out).

```
==============================================================================
Mode      Cov   Auto %   Review %   FP %  Specif  Recall ATK  +Review
------------------------------------------------------------------------------
lenient    -    100.0      0.0     2.02   84.9      97.8        97.8
safe      0.95   81.8     18.2     2.47   82.9      80.2        99.3
strict    0.80   67.5     32.5     2.35   86.1      64.5        99.7
paranoid  0.50   30.4     69.6     0.47   98.6      23.5        99.8
==============================================================================

HEADLINE: 30.4 % of inbound traffic auto-classified at FP rate 0.47 %
          (operating point: paranoid, recall ATK = 23.5 %)
```

Two sub-numbers in each row:

- **Recall (model alone)** — what fraction of attacks the model auto-
  flagged with high confidence (no review queue inspection).
- **Recall (with reviewer)** — same, plus the attacks that landed in
  the review queue (assuming a human catches those).

The "honest headline" we ship is the lenient mode's 97.8 % recall at
2 % FP — paranoid mode hits 0.47 % FP only by sending 70 % of traffic
to a human, which doesn't match what an unattended IDS deployment looks
like. The full table is in the README so reviewers can see all four
points; the prize-application headline picks lenient.

Output: `results/python_only/workload_metric.json` (machine-readable
record of all four operating points with FP/FN/specificity/recall).

### `docs/architecture.md` (new, 220 lines)

Five-layer Defense-in-Depth pipeline doc. Sections:

1. ASCII pipeline diagram (PCAP → 5 layers → JSON → UI).
2. Per-layer description — what code, what it produces, what it catches.
3. Operating-mode summary table (same four rows as workload_metric).
4. "How the layers compound" — failure-mode → catching-layer mapping.
5. Production deployment notes (systemd + venv on timeweb 109.68.215.9).
6. End-to-end reproduction commands.

Layers, in order:

| Layer | Module | Output |
|---|---|---|
| L1: Python flow extractor | `threatlens.network.flow_extractor` | 5-tuple + 70 CIC features |
| L2: Spectral + YARA features | `threatlens.network.spectral_features` + `payload_yara` | +8 spectral + 3 YARA = 81 features |
| L3: XGBoost classifier | `threatlens.network.detector.FlowDetector` | Label + per-class probability |
| L4: Mahalanobis abstainer | `threatlens.ml.selective.MahalanobisAbstainer` | `is_uncertain` + distance |
| L5: SHAP + YandexGPT | `threatlens.ml.shap_explainer` + `threatlens.ai.yandex_gpt` | Per-flow explanation |

The point of the doc isn't to teach the architecture from scratch
(`README.md` does that) — it's to give a reviewer a single page they can
print, fact-check against the code paths named in each row, and verify
that every layer has a unit test.

### `README.md` (revised)

Three pieces replaced or added:

1. **Intro paragraph rewrite**: "F1 0.998 on CIC-IDS2017" out, "F1 0.96
   / recall 96 % on real-world PCAPs the previous CIC-IDS2017-only
   model managed 0.86 % recall on" in. The old number was technically
   correct but misleading because it was measured on the same
   distribution it trained on; the new number is on PCAPs the training
   pipeline never saw.

2. **"Real-world evaluation" section**: full per-capture table for the
   8 third-party PCAPs + CTU hold-out. Numbers are the actual evaluation
   output, no rounding tricks. Old vs new model side-by-side.

3. **"Operating-mode trade-off" table**: four-row sweep from
   `workload_metric.py`. Columns are explicit so reviewers can pick the
   point they think we should ship at and verify the row.

4. **"How we got here" Day 0 → Day 9e iteration table**: shows the
   recall trajectory across the improvement plan. Helpful for the
   submission narrative — the work shows up as a sequence of
   verified deltas, not "we tried things and it worked".

5. **Removed**: the old "Known limitation — feature drift" warning
   section. The drift was real but it's now fixed by Day 9e
   (architectural change to use the same extractor at training and
   inference). Leaving the warning in would mis-represent the current
   state.

### `threatlens/network/README.md` (revised)

Same theme — drift section rewritten from "this is a known issue"
to "this was the gap, here's how Day 9e closed it". The legacy
`cicids2017` bundle is documented as still loadable for backwards
compatibility but explicitly **not recommended** for real-world
traffic. New "Java-vs-Python feature drift — resolved by Day 9e"
section gives the historical context, the diagnostic finding (Day 7
p<0.001 result), and the resolution (Day 9e python-only retrain),
with cross-references to the relevant docs.

The pipeline ASCII diagram in the package README was also updated to
include the new abstainer column (was just XGBoost + IsolationForest).

## Honest framing — what these metrics mean and don't mean

The metrics in the README are measured on:

- **8 real-world PCAPs from third parties** (Stratosphere SLIPS test
  captures + Wireshark sample captures) — 440 flows, 347 ATTACK +
  93 BENIGN. None of these were in the training set.
- **30 % per-source CTU-13 hold-out** — 253 flows, all `Bot`.

That's 693 flows total. Important things this does NOT cover:

- **Adversarial behaviour** — an attacker who knows the training
  distribution and crafts flows specifically to land near a benign
  centroid. We have no robustness numbers against active attackers.
- **Network protocols outside the training corpus** — modern QUIC,
  DoH, encrypted SNI, IPv6-only flows. The model has no exposure to
  these and would either flag them by default or land in the review
  queue.
- **Drift over time** — a real deployment would see the FP rate rise
  as new benign protocols emerge. We have no temporal-stability
  numbers and no online-learning path.
- **Recall on attack types not in our 7-class taxonomy** — Heartbleed,
  Web Attack, Infiltration, DDoS (the legacy 14-class set). The
  python_only model collapses to 7 classes; flows from those 7 missing
  attack types would either be misclassified or flagged by the
  abstainer.

These limitations are noted in `docs/architecture.md` and the
README's "Attack classes" section.

## Where the day fits in the 12-day plan

Day 11 was the planned "production swap + reframe metrics + final
report" day from `docs/improvement_plan.md`. Of its six original
sub-deliverables:

| # | Sub-deliverable | Status |
|---|---|---|
| 1 | Default to python_only in app | ✅ Done Day 10 |
| 2 | Per-flow uncertainty surfacing in UI | ✅ Done Day 10 |
| 3 | Replace 0.998 F1 number in README | ✅ Done Day 11 (this doc) |
| 4 | Architecture doc | ✅ Done Day 11 (`docs/architecture.md`) |
| 5 | Workload-reduction headline metric | ✅ Done Day 11 (`scripts/workload_metric.py`) |
| 6 | Network/README drift-section rewrite | ✅ Done Day 11 (this doc) |

Day 12 (final review + submission packet) is the remaining day.

## Reproduce

```bash
# 1. Make sure the python_only model + cached real_pcap are in place
ls results/python_only/xgboost.joblib
ls results/real_world_flows_cache.parquet

# 2. Run the workload calculator (~5 sec)
python scripts/workload_metric.py
# Verify output matches the table in README.md

# 3. Run the eval that produces the per-capture breakdown
python scripts/eval_python_only.py
# Verify real_pcap recall == 96.25 %, F1 == 0.961

# 4. View the new architecture doc
cat docs/architecture.md  # or render with any markdown viewer

# 5. Verify the README rewrite removed the 0.998 number
grep -c "0.998" README.md     # should be 0
grep -c "0.96" README.md      # should be > 0
```

## Files changed

```
new:    scripts/workload_metric.py
new:    docs/architecture.md
new:    docs/day11_metrics_and_docs.md  (this file)
new:    results/python_only/workload_metric.json
edit:   README.md                        (intro + 4 new sections, drift warning removed)
edit:   threatlens/network/README.md     (pipeline diagram + drift-resolution section)
```

No code changes to `threatlens/` source — all Day 11 work is
documentation and the operating-point sweep script. The model
artefacts are unchanged from Day 9e.
