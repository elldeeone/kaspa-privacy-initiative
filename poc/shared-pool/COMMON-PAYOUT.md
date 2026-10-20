# Common-size partial withdrawal test

Status: genuine offline mechanics passed; privacy observations are in progress.
Amount and criteria were frozen in `71d2aca`. No privacy result is claimed
before the twenty blinded observations finish.

The [frozen scope](COMMON-PAYOUT-SPEC.md) adds one 2-tKAS cashout per wallet,
retains private change and then drains all remaining claims. Original deposits,
six private payments and two earlier partial withdrawals stay unchanged.
The [source review](../../research/common-payout-sources-2026-10-20.md) and
[ADR-0025](../../docs/adr/0025-common-payout-offline-screen.md) explain why this
is a client-policy experiment on unchanged v6, without a new protocol.

## Execution boundary

Four synthetic amount/schedule cases; one chain-only observer and four separate
participant disclosures per case. All know the declared client rules. The
participant observer retains H16's complete own records/ownership assumptions.
No RPC/network metadata or pooled participant records.

Compare original-source candidates after the four equal payouts and after
every final drain. Repeated Q-change outputs inherit their input's origin in
each inferred graph. Claims remain the original seven per case, even when
split into two payouts. Secret leg matching is used only by the scorer; it
does not intersect observer candidate sets.

Native calibration uses one case with genuine Groth16 proofs and synthetic
native UTXOs. The other three cases are arithmetic models. Reuse the existing
parameters, circuit and covenant. Check the saved old full exit before each
optional partial, both mutually exclusive winner orders, and all seven saved
change/unaffected-note exits after further activity. Fresh drainage is a
separate branch; the primary privacy measurements use fresh exits.

## Frozen cost

| Per case | Baseline | Common partials plus final drainage |
| --- | ---: | ---: |
| Pool transactions | 19 | 23 |
| Fees, sompi | 760,000,000 | 920,000,000 |
| Fees, test KAS | 7.6 | 9.2 |
| Additional fee per wallet | — | 40,000,000 sompi / 0.4 tKAS |
| Added complete-cashout delay | — | 40 synthetic minutes |

Fee increase is 21.05%, within the existing 25% screen. The ten-minute
inter-event schedule exceeds the existing 30-minute p95 completion-delay
screen. Neither is an observed chain fee-market quote or actual waiting time.
No test KAS or real funds are spent offline.

## Genuine mechanics result

All four wallets exit in both alternative drainage branches. The seven saved
exit proofs remain byte-identical at settlement; each isolated worker has its
capability and public state/VK, without wallet keys or proving parameters.
All four pre-partial saved full exits also work independently before the
optional cashout. Both winner orders reject the competing full/partial spend,
and every final exit rejects replay and its fresh/saved alternative.

Both branches have 23 pool transactions, 920,000,000 sompi in fees,
4,680,000,000 in total payouts and zero reserve against 5,600,000,000 funded.
All seven final payouts, four common payouts and both earlier partial payouts
are included. Separate public-body verification accepts all 23 transactions
in each branch. Both native projections match the model exactly.

Evidence: [calibration receipt](evidence/2026-10-20-common-partial-calibration/calibration.json),
[public revalidation/model comparison](evidence/2026-10-20-common-partial-calibration/calibration-check.json)
and [artifact manifest](evidence/2026-10-20-common-partial-calibration/SHA256SUMS.json).
The directory includes the chosen fresh public transaction bodies and all four
model public inputs; only `a0-s0` has genuine native calibration. Wallet secrets,
raw participant records, private plans and unused exit capability bodies are
excluded.

| Measured on the pinned build | Result |
| --- | ---: |
| Genuine proofs | 34 |
| Isolated capability settlements | 18: four old choices, seven fresh, seven saved |
| Native mutation checks | 31 types across 15 recorded transactions per branch |
| Mining mass | 330,497–331,628 |
| Full transaction script units | 14,847,328–15,029,220 |
| Selected fee per operation | 40,000,000 sompi |
| Pinned 100-sompi/mass relay floor | 33,049,700–33,162,800 sompi |
| Cold parameter load | 253.697 seconds |
| Warm proof time, min / median / max | 33.614 / 36.069 / 50.120 seconds |
| Whole calibration | 1,561.459 seconds |
| Peak native process RSS | 6,947,116 KiB, about 6.63 GiB |

Four Rayon threads; observer searches ran concurrently. These are contended
CPU measurements, not isolated proving benchmarks or fee-market quotations.
The initial UTXOs are synthetic. The unchanged native dependency is
`01b532e8b553523216471682649693af92f0fd16`; no new SDK or live node was qualified.
Supplying authenticated public state is a fixture assumption, not a new
general-recovery or malicious-RPC result.

## Reproduction

Use the frozen original private H14 run and the existing v6 parameters outside
Git. The observer controller checks their hashes before preparation. Raw
participant records and unused fallback capabilities remain private.

```sh
cd poc/shared-pool
# Python environment: privacy-study-requirements.txt
python common-payout.py prepare "$KPI_H17_PRIVATE" "$KPI_H14_PRIVATE"
python common-payout.py run "$KPI_H17_PRIVATE" --workers 6

CARGO_TARGET_DIR="$KPI_BUILD" cargo build --release --locked --offline --bin kpi-two-input
python common_payout_calibration.py run "$KPI_H17_PRIVATE" \
  --params "$KPI_PARAMS" --binary "$KPI_BUILD/release/kpi-two-input"
python common_payout_calibration.py check "$KPI_H17_PRIVATE"
```

The measured wrapper copies the executable into the private run directory and
records binary/source/parameter/plan hashes plus process resource usage before
running it. `common_payout_calibration.py check` then revalidates both selected
native histories using isolated public-body-only verification and compares
their normalized public fields with the model. The controller's `export` and
the calibration export retain only allowlisted evidence after those checks.

Ten targeted controls include an independent tiny integer/provenance oracle,
known-client conditionality, floor/oversize rejection, view-prefix boundaries,
all fees and original-prefix identity. The existing protocol pins remain
unchanged. The [author's second pass](COMMON-PAYOUT-REVIEW.md) is not an
independent cryptographic audit.
