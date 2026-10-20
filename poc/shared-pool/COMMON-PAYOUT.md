# Common-size partial withdrawal test

Status: the frozen privacy screen and genuine offline exit checks pass.
The combined policy gate fails its delay condition. Amount and criteria were
frozen in `71d2aca`; all twenty blinded observations finished before scoring.

Separate participant views force the original source of **4/28 cashout claims,
down from 7/28**, after complete drainage. No case/participant pair regresses
and no original payment acquires a new unique source. Keep optional common
cashouts as a research candidate; do not adopt this fixed schedule or close
Stage 2. These are four synthetic cases, not a real-world anonymity estimate.

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

## Privacy comparison

The complete-history comparison counts the same original claims in both arms:

| Forced source links after full drainage | Baseline fresh exits | Common partials and tails |
| --- | ---: | ---: |
| Chain-only, original cashout claims | 0/28 | 0/28 |
| Separate participants, distinct original cashout claims | 7/28 | 4/28 |
| Separate participants, overlapping claim observations | 7/84 | 4/84 |
| Chain-only, original private payments | 2/24 | 2/24 |
| Separate participants, distinct original private payments | 4/24 | 4/24 |
| Separate participants, overlapping payment observations | 6/48 | 6/48 |

A participant row means one participant's own records added to the chain view.
The distinct count is the union of targets linked by at least one such view,
without combining their evidence. All singleton claims must retain the true
source; other results are candidate sets with abstention, not probabilities.
The early equal-payout horizon is diagnostic only: it has not yet completed
the original claims.

The three removed links belong to split claims. All four remaining links
belong to claims that were not split. No equal-payout leg has a unique source
at either horizon: 0/16 chain-only and 0/48 separate-participant observations.
After full drain, equal-payout legs retain 9–10 chain-only sources and 6–9
participant sources; their earlier ranges were 12 and 10–11. Tail payouts
retain 9–10 chain-only sources and 1–9 participant sources. The median minimum
leg count per original claim is 9 chain-only and 7 with one participant's
records. These are possible creating transactions, not people or equal odds.

All four participant singleton inferences are correct under the model;
the other 80 eligible claim observations abstain. Chain-only abstains on all
28. All 136 checked payment/Q candidate sets narrow or stay equal when the
final history is added. Summed payment-source alternatives rise from 722 to
724 chain-only and from 835 to 861 across participant views, without changing
the number of uniquely linked payments. Neither sum is an anonymity measure.
The earlier startup links remain: later cashouts do not erase what was already
deducible before other participants supplied alternatives.

Evidence: [summary](evidence/2026-10-20-common-partial-reconstruction/summary.json),
[per-pair and horizon audit](evidence/2026-10-20-common-partial-reconstruction/derived-metrics.json),
[costs](evidence/2026-10-20-common-partial-reconstruction/costs.json)
and [manifest](evidence/2026-10-20-common-partial-reconstruction/SHA256SUMS.json).
The bundle includes sanitized per-observer candidate sets and scores, not raw
participant views, plans or note openings. H17 measures fresh-path privacy;
its saved-proof branch is an exit-mechanics test, not a new privacy measurement.

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
These totals include every transaction in the frozen pool trace. Starting
reserve and depositor UTXOs are synthetic fixtures: creating/funding them is
outside this offline trace. A funded trial would also have to count its actual
allocation/genesis transactions; 9.2 tKAS is not an end-to-end live fee quote.
The 40 minutes come from this deliberately unchanged schedule, not a required
Kaspa confirmation delay. A separately scoped scheduling comparison could test
whether the benefit remains practical. This result authorizes no funded trial.

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
The matched H14 calibration generated 26 proofs. H17 generates eight more:
four partial authorizations and four replacement-change saved exits. Both
calibrations also create fresh final alternatives for their comparison.
The initial UTXOs are synthetic. The unchanged native dependency is
`01b532e8b553523216471682649693af92f0fd16`; no new SDK or live node was qualified.
Supplying authenticated public state is a fixture assumption, not a new
general-recovery or malicious-RPC result.

## Validation and execution

All 20 logical observations, 540 complete prediction rows and 40 checks of the
original integer amounts/input graphs pass. Ten base controls cover the
independent tiny oracle, policy boundaries, fees, drainage and hidden leg
matching. Additional solver controls check the same oracle and preserve a
normal payment using two positive inputs. An incomplete-matrix control rejects
collection before any truth files are available.

Nineteen completed plain/bounded SMT observations were retained. The final
participant case completed with direct integer CP-SAT search, using the same
relation, public arithmetic cuts and a separate fixed-graph integer check.
Across the chosen runs, 6,617 positive graphs received integer certification.
Five complete same-input comparisons agree on all 27 rows each: two
plain/bounded comparisons and one each for batching, explicit one-input
equations and direct integer search. The source pins identify the actual
implementation for every observation; no timeouts count as privacy.

Individual selected runs took 60.578–5,875.550 seconds under contention and
different solver strategies. CP-SAT used four search workers. The last case
finished in 60.578 seconds using that path; the earlier SMT variants remained
unfinished and were stopped after complete observations and truth checks were
preserved. This is not a controlled solver benchmark or a wallet-latency cost.
[Execution notes](evidence/2026-10-20-common-partial-reconstruction/execution-notes.json)
retain interrupted attempts and a final metadata-writer error. That error
occurred after scoring; collection/validation was repeated with identical
predictions and an identical complete summary. The resource file measures only
final validation/scoring, as described in its
[scope receipt](evidence/2026-10-20-common-partial-reconstruction/resource-scope.json).

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

The default SMT run can be slow. To complete a difficult participant case with
the same integer relation, use `common_payout_propagating_run.py ROOT ORIGINAL
CASE PARTICIPANT --engine integer`. First run it on a completed case for an
exact comparison. `common_payout_collect.py DEST ORIGINAL --alternative CHECK
--alternative RESULT` accepts only complete observations with recognized
source/input pins and a matching completed-case comparison for an alternative
engine. It requires all twenty observations before opening scoring truth.
The measured collection reused nineteen earlier results and one integer result;
it did not generate a different workload.

Existing protocol pins remain unchanged. The
[author's second pass](COMMON-PAYOUT-REVIEW.md) is not an independent
cryptographic audit.
