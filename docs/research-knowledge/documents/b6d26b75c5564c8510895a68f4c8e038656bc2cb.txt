# RFC-0016: Requested withdrawals with a working private balance

**Status:** Evaluated — frozen arithmetic gate failed; wallet policy not adopted.

**Date:** 2026-10-21 Australia/Sydney.

**Source checkpoint:** `feef0e02150aca9f74081c89e75ffd7a2a31fb69`.

## Context and question

The [native-usage screen](../../poc/shared-pool/NATIVE-USAGE-PRIVACY.md) found
12/36 primary amount guesses within 10% after the next public withdrawal,
against 7/36 from the prior. Those successful guesses are not forced disclosures.
The [subsequent investigation](../../research/shielded-kas-withdrawal-privacy-2026-10-21.md)
explains how full-note payout values and fees supply candidate private amounts,
and why unrelated similarly priced withdrawals can also produce correct guesses.

Can users meet the same native liquidity needs while exposing less about private
payments by withdrawing only the requested amount, then retaining and spending
private change? The question concerns wallet behavior on the existing v6
relation. It does not ask whether ordinary native outputs can hide their values.

At the current 0.4-tKAS pool fee, fully withdrawing a 40-tKAS note publishes
39.6. A 20-tKAS partial retains 19.6 privately, but a linkable 19.2-tKAS tail
and both fees reconstruct 40 again. Any benefit must survive the actual use of
change and final drainage, rather than just delaying that disclosure.

## Goals, constraints and alternatives

Preserve native-KAS conservation, owner authorization, replay rejection and
immediate independent exits under the existing
[security invariants](../../SECURITY-INVARIANTS.md). No new token, operator
withdrawal permission, trusted execution service, cryptographic primitive,
parameter setup or consensus change is introduced. Research remains offline;
no real funds or broadcasts are part of this experiment.

| Option | Assessment for this experiment |
| --- | --- |
| Whole-selected-note exits | Retain as the matched baseline. Public payout plus fee reveals the selected total; extra native liquidity remains owned value. |
| Requested payout with reusable private change | Candidate. Existing v6 SPEND supports it; whether its amount privacy improves is unproved. |
| Common payout with a scheduled full tail | H17's bounded improvement failed its delay target; H18 found no attack improvement. Preserve both outcomes, without tuning them into a new success. |
| Self-PAY then whole exit | Existing PAY can reshape value, but adds an operation when partial SPEND already supports the required relation. Not this comparison. |
| Cross-user batching or a new runtime | Adds design and cooperation questions without resolving this narrower mechanism question. Not selected. |

## Proposed experiment

The [prospective specification](../../poc/shared-pool/WORKING-BALANCE-PRIVACY-SPEC.md)
is the canonical workload, policy, attack and decision contract. Its exact bytes
and executable sources must be frozen before fresh sampling. This RFC does not
override its selectors, integer ranges, tie-breaks or failure rules.

Use four fresh economic histories, each replayed under both policies: overlapping
and sparse activity crossed with independent and receipt-correlated liquidity
requests. The two independent-request histories are primary. The correlated
histories stress the known half-invoice request rule. There is one paired ledger
per cell, with 32 roles, eight colluders and 64 original payment obligations;
these are descriptive cases, not independent trials per payment.

Native requests cumulatively earmark cash held outside the pool, rather than
simulate external merchant payments. Both arms use already-held surplus before
withdrawing again. Whole-note overshoot is retained and accounted for; it cannot
be discarded to make partial withdrawals look cheaper or more private. Re-entry
can use only surplus beyond earlier obligations, with modeled bridge/admission
fees and public ancestry. Report every merge, overshoot, tail and failed request.

Both arms execute the same original payment and cash obligations. Partial
withdrawals leave reusable change rather than schedule an automatic tail.
Immediate complete-exit requests and eventual full drainage remain in the
workload. Small change cannot be silently burned, requests cannot be underpaid,
and no private transfer may be invented to improve the candidate's activity.

## Observation and decision

Observers receive public arithmetic events and the initial funding-owner
directory; the stronger profile additionally pools all eight colluders' permitted
records. Private cash-request labels, honest-authored input mappings, honest
wallet state, hidden activity classes and the seed remain withheld.
Opaque commitments/nullifiers assume ideal
hiding: these are not genuine proofs, ciphertexts or native transaction bytes.

Freeze amount priors, residual/split attacks, partial-tail and bounded subset-sum
attacks, receipt correlation and tagging, plus unchanged public-only and earlier-
prefix strategies. Every positive-payout SPEND is a public withdrawal. Every
zero-payout SPEND is a possible observer target, including self-merges; only the
original eligible economic payments enter the primary score after predictions
are sealed. Do not expose that private target mapping to observers.

At next public payout and final drainage, each primary cell/profile must show
at least five percentage points less amount-guessing success for the candidate's
strongest frozen strategy than the baseline's, with at most five points advantage
over its proper prior. Sender, recipient and joint family maxima must not regress
by more than five points in primary or stress cells. Stress amount outcomes are
reported separately. These are prospective directional conditions, not revised
qualification targets or a per-target oracle selecting correct guesses.

An arithmetic privacy failure rejects this candidate before native construction.
Invalid accounting, missing observations or unmet obligations produce an invalid
implementation/model result, not a privacy result. Only a complete directional
pass permits a separately frozen genuine-native continuation. No result closes
milestone 3, qualifies anonymity or establishes cryptographic correctness.

## Source grounding and evidence boundary

| Source | What is reused, and its limit |
| --- | --- |
| [Pinned v6 circuit][circuit] and [native builder][builder] | Conservation already permits private outputs plus a public payout and fee. Native outputs still publish value. This is a source fact, not a new cryptographic review. |
| [Pinned harness][harness], [H13](../../poc/shared-pool/TWO-INPUT-TN10.md), [H17](../../poc/shared-pool/COMMON-PAYOUT.md) | Existing partial-withdrawal/change mechanics motivate reuse of v6. Their bounded evidence does not establish this new wallet policy or backup recovery. |
| [Pinned wallet][wallet] | Current PAY has no public payout and EXIT drains selected notes. The arithmetic candidate does not add a new wallet command. |
| [ZIP-315][zip315] | Public value balances, transparent outputs and receipt-triggered activity belong in the leakage model. Draft Zcash guidance is not a security argument for this prototype. |
| [Kappos et al.][kappos], §§6.3–7 | Test amount/timing linkage and intervening private activity through complete histories. Historical Zcash rates do not transfer to Kaspa. |
| [Current source and mature-protocol review](../../research/shielded-kas-withdrawal-privacy-2026-10-21.md) | Retain the pinned Kaspa/Toccata/vProgs context and Orchard/Aztec/RAILGUN/Monero/MWEB distinctions; no new runtime or privacy primitive is selected. |

## Security, operations and unresolved questions

The arithmetic checker must enforce integer amounts, positive-note and payout
floors, unique consumption, reserve conservation and ownership for every modeled
action. Urgent exits cannot wait for another user or a privacy timer. These checks
do not demonstrate actual signing, proof soundness, authenticated chain state,
backup scanning, reorg handling or recovery after a service disappears.

The known price prior has expected within-10% success about 21.10%, exceeding the
unchanged 20% absolute amount target. The current 0.4-tKAS operation fee also
already exceeds the 1% payment-fee target at a 10-tKAS payment, before lifecycle
costs. Report both qualification gaps alongside any directional improvement;
neither threshold nor workload may be retuned after observing results.

Sparse activity, recognizable cash demands, colluding recipients and final-tail
recombination may defeat the candidate. One ledger pair per cell provides little
evidence about repeatability. Any later implementation must verify original-backup
recovery of retained change and payout keys, invalidation of consumed-note exits,
and independent exit of every new positive note. New protocol/runtime or exit-
invariant changes require a separate design decision.

## Outcome

The [completed comparison](../../poc/shared-pool/WORKING-BALANCE-PRIVACY.md)
rejects this candidate under its frozen gate. All 1,506 observer jobs and eight
arithmetic accounting checks completed. In the overlapping independent-demand
case, strongest amount success falls 13/40→8/40 through final drainage. Sparse
C+D improves only 10/37→9/37; sparse pooled final remains 11/37 in both arms,
with the partial arm 5.41 percentage points above its prior. Receipt-correlated
partial payouts worsen amount guessing to 21/42 and 22/36. Identity gates also
fail in some cells, with explicit prior-guess variation caveats in the report.

All payments, requested cash, urgent exits and final drainage complete with
exact arithmetic conservation. Partial payouts avoid ordinary-request
overshoot and reduce re-entry in the independent cases; correlated cases cost
more. These are arithmetic policy results, not new native/proof/recovery tests.
The independent aggregate consistency audit found no discrepancies.

[ADR-0031](../adr/0031-arithmetic-working-balance-screen.md) therefore stops
the conditional native continuation. Retain partial payouts/private change as
mechanics, without adopting this policy as a privacy fix. Investigate sparse
split/tail attribution and cash-demand correlation before a separate prospective
candidate test. Preserve this rejection and the unchanged qualification targets.

## Subsequent sparse-case diagnosis — 2026-10-22

The owner-authorized [diagnosis](../../poc/shared-pool/WORKING-BALANCE-SPARSE-DIAGNOSIS.md)
replays all final predictions before joining truth. In the partial pooled view,
eight of eleven within-ten-percent hits use unrelated payout supports and three
touch actual ancestry without closing receipt/change accounting. Both exact
matches use unrelated supports. All 1,074 retained constructions have false
actual-PAY-input hypotheses. This does not erase any numerical hit or rule out
other attacks/additional transaction signal.

Prior→attack contains six gains and four losses. Whole→partial stays 11→11
but shares only three hits, with eight gains and eight losses. These observations
explain the rejected score without identifying a required structure change.
[ADR-0032](../adr/0032-sparse-diagnosis-and-privacy-evaluation.md) closes general
cashout tuning as the next work item and calls for a public-information and
evaluation-design audit. This RFC remains evaluated and rejected under its
original gate; no policy, requirement, invariant or native continuation changes.

[circuit]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/feef0e02150aca9f74081c89e75ffd7a2a31fb69/poc/shared-pool/src/two_input/circuit.rs#L220-L273
[builder]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/feef0e02150aca9f74081c89e75ffd7a2a31fb69/poc/shared-pool/src/two_input/mod.rs#L194-L214
[harness]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/feef0e02150aca9f74081c89e75ffd7a2a31fb69/poc/shared-pool/src/two_input/harness.rs#L453-L500
[wallet]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/feef0e02150aca9f74081c89e75ffd7a2a31fb69/poc/shared-pool/src/two_input/wallet.rs#L466-L526
[zip315]: https://github.com/zcash/zips/blob/d167dd3994e40790971f8f00b0b330885d2c9fe5/zips/zip-0315.rst
[kappos]: https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-kappos.pdf
