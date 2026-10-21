# ADR-0031: Screen working-balance withdrawals with arithmetic first

**Status:** Accepted — bounded arithmetic experiment only; no adopted wallet or
protocol change.

**Date:** 2026-10-21 Australia/Sydney.

**Related RFC:** [RFC-0016](../rfc/0016-working-balance-withdrawals.md).

## Problem and evidence

The [native-usage result](../../poc/shared-pool/NATIVE-USAGE-PRIVACY.md) exceeds
the frozen amount-guessing limits after public withdrawals. The
[investigation](../../research/shielded-kas-withdrawal-privacy-2026-10-21.md)
identifies whole-note arithmetic and public value/timing relationships as useful
attack inputs. Correct guesses need not identify the actual receipt, and do not
establish uniquely forced disclosures.

The unchanged v6 relation already supports partial native payout with private
change; the current wallet's EXIT command drains its selected notes. H17 supplies
bounded partial-withdrawal mechanics and a limited privacy improvement with an
unacceptable delay. H18's practical short-tail policy showed no attack reduction.
Neither finding justifies implementing another policy before testing its premise.

## Decision and rationale

Conduct the owner-authorized comparison in the
[prospective specification](../../poc/shared-pool/WORKING-BALANCE-PRIVACY-SPEC.md)
as an arithmetic falsification screen first. Compare whole-selected-note exits
with requested payouts that leave reusable private change. Do not add mandatory
remainder timers, cover traffic, a privileged coordinator or a new token.

Use four paired economic histories: overlapping/sparse activity crossed with
independent/receipt-correlated liquidity requests. Independent-demand cells
decide directional continuation; stress amount leakage remains visible rather
than being averaged into primary gains. Immediate full exits and final drainage
are required. Match original payment obligations and cumulative native cash
requirements, preserving overshoot, re-entry ancestry, fees and all tails.

This chooses the smallest test that can reject the mechanism without spending
time on new proofs or wallet integration. Retain whole-note exits as baseline;
reject tuning the failed H18 denomination/timer into a claimed fix. An extra
self-PAY is unnecessary for the existing partial-payout relation. Multi-owner
batching and a runtime migration are outside this narrower experiment.

## Safeguards and decision boundary

Freeze the specification, executable policies, attacks, scorer and controls
before generating a fresh private seed. Keep observers separate from hidden
truth; include legitimate public-only and earlier-prefix strategies in stronger
views. Complete and seal every prediction before scoring. Opaque arithmetic
labels are idealized hiding, not tested encryption or actual native bytes.

At next public payout and final drainage, every primary cell/profile must meet
the specification's five-percentage-point amount improvement and prior-advantage
conditions. Sender, recipient and joint inference must meet its non-regression
conditions, including stress cells. Missing requests, invalid accounting or
incomplete observations invalidate the evidence; they are not privacy successes.
Preserve every failed attempt and result without post-result tuning.

A complete arithmetic rejection ends this policy continuation before native
construction. A complete directional pass permits a separately frozen native
continuation; it does not itself qualify privacy, change the wallet or establish
recovery. New cryptography, setup, covenant, key derivation and consensus changes
are not authorized by this decision. No broadcasts or funds are involved.

The unchanged security invariants, immediate owner-controlled exit requirement
and native backing remain mandatory. Do not lock retained change until another
user appears or accept a fee/dust shortcut that destroys a claim. Any later
wallet integration must validate backup discovery, change spendability, correct
payout keys, replay rejection and competing old/new exits explicitly.

## Objections and outcome

One pair per scenario cannot establish repeatability or real-user anonymity.
Receipt-correlated requests can reveal amounts even when outputs are partially
withdrawn. The public price prior already conflicts with the absolute 20% amount
target, and current fees fail adopted low-value payment targets. A directional
result cannot close those qualification gaps or justify milestone 3.

The [completed arithmetic result](../../poc/shared-pool/WORKING-BALANCE-PRIVACY.md)
fails the frozen gate. Overlapping independent demand improves 13/40→8/40
amount guesses through final drainage. Sparse pooled final remains 11/37 in
both arms and the candidate exceeds its prior by 5.41 points. Sparse C+D's
one-hit improvement is below the required five points. Receipt-correlated
partials worsen amount scores; these stress outcomes remain separate. Some
identity non-regression failures include arm-specific prior-guess variation,
so they are not all causal withdrawal-disclosure findings.

All 1,506 predictions completed before scoring; eight independent arithmetic
replays and the subsequent public aggregate audit pass. The experiment is
valid within its declared arithmetic scope, and its privacy continuation gate
fails. Stop before genuine-native construction or wallet adoption. Retain the
mixed evidence, existing partial-payout mechanics and all H17/H18/native-usage
results unchanged. Any revised policy requires a new prospective comparison;
this result does not qualify anonymity, recovery or cryptographic security.
