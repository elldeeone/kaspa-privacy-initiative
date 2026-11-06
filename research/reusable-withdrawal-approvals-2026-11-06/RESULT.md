# Reusable withdrawal approvals under current L1

**Owner request:** commit/push completed work, keep the optional payout-ownership
improvement, and fix repeated approvals during unrelated activity. The earlier
work is pushed at `44d28516`. No consensus change, real funds or mainnet action.

The [selected experiment](SELECTION.md), [source review](SOURCES.md),
[ADR-0111](../../docs/adr/0111-reusable-withdrawal-intents.md) and
[prototype](../../poc/reusable-withdrawal-approvals/README.md) preserve the previous
failed exact-effect design and define the new conditional consent branch.

## What changes

Wallets authorize a fixed economic intent: the pool/config and reference anchor,
complete claim and equal-value payout sets, nonce and maximum aggregate fee.
The payout addresses and amounts cannot change without fresh approval. The
coordinator can rebuild the surrounding bank transaction using public data when
unrelated activity changes its reserve, outpoint or continuation shape.

The original complete wallet circuit and setup are unchanged. Its context hash
binds the full intent; the current Ledger still verifies proof authority, accepted
historical membership and current nullifiers. Every final RISC Zero/native receipt
still binds exact current state/outpoint/value, full actual effects and ordered
payload. I-6 is unchanged: owner consent is not a portable state-transition receipt.

## Result

**The bounded fix passes: two wallets approve once, and their exact proof bytes
remain usable after three unrelated accepted updates.** No new cohort approvals
are generated. The backend still makes a fresh current-state receipt.

The actual private-payment fixture credits Alice 30 KAS, pays Bob 20 KAS and has
Bob decrypt/re-spend 10 KAS to Carol. Bob and Carol then approve their fixed
10-KAS-each intent. Alice privately splits her remaining 10 KAS into two positive
5-KAS notes and independently withdraws both. Their original group approvals
still work after all three accepted updates, even though the payout now drains
the bank instead of leaving a continuation.

A separate continuing withdrawal at the first changed prefix uses the same
approvals, with a repriced fee of 16,444,700 sompi within the fixed 20,000,000-sompi
cap. The terminal payout uses 16,442,600 sompi. Each has a genuine complete
receipt and native Full validation. They are separate counterfactual histories,
not two spends of one bank input. Continuing leaves 10 KAS correctly backed;
the main terminal history leaves zero reserve, liability and active bank outputs.

One-time cohort approval work took 16.805 seconds. The byte digest remains
`481f3501d38baa3a2058f08a29e1cc063b150f0e12488f2360b888628723ac44`
before and after the updates. The previous exact-effect branch still refuses
its earlier approvals as expected; it is preserved rather than weakened.

## Refusal and independent replay

Seven distinct complete RISC Zero receipts and eight distinct native Full
transactions independently reverify from public evidence, without wallet keys,
issuer secrets or private proving parameters. Forty host controls cover changed
consent/context/cohort/payout, fee/monetary bounds, malformed proof/packet,
current spentness, zero unused allowance and operation-order independence.

A genuine alternative Bob solo exit leaves enough other users' backing for a
forged repeat payout; the actual guest refuses Bob's already-spent note. Changed
actual recipients also fail the real guest. A real old receipt transplanted to
the changed current state fails native Groth16 verification. A valid receipt with
reordered actual payload also fails native cryptographic verification. Changed
successor program/root fail the immutable native successor guard. These tests
preserve I-6/I-7 rather than treating cached consent as a settlement certificate.

## Cost and privacy scope

The main stress route quotes **0.821919 KAS** in native fees, including Alice's
extra private payment and two solo exits. The earlier comparable stress route
quoted 0.821538 KAS: **0.000381 KAS more** for this format/workload. Withdrawal order
differs between the routes; this is not a new identical-sequence service-price
comparison or the fee for a simple quiet batch.

The 33-KAS supplied source reconciles to 30 KAS paid principal, 0.996322 KAS
ordinary funding change, 1.181759 KAS refunded allowance and 0.821919 KAS fees.
The main path's five complete outer proofs take 1176.232 seconds (19.60 minutes).
All seven receipts include two additional research counterfactuals, whose work is
not silently charged to the main path. Main-proof GPU-only energy is 47.71 Wh;
CPU/whole-host power, depreciation, idle utilisation, operator/transport and
availability costs remain unpriced. No complete commercial or two-percent pass.

The scoped public-chain/prover observer retains two payout-owner assignments for
the two assumed honest cohort members; one known participant or the published
solo counterfactual reduces this to one. Independent sorting adds no individual
claim-to-payout field. This preserves the narrow common-set mechanism, without
qualifying stronger financial privacy or anonymity of published research keys.

**Decision:** keep the optional reusable intent branch. It removes the selected
wallet reapproval failure. Backend reproving/serialization, real independent
clients, approval transport and full lifecycle financial privacy remain open.

## Limits retained

Accepted spending of a cohort note revokes that note's old consent. Changing a
recipient, amount, group, cap or immutable configuration requires fresh consent.
An exhausted fee allowance or removed historical anchor can also force a refresh.
Deleting a local request or changing its nonce is not on-chain cancellation.
Anyone holding the complete released approval set can execute the approved
payout while its conditions hold. There is no wall-clock expiry or second owner
confirmation of execution timing; delayed/strategically timed withdrawal remains
an explicit opt-in risk and timing privacy is unqualified.

The backend still needs a fresh outer proof after a bank update; old outer
receipts must remain invalid. This addresses wallet reapproval, not the entire
serialized-bank/prover race, sustained traffic, reorg recovery or availability.

The optional common-set payout privacy keeps its earlier conditions: adequate
honest cohort, protected registration and fresh destinations. Known owner maps,
amounts, timing, collusion and later disclosure remain attacks. Approval transport
and independent users remain unqualified. The two-owner busy fixture is not the
earlier three-owner anonymity experiment or stronger financial privacy evidence.

All native sources are supplied synthetic UTXOs, and counterfactual branches are
separate histories. No bank/image upgrade, consensus/invariant amendment, issuer
spending key, admin lock, new crypto primitive, Tor expansion or MPC restart.
