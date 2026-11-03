# RFC-0027: One owner-private native KAS lifecycle

**Status:** Open. **Date:** 2026-10-24 UTC.
**Baseline:** `760d27491b3a7ab28a14712ee41e107ebdc76b76`.

## Question

Can one coherent testnet profile compose the new confidential multiparty
constructor with real native backing, repeated payments, seed-only change
recovery and an independent full-note exit, ending in confirmed native payouts?

The [ADR-0063 result](../../research/next-session/owner-private-prototype/RESULTS.md)
has genuine financial/local native verification and a bounded grouping study,
but deliberately has zero payouts and no accepted backing. The earlier
[four-wallet run](../../research/next-session/four-wallet-testnet/RESULTS.md)
and [private-change run](../../research/next-session/private-change/RESULTS.md)
have confirmed native payouts under different relations. None establishes the
combined question.

## Selected experiment

The owner requests implementation and execution of coherent profile, repeated
use/recovery, coordinator/prover-loss recovery, and complete TN10 payout/accounting
steps. [ADR-0064](../adr/0064-owner-private-native-kas-lifecycle.md) records root's
selection and the [shared interfaces](../../research/next-session/owner-private-lifecycle/INTERFACES-01.md)
fix the new domain and roles. Preserve existing profiles and evidence.

Select GN3 admission, genuine three-spend/six-output confidential rounds, and a
direct one-owner no-append Exit152 proof. Reuse maintained primitives and exact
native state/effect checks; do not collect witnesses, expose output partitions,
or make independent exits wait for a new mix or the original shared prover.

## Questions the execution must answer

1. Do actual signed funding sources establish exactly the three admitted claims,
   initial CM/NF state, immutable native policy and fully backed reserve?
2. Can recipients restore only their original backup plus authenticated public
   history, find new payments/change, spend received notes and recover again?
   Does the new public API keep recovered note CMs/positions private?
3. Can each accepted note obtain a genuine direct exit after loss of the original
   coordinator and shared prover, using independently retrieved full public
   history/software/proving keys? Which unavailable data or access prevents it?
4. Do actual accepted native bodies enforce current state/NF insertion, exact
   payout/fee/destination and continuing reserve, with no admin authority or
   reliance on host acceptance flags?
5. Do all payouts confirm and final reserve/liabilities reconcile? What is the
   complete fee ratio including acquisition, admission, mixed rounds and every
   independent exit, without counting change/refunds as useful payment demand?

The expanded privacy experiment is not selected in this execution batch.
Existing financial correctness controls, adversarial second-pass implementation
review and privacy-preserving interfaces remain required. The current privacy
target, known amount/ancestry/endpoint limitations and previous failed thresholds
are unchanged. Functional completion cannot itself qualify financial privacy.

## Open beyond a successful rehearsal

The composed cryptographic privacy argument; active/adaptive attacks and larger
useful anonymity sets; independent human/operator administration; independently
verified consensus; durable public history/parameters under pruning and provider
loss; practical fee spikes; low-demand liveness and full-tree private change
remain separate questions. A content hash, two same-administrator downloads or
replacement software running on the original trusted host cannot answer them.

Retain exact source/proof/body/accepted-history identities, genuine negative
results and separate financial, recovery, privacy, fee and availability verdicts.
