# ADR-0059: Scheduled private actions with public settlement proofs

**Status:** Accepted for a separate unfunded two-action prototype, after
independent design review. No existing pool upgrade or production adoption.
**Date:** 2026-10-23 UTC. Baseline `5aaf99532d8714e510d421102df719f60f54d073`.
**Origin:** [RFC-0024](../rfc/0024-independent-private-payment-settlement-and-recovery.md).

## Problem and comparison

The actual public two-action checker verifies genuine owner proofs and exact
ordered public state/native effects. It rejects competing successors, current
occupied nullifiers, false CM updates and coherent header/body mutations even
when the private proof is valid. It also demonstrates why the original exact
outpoint/fee policy cannot become one cheaper settlement unchanged.

Compare unchanged native sequencing, mixed-key proof aggregation, an explicitly
scheduled virtual transition policy proved by established RISC Zero composition,
and a Based App. Retain unchanged native execution as control. The inspected
SnarkPack implementation uses one prepared VK and has no drop-in mixed-role
native verifier. A Based App remains a comparison, not an assumed requirement.

Select the narrow scheduled virtual-policy prototype specified in the
[public contract](../../research/next-session/independent-payments/settlement/VIRTUAL-P0-CONTRACT-01.md)
and [R0 execution plan](../../research/next-session/independent-payments/fees/PLAN-R0-SETTLEMENT-01.md).
These are application semantics around established primitives; no new
cryptographic primitive is selected. The final reviewed plan hash before
implementation is
`762066d94b2e4a67cff6460b691a8dc3dfd549a9b21d8a57b7c2f569eb41013d`.

## Selected bounded contract

1. A fresh wrapper W, explicitly chosen by its clients, governs the actual
   current pool point Q0/stateS0/reserveR0. It fixes wrapper/child domains,
   private compact VK, the child virtual template, public outer image/key and
   its own immutable native policy. No old funded output gains a migration or
   new aggregate authority. Retained old public proofs are semantic controls
   only; any new financial profile needs fresh identities/parameters/owners.
2. Exactly two scheduled compact mode2/P0 child actions retain owner-local note
   witnesses. Export only selected public Auth/proof/update bytes. Child0
   binds actual Q0; child1 binds the official canonical virtual-body ID of
   child0. Verify both private predicates and all public native-owned checks:
   current NF absence/sequential updates, CM placement/empty append, ordered
   output/cipher digests, ranges, states, reserves and cross-child uniqueness.
   Child-template SPKs are explicit virtual contexts, not accepted wrapper UTXOs.
3. Quote the complete actual outer body first, allocate positive integer fees
   F0,F1 with F=F0+F1, and then fix exact owner output values/CMs/ciphers/Auths
   and canonical virtual bodies before proving. Each child's private equation
   charges its authorized Fi. Native final equation is R0=R2+F. No hidden
   sponsor, haircut, rebate, fee surplus or relayer output is authorized.
4. The actual transaction consumes exactly Q0 and creates one exact immutable W
   continuation of stateS2/reserveR2, with no native payout list. Independently
   reconstruct these effects, canonical header fields, complete public payload
   and financial projection from native introspection. Do not trust a guest-
   supplied body hash or currentness flag. A later batch starts from actual Q1;
   it does not make virtual child bodies accepted L1 transactions.
5. Prove the public settlement predicate with established RISC Zero and
   same-claim Groth16 compression. The fixed424-byte journal binds domains,
   count, actual starting point, states, reserves, fees, ordered complete child
   record hash and actual financial projection hash. The actual payload is
   child-only `KPX5VP01` framing plus two fixed childpayload/proof records. The
   journal, its own hash, current transaction ID and outer proof are absent
   from that payload; native reconstructs the journal. The outer proof is in
   signatureScript. Compile the guest before pinning its image in W; W SPKs
   are public body inputs independently authenticated by native code, not an
   own-image constant inside the guest. These rules prevent self-hash cycles.
6. Retain a direct owner-local private fallback with the same original real
   nullifiers and current public state. It must not require another child,
   operator, outer-proof assets or future arrival. General capacity liveness
   requires ADR-0058's separately verified no-append full-note cashout. A caller
   cannot treat REVEAL as a private fallback or an unaccepted virtual receipt
   as settled value. Preserve public delivery/history availability after an
   accepted aggregate; a data hash is not retrievable data.

## Implementation gates and economics

First implement a host semantic oracle and independent native body-binding
controls, with exact public codecs, complete fee closure and rejection of
coherently mutated points/roots/NFs/CMs/fees/outputs/headers. Independently review
those code paths before a new outer receipt. Then validate a genuine compressed
receipt and exact native Full/all-engine body, or record a concrete failed gate.
No proof run is justified merely to reprove two private predicates without
settlement semantics. Reauthenticate existing official prover/compression assets
before use. Schedule CPU/RAM-heavy proving separately from other large jobs.

Price complete cooperative settlement and direct private fallback, including
wrapper bytes, public delivery, entry, each native exit and any abandoned work.
Even an ideal compressed outer verification plus one independently settled
private exit per10-KAS payment has a reference100 verification-only cost of
1.475%+1.55%/N. N2 is2.25% before overhead; this prototype cannot qualify the2%
individual/low-demand target. Do not pad N, manufacture demand or count refunds
as payments. Actual lower complete fees are an experiment result, not a premise.

Scheduling changes liveness: witnesses remain local, but participants must
consent to an exact public prefix/fee allocation, publish recoverable data and
refresh on abort/current-head changes. Coordinator disappearance may delay
cooperative settlement; it must not steal, inflate, consume unaccepted notes or
disable private fallback. Invoice/output partitions remain visible, so this
decision does not solve the demonstrated privacy leaks.

Reconsider on failed actual-body binding, fee closure, private fallback, data
availability, source/receipt/native verification, or infeasible proving costs.
Passing supplied-context tests never establishes accepted backing/currentness,
independent operators, cryptographic soundness, financial privacy or readiness
for a fresh testnet rehearsal through confirmed payouts.

## Observed prototype results, 2026-10-24

Two fresh owner-local compact proofs, the selected RISC Zero guest and native
W now agree on the same 424-byte journal and exact public financial projection.
The actual GPU Succinct receipt takes 408.730 seconds; same-claim Groth16
compression takes 4.436 seconds. Independent CPU verification and the genuine
W native Full/all-engine transaction pass at 15,646,440 units. Five coherent
unchanged-proof native-body mutants reject. Outer fee is 18,508,000 sompi;
reserve changes 4,000,000,000 -> 3,981,492,000. This is a constructed two-owner
cross-payment, not accepted funding or independently measured economic demand.

The SDK-to-native proof converter initially rejected genuine raw G2 coordinates.
The correction retains strict canonical-field, curve, subgroup and nonidentity
checks instead of treating coordinate bytes as Arkworks affine flags. Original
RED evidence is retained; guest/image/receipt bytes did not change.

The complete private-input source bound 14,957,286 supports selecting budget 1500
for fresh private fallback quotes/Auths/proofs; aggregate budget remains 1600.
Historical direct budgets are canonical protocol u16 values checked through
fresh native Full, not restricted by this client's fee preference. Both
original backups now recover their two current claims, use the exact
HTTPS-restored current runtime/PK and make genuine two-real-input private
no-append exits. Exact outer plus two-exit fees are 52,512,100 sompi; native
payouts total 3,947,487,900 and remaining reserve is zero. That is 2.625605% of
the two declared 10-KAS synthetic payments before unperformed entry costs. Public
software/parameters do not supply an accepted-currentness adapter, a trusted
setup ceremony, independent retention or financial privacy. See the
[current results](../../research/next-session/independent-payments/RESULTS.md).
