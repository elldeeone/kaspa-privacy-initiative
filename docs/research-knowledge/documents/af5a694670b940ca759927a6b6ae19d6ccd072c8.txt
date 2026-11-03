# Optional asynchronous payment batching

**2026-10-25. Batching can amortize one native verification, but current Spend
proofs cannot be repacked asynchronously. A new, explicitly reviewed intent
authorization is required. Payment batching alone cannot meet the frozen 2%
target while retaining nine independently executed exits.**

This is design research alongside the live campaign, not a launch gate. No
selected source, setup, proof, key, GPU job, native policy or live state changed.
It extends [the direct Groth16 memo](DIRECT-GROTH16-FEASIBILITY-01.md),
[RFC-0029](../../../../docs/rfc/0029-local-native-kas-private-transfer.md) and
[ADR-0066](../../../../docs/adr/0066-local-native-kas-payment-prototype.md).

## What is possible

| Candidate | Consent and head binding | Cost/liveness implication |
| --- | --- | --- |
| Direct combined 1×2 | One owner approves the exact transaction/current point | Avoids R0 verification of three inner proofs; still one native verifier/payment. Time and fees remain unmeasured. |
| Batch current Spend/Output proofs | Every Spend commits the complete final batch effects | Changing batch members, order or head needs new payer authorization. This restores a coordination/retry dependency; it is not the asynchronous solution. |
| New point-bound intent queue | Each owner approves its exact outputs/fee and one current reserve point | No live peer roster is needed within that unchanged-head window. Another accepted payment/Exit stales unconsumed intents. |
| New durable intent queue | Owner explicitly permits a constrained set of later heads; final outer/native proof binds the actual point | Owners can remain offline during public-only rebatching, but authenticated pool lineage and historical-anchor consistency are new obligations. Final outer proofs can still become stale while proving. |

The incompatibility is concrete: [wallet consent](../../../../poc/local-private-payment/wallet/payment.py#L114-L175)
checks the exact point/state, ordered tuple bytes and fee, then creates Spend200.
[The guest](../../../../poc/local-private-payment/verification/common/src/lib.rs#L222-L252)
reconstructs one whole-body effects digest for every Spend. Output168 can be
reused only for its unchanged D/CM/CV/CFhash tuple. Neither an output proof nor
an old whole-transaction Spend proof grants a batcher new authorization.

## Candidate intent contract

An intent would commit to its domain/role/profile, authenticated pool/lane
identity, anchor root/count, original NF and CVin, **two exact complete output
tuples**, exact integer `fee_i`, canonical Delta, unique intent ID and explicit
validity constraints. The payer locally verifies the authenticated invoice,
private payment amount, recoverable change and tuple ordering before proving.
No opaque batch hash, other payer roster or batcher signature substitutes for
that consent. Keep witness generation local; batchers receive public proofs and
public intent bytes only.

For every intent separately, verify genuine Spend/Output predicates and
`CVin_i − CVout_i,0 − CVout_i,1 − fee_i*V = Delta_i*R`. Global conservation alone
could hide unauthorized fee redistribution between payers. All NFs must be
distinct and absent from current NF state. The final transaction must satisfy
`actual_fee = sum(fee_i)` and `new_reserve + actual_fee = old_reserve`, using
checked integer sums bounded by MAX, with zero
native payment, exactly one continuing same-policy reserve and no batcher
payout/tip/refund discretion. Every output occurs exactly once. Preserve the
existing within-action CM rules and position-based NF semantics.

The outer verifier folds N indexed-NF insertions and 2N ordered CM appends from
the **actual authenticated prior state**, checks capacities/counts and emits a
journal bound to the complete actual batch/effects/current outpoint. Native
Script independently reconstructs those effects and enforces the selected
image/profile/current reserve. Use an explicit canonical intent order and retain
each payer's approved internal tuple order; do not spend newly created outputs
within this minimum batch design. Recipient positions come from accepted public
history, rather than an unconfirmed batcher's assignment.

Durable intents require a real authorization change: the payer cannot both
approve one exact outpoint and remain valid after that outpoint is consumed.
The allowed later-state set must be explicit under invariant I-6. Review must
demonstrate I-6 compliance: fixed authorized intents and context sets, with the
final proof bound to the actual current state. A domain or a
batcher-supplied genesis label is not authenticated pool lineage. Demonstrate an
existing immutable lineage binding, or review a committed pool identifier in
bootstrap/state/policy. State112 currently has no generic anchor-history rule.

Historical membership must be connected to accepted current CM state, using a
reviewed append-prefix consistency proof or authenticated anchor-history state.
Specify the hidden position/count obligation; a host cannot inspect a private
membership position. Orchard accepts historical anchors through explicit
consensus rules (specification v2026.7.0-344-g2bdf39, 2026-10-21); that rule is
not automatically available here. RFC9162 provides
an established append-consistency analogue, not a drop-in proof for this tagged,
fixed-depth tree. [Zcash specification, §3.7](https://zips.z.cash/protocol/protocol.pdf),
[RFC9162 §2.1.4](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.4).

## Availability, retries and privacy

Fixed outputs and exact fees mean a batcher cannot silently adjust change to
share savings. Choosing a lower fee in advance may require waiting for enough
demand; low fees and bounded settlement latency are not both guaranteed. A fee
change needs new owner consent and changed outputs/proofs. Owners must retain a
direct-payment/independent-Exit fallback; no permanent note lock is introduced.

An exported intent is **not a reservation or a revocable host flag**. A direct
payment or Exit consumes the same original NF; first accepted consumption wins.
After stale heads, unknown submissions or reorgs, replay accepted history,
recheck spentness and anchor consistency, and rebuild only eligible public
packages. Orphaned outputs are not accepted claims. Expiry must use an
authenticated native/consensus context, never the batcher's clock; a count-based
window alone does not expire while the pool is idle.

There is no privacy improvement claim. The batcher receives the mapping from
each NF to its two CF tuples and can disclose it. Tor does not remove timing,
invoice or endpoint linkage. Do not introduce authenticated owner lists,
peer-presence polling or requests for new consent merely because a batcher
changes subsets. No six-output metric or active-abort result is converted into
a pass. Public-only proof aggregation removes neither these observer channels
nor the shared-head contention during a long outer proof.

## Honest fee floor for the unchanged 21 KAS

Use the observed roughly 14 million Script-unit verification floor as an
**optimistic conditional model**, not a universal future protocol theorem.
Budget/mass conversion and 100 sompi/gram give roughly 14,000,000 sompi, or 0.14
KAS, per native verification before bytes, state logic, deposits and other fees.
The official rate/units are pinned in [the fee note](../fees/FEE-FLOOR-01.md);
[native budget conversion](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs#L4-L7).

| Retained workload shape | Optimistic verification-only cost | Of 21 KAS |
| --- | ---: | ---: |
| Six payment transactions + nine exits | 2.10 KAS | 10% |
| Two payment batches + nine exits | 1.54 KAS | 7.33% |
| One ideal payment batch + nine exits | 1.40 KAS | 6.67% |
| Nine exits alone | 1.26 KAS | 6% |

The 2% budget is 0.42 KAS. The one-batch row is deliberately over-generous:
three genesis notes and six accepted-prestate-only spends require at least two
batch layers; dependency depth may require more. Batching exits would be a
separate architecture/workload comparison. Neither external fee subsidies nor
unrelated payment volume may silently improve this frozen denominator/verdict.
The current **FAIL remains unchanged**. An N-intent R0 batch also verifies 3N
inner proofs and grows public state/payload work; no proof-time saving is measured.

## Smallest falsifiable experiment after review

1. Two owners independently create genuine candidate intents, then stop both
   owner processes. A public-only batcher must include both exact pairs/fees in
   one accepted 2-input/4-output native transaction without owner contact. Reject
   fee/CF/tuple substitution, global-only balance tricks, duplicate NF/intent,
   wrong pool/profile, forged anchors/counts and any coordinator payout.
2. Advance the head through an unrelated valid Exit. Point-bound intents must
   fail safely. A durable-intent candidate must rebuild from public history and
   accept at the new point without owners; its stale final outer proof must
   reject. Also test reorg rollback and an Exit competing for one queued NF.
   The remaining intent can proceed only under its unchanged fee policy.
3. Freeze a malicious subset/abort schedule. Require zero owner-roster/contact
   requests after export, record the still-visible NF→two-CF mapping, and recover
   received/change notes from original seeds plus accepted public history.
   Measure actual paid fee, native mass, cycles/time/RAM and queue delay against
   the matched direct 1×2 path; do not substitute an unequal workload.

ADR candidates are **point-bound optional queue first**, or **durable intent plus
authenticated anchor/pool lineage** if offline rebatching after head movement is
required. Candidate copies would touch relation statements/circuit/requests;
`wallet/payment.py` and `worker.py`; `verification/wire.py`, common verifier,
guest/profile/image and native `policy.rs`; `recovery/history.py`, chain replay/
preflight/confirmation; and independent public fixtures. None of those selected
files was edited. The live six-payment/nine-payout campaign continues unchanged.
