# Native accounting and resource rules

[Draft scope](README.md) applies. No invariant amendment is adopted here.

## Value conservation and native stock

All values are integer sompi. Tin/Tout are sums of actual ordinary UTXO input
values and new ordinary outputs. Sin/Sout are private real-note totals under
the complete construction; F is explicit network fee, not a hidden service fee.

```text
b = Sin - Sout
Tin + b = Tout + F
B_next = B - b
Sin + Tin = Sout + Tout + F
```

Require public amounts/totals and B/B_next in [0,M], b in [-M,M]. Ordinary
outputs are positive; zero private padding is allowed. Reject signed minimum
and out-of-range b before negation/narrowing. Use checked i128/u128 for totals
and comparisons. Never apply the old Tin>=Tout/fee=Tin-Tout rule alone to a
shielded withdrawal; its real accepted fee is **F**.

The unchanged Action circuit supplies nonnegative u64 notes, not a hidden M
comparison. With two Actions each private side is <2^65, far below the group
order. The complete binding construction must imply the **integer** equation,
not only field equality. Under sound proofs/binding, unique Action-linked
creation rho, current global single spending, authentic B=0/no-positive-note
genesis and no imported/queued liabilities, induction gives:

```text
total outstanding positive-note value = B <= M
```

Thus each live note and distinct consumed-note total is <=M. A public B counter
does not alone establish that claim; all premises are review obligations. No
builder-only range check substitutes for a circuit constraint. If the induction
or complete construction is rejected, a changed hidden-range relation/key needs
its own reviewed profile, not a silent assumption.

For each accepted non-coinbase transition:

```text
delta(sum(ordinary UTXO values) + B) = -F
```

Count B once as native value controlled by consensus, not also a reserve UTXO.
Hidden liability is not a second asset. Feed accepted F once into the existing
origin-block accepted-fee/mergeset reward accounting. A skipped/rejected event
has no fee; reorg undo removes/restores the same fee exactly. Coinbase emission
and reward maturation/payment retain Kaspa rules; never invent a same-block
refund or mint F again from B. The existing
[coinbase source](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/processes/coinbase.rs#L80-L181)
governs those DAG rewards. No new emission or treasury entitlement exists.

The direct boundary action is atomic: a note is not burned until its authorized
native output/change and native state are installed. There is no unpaid queue
in profile 1. A later queue/migration must keep its full liability backed until
actual payment or authorized replacement. Rent/treasury/service assets cannot
be counted as user reserve. Service payment, if any, is separately authorized
ordinary/shielded output value, not extra network F.

## Explicit proposed invariant wording

The actual [SECURITY-INVARIANTS.md](../../../SECURITY-INVARIANTS.md) remains
unchanged. Its independent-review rule applies before adoption/implementation
of a changed invariant; this draft records the concrete proposal to review.

**I-1 proposed addition:** "For a consensus-native pool, reserved native value
includes the unique consensus balance B, controlled only by protocol rules and
not simultaneously counted as an ordinary reserve UTXO. Outstanding liabilities
include every spendable native note and every valid unpaid exit claim. A queued
or migrated claim remains counted until actual payment or authorized replacement."

The existing inequality `outstanding liabilities <= native KAS reserved for
users`, pending-claim protection and treasury exclusion all remain.

**I-2 proposed replacement of the equation paragraph:** "For every valid
transition, sum(private inputs) plus sum(actual ordinary native inputs) equals
sum(private outputs) plus sum(actual ordinary native outputs) plus explicit
allowed network fees. Count each input/output once in its domain. With no
ordinary crossing this reduces to the private-transition equation. Payout
principal is never a fee. No hidden inflation, rounding creation, negative-value
behavior or field-wrap creation is permitted."

No change to I-3–I-16 is proposed. Independent review must assess the complete
native backing/authority/state/supply argument and the invariant amendment,
not infer approval from arithmetic vectors or this ADR's draft status.

## Resource accounting, without hidden note-value pricing

The activation manifest contains this exact `MassSchedule` record:

```text
U16(1)
|| U64(C_bundle) || U64(C_action) || U64(C_signature)
|| U64(C_tree_hash) || U64(C_sparse_hash) || U64(C_log_hash)
|| U64(S_event_byte) || U64(S_marker) || U64(S_note) || U64(S_anchor)
|| U64(native_block_compute_limit) || U64(native_block_storage_limit)
|| U64(native_block_transient_limit)
```

All coefficients/limits must be positive, checked <=u64 maximum and reviewed
against actual implementation measurements before activation. No real values
are selected by this document. A conformance example is not network pricing.

Ordinary noncontextual byte/script/declared-budget costs use the existing
version-1 compute-budget units (U16) and native maximum/limits, extended to count
**all** new wire bytes. For the v2 storage calculation, use existing ordinary
UTXO cells plus one **mass-only virtual boundary cell** of plurality 1:

- b>0 adds an input cell with amount b;
- b<0 adds an output cell with amount -b;
- b=0 adds no cell. If both ordinary sides are empty, ordinary storage is zero.

Run the existing deterministic integer `calc_storage_mass` relation on that
augmented list. The virtual cell has no outpoint, backing, authorization or
supply effect and is never persisted as a UTXO. Native positive-note values
are not revealed or invented for pricing. This explicit adaptation needs review
for boundary/UTXO price incentives; it is not already current Kaspa behavior.

Add the following exact draft charges:

```text
native_compute = C_bundle + 2*C_action + 3*C_signature
               + (2*32)*C_tree_hash + (4*256)*C_sparse_hash + 64*C_log_hash
event_bytes = 60 + byte_length(Wire(tx))
native_storage = S_event_byte*event_bytes + 2*S_marker + 2*S_note + 2*S_anchor
committed_storage_mass = ordinary_augmented_storage + native_storage
```

The sparse/anchor charges reserve worst-case work; sharing/batching never
changes validity or grants a negative storage refund. Count new bytes in
transient mass using the existing byte factor. For v2, the existing ordinary
noncontextual size term uses the full Wire length exactly once; retain its
remaining ordinary script/declared-budget terms, then add native_compute.
Contextual storage is committed_storage_mass. Existing block checks consume
these extended component vectors for v2 and unchanged vectors for old formats.
Additionally check sums of native_compute, native_storage and the incremental
native-extension byte transient mass against their respective manifest limits
in exact integer arithmetic. Reject arithmetic overflow.
Permanent event, global-marker and recovery retention are charged; the formula
does not claim actual disk usage or validated sustainable economics. No float
fee threshold enters consensus. Existing mempool floating fee-rate policy is
separate; a valid transaction need not be relayed/included economically.

The linear native charges coexist with existing ordinary mass; they do not
hide a one-time free reserve release or price only the bare Halo2 predicate.
Complete lifecycle costs must still include ordinary preparation, all transfers,
change, exits, rent/retention and service costs under the unchanged denominator.
Mass coefficients, consensus implementation and cost qualification remain gates.
