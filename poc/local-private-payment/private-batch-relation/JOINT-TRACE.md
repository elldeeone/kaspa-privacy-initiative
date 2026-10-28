# Joint financial witness construction

`src/joint_trace.rs::construct` takes declared `OwnerColumns`, the public exact
Context and accepted public history, and emits `PreparedJoint` recipes. It
accepts no clear combined witness, owner-chosen permutation or arbitrary effect
bytes. Existing owner-local constraints remain responsible for authorization,
notes, CV/curve bindings and per-owner conservation. This constructor emits
the shared sort, arithmetic and state witnesses needed to join those components.

The result has all10,364 effect bytes as eight LE bit LCs per byte, the3x3 and
6x6 selectors indexed `[source][public destination]`, the64-bit selected-input
remainder and8-bit delta quotient. The batch adapter must assign these recipes
to the actual retained Ark model column IDs and construct every remaining
constraint auxiliary. These scratch operations alone are not a proof.

1. Sort complete32-byte NF/64-byte CV input records by unsigned256-bit LE NF.
   Three compare/exchanges use a fixed adjacent schedule; duplicate/zero/spent
   NFs refuse through private state assertions. No host secret comparison or
   secret address selects a record.
2. Generate128 fresh active `RANDOM_BIT` values for each of six complete520-byte
   output tuples. Sort by random key then fixed original three-bit source index.
   The index only breaks collisions; no source marker or random key enters
   Effects. One-hot markers undergo the identical swaps as complete tuples.
   Input ordering and output permutation are independent.
3. Sum three u64 fees and three u64 selected input values in66 bits. Require
   total fee in `[1,MAX]`, new reserve in `[NOTE_FLOOR,MAX]` and exact nonnegative
   selected-input remainder in `[0,MAX]`. Explicit subtraction carries a private
   final borrow and checks high bits; no truncated add or wrapped host integer
   supplies the result.
4. Require each private delta canonical below Babyjub's Q, add its251 bits in
   253 bits, then privately subtract Q up to twice. Return the canonical public
   delta and exact quotient0,1,2. Because sum<3Q<P, no Fr wrap hides a mismatch.
5. Pass sorted private NFs and permuted private CMs through
   [`state_trace`](STATE-TRACE.md), then assemble the exact `Effects::bytes`
   order, including every NF witness, CM path, new root and count. Global SHA
   and actual model auxiliary mapping belong to the batch trace adapter.

Random-key collisions have probability at most `15/2^128` by a union bound.
Conditional on distinct keys, symmetry gives a uniform permutation; fixed
source-index tie breaking introduces at most that statistical distance from
uniform. There is no collision retry. This tiny bias is explicit, rather than
an exact-uniform shuffle claim. Real security also depends on fresh checked
MASCOT preprocessing, the stated corruption model and the existing CSPRNG.
The private internal algorithm seam accepts keys for public differential tests;
the only public constructor generates all768 key bits itself.

## Executed public controls

Three small arithmetic/sort controls passed: exhaustive five-bit subtraction
with borrow, complete row/selector routing under changed and colliding keys,
and delta reduction across all three quotients and Q boundaries. Five shared
trace controls passed for count/hash/text-size equivalence, explicit public
random tapes, missing/excess/invalid tape refusal, canonical headers and prior
public reference/deferred-failure semantics.

The full dynamic control invokes the public `construct` entry point with an
explicit PUBLIC reference tape supplying exactly768 `RANDOM_BIT` values. Two
assignments change NF owner ordering, nontrivial old-list predecessor routing,
output ordering/collisions, fees, values and delta quotient1→2. Every10,364
effect byte, all45 selectors, remainder and quotient matched an independent
Python oracle using the retained public sparse-tree implementation and plain
integer/order arithmetic. The input tuples deliberately contain arbitrary
public filler rather than valid authorization or genuine Output proofs.

Both assignments emitted18,636,595 wires and12,155,408 operations with identical
structural graph SHA256
`c1bb0d3ab6c58806a11ee5db6a0f83c64e9b95c5d95ac1410a5436eb7b993df9`.
The two-fixture run took25.52s under2CPU/4GiB, with1,563,840,512 bytes measured
scope peak memory. Source/argv/output receipts are retained under
`.local/private-joint-trace-dynamic-20261028-03/`; no full trace body was dumped.
Attempt01 selected an old cached test binary and matched zero tests; it is
retained as `INVALID_CONTROL_ZERO_MATCHED_TESTS`, not a pass. Attempt02 tested
the same algorithm with declared public test-key columns;03 additionally
exercises actual `RANDOM_BIT` instructions and the production constructor.

Independent source passes found no blocking algorithm/routing issue and no
production clear-value route through Count/PUBLIC-fixture tape modes. These
are source and reference-oracle results: they do not execute MASCOT, validate
the entire physical financial model, test active preprocessing randomness,
construct global SHA/model auxiliaries or produce a proof. Those remain
integration obligations below.

All owner bytes and key bits have private Boolean assertions. All loops and
memory addresses depend on fixed three/six shapes and accepted public history,
not their values. The operation graph must remain identical across changed
public reference assignments, including changed sort routing. Only public
fixture tests decode values; actual execution uses authenticated trace workers.

Before any prefix/effect/proof-related opening, the same complete authenticated
assignment, all helper witnesses and all private assertions require the
reviewed validation barrier. Subsequent proof, MAC/group checks and independent
normal SNARK verification remain mandatory. The proved R0 composition must
verify all six genuine Output proofs, public CV balance and current public
transitions; native acceptance must check the actual selected receipt/effects.
No public tree history check establishes consensus or latest-head authenticity.
The existing abort/retry/history policy and known active-intersection failure
remain unchanged.

This source is part of the unfunded research work in
[RFC-0030](../../../docs/rfc/0030-private-batch-construction.md) and
[ADR-0074](../../../docs/adr/0074-private-batch-construction.md). Algorithm
controls do not qualify a full financial MPC, anonymity, native lifecycle,
wallet recovery or production safety.
