# Regression contracts from the control branches

[Knowledge guide](README.md) · [Proof checks](proofs.md) · [Commit ledger](commits.md)

These concrete contracts carry forward knowledge from code-only side branches.
The original messages and changed paths are in the local ledger. Cases below
describe the retained source contracts, not new executions of the old harnesses.
Use the historical evidence level when deciding what a case establishes.

## Native payout and immutable successor

`dd00ceed35a95d10b6c79b80b744642244cb3226`,
`poc/native-guard-controls/controls.py`, retains nine selected cases:

- Continuing and terminal genuine-proof baselines.
- Continuing payout amount and destination mutations.
- Successor verifier-key, domain and code mutations.
- Current redeem-domain mutation against the unchanged actual predecessor script.
- Terminal payout-destination mutation.

The proof and payload stay unchanged while the intended native field changes.
Native guards can reject before proof execution; these negatives are native-VM
guard evidence, not changed-statement pairing rejection or chain acceptance.

`c430dd8a`, `poc/native-continuation-controls/controls.py`, is recorded with its
full commit ID in [the ledger](commits.json).
It separates partial-payout mode 1 from terminal mode: preserve two commitment
appends and test actual payout amount/destination plus successor key/code.
Its admission baseline is separate. Two admission-successor mutations were
explicitly **not executed** because a full transaction failure could also be
caused by the depositor signature; that is not isolated covenant coverage.

## Per-input admission attribution

`fde0c288` adds `poc/shared-pool/src/bin/kpi-admission-input-controls.rs`.
Its proposed fixed-fixture adapter preserves both inputs and UTXOs, runs each
input VM and the unmodified full validator, and separates funding-signature
failure from covenant successor failure. Removing the other input would change
the statement. Pre-script checks are prerequisites, not transaction acceptance.
Source acceptance and an execution plan must not be relabelled as executed
native qualification.

## Relation ownership, bounds and padding

`2251864a`, `poc/relation-controls/src/main.rs`, distinguishes full-circuit
constraint satisfaction from an isolated bounds-helper result. Its 16 cases
cover reversed mixed owners, wrong owner with recomputed public nullifier,
slot-1-only input, equal commitments at distinct positions, aggregate MAX and
MAX+1, zero fee/fee-only burn, forbidden drain outputs, below-floor payout,
compensated nonzero padding value, nonzero padding secret, and four helper
boundary cases including inactive MAX+1.

The helper's inactive range guard permitting MAX+1 is not a full-circuit
authorization to create an out-of-range note. Constraint results are not new
proof verification or native/chain acceptance. Position-dependent nullifiers
must preserve separate spentness for equal note openings at different positions.

## Capacity refusal must leave state unchanged

`67793fa4`, `poc/tree-capacity-controls/src/main.rs`, tests the retained
production depths 16 and 17 against an independent dense reference. For each
depth it distinguishes the penultimate append, exact-full append and rejected
over-capacity append. Check full stored state, root and sampled paths; refusal
also preserves allocation metadata, not just the root. No circuit/proof API or
funded-state conclusion follows from these tree controls.

## Actual changed-input proof rejection

`acba8b04` introduced one-v6 reference/candidate adapters; `6fdc5fc6` added a real
changed-public-input pairing rejection. The candidate source at
`poc/takeover/host/src/bin/one_v6_candidate.rs` distinguishes fixture integrity,
canonical decoding, statement binding, verifier-interface errors and actual
verification rejection. Preserve complete consumption, point/subgroup checks,
nonidentity checks, scalar-byte agreement and the exact selected fixture.
One-bundle host compatibility does not establish a paired state transition,
guest execution, accepted backing or independent exits.
