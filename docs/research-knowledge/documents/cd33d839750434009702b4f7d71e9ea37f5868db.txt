# Explicit private reserve and funded outbox: bounded result

**Completed 2026-10-26 UTC.** All eight frozen synthetic cases exhausted their
finite graphs without a modeled accounting/authorization mismatch. All twelve
deliberately broken variants produced the required counterexample. This checks
an ideal-oracle accounting proposal; it selects no native architecture.

The new evidence is the explicit reserve split: accepted conversion removes two
notes from private liabilities, creates two unpaid entitlements, funds their
separate escrow, and charges each owner's exact settlement fee once. Claims in
either order preserve the other entitlement and its backing. A third note
remains privately backed and retains its separate direct-exit obligation.

The existing [ADR-0039](../../../../docs/adr/0039-exit-liability-and-native-claim-experiments.md)
bounded modeling scope applies, as decided before implementation in
[DESIGN-01.md](DESIGN-01.md). The earlier generic model is retained and was not
rerun. The Outbox memo remains a proposal. No proof/profile, note format, wallet,
native covenant, live source, helper, service or frozen campaign changed.

## What was checked

| Frozen search | Actual completed count |
| --- | ---: |
| Initial accounting cases | 8 |
| Financial/history states, including one rollback branch | 1,730 |
| State × ideal availability/quote products | 83,040 |
| Accepted financial proposal edges | 1,784 |
| Rollback edges | 686 |
| Rollback × unchanged environment products | 32,928 |
| Deliberately broken variants detected | 12 / 12 |

There was no depth, sampling, time or state-count cutoff. Counts include
distinct accepted histories/fork identities; they are not counts of unique
balances. The environment product is exact for the model's disabling-oracle
semantics. It does **not** establish physically reachable witness-refresh
histories. Retained CURRENT witnesses and enough accepted update data are an
explicit availability premise, rather than an old path becoming current by
itself.

The independent origin ledger checked private reserve, separately funded escrow,
unpaid gross liabilities, authorized destinations, original-NF single use,
stable economic identities, paid-state preservation and separate settlement,
claim and direct fees. Each case begins with public synthetic 3/5/7 integer
sompi notes, not real funds or viable native transaction amounts.

Directed controls exercised both claim orders in all eight cases and direct
exit of the remaining note. Both tickets fully paid in the six fee-viable cases;
the two deliberately fee-exhausted cases preserved A's unpaid backed ticket in
both orders. Additional controls rejected still-private NF2 as a ticket in all
eight cases, and rejected orphan creation against a replacement accepted outbox
in all 384 case/environment products while preserving economic ticket identity.
Wrong root/role/signer/fee, stale private/outbox points, duplicate conversion NF,
paid replay and invalid amounts were explicit proposals. MAX is a valid uint
that rejects as the wrong principal; overflow/type boundaries were separate.

## Failures deliberately retained

- Missing all current public data/witnesses blocks claims. An authenticated root
  alone supplies no recovery data.
- A fee rise above exact owner consent blocks payment while its complete gross
  liability remains backed. Two cases also have gross equal to claim fee, so
  their zero payout is rejected and the entitlement remains unpaid.
- Service loss before conversion creates no cheap ticket. The modeled direct
  fallback works only with independent prover/data and enough approved fee.
  Service loss alone does not block viable already accepted tickets.

The twelve mutants exposed omitted NF consumption, absent escrow, a missing
ticket, double-charged settlement fees, owner fee redistribution hidden behind a
correct global sum, absent/root-local/historical/overwritten paid state, changed
destination, changed principal and service-dependent accepted claims. Each
mutant stopped at its first independent safety or conditional-liveness failure;
these mutant searches are not labeled exhaustive safe graphs.

One rollback restores chain accounting and payout observations together.
Observer knowledge of conversion and the selected loss/quote environment remain
unchanged; replacement branch identities differ. This is a symbolic rollback,
not Kaspa consensus/reorg validation.

## Scope and evidence

The modeled quote governs claim/direct redemption only. Checkpoint fees are
accounting allocations; even a zero-fee checkpoint has **no native admission
claim**. Proofs, authenticated acceptance/lineage, signatures, consent and witness
reconstruction remain ideal oracles. There is no native Script/Full/relay/testnet
acceptance, real backup recovery, fee-saving, proof-soundness, privacy or
production-safety result. The existing workload's **2% FAIL is unchanged**.

Root closed pre-execution review for the exact final source/design. Two
pre-observation corrections are preserved with their preimages: accurate
liveness-attempt reporting, then quote-scope/explicit NF2-orphan coverage and
MAX labeling. Candidate, independent ledger and financial search were unchanged
by the second correction. No result was retuned or discarded.

| Evidence | SHA256 |
| --- | --- |
| [model01.py](model01.py) | `0fe47fc85a83a56245dae59969e3153628494c0dd9b15818694a95b84572d3d4` |
| [DESIGN-01.md](DESIGN-01.md) | `34cac6e926f72578f3b825b191d864d3c3ac175531c23a7772e7f28d3370b980` |
| [SOURCE-PINS-03.json](SOURCE-PINS-03.json) | `612aa57f27f0b996da068e0aa04e8decf07b2e9dd02cb38578089f03ff2f8338` |
| [Root review](ROOT-PREEXECUTION-REVIEW-01.json) | `db5a602de74200aedddad04ea8397a46313a724c6aa324b567162c78e743b2dc` |
| [RESULT-01.json](RESULT-01.json) | `a3e1d18c691d2e3475945446a785eda0f252f25f3a55dcc9ca67098fdf814ec8` |

[RECOUNT-01.json](RECOUNT-01.json) checks all eight completion flags, unique
mutant coverage and exact environment/rollback products without rerunning the
model. [RUN-01.md](RUN-01.md) retains the executed command. Source and design
matched their selected hashes before and after execution. The module execution
interval was 2.879 seconds; this excludes preceding/following guard reads.
Process peak RSS includes helper09 and the wrapper, not isolated model memory.
No commit, staging, push, native/cryptographic experiment, network request,
wallet/private-data access, funding or broadcast occurred in this experiment.
