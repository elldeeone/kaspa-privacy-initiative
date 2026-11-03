# ADR-0013: Offline paid-claim recovery and terminal reserve drain

Status: Accepted for the owner-authorized R07 offline model, 2026-10-18.
No production exit construction or native terminal transaction is selected.

## Problem, evidence and alternatives

[ADR-0012](0012-offline-restored-transitions.md) preserves unpaid claims, but its
log cannot represent payment. Restoring every claim as unpaid after payment
would permit a second model payout. R07 must retain consumed claim identities,
reconcile separate rent, and handle both a final user claim and a final fee.

Reuse the existing ideal model's exact payout and fee checks, and the
[source review's](../../research/recovery-source-review-2026-10-18.md) requirements
to distinguish requests, accepted claims and payment. The pinned vProgs/native
[enforcement map](../../poc/native-value/MAPPING.md) identifies actual permission
consumption, destination, reserve change and rent rules. Its existing native
builder's strict-remainder limitation is not removed by an offline model test.
The mature-protocol discovery/spentness comparisons in the source review remain
relevant; no foreign circuit, crypto or recovery server is imported. This work
reuses dated pinned research and local code, with no online source refresh or
new upstream compatibility claim.

Deleting paid claims loses replay evidence. Recreating a live Pool snapshot
would conceal recovery dependencies. Treating an exit request as payment loses
backing too early. Reject these alternatives; replay explicit ordered effects.

## Decision and public interfaces

Extend the existing RecoverySession, reconstruct_public/restore_wallet and
fresh-process CLI boundaries. Archive/checkpoint v3 adds `payout` and
`fee_payment` events bound to an existing unpaid claim, its exact destination,
principal, applicable rent and resulting principal reserve. Preserve paid flags
and rent already returned across restore. Keep the claim and operation IDs after
payment. Missing/altered effects fail against the separately trusted horizon;
duplicate payment fails even if its remaining-reserve argument is updated.

Match existing model u64 semantics, including checked principal-plus-rent output
value. Keep principal, fees and externally funded rent separate. A final user
payout may leave zero reserve; a fee may instead be last. Zero reserve is valid
only with no outstanding principal liabilities. Unallocated sponsor rent remains
separate; these tests do not invent a sponsor withdrawal path. v1/v2 remain
readable with initially unpaid claims. Wire versions do not change economic
domains, note/nullifier rules, keys or backup formats. A later refund request must
not downgrade a v3 archive.

## Trust, safety and validation limits

These events model successful payment effects; they are not native transactions,
proofs of payment, UTXO observations, fees paid to miners or reserve authority.
Exact pre-existing claim terms constrain the model, not a new admin signature.
The model checkpoint and historical ideal-proof predicates remain trusted.
Restoring an earlier internally valid horizon cannot detect a later payment;
this work guarantees single payment on the supplied ordered history, not across
forked/stale histories or distributed writers. Reorgs and crash atomicity remain
R08/R09. No network access, real funds or testnet broadcasts are involved.

Validate before/after payment in fresh processes, wrong destination/amount/rent/
remaining reserve, duplicate and unknown claim, cross-claim confusion, malformed
integers, output overflow, omitted/reordered/forged accepted effects, and later
valid continuation. Drain the worked three-user ledger in fee-last and user-last
orders, plus a fee-free one-note terminal case. Reconcile paid user principal,
fees and rent against fixed expected values and seeded boundary cases. Keep
prior evidence intact and perform an adversarial second pass before reporting.

Follow-up: [ADR-0014](0014-offline-recovery-failure-programme.md) adds bounded
offline fork replacement, local process-crash and per-user shutdown controls.
The full real-proof/native recovery requirements remain open.
