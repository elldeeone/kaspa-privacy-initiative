# ADR-0110: Test requester privacy and contention before extending withdrawals

Status: accepted for the owner's bounded 6 November 2026 follow-up experiment.

The batched common-set mechanism has a narrow payout-key benefit at the same
native fee as named batches. Identified eligibility and state-bound approvals
remain material limitations. The owner authorized checkpointing, testing those
privacy leaks and busy operation, and reusing the existing proof optimization.

Use proof-authorized eligibility without a human owner field, established blind
registration and source-reviewed anonymous transport. Do not replace missing
network evidence with shuffled labels. Preserve known-nullifier, timing, amount,
collusion and later-disclosure attacks in the observer model.

An unrelated accepted payment must invalidate old whole-set approvals because
they bind the exact bank outpoint and effects. Test refusal and fresh-proof
recovery, rather than removing that binding. Retain independent owner exits.

Reuse the existing immutable program-pinned wallet-key path in an isolated
guest variant: checked canonical host generation, image-bound key, unchanged
submitted-proof checks. The old guest and evidence remain intact. This is a
new unfunded bank profile, not an upgrade or consensus change. Keep the original
wallet relation, reserve accounting and security invariants unchanged.

The [frozen selection](../../research/withdrawal-request-and-busy-pool-2026-11-06/SELECTION.md)
defines hypotheses, observers, controls, stop rules and claim limits. Costs and
privacy remain unqualified beyond measured cases. No funded or public action is
authorized by this ADR.
