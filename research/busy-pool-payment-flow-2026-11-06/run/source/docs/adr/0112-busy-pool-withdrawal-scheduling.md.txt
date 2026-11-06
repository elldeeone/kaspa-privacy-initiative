# ADR-0112: bounded busy-pool withdrawal scheduling

Status: experiment selected, not a production or privacy qualification.
Date: 2026-11-06. Supersedes no security invariant or prior negative result.

The owner authorized testing concurrent arrivals, fixing the queue if necessary,
and checking the complete payment/withdrawal flow. No consensus changes.

Reuse ADR-0111's immutable program, complete wallet relation, public parameters
and reusable full-set approvals. New requests alone cannot stale a receipt.
An independently accepted native update can. Scheduling cannot prevent that race.

Compare an explicit admission-first, individual-payment reference scheduler with
an oldest-withdrawal-first scheduler that preserves request age across retries
and subsequently batches compatible PAYMENT operations. Neither is a consensus
lock or a privileged withdrawal path. Independent holders may still update the
bank or exit. Never mark projected child transactions or queued requests settled.
Only genuine receipts and native Full validation advance accepted local state.

The experiment is finite: the existing depth-four circuit has sixteen leaves.
Four wallet processes generate their own secrets and use the existing public
parameters. One precomputed competing receipt is accepted while the original
withdrawal proof is really running. Its precomputation is charged and disclosed;
it represents an operator with a head start, not impossible parallel GPU work.

The detailed frozen selection is
[here](../../research/busy-pool-payment-flow-2026-11-06/SELECTION.md).
This adds no cryptography, mixed transaction mode, privileged lock or wallet
circuit change. Same-host wallet processes do not establish independent users.
