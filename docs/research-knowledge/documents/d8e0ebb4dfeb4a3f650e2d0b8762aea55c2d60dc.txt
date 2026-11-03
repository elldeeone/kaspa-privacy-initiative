# ADR-0012: Offline restored transitions and pending refund claims

Status: Accepted for the owner-authorized R05/R06 model extension, 2026-10-18.
No production architecture, cryptography or native exit path is selected.

## Problem and decision

[ADR-0011](0011-offline-model-recovery.md) restores a wallet but does not resume
the canonical model. R05 needs persistent spentness/operation identities and
allowed historical roots after a fresh-process restore. R06 needs credit/refund
competition to preserve liabilities, including before an actual payout exists.

Reconstruct the complete trusted-model event log, then hydrate only the public
economic Pool state with a **new empty ideal proof oracle**. Never import a
producer proof registry or register old public statements as new valid proofs.
New local model proofs are created from the restored user's synthetic secrets.
Keep rejected attempts as ordered no-ops and retain the full prior log between
batches. The [existing source/reuse review](../../research/recovery-source-review-2026-10-18.md)
supplies the current-spentness, historical-anchor and recovery obligations.

For recovery refunds, use a distinct **pending refund request**, not the older
model `refund` helper which immediately simulates payment. A request must prove
the recorded refund-owner's existing Ed25519 model authority, bind pool/network/
statement version, deposit ID, exact principal and recipient, and consume a
currently pending deposit once. Create an equally backed unpaid claim, lock
separately funded permission rent and leave native principal reserve unchanged.
Credit after refund request and refund request after credit both reject.
There is no signature-only reserve release or admin bypass.

The new refund record uses archive/checkpoint **v2**, while v1 remains readable
for the existing fixtures and R05 transitions. This is an offline wire-format
version, not a second economic protocol/spend domain. Note/nullifier derivation
and statement version 1 remain unchanged; mismatched archive/checkpoint versions
must fail. No snapshot or orphan/rollback path is introduced.

Backup v2 additionally retains private pending-note metadata bound to the deposit
ID, amount, commitment and refund owner before retrying credit. A key-only v1
backup can authorize a refund request but cannot derive an unpublished pending
note from its commitment. The existing spending/incoming keys remain unchanged;
no secret metadata is included in public evidence. These synthetic backups are
unencrypted and are not a production wallet format.

## Alternatives and limits

Serializing the live Pool would hide missing state dependencies. Re-registering
historical oracle tokens would manufacture proof validity. Immediate model
refund payment would discard the liability before a native payout exists.
Those alternatives are rejected for these tests.

The separately retained checkpoint and original ideal-model acceptance remain
trusted assumptions. A new model checkpoint is a harness output, not proof of
Kaspa acceptance, cryptographic soundness or independent service recovery. A
fresh process containing synthetic wallet/executor roles is not an enforced
private-witness separation. Unsolicited native transfers, native refund payout,
reorgs/crash durability, migration and fee-market liveness remain open.

## Validation

Test two individually valid competing spends from one old allowed root across
two batches and fresh processes, same-batch competition, exact/changed-intent
replays, invalid then valid continuation and incorrect domain/root controls.
For both credit/refund orders and restarts, test wrong owner, altered deposit/
principal/recipient/domain, duplicate requests, insufficient rent and numerical
boundaries. Reject without economic mutation; reconcile pending/private/unpaid
principal and separately funded rent. Preserve prior R01–R04 artifacts as dated
evidence rather than attributing them to changed source hashes.

The [reproduction and results](../../poc/shielded-design/TRANSITIONS.md) record
56 passing tests, including 14 R05/R06 tests, 40 seeded principal/race vectors,
and six fresh continuation processes. Native payout and all real-proof recovery
acceptance requirements remain open.

Follow-up: [ADR-0013](0013-offline-paid-claim-recovery.md) adds v3 synthetic
payment effects and preserves consumed claims/returned rent across restore.
The 56-test report above remains historical; native payment, reorg/crash and
independent-chain authentication limitations are unchanged.
