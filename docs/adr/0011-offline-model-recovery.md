# ADR-0011: Offline model recovery formats and R01–R04

Status: Accepted for the owner-authorized offline prototype, 2026-10-18.
This selects experiment formats only, not a production note, archive, consensus
checkpoint or shielded architecture. RFC-0001 remains Open and RFC-0002 Proposed.

## Problem and alternatives

The existing wallet helper decrypts supplied records without accepted-history
completeness or current spentness. R01–R04 need a fresh process that restores
from explicit inputs without the producer's Pool, wallet database or ideal
proof registry. See the [test design](../shielded-recovery-test-design.md) and
[primary-source/reuse comparison](../../research/recovery-source-review-2026-10-18.md).

Serializing the Pool/oracle would preserve hidden coupling. A hash manifest
supplied by the archive cannot authenticate omission. Real L1 authentication
would require the still-missing private relation/native integration. Therefore
use an explicitly trusted, separately retained **model checkpoint** for this
offline experiment, and never present it as a Kaspa or ZK acceptance proof.

## Decision and assumptions

Use strict versioned JSON for (1) a user-held model backup, (2) public accepted
model effects, and (3) a separately supplied checkpoint binding the fixed model
descriptor, complete event count and canonical archive digest. The producer
executes the existing ideal model; the restorer reconstructs public effects
without loading its oracle or trusting per-operation validity flags. Authenticity
of the checkpoint and original model acceptance are explicit test assumptions.
An attacker replacing the trusted checkpoint defeats that assumption; a hash
does not certify a private predicate, chain acceptance or fresh/current state.

Back up model spending/incoming seeds, derived public identities and optional
user-known expected receipt commitments. Reuse the existing model's PyNaCl
keys/sealed boxes and nullifier function. Do not select or invent production
cryptography. Expected receipts detect known bad/missing delivery; anonymous
scanning alone cannot detect a sender encrypting to someone else's key. This
prototype must not claim complete recipient spendability from that scan.

Only data authenticated to the supplied horizon may enter wallet restoration.
Track discovery, accepted inclusion and current spentness separately. On missing
or unverifiable inputs return explicit failure without a spendable balance.
Private backup and restoration outputs use new mode-0600 files; stdout contains
only a bounded public verdict. All secrets/values in published fixtures are
deliberately synthetic, and this is not a backup tool for real wallet material.

## Consequences and validation

R01–R04 run through backup/restore interfaces and fresh subprocesses. Independent
literal accounting comes from the worked three-user ledger, not the restored
state itself. Controls cover missing history/ciphertexts, archive replacement,
domain/version/reordering/duplicates, current nullifiers, bad recipient delivery,
strict amount encoding and key mismatch. Full native recovery, reorg/crash
handling, proofs, fees, migration and exits remain R05–R16/integration work.

No new reserve authority, admin exit or weaker invariant is introduced. Replace
this checkpoint assumption with reviewed accepted-L1/proof authentication before
making a real-protocol recovery claim. Revisit the backup format when the final
note/discovery construction changes; no future seed-only restore is promised.

Follow-up: [ADR-0012](0012-offline-restored-transitions.md) extends the model
with R05/R06 restored transitions and private pending-note backup metadata.
The later [R07 extension](0013-offline-paid-claim-recovery.md) adds synthetic
paid-claim recovery. [ADR-0014](0014-offline-recovery-failure-programme.md) adds
bounded R08–R16 offline controls; their full native/proof requirements remain open.
