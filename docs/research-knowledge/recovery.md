# Recovery, scanning and exits

[Knowledge guide](README.md) · [Architecture](architecture.md)

## Recoverability depends on available data

The core retained failure is [missing-parameter investigation](documents/203ff134e8bff0bc6e049227675f5ab4056b2124.txt): an old instance's proofs could
be verified and its state reconstructed, but inspected distribution points
lacked the exact public proving parameters needed to create a fresh exit proof.
A replacement setup repaired a different synthetic instance, not the old one.

A recovery package must identify the user's own secrets/backups, authenticated
public history and ciphertexts, exact parameters, compatible software and an
independent way to reach settlement. A state root, verification key or old valid
proof is insufficient by itself. Public proving parameters are not private
spend keys; they still require exact identity and independent retention.

## Historical capabilities and their limits

| Capability | Lesson | Boundary |
| --- | --- | --- |
| A1 authenticated successor/physical loss | Preserve real historical input context, reorg evidence and scanner rollback; a fresh machine can recover in the selected trial. | Loss of one machine is distinct from loss of every archive/operator. See [A1 trial](../poc-a1-official-trial-2026-10-08.md). |
| Roster-free public replay and own-key admission | Reconstruct accepted state and scan with the owner's own keys, without a privileged participant roster. | Ciphertexts, complete accepted history and exact instance identities must still be available. See [research journal](documents/a99d0c7618070857506be9bfaa31780dadf32d56.txt). |
| Saved exits and repeated spending | A saved proof is useful only for the state/claim it actually authorizes; later nullifiers, liabilities and reserve context still matter. | Successful backup-only exits in one profile do not prove every operator-loss scenario. |
| Cold/HTTPS/hosted replay | Isolated and hosted replay provided real reproducibility evidence in their selected profiles. | Same-host namespace, a cold cache, physical machine loss and loss of every hosted service are different experiments. See [matched lifecycle checkpoint](documents/fdfd544f40bd93450cab30c7bda64dcab3ec69fa.txt) and [paused handoff](documents/8afbd3d859a68dc4d80194cbdc3f0cc36e5e9961.txt). |
| Partial and final reserve withdrawal | Full user-principal drainage and exact remaining rent/backing are separate accounting fields. | A terminal exit must be independently authorized and leave every remaining claim backed. |
| Owner-signed reveal exit | [owner-signed reveal exit](documents/33ec1c21fd325c288ffbc8f1dce471e5113e9f9c.txt) avoids a fresh SNARK in its branch. | It reveals a note opening and retains fee/tail limits; it is not automatically a private exit. |

## Scanner and state identity

[position-based replay design](documents/9d86936076da220e649e7057237c0cd4e8c58a1d.txt) preserves a subtle lesson absent from branch names: **that legacy profile** identifies
claims by global commitment position, not commitment/ciphertext equality.
Equal records at different positions are separate claims with separately derived
nullifiers and membership witnesses. Do not deduplicate them into one owned note.
This was a proposed adaptation; its old scanner control did not execute the new
paired branch or test every identical-ciphertext case. It is not a universal
note-identity rule. The [RFC-0004 crypto review](../../research/rfc0004-cryptographic-profile-review-2026-11-03.md#creation-identity-duplicates-and-version-races)
selects Orchard's Action-linked freshness and **position-independent** nullifier.
Keep positions for authenticated replay/witnesses, but never credit the same
Orchard spend identity twice. Reusing the old positional NF changes the relation.

Replay ordinary, paired and exit branches using their exact framing. Preserve
record multiplicity, sequential nullifier/commitment updates and historical
prefixes. A history prefix is not necessarily an intermediate accepted UTXO.
[state-aware journal proposal](documents/b6002dff3bc25e9b1b89aee3c42682d34946d20b.txt) and [native/guest source review](documents/ba12e9a205a1f2143a88b20d34199eb1a93ba1e1.txt) distinguish authentic public replay from
pretending to re-execute hidden inner witnesses.

The complete N-user/all-normal-service-loss gate in the [current roadmap](../ROADMAP.md)
remains unqualified for one current design. Reuse these mechanisms and negative
lessons without replacing that gate with a narrower successful trial.

The [Q6 review](../../research/rfc0004-consensus-accounting-review-2026-11-03.md#q6-recoverable-data-and-authenticated-bootstrap)
distinguishes full validator replay, which additionally needs ordinary funding
context, from wallet recovery on consensus-authenticated native state. Full
retention is the first research reference; exact native header/bootstrap
authentication and independently available complete data remain unimplemented.
Orchard's selected public proof keys are derivable from its circuit/constants;
the old missing-Groth16-parameters failure is not the same setup requirement.

The [native bootstrap draft](../spec/native-shielded/bootstrap.md) now specifies
full ordinary/native replay first and a snapshot format restricted to already
qualified state. It adds no fresh-node fast-sync trust shortcut. The
[forest/state draft](../spec/native-shielded/state-header.md) preserves old-tree
anchors and global markers when a depth-32 tree fills; old notes are not moved
into a new NF namespace. Permanent data costs and real cold recovery remain
unqualified, and the fixed mathematical key capsule is not a native importer.


## Reusable withdrawal approvals

The [reusable approval follow-up](../../research/reusable-withdrawal-approvals-2026-11-06/RESULT.md)
retains owner-only exits and current nullifiers. A genuine accepted cohort-note
spend revokes that old intent even when sufficient other users' backing remains.
Off-chain cancellation/nonce replacement does not revoke published consent.
Removed historical anchors or unavailable parameters/history still require
recovery/refresh; this is not independent all-service-loss qualification.
