# Portable public recovery material for the compact batch

Status: ADR-0057 implementation released. Public structural capsule controls
have passed; actual new-role parameter copying, owner proof/native integration
and provider publication have not been executed in this lane.
Base: `a6fcdf1edd904dbe1bb395285230649b6c40d44c`.

## Research question and success boundary

Can a compact owner reconstruct and spend its backed claim when the original
operator files, original parameter cache and preferred public-data source are
absent, using its original backup and independently authenticated public data?

The preceding trial demonstrated fresh node acquisition and local proving, but
its 1,290,878,896-byte public proving parameters remained a locally available
dependency. Copying those bytes to another directory is artifact portability,
not independent-host/provider availability. The older [P10 investigation](../../../p10-recovery/ARTIFACT-AVAILABILITY.md)
shows why an exact public PK must be retained: a new setup/VK cannot recover an
old instance whose selected parameter bytes have disappeared. That is a dated
finding for the checked older instance, not a renewed availability claim.

This work has three separate evidence levels:

1. **Transport/integrity controls:** retrieve the exact public objects from a
   second source after the preferred source is unavailable; reject damaged,
   incomplete or substituted objects before touching a synthetic private-input
   sentinel. These controls do not execute a wallet proof or native settlement.
2. **Isolated artifact-loss rehearsal:** restore from the original own backup,
   a copied public capsule and separately selected software, with original
   operator/cache/source paths absent from the namespace. Authenticate the new
   compact PK before backup bytes, reconstruct the sparse state, generate a new
   proof and run native Full. Supplied-context results remain supplied-context
   results; a real network observation is identified separately.
3. **Durable independent availability:** separately operated hosts/providers
   retain and serve the exact bytes over time, with independently observed
   retrieval after loss. This needs real distribution and retention evidence.
   No result from two local directories, two processes or one host satisfies it.

The bounded implementation can advance levels 1/2 without claiming level 3.
No paid storage, external write, privileged exit or custom cryptography follows
from this proposal.

## Authority stays outside the mirror

The owner independently authenticates the selected instance descriptor and
software release. The descriptor binds network/genesis, D, founding outpoint,
initial complete program, both role VKs and role-specific public manifests.
Exact field names are coordinated with the new lifecycle/runtime; the compact
PK is the only proving-parameter dependency of an owner exit. A wide PK is not
required merely because the initial payer used wide32.

Use the existing SHA256/strict canonical-JSON identity pattern. A signature
would be useful only if its verification key were independently authenticated;
a signature or hash supplied by the same untrusted mirror adds no authority.
There is no new signing key or administrator recovery path in this design.

Separate the **static instance authority** from a **historical snapshot root**.
An externally selected capsule-root SHA identifies the exact object index used
in the bounded loss experiment. It does not prove accepted-chain inclusion,
complete history or currentness. Mutable historical packs can have new roots;
they never replace the independently pinned descriptor/program/parameter roots.
The original seed plus an attacker-selected descriptor is not an authenticated
instance selection. This public identity dependency remains explicit.

## Public capsule and API

The proposed `kpx4-public-recovery-capsule/v1` is one strict canonical JSON index
with exactly five typed object references. Every reference is `{sha256, bytes}`;
objects are stored as `objects/sha256/<lowercase64hex>`, without archive member
names, arbitrary paths, executable selection or secret-bearing free-form data.

| Object | Purpose and checks |
| --- | --- |
| descriptor | Exact independently selected instance; complete approved program/D/both VK roles, rather than matching substrings or dimensions. |
| compact parameter manifest | `kpx4-public-proving-parameters/v1`, role `compact2`, arity2, Auth `KPX4AU01`, selected D/genesis, exact PK/VK/source/build/query identities. A same-shaped manifest for another D/VK is rejected. |
| compact public PK | Exact role-manifest length and full SHA256. Consumer loader repeats owned-buffer authentication, Ark decode/exhaustion, extracted VK and dimensions before backup bytes. |
| historical records | Exact native transaction bodies and input contexts, with explicit synthetic/accepted-evidence provenance. Hashes verify retained bytes, not semantic validity or acceptance. |
| software inventory | Public source/release identities and required data formats. It cannot select an executable, shell command, import path or dynamic callback; trusted installed software selects the actual code. |

The index also has fixed schema/network/genesis/D/profile/role fields. Unknown,
duplicate, missing or role-inconsistent fields are rejected. The public package
must never include a backup, seed, private witness, receipt plaintext, owner map,
prepared unbroadcast alternative or hashes/paths of those private inputs.

Initial API, deliberately transport-only:

```text
stage_capsule(manifest, expected_capsule_sha256, independently_selected_anchors,
              mirror_object_roots, fresh_client_directory, forbidden_inodes)
  -> PUBLIC_CAPSULE_CONTENTS_VERIFIED_AT_COPY
```

`forbidden_inodes` comes only from metadata/stat of the one own backup before
any caller-controlled public read/hash. Reject symlinks, path traversal and
hardlink/inode aliases. A malformed public-object digest must not print the
actual unexpected digest: an incorrectly supplied private file must not become
a private-input fingerprint. Errors are fixed public categories.

Read small JSON objects into owned buffers. Stream the large PK into a fresh
private-stage temporary file while checking exact length/hash, then install it
read-only. Paths are not everlasting verification receipts. The owner loader
still authenticates its own complete PK buffer immediately before use. Host
and selected release-directory integrity during the operation remain the
explicit ADR-0054 premise; same-host malicious writers are not solved here.

A source unavailable/corrupt object can be retried from another mirror only for
the same expected digest/length. Never splice different objects, accept the
newest timestamp, lower an integrity check or silently select another setup.
The stage has no proof, key derivation, backup parser, native validator, RPC or
broadcast API.

## Sparse history and currentness

Lifecycle owns semantic reconstruction. Its proposed history schema is
`kpx4-compact-batch-history/v1`, with exact ordered native bodies/entries; replay
derives the mode, aligned start, ordered CMs/ciphers and roots from each body.
It does not trust capsule-provided append maps, owner labels or expected values.

After initial n1 and a wide32 append, actual output positions are32..63 and
cursor n64. Positions1..31 remain canonical empty CM leaves. Recovery must
preserve `position=start+i` for every emitted slot, including dummy output
records. It cannot compact receipt indices to1..32: the original positioned
real NF would change, breaking spend identity and potentially single-spend
reasoning. The new sparse view has `cm_cursor`, positioned deliveries, indexed
NF entries and derived state/reserve/outpoint. The old contiguous V2 Snapshot
is not claimed compatible without the lifecycle adapter.

The capsule result is never `current`, `complete`, `spendable` or `zero-balance`.
A separate acquisition/replay must establish a selected validating node's fresh
accepted prefix/suffix, actual input contexts, fixed frontier, removals, current
head/payout/spentness queries and post-query reconciliation. Current data must
join the reconstructed history without a gap or conflicting successor. Missing,
pruned, stale, truncated, reorganized or conflicting evidence is INCOMPLETE,
not a zero balance. Local native Full verifies supplied scripts/proofs; node
acceptance/currentness remains a separate selected-node trust assumption.
SDK transaction/header hashing does not independently prove PoW, GHOSTDAG,
accepted-ID inclusion or consensus.

No timestamp threshold or self-asserted `fresh:true` flag can promote retained
bytes into a current exit decision. Root's broadcaster still rechecks the actual
current UTXO immediately before its sole selected submission.

## Frozen fault questions before execution

The independent fault-review lane prepares an evidence-tiered matrix. Required
public-only controls include absent/corrupt/truncated PK/history objects,
wrong-root/D/role/VK/program/schema/reserved fields, same dimensions with wrong
identity, duplicate JSON names, path/symlink/hardlink aliases, source mutation,
and source failover to one exact valid object. All-invalid sources stop safely.

Currentness controls are distinct: an intact old capsule does not supply a fresh
head, missing suffix is incomplete, conflicting successor/reorg cannot be
ignored, and a previously unspent output later spent is not current. Those
controls require actual semantic/current-view verification rather than passing
transport hashes; a mock predicate is labelled as a mock.

Pre-backup-read controls use a synthetic non-seed0600 sentinel and, where
available, kernel `IN_OPEN` observation; private input contents/hashes never
enter public reports. These controls do not read real backups or PKs. Actual
new-parameter/owner/native integration waits for root release and the completed
role relation/native profile. Large file copies are scheduled outside setup/
proving peaks, with generous operational limits and exact evidence boundaries.

## Reused sources and unresolved requirements

Reuse [RFC-0008](../../../../docs/rfc/0008-independent-wallet-recovery.md)'s
dependency table, [ADR-0049](../../../../docs/adr/0049-receiver-driven-network-recovery.md)'s
accepted-record/current-view separation, [ADR-0053](../../../../docs/adr/0053-private-network-recovery-and-local-owner-proving.md)'s
parameter identity/pre-backup-read ordering, and its later ADR-0054 ordinary
trusted-release execution correction. Exact source refresh and mature-protocol
reuse/rejection remain in the new phase's source record. Do not reuse the old
contiguous history adapter or complete24417-byte policy gate unchanged for the
new compact profile.

Still open: actual independent public retention/distribution of the exact new
compact PK and retained history, authenticated instance bootstrapping for real
users, durable software distribution, and recovery when every available source
has pruned required ciphertexts. A state root alone cannot reconstruct missing
encrypted delivery data. The prototype can expose those dependencies and prove
bounded replacement of one source; it cannot manufacture their availability.
