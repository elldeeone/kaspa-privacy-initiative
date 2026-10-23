# ADR-0053: Private network recovery and local owner proving

**Status:** Accepted for a fresh TN10 research rehearsal; not production adoption.
**Date:** 2026-10-23 UTC. Baseline `2ee3e0850a277f2d4a2f512da67683540be01958`.

## Problem, reuse and alternatives

The new Auth528 private cashout works in supplied contexts. Independently fetched
backup-only recovery has reached confirmed payouts only through the older
revealing fallback. The next falsifiable target joins network discovery, private
ownership, local proving and native private payout in one fresh instance.

Reuse the unchanged ADR-0050 relation and native program, ADR-0052 public state
decoder, reviewed FullV2/header/transaction reconstruction and V2 recipient
derivation. Reuse established Groth16 public proving parameters and Arkworks
serialization with the authenticated-cache ordering in ADR-0045. The current
Kaspa and mature-protocol comparison in `privacy-recovery/SOURCES.md` applies;
no primitive, token, privileged exit or based-app requirement is introduced.
Operator snapshots cannot establish independent discovery. A hosted prover
receiving another owner's witness is rejected. Automatic revealing fallback is
rejected. Each owner instead runs its own local prover with authenticated public
parameters and fresh verified public history.

## Selected minimal rehearsal

Create a fresh private domain, notes, backup seeds, source clone, setup/VK and
immutable pool. Never fund the public AA development fixture, migrate a funded
instance, or load any earlier development/S7/AA proving key.

Directly found one whole Alice note from one ordinary test-KAS coin with explicit
ordinary change. Its value is two 60M-sompi claims plus the actual quoted P0 fee.
The existing founding path supports this shape, so prep and ADMIT are unnecessary
for this experiment. A P0 payment creates Bob and Charlie's two claims. Bob's
whole-claim private cashout continues the pool; Charlie's private cashout is
terminal. Actual integer fee/storage fixed points prevail over projections.

Before funding, complete a local four-body rehearsal with three genuine proofs,
native Full/all-input-engine validation, exact prior-output links, SDK lossless
roundtrips and terminal zero accounting. Bind its first input to the exact
prospective ordinary funding-merge output. Only after that merge confirms may
the operator publish founding and P0 once. Stop its prover before cold recovery.
Local precomputed exits remain excluded from every cold-client input.

Bob then independently fetches public records, recognizes with his own backup,
loads his own authenticated public parameters and generates a new private exit.
After its payout confirms, Charlie repeats from a new chain view. Confirm both
native payouts and a fresh public terminal zero-reserve replay. No REVEAL is
part of this rehearsal. Missing dependencies halt without disclosing a note.

## Public identity and parameters

The new descriptor is `kpx3-private-network-descriptor/v1`: exactly the nine
public identity fields of the approved new-program descriptor plus
`public_params_manifest_sha256`. Canonical recursively sorted JSON SHA256 is the
separately user-pinned descriptor identity. The founding outpoint selects the
instance; a matching domain/VK alone does not select among clones.

The public `kpx3-public-proving-parameters/v1` manifest binds network/genesis,
fresh domain, VK328 and its hash, exact uncompressed public-parameter length/hash,
core source identity, dependency lock/toolchain/build identity and measured
constraint shape. Its canonical hash is the descriptor's tenth field. Fetch and
replay may receive these small public manifest bytes to authenticate domain/VK;
they never read the proving-key blob. The manifest selects no executable or
archive. Trusted wallet software separately pins its prover/native executables.

Keep authority acyclic: fresh setup exports the parameter manifest; the cold
client embeds that selection; the wallet release pins the final client binary.
Do not put the final client hash back into its own manifest. Public parameter
mirrors are outside Git and are not operator state archives. Their availability
and development setup honesty are explicit assumptions.

## Owner, proving and native boundaries

Use separate new packages; keep all earlier frozen modules and packets unchanged.
Network replay independently checks canonical SDK IDs/headers, finite-frontier
coverage, all actual input contexts, consumed/current heads, every native payout
query and subsequent activity. It composes the unchanged offline public decoder
with fresh local native validation. Do not relabel its offline `complete:false`
as network completeness without these separate checks. Selected-node assertions,
retained history, development setup and correct receiver encryption remain trust
assumptions; multiple endpoints do not establish independent consensus.

Before reading an owner backup, validate public history, descriptor/manifest and
software. Execute authenticated immutable ELF snapshots, such as fully sealed
memfds; an opened pathname or inode alone does not prevent in-place mutation.
Launch the owner's local prover with an empty witness pipe. It authenticates the
selected manifest/core, hashes its entire owned parameter buffer before decode,
requires complete uncompressed decoding, and checks the extracted VK. Only its
matching `parameters-ready` response permits backup recognition/witness creation.
It then reads one strict `kpx3-private-action-witness/v1` message, proves, verifies
and stops. Fixed error codes/public output allowlists exclude seeds, s/k, note
openings, payout secret, and private witness bytes/hash/path.

For one full-claim exit, derive a recoverable payout scalar by HMAC-SHA256 with
the 32-byte owner seed as key and exact message
`KPX3PAY\0 || D32 || foundingOutpoint36 || CM32 || position:u32LE || retry:u32LE`.
Outpoint36 is txid raw32 followed by index:u32LE. Parse the digest as a secp256k1
scalar using the established library; reject invalid/zero scalars, never reduce
modulo the order. Advance retry until its x-only key also differs from every real
consumed note's emergency native key. This domain-separated application of the
existing HMAC/libsecp primitives avoids reusing invoice keys. Keep the payout
secret in the wallet; send only its canonical version-zero P2PK script to the
private circuit/native helper. It is recoverable from the backup and public
instance/owned-note context, not an issuance counter.

The keyless native helper quotes or verifies public Auth528/cipher528/update3344.
A placeholder quote must reach the expected Groth16 seam, never claim Full
acceptance. Bind the quote to the entire normalized body and all actual contexts,
not just v1 txid. Final proof substitution must preserve everything else and pass
native Full/all engines. Preserve both NF inserts, continuing two dummy appends
with genuine sealed-box padding and terminal complete zeros/no CM append.

## Scope and stop conditions

This tests one recognized claim per owner and full private cashouts; it does not
recover missing invoice issuance state or qualify general wallet behavior.
No private witness pooling, hidden payer, new principal, admin withdrawal or
mainnet broadcast is allowed. Strict theft/inflation/replay/state checks remain.
Operational limits are generous; failed trials use fresh identities without
rebroadcasting an already used identity. All failed attempts are retained.

The existing fee and privacy failures remain unchanged. This rehearsal cannot
establish general financial privacy, durable data/parameter availability,
independent consensus, setup soundness, p95/resource targets or production safety.
