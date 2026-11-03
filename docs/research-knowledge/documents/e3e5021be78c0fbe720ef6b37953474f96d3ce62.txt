# One-owner private cashout wallet

Status: interface aligned with accepted ADR0053, before implementation or setup.
All completed KPX2 recovery and Auth528 prototype files/packets remain unchanged.
This module never funds, broadcasts, creates a setup, or falls back to REVEAL.

## Small external interface

The new `poc/private-cashout-wallet/private_wallet.py` accepts one stdin JSON
request. Proposed operations are `recover` and `prepare-private-exit`. Common
inputs are one own seed-only backup path, the separately authenticated strict
ten-field descriptor/digest, fresh raw network fetch and a fresh private output
directory. Preparation also selects local paths for the authenticated mirrored
public parameter manifest/PK and installed proving/native/crypto executables,
plus a canonical integer fee rate. Paths do not select their expected hashes:
trusted software selection contains those hashes and the chosen parameter/core
identities. Descriptor schema/field spelling follow accepted ADR0053.

The descriptor's tenth field is `public_params_manifest_sha256`, under
`kpx3-private-network-descriptor/v1`. The owner authenticates the entire canonical
descriptor, including the founding outpoint/birth anchor. Matching D alone does
not choose a canonical funded instance.

No request accepts a snapshot, private fixture, expected amount, owned position,
note opening, precomputed exit, replacement PK/hash or caller-chosen destination.
The measured first private exit consumes one complete recognized actionable
claim. P is its locally derived value minus the quoted fee. The first actionable
position in ascending order is selected locally. General private change and
arbitrary external destinations remain outside this wallet interface.

## Private implementation seams

New modules are `private_wallet.py`, `private_action.py`, `owner_runtime.py`,
`owner_rules.py`, `receiver_tools.py` and `owner_selection.py`. Avoid colliding `replay.py`/`dependencies.py`
names. Import the new `private-network-recovery/network_replay.py` and exact
hash-pinned V2 receipt/tree utilities without mutating old module globals. New
source copies may adapt orchestration or pure tree-update code; the old wallet,
assembler, proof fixture parser and their constants are not patched.

The accepted method/source basis is the current Toccata/vProgs and mature
Orchard/Aztec/RAILGUN/Monero/MWEB comparison in
`../../privacy-recovery/SOURCES.md`, the ADR0050 Auth528 contract, ADR0051's genuine
sealed-format dummy correction and ADR0052's separate public semantic replay.
Reuse established SHA256/HMAC, supported crypto_box SalsaBox and libsecp256k1,
the unchanged V2 receive authority and the reviewed Auth528 relation. No new
primitive or hosted proving arrangement is introduced.

### Trusted software and public parameters before seed access

Copy every selected executable into an authenticated sealed memfd: hash the exact
copied bytes against fixed trusted selection, then add WRITE/GROW/SHRINK/SEAL
seals. Execute that descriptor through `/proc/self/fd/N` with explicit inherited
FDs. An opened ordinary read-only file is insufficient because its inode remains
writable. Sealing avoids both pathname replacement and in-place writes changing
the bytes that receive secrets. The selected software/selection itself remains
an owner-authenticated installation premise. This host's enforced bwrap policy
rejects direct memfd execution. The public network lane retained that failure and
demonstrated the unchanged sandbox executing the same sealed payload through the
pinned root-owned system dynamic loader. Use that route, with a fixed clean child
environment containing no LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH or PYTHONPATH.
System loader/shared-library integrity remains a separate runtime assumption.

All public source, descriptor, manifest, original private-path metadata and
fresh-output checks occur before reading a seed. Public replay is invoked from
the raw fresh fetch inside this client; it authenticates the new full policy,
every public transition/native body, current head and complete observed view.
Unverifiable/incomplete data halt before seed access. A node never supplies code
or executable authority.

For preparation, start the selected local prover with an empty witness pipe
before the backup is read. Its interface is:

```text
private-cashout-prover prove PUBLIC_PK WITNESS_FD NEW_PRIVATE_OUTPUT_DIR
```

It authenticates its compiled selection/core/build, the selected manifest, the
same-owned complete PK bytes, official decode/exhaustion and checked extracted
VK before reading witness input. It then flushes exactly one readiness line:

```text
event: parameters-ready
parameter_manifest_sha256, domain_hex32, vk_sha256,
compiled_build_identity_sha256
```

Match all four identities to trusted selection before reading the own backup.
Only then recognize receipts, construct/quote the private action and send its
strict private witness over the inherited FD. No witness path, bytes or hash is
logged or published. This handshake avoids loading/hashing the multi-GB PK twice.
Missing/corrupt public parameters are an explicit private-exit liveness failure;
they never trigger a new setup or a revealing fallback.

### Receipt recovery and recoverable payout key

Use one V2 seed-only backup and one recognition pass. Recompute every receipt's
invoice/keys/CM and positioned NF, including duplicate-but-actionable positive
claims. Construct membership and NF paths from the freshly replayed current
state. The legacy V2 sparse-tree compatibility types do not authenticate chain
acceptance by themselves; the new public replay is the prior acceptance gate.

ADR0053 freezes a new HMAC purpose separated from invoice `NATIVE`. Its exact
message is `b"KPX3PAY\0" || D32 || canonical_founding_outpoint36 || input_CM32 ||
position:u32LE || retry:u32LE`, keyed by the own root seed.
Use the first valid libsecp scalar whose x-only public key differs from the
consumed note's emergency native key. Reject invalid scalars without reducing
modulo the curve order. Retry starts at zero and is bounded by u32 encoding.
Do not use an issuance counter, random private-key log or the note-bound key.

The root seed remains in the wallet. The supported narrow crypto bridge receives
only the derived scalar needed for checked x-only conversion. Neither root seed
nor payout scalar reaches the prover or native transaction helper. The payout
secret need not be written: seed + authenticated history recover it. A later
rebuild derives this destination for each recognized historical CM/position and
matches actual public payout SPKs, including notes whose original NF is spent.
This covers the wallet's deterministic default destinations, not unrelated
externally chosen keys.

### Current action and local proof

Build one real input in slot0 and canonical dummy input in slot1. The real input
uses the recovered Note168, own s+k and current CM membership. The dummy uses
fresh secret key/seed and the established dummy-NF HMAC with slot1. Require
nonzero/distinct/currently absent NFs and authenticate both sequential linked-NF
updates against their exact roots. Resample only dummy entropy collisions.

For full-claim withdrawal, `P = noteV - f`, `R' = R - noteV`; all amounts use
explicit integer-sompi ranges and the payout floor. Continuing `R'>=60M` builds
two canonical zero-value output notes with independent fresh rho and distinct
CMs, two real SalsaBox sealed-format opaque dummy ciphertexts, and both actual
sequential empty-CM append paths. Dummy ciphertexts seal random216 to fresh
throwaway X25519 keys, following ADR0051. Terminal `R'=0` instead has complete
zero Note168 outputs, CM0/CM1, cipher528 and CM-append1024, preserves CM root/count
and still inserts both NFs. State112/domain/count/capacity checks remain exact.

The new strict private witness has schema `kpx3-private-action-witness/v1`,
`auth_hex528`, `inputs[2]`, `outputs[2]`. Each input has real, note_hex168,
s_hex32, k_hex32, position, cm_path_hex[16], dummy_key_hex32 and dummy_seed_hex32.
Each output has only note_hex168. No synthetic-public classification or old
secret fixture serializer is used for actual owner witnesses.

The public native helper receives current authenticated redeem/outpoint/UTXO,
Auth528, cipher528, public-update-witness3344, VK328 and proof128. Quote uses zero
proof bytes and proves only the intended public checks reaching Groth16 decode;
it cannot claim Full success. Iterate the actual native mass at the selected
integer rate before proving, keeping dummy material fixed during quoting.
The quote identity binds the entire normalized body/context/rate, normalizing
only proof128. A version1 transaction ID alone is insufficient.

After local checked proof generation, require identical Auth/VK, expected quote
identity, actual exact fee/payout/current input/successor and genuine native
Full/all-input-engine acceptance. The private branch has zero sig65 and a proof;
it does not use a native Schnorr signature. No operator-produced exit is loaded.

## Output and disclosure discipline

Only fresh0700 directories and0600 files outside Git contain owner output.
Never write a private witness, seed, s, k or payout scalar. The prover emits
only proof128, public Auth/VK and public parameter/source diagnostics to its
private output. Native bodies/context stay owner-controlled until submission.

Public stdout/export contains only public transaction effects/identities,
descriptor/software/parameter identities, native verdict and output path.
Do not publish owned input position, input CM, Note168, invoice index, note-native
key, membership witness or hashes of private witnesses/owner reports. Recognition
details remain owner-only. Review export separately before adding evidence to
Git; an owner-labelled execution report is not an input to the frozen privacy
observer projection.

Successful preparation returns `PROVED_NATIVE_FULL_VALID_UNBROADCAST`, requires
a fresh head check before submission, and never broadcasts. Root owns the one-use
submission and confirmed native payout check. After Bob, Charlie must get a new
descriptor-only chain fetch and authenticate the new head/NF paths.

## Falsifiable controls and limits

Test descriptor/software/manifest/readiness mismatch and incomplete replay before
seed; sealed-executable replacement/in-place mutation; exact key derivation and
cross-D/founding/CM/position separation; scalar retry/key inequality; owned/foreign/
duplicate/spent receipt handling; both sequential NF paths and stale/wrong roots;
terminal inactive zeros; conservation/ranges; quote/proof/context substitution;
private parser malformed/unknown/duplicate fields; and final Full rejection of
competing current-state spends. Reuse prior fixed relation controls without
claiming they prove cryptographic correctness. Meaningful actual proof/Full and
confirmed payout rehearsals remain required after source review.

The selected-node, retained-history, user-pinned descriptor and single-party
development-setup assumptions remain explicit. Public PK mirroring fixes access,
not setup trust. Ciphertext validity is still not proved to the receiver:
recognition covers correctly encoded/encrypted owned receipts, not all possible
maliciously undeliverable liabilities. Public payout/fee/timing/drainage and
counterparty records can still reveal amounts/links. This measured liveness
experiment does not qualify fees, population privacy, durable DA, independent
consensus, mainnet, production safety or fresh-machine performance.
