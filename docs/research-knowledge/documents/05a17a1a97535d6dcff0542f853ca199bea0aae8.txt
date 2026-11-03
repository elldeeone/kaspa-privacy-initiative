# Cold owner prover and public proving parameters

Implemented under ADR-0053 and its ADR-0054 execution amendment; see
[measured results](RESULTS.md). The completed AA source, parameters and packets
remain immutable. This lane performs no funding or network action.

The owner should recover a private note, authenticate a mirrored public proving
parameter artifact, prove locally and submit only the proof/public transaction.
No hosted prover receives s, k, incoming secret, note openings or CM paths.

## Relation and parameter authority

Clone the existing Auth528 library into this new package, changing only its
compile-time D to the fresh trial D. Preserve the established SHA/HMAC,
integer/range, original-NF, current-CM, payout/terminal and key-inequality relation.
No old/AA/S7 PK is mounted, read or loaded. New D changes matrices and requires
one fresh setup, under explicit root release, for the complete local rehearsal.

The resulting public parameter manifest binds:

- Schema, fresh trial identity, TN10 network/genesis and D; exact
  relation/compiler/dependency identity.
- VK328 and its SHA256, PK byte length and full SHA256.
- Official Arkworks 0.6 uncompressed encoding, curve, measured constraint shape
  and checked actual query dimensions.
- Exact fresh setup software/build provenance, and fresh setup report SHA256.

The manifest is public data; it cannot authorize itself. The selected owner
software embeds its exact root-selected SHA256 and VK328. A changed runtime
sidecar or caller-provided expected PK digest cannot replace those compiled pins.
Export recursively sorted compact JSON without a trailing newline and require
that exact canonical representation; raw and canonical SHA256 are then equal.
Mirrors need no authority and may disappear without changing authenticity.
Parameter availability remains a liveness dependency: owners need any matching
copy and should retain one locally.

## Software authentication boundary

A program cannot prove its own authenticity by hashing itself and trusting a
sidecar delivered with it. Avoid a circular manifest that contains the hash of a
binary which in turn embeds that same manifest hash.

Use two acyclic selections: first root selects the fresh parameter manifest;
then compile the cold client with its manifest/VK pins and publish its exact
executable SHA256 in the wallet's trusted software selection. The wallet launcher
authenticates that executable before deriving a private witness or launching it.
ADR-0054 selects ordinary executable files in dedicated mode-0700 releases,
mode-0500 binaries, complete SHA256 before launch and read-only sandbox mounts.
The host and release owner are trusted to keep that file and pathname unchanged
through execution. This does not protect against a malicious host/inode writer.
The initial sealed-snapshot proposal was superseded; this lane executed no
special executable-FD/system-loader launch and changed no host policy.
The client additionally compares its compiled core/Cargo.lock/build identity to
the selected parameter manifest before accessing witness input. Self-executable
hashing may be retained as evidence, but is not a new trust root. Replacing both
wallet and trusted selection is outside this cryptographic loader boundary.

## Proposed process API

Selected API:

```text
kpi-private-cashout-setup session PRIVATE_SHAPE_JSON NEW_SETUP_DIR NEW_PUBLIC_PK
kpi-private-cashout-prover loader-only PUBLIC_PK NEW_PUBLIC_REPORT_DIR
kpi-private-cashout-prover prove PUBLIC_PK WITNESS_FD NEW_PRIVATE_OUTPUT_DIR
kpi-private-cashout-prover verify PUBLIC_AUTH PROOF128
```

Setup is a separate unselected development executable. It creates a fresh PK
with OS randomness, serializes official uncompressed bytes directly while the
key is resident, writes mode 0600 outside Git without overwrite and fsyncs file
and parent. Its session can prove the complete local rehearsal before exit.
The cold client has no setup, alternate-key or generic unchecked-decode switch.

For `prove`, parse only public command arguments first. Validate compiled
selection and selected public manifest, then read the PK into one owned bounded
buffer; authenticate its exact length and complete SHA256 before the sole
private trusted-input uncompressed decode. Require full exhaustion, release the
encoded buffer and compare the extracted VK using the existing checked decoder.
Only then emit and flush one public JSON readiness line:

```json
{"event":"parameters-ready","parameter_manifest_sha256":"...","domain_hex32":"...","vk_sha256":"...","compiled_build_identity_sha256":"..."}
```

The wallet launches this client with an empty witness pipe before reading its
backup. It checks all four ready identities against trusted selection, then
reads its own backup, quotes the exact native fee, creates the private witness
and writes the pipe. Only after readiness does the client read WITNESS_FD and
parse the private request. This authenticates actual loaded parameters before
seed processing without loading the multi-GB PK twice. Prove with OsRng and
verify with the selected VK locally. Emit only proof128/public Auth528/public
diagnostics to a new private mode-0700 directory, never witness/secrets. Public
reporting is an explicit redaction/export step owned by the caller.

Use the selected software/parameter provenance in reports. Do not log the witness
FD bytes or include witness hashes in public output: a hash can become a
confirmation channel for low-entropy private content. Command arguments carry
no note openings or secrets. The loader itself makes no network calls.

The strict private request has `schema: kpx3-private-action-witness/v1`,
`auth_hex528`, exactly two `inputs`, and exactly two `outputs`. Each input has
`real`, `note_hex168`, `s_hex32`, `k_hex32`, `position` (u32), `cm_path_hex`
(exactly 16 hashes), `dummy_key_hex32`, and `dummy_seed_hex32`. Each output has
only `note_hex168`. Reject unknown fields, duplicate fields, uppercase or
noncanonical hex, wrong widths/arity, and trailing payload. D is already bound
inside Auth528 and checked against the compiled fresh D; no duplicate D field is
needed. The root seed and payout private key never reach the prover. Local
resident rehearsal labels are `spend`, `bob-full`, and `charlie-terminal`.

Do not copy the old fixture generator/serializer or cache CLI. The old synthetic
fixture serializer intentionally contains every note secret, and the old cache
CLI parses and hashes its public synthetic fixture before loading parameters.
Only the reviewed cache ownership/authentication boundary is reused. New private
errors expose fixed stage/error codes, not raw serde payloads or Debug values.
Prove output files are mode 0600, created without overwrite only after checked
verification; the atomically created output directory is mode 0700.

## Required controls before adoption

1. Unselected pins, malformed manifest/unknown fields, wrong D/source/Cargo.lock,
   wrong VK/arity/encoding and wrong selected manifest SHA reject before witness
   input is read. Instrument a test reader to make this order falsifiable.
2. Truncated, extended, same-length mutated and wrong PK reject before decode;
   one authenticated owned buffer prevents file-replacement TOCTOU. Any trusted
   decode requires the exact compiled selected digest, not just an embedded VK.
3. A correctly authenticated cache with the wrong extracted VK rejects. Test this
   with a small independent Arkworks test relation/key, never an old PK. This
   small test setup also waits for the root's ADR/API release; it is not the
   selected full-relation setup or a parameter authority.
4. A tiny fresh test key exercises actual official serialization/load/prove/
   checked verification and malformed request handling. It does not substitute
   for the eventual full-relation cold owner proof under the fresh native VK.
5. Test private canary bytes and their hashes never appear in success/failure
   stdout, stderr or reports. Test output permissions and no-overwrite behavior.
6. Test the actual cold client/wallet software hash mismatch before seed/witness
   processing. Source review must establish that arbitrary caller-supplied
   manifest/hash metadata cannot authorize the decoder.

No setup/proof is run before exact source/fixtures and the fresh authority are
reviewed. Use a small offline compile allocation first, then coordinate the sole
fresh full setup/proof and cold loads with root. Operational measurements remain
single-run evidence unless a separate qualification sample is selected.

## Reuse and limitations

This adapts the existing ADR-0045 authenticated cache boundary and official
Arkworks serialization. The private relation is the completed ADR-0050 relation
under fresh D; Orchard/Aztec/source comparisons already retained there remain
its research basis. Neither reuse nor passing controls establishes cryptographic
security. A single-party development setup retains its setup-trust assumption;
mirroring its PK does not create a multiparty ceremony. Current native absence,
accepted ancestry, recipient decryption, node data and transaction confirmation
remain independent checks.
