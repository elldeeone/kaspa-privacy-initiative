# RFC-0004: Candidate private-payment primitive suite and public intent bytes

Status: Open, 2026-10-18. Implementation/review package for
[RFC-0003](0003-private-payment-proof-and-settlement.md), under
[ADR-0018](../adr/0018-private-payment-implementation-package.md).
This candidate has a separate-agent design review for unfunded offline work.
It is not an accepted private wallet circuit or native deposit contract.
Code-level proof review, native binding and actual artifact identities remain
required. Testnet execution is owner-authorized once actual proof/native
prerequisites qualify; no mainnet or real funds.
The separate-agent AI review and its precise offline scope are recorded in
[ADR-0019](../adr/0019-separate-agent-prototype-review.md). This route does not
supply external human audit assurance or close native qualification.

## Primitive choices for review

- Orchard 0.16.0, exact commit `616a669df8c9a59c33d47064d3ce04b25d026b2e`.
  Existing public APIs only; no new curve/hash/AEAD/key-derivation primitive.
  V2 notes exclusively, repaired post-NU6.2 relation obligations, Pallas checked
  encodings, established spending/full-viewing/incoming hierarchy, depth-32
  Sinsemilla tree and exact note-derived nullifier. Unsupported V3 rejects.
- Require private knowledge of the full Orchard spending key and derive the
  full recipient ownership relationship. No view key or dummy spend can
  authorize another user's note or pending deposit. Initial wallets retain a
  separate independently generated spending key for the pool; seed-only
  recovery or a novel cross-pool master KDF is not introduced here.
- Incoming delivery is the complete 580-byte V2 encrypted note plus its
  32-byte ephemeral key. `rho_new[i]` is exactly slot `nf[i]`. The selected
  algorithm derives the ephemeral secret from the same seed/rho. Prove the
  entire encryption computation and ciphertext equality; trial decryption
  independently validates the recovered note. No outgoing-viewing ciphertext
  is delivered in this initial profile. That omits outgoing audit recovery,
  not incoming receipt/current spentness reconstruction. This choice requires
  composition review; it is not an unchanged Orchard bundle.
- A note value is integer sompi in u64, with checked u128 two-slot sums.
  Two action slots/dummy rules and the explicit `exit_only` adaptation preserve
  the obligations in RFC-0003; neither is established by the primitive checks.
- Recovery signatures use strict Ed25519 over the fully tagged canonical
  credit/refund tuples from RFC-0003. Exact native descriptor-to-outpoint/key
  binding remains an explicit unresolved native design requirement.
- Wallet proof candidate: RISC Zero 3.0.3 proving the full ordinary computation,
  followed by a total ordinary verifier in the outer application. The proven
  program/verification/control identities must be generated and reviewed from
  actual builds, never filled with a fabricated ID. The small proxy circuit or
  proof that a fixed public test vector computes correctly does not implement
  the private wallet relation.

The exact established algorithms are referenced by source, rather than
reimplemented as new cryptography. The package pins direct/transitive versions
for its existing-library checker. Independently reviewed wallet and outer
program artifacts, private witness packing, final native descriptor/script
binding and a full implementation are still separate deliverables.

## Candidate public intent encoding

Encode the fixed ASCII tag `KPI/private-payment/intent/v1` verbatim, followed by
the fields below in order. Integers are unsigned, fixed-width little endian.
There is no JSON serialization inside the consensus bytes. JSON hex in the
review tooling is lowercase without `0x`; it is only a human-readable fixture
boundary. A decoder rejects trailing data, unknown enums/flags, overlong/truncated
values and all semantically irrelevant kind fields.

| Field | Exact bytes |
| --- | --- |
| `G_hash`, `D`, `network_genesis`, `pool_id` | 32 each |
| `lane_id` | 20, the full native subnetwork/lane identifier |
| `statement_id`, `proof_suite_id`, `wallet_program_or_vk_hash` | 32 each |
| `operation_kind` | u8: CREDIT=0, TRANSFER=1, EXIT=2 |
| `append_mode` | u8: full=0, exit_only=1 |
| `expiry_order_bound` | option flag 0/1; if present, u64 ordinal |
| `anchor` | 32, checked canonical Orchard anchor by the actual relation |
| `nf` | two 32-byte values, slot order |
| `cmx_new` | two 32-byte values, slot order |
| `ephemeral_key` | two 32-byte values, slot order |
| `ciphertext` | two fixed 580-byte incoming ciphertexts, slot order |
| `deposit_reference` | flag 0/1; if present: native txid32, output index u32, descriptor hash32, recovery public key32 |
| `deposit_principal` | u64; zero if absent |
| `exit_script` | flag 0/1; if present: script version u16, byte length u32, script bytes |
| `exit_principal` | u64; zero if absent |
| `fee_script` | flag 0/1; if present: script version u16, byte length u32, script bytes |
| `private_fee_sompi` | u64; zero if absent |

Scripts in this candidate encoding have 1–10000 bytes. This is a review-profile
bound, not a claim about current relay/mass/consensus acceptance. Actual native
limits, destination validity, fee/rent and script version support still qualify
at P4. Empty present scripts reject. Optional absence has one encoding and is
distinct from a present zero expiry. A fee script is present exactly when the
fee is positive. CREDIT requires deposit presence/positive principal, no exit
or fee, and full mode. TRANSFER forbids deposit/exit and requires full mode.
EXIT requires a positive exit principal and destination, no deposit; it may use
either mode, with the zero-new-values predicate enforced in its private proof.

`intent_id = SHA256(the complete bytes above)`. The actual proof must bind its
entire fixed journal to that digest and descriptor/artifact IDs; hashing these
bytes alone does not establish spend authority or current state. Nullifier
uniqueness/spentness and point/scalar validity remain mandatory actual relation/
transition checks even when the public codec accepts structurally valid bytes.

The candidate deposit reference binds a **descriptor hash**, not an invented
native covenant encoding. The outer adapter must recompute it and authenticate
the exact recovery key/principal against the actual deposit outpoint. Until
the full descriptor/native binding is specified, reviewed and implemented, a
codec result cannot authorize CREDIT or refund. Golden fixtures use explicitly
synthetic descriptor/program IDs and cannot be deployed as a private pool.

## Review evidence and remaining gates

The existing-library vector checker compares public Orchard key/note/nullifier,
encryption and tree vectors against the pinned upstream implementations. A
separately pinned Zcash Python reference produces depth-32 path fixtures.
The Rust-embedded and Python encryption corpora differ in rho and derived
ciphertext bytes; both complete corpora are checked rather than reported as
identical. Primitive interoperability is not a soundness proof of a new circuit.

The owner-selected separate-agent design review and corrected C1–C4 findings
are recorded in [the review result](../../poc/private-payment/REVIEW-RESULTS.md).
It permits unfunded offline P2 implementation of the specified relation with
synthetic policy/deposit fixtures. Actual guest/outer enforcement, native
descriptor linkage, proof artifact IDs and code-level qualification remain
unimplemented or unqualified. External audit remains unavailable. No full P1
completion or native trial readiness follows from this design review or codec
tests.

## Candidate recovery-signature validation profile

P1 additionally qualifies an **isolated public-vector checker**, not a wallet
or refund implementation, using `ed25519-dalek 2.2.0` and
`curve25519-dalek 4.1.3`. The upstream release tag `ed25519-2.2.0` resolves to
`8016d6d9b9cdbaa681f24147e0b9377cc8cef934`. Use plain Ed25519 with SHA-512 as
defined by RFC 8032, not Ed25519ph/ctx or a signature over an implicitly
substituted prehash. Disable `legacy_compatibility`, batch and hazmat features.
Direct and transitive dependencies are locked separately from the previously
proved Orchard experiment; do not rewrite that experiment's locks or evidence.
Curve25519-dalek 4.1.3 has its own release commit
`5312a0311ec40df95be953eacfa8a11b9a34bc54`; compiled curve source is checked
against that commit, not the later curve code in the Ed25519 release checkout.

The candidate profile checks these public bytes before calling the established
`verify_strict` implementation:

1. Public key length is 32 and signature length is 64.
2. Decode key `A` and signature point `R` with the existing Edwards point APIs;
   recompression equals the original bytes. Comparing `VerifyingKey::to_bytes`
   to its input is insufficient because that type preserves the original
   encoding. Reject identity/small-order and non-torsion-free `A` and `R`.
3. Parse the signature's final 32 bytes using the established canonical scalar
   decoder (`S < l`); then require `verify_strict(message, signature)` success.

This selects a deliberately restricted validation profile for review. It is
not a claim that every signature accepted by other Ed25519/ZIP-215 verification
rules must be accepted here, or that strict verification alone supplies every
canonical-input rule. No signing/hash/group algorithm is reimplemented.

The CREDIT signing message is exactly raw ASCII `KPI/credit-recovery/v1`,
then `G_hash[32]`, then `intent_id[32]`, with no length prefixes or JSON. The
signature is outside the intent bytes. Its verification establishes only
authorization of that intent by the supplied key. The actual wallet and outer
composition must still authenticate that key to the same pending native
deposit and serialize/validate the public authorization envelope consistently.
No signature alone prevents replay, proves reserve backing or decides a
credit/refund race. Refund tuple encoding/rent semantics and actual proved
credit/refund integration remain open.

Required checker cases, declared before implementation: published RFC 8032
Ed25519 signing/verification vectors; changed message/key/R/S; wrong-length
inputs; identity and all eight torsion points; canonical/noncanonical aliases;
mixed-order keys/R; S equal to or above the group order; key or intent/domain
substitution; correct CREDIT byte agreement between independent encoders.

## Candidate private witness packing for review

This section fixes the reviewed bytes. The subsequent [offline wallet prototype](../../poc/private-payment/WALLET.md) implements them; actual proof/code
qualification is recorded separately and does not qualify native backing.
Logical public I/auth bytes and private note secrets share this VM input frame;
the public fields are not promised secrecy by their placement in the stream.
The proposed private VM input is the raw ASCII
`KPI/private-payment/witness/v1`, then u32 length + complete canonical intent,
followed by exactly two old-note records and exactly two new-note records in
action-slot order. The length-prefixed intent must itself consume its complete
frame. All integers are unsigned little endian; no trailing bytes are allowed.

Each old-note record is `spending_key[32] || scope_u8 || diversifier[11] ||
value_u64 || rho[32] || rseed[32] || membership_option`. Scope is External=0 or
Internal=1. The relation derives the full key/address from this same spending
key, scope and diversifier; callers cannot supply trusted derived key material.
Membership option is exactly flag 0 for a zero-valued dummy, or flag 1 followed
by `position_u32 || sibling[32][32]` for a positive real note. No independent
real/dummy flag exists. A dummy still reconstructs a valid zero-valued note and
its dependent nullifier; it skips membership only. A real note cannot omit its
path. The relation verifies all of RFC-0003's key/point/range/nullifier rules.

Each new-note record is `raw_recipient_address[43] || value_u64 || rseed[32] ||
memo[512]`. There is no supplied new rho or ephemeral secret: rho derives from
the corresponding public input nullifier, and the established V2 API derives
dependent randomness. The proved computation must reconstruct the exact note,
ephemeral key and complete delivered ciphertext. `exit_only` still supplies and
checks both zero-valued outputs; it does not omit their data or predicates.

Finally encode recovery authorization as flag 1 + signature[64] for CREDIT,
and flag 0 for TRANSFER/EXIT. This is witness material, not a substitute for the
required canonical public operation envelope. These exact bytes must equal the
actual public operation's authorization through the following journal binding;
some different signature in the VM input cannot validate arbitrary public auth
bytes. Reject unknown flags, wrong kind/presence, truncation and trailing bytes.

`authorization_digest = SHA256(raw ASCII
"KPI/private-payment/authorization/v1" || canonical_auth_bytes)`.
The guest checks CREDIT's strict signature over the unchanged G_hash/intent_id
tuple using those same auth bytes, then commits their digest. The outer derives
it independently from its actual accepted public envelope and requires complete
journal equality. Authorization remains outside the signed intent, so its
signature never signs itself or the resulting proof/native transaction ID.

The candidate wallet journal is raw ASCII
`KPI/private-payment/wallet-journal/v1`, then `G_hash[32]`, `statement_id[32]`,
`proof_suite_id[32]`, `wallet_program_or_vk_hash[32]`, `intent_id[32]`,
`authorization_digest[32]`.
It exposes no keys, note values, paths or memos. The outer verifier must enforce
the complete journal equality and immutable descriptor/suite policy. A wallet
guest must **not** hardcode its own image hash: build it first, then bind its
actual image in descriptor/outer-verifier policy. An image containing its own
hash would introduce a build-time cycle. These bytes are proposed review
inputs, not accepted proof artifact identities.

The guest is generic and enforces this fixed cryptographic profile; it binds
context bytes without authenticating a pool policy or its own image. The
**proved outer transition** must authenticate policy from its authorized state
and compare G_hash, D, network genesis, pool ID, lane ID, statement ID, suite ID
and wallet image to it, including verification against the actual admitted
receipt image/parameters. Never select spentness using caller-chosen D before
those checks. Offline policy fixtures are explicitly synthetic. Unknown actual
native descriptor/artifact fields cannot pass native acceptance. This assigns
admission without adding a descriptor to the private witness or a self-image
hash to guest code; it does not claim native bootstrap is implemented.

## Native deposit binding: source result and unresolved design

At vProgs `f9b84a863a7c7c20586a9cf947550475e894f72e`, the example deposit
policy pays the P2SH of a 53-byte delegate-entry script derived from covenant
ID. Its action parser authenticates the funding output from the **same native
transaction**, with script version 0, exact script bytes and actual value.
The script contains no per-deposit recovery key. The example's user/action lock
is not automatically the independent recovery authority proposed here.

Current Rusty Kaspa `f7d7877363fb97c2ec6871be0e8cbc351d44df10` sighash source
commits to the payload hash as well as subnetwork and outputs. This supports
studying a stable, funding-transaction-carried deposit registration. It does not
by itself prove a new descriptor is recognized by our outer/native relation.

The leading **unimplemented candidate** splits (a) stable deposit terms carried
by the funding transaction, from (b) its reference, derived after the native ID
is known. Terms would bind the immutable pool context, output index, exact
principal, deposit script/version and recovery public key. The outer relation
must derive the actual outpoint and authenticate these same bytes from accepted
funding data. Putting that funding transaction's own ID inside the descriptor
in its payload would create a hash cycle; do not do that. A caller-provided
descriptor hash or metadata attached only to a later CREDIT is not authority.

Alternatives remain: a per-deposit script that commits the key, or another
proved native binding. Reusing the shared delegate address plus unrelated host
metadata is rejected as insufficient. Separate stable registration from inner
wallet-proof support so an unsupported/bad CREDIT proof leaves a recognized
pending deposit recoverable. No direct owner-key bypass may spend the deposit
after it has been credited. One current pending record must arbitrate CREDIT
and refund across restore/batches; actual native consumption and paid evidence
must still prevent duplicate payout. Final descriptor bytes, script recognition,
rent accounting, bootstrap identity dependencies and the native proof adapter
remain explicit P1/P4 review/implementation questions.

Primary references: [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032),
[pinned Ed25519 verifier](https://github.com/dalek-cryptography/curve25519-dalek/blob/8016d6d9b9cdbaa681f24147e0b9377cc8cef934/ed25519-dalek/src/verifying.rs),
[pinned deposit policy](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/runtime-processor/src/deposit_policy.rs),
[pinned deposit action](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/runtime-processor/src/action/deposit.rs),
[pinned delegate bytes](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/abi/src/delegate_script.rs),
[pinned native sighash](https://github.com/kaspanet/rusty-kaspa/blob/f7d7877363fb97c2ec6871be0e8cbc351d44df10/consensus/core/src/hashing/sighash.rs).
