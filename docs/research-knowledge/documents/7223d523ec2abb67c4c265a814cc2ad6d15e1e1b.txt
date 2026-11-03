# Restricted-intent private batch relation

This implements the new research interface selected by
[RFC-0030](../../../docs/rfc/0030-private-batch-construction.md) and
[ADR-0074](../../../docs/adr/0074-private-batch-construction.md). It does not use
legacy financial keys or claim native acceptance, private proving or readiness.

`BatchCircuit` constrains three AK-bound notes and correct HMAC nullifiers,
depth-16 membership, six actual note commitments/value commitments, ciphertext
hashes, independently permuted whole NF/CV and Output520 rows, per-owner bounded
integer conservation, aggregate fee/reserve balance and canonical Delta group
balance. It hashes all three canonical 1460-byte intents and the complete
10364-byte public effect core inside the actual constraint system. Public NFs
are strictly increasing as little-endian 256-bit integers. Output order is
independent. Signing secrets are not inputs.

The native component has 201 instance columns: ONE, aggregate digest2, and
three sets of intent digest2/AK64 edges. `compose::join` keeps every native and
signature matrix row, term, coefficient and assignment independently, links
all 198 owner edges to three exact selected EdDSA components, and makes those
edges private. The final joined relation has only ONE and aggregate digest2
as its public prefix. A caller must pin the actual signature matrix/model and
new verification key; an arbitrary 67-input matrix is not a signature verifier.

The canonical new Output producer is the matching
[wallet/AuthExit package](../private_batch_trial/auth_exit). Its Output statement
uses `KPXAOU01 || D || CM || CV || CFhash` (168 bytes) and the selected fresh
D/setup/key. This aggregate crate supplies no competing Output setup. Recipient
invoice validation, actual seed-derived delivery/scanning and matching AuthExit
remain mandatory. Encryption correctness is not supplied by a CM/CV proof.

`Effects::validate_public_fields` performs the actual public current-context,
integer reserve/fee, canonical CV/Delta balance, ciphertext hash, indexed NF
nonmembership/insertion and empty-slot CM append checks. The selected **proved
R0 guest must execute these checks**, verify the aggregate proof and all six
real Output proofs. The covenant must check that selected guest/image/journal
and bind the actual native reserve input, output, state, policy and fee. An
ordinary host call to this function is only a public payload check. A missing
proved wrapper is a missing acceptance path, not an optional check.

The SHA implementation is copied byte-for-byte from the preserved NativeAuth
source, with its MIT notice. Native note tags, HMAC, membership and Pedersen
parameters/gadgets are adapted from that source. The mature signature circuit
is reused through its actual matrices; no new signature primitive is invented.

The ordinary Rust `ConstraintSynthesizer` is a clear synthetic construction
and model-generation interface. This crate does **not** implement private
client-to-slot routing, secret-shared SHA/EdDSA witness extension, a malicious
MPC prover, its release history, setup, or native settlement. A clear combined
assignment/WTNS is not a private witness generator. No such assignment may be
used as a replacement for the required private owner-input path.

Small tests check actual selector/range/comparison constraints, whole-row
binding, matrix admission/linking and byte offsets. They do not qualify the
complete batch, cryptographic correctness, anonymity, fees or recovery.
