# Separate Spend and Output relations

Source preparation for ADR0063. No old financial identity, parameter or owner
backup is selected. Relation implementation starts after the agreed contract
review. This is an unfunded research prototype, not a security qualification.

The crate is `kpi-owner-private-relation` (`kpi_owner_private_relation` in Rust).
Host proving uses its default `prover` feature. Guests use
`default-features = false` for public codecs, verification and commitment helpers.

## Public statements

Every field is fixed width. Hash the complete statement with SHA256, then use
the first and last 16 bytes as two **little-endian 128-bit** BN254 Fr inputs.
Never reduce a complete 256-bit digest modulo Fr.

* Spend200: `KPX7SP01 || D32 || anchor_CM_root32 || original_NF32 || CV_in64 || effects_digest32`.
* Output168: `KPX7OU01 || D32 || note_CM32 || CV_out64 || SHA256(CF264)`.

Genuine Groth16 proofs retain the existing canonical compressed 128-byte proof
and 328-byte two-input VK conventions. Public parsing checks exact lengths,
canonical round trips, subgroup membership and nonidentity proof/VK points.
Spend and Output keys and the new domain are independently selected, never
provided as authority by a witness or proof.

There is no public note native key, owner/output subset digest, individual beta
or beta point. Spend proofs authorize the complete effects after mixing.
Effects include all complete Output tuples and their premix proofs, and omit
Spend proof bytes to avoid a self-reference. Valid proof-byte malleability for
unchanged financial effects is an explicit boundary.

## Commitments and balance

Use arkworks 0.6 Baby-Jubjub over BN254 Fr, stock Pedersen parameter generation
and stock fixed-base Edwards gadgets. A value commitment is `v*V + r*R`.
Its wire encoding is canonical uncompressed `xLE32 || yLE32`, 64 bytes.
The subgroup scalar modulus is
`2736030358979909402780800718157159386076813972158567259200215660948447373041`.
All 256 private blinding bits must satisfy `r < modulus`; do not rely on the
stock randomness gadget, which otherwise leaves unused upper bits.

Values retain the existing integer-sompi range
`60,000,000 <= v <= 2,870,000,000,000,000,000`.
Fixed subgroup bases and in-circuit equality to the computed commitment enforce
the commitment's group relation. Public point allocation alone does not enforce
prime-order subgroup membership. Native point decoding checks it explicitly.

Input CV blindings are fresh per Spend and attempt. They are not persisted in
the note or inherited from an earlier output. Each participant privately sums
`beta = sum(r_in) - sum(own r_out)` in the subgroup scalar field. The existing
checked private sum opens only global Delta. The native predicate directly
checks `sum(CV_in) - sum(CV_out) - fee*V == Delta*R`; there is no BindingSig.

## Private witnesses and delivery

Spend witness: existing Note168, owner secret32, nullifier secret32, position
u32, sixteen sibling hashes32 and fresh blinding32. Preserve the existing
SHA note/owner/key formulas, raw-CM Merkle leaves, and positioned HMAC-SHA256
nullifier. Constrain the high sixteen position bits to zero. The original NF
does not depend on session, attempt or effects, so retry cannot create a second
nullifier for the same note and position.

Output witness: existing Note168 and blinding32. The relation links its bounded
note value to both CM and CV and binds the exact CF hash in the statement.
It does **not** prove ciphertext encryption correctness. The recipient must
decrypt CF264, check the existing Receipt216, invoice, note CM and value, and
verify the genuine Output proof before accepting it. The output creator checks
its own CV opening. No new receipt field or blinding-key derivation is needed.

Private witness types must not implement Debug or Serialize. Private parse,
proving and filesystem errors must not echo witness bytes or values.

## Integration surface

Public: `SpendStatement`, `OutputStatement`, `Note`, statement byte codecs and
digest fields, canonical point/scalar codecs, `value_commitment`,
`check_balance`, `Verifier`, and canonical VK/proof codecs.

Prover feature: `SpendWitness`, `OutputWitness`, `SpendCircuit`, `OutputCircuit`,
independent setup/prove helpers, and strict private-request parsing. Runtime
requests select their relation role externally and cannot override it.

Complete anonymous output tuple520:
`CM32 || CV64 || CF264 || CFH32 || OutputProof128`.
Actual state/NF updates, empty-slot CM append checks, native reserve/fee effects,
attempt roster and duplicate/replay rejection remain independently enforced by
the native adapter and construction protocol.
