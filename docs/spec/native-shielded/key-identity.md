# Portable verifier and native profile identity

[Draft scope](README.md) applies. The actual captured mathematical key replaces
the temporary **external** Rust Debug diagnostic as this draft's key identity.
It does not replace the existing proof transcript or implement a native importer.

## Fixed artifacts and identity

The [capsule](artifacts/fixed-post-nu6-2.vk-capsule.bin) is exactly 206,564 bytes.
Its standard SHA-256, the fixed `key_id`, is:

```text
743fa19c541fa2c7881c4ed0e3340c82d88780dbbc549cc2f3bfd982c2e517e0
```

It contains the actual Vesta VK, full fixed parameters, post-compression
constraint/query/permutation data and stored compatibility transcript scalar.
It contains no secret/proving key, witness or proof-specific challenge. The
[manifest](artifacts/portable-key-manifest.json) records exact layouts/counts;
the [source audit](../../../research/native-shielded-key-identity-sources-2026-11-04.md)
pins every relevant upstream file and the complete ordered format.

The native [72-byte ProfileRecord](artifacts/profile.bin), in exact order, is:

```text
ASCII("KNSPRF01")[8] || U16(1) || key_id[32]
|| U8(2 note_plaintext) || U8(3 flags) || U8(2 actions) || U32(7264 proof_bytes)
|| U8(32 tree_depth) || U16(1 effects_rules) || U16(1 forest_spentness_rules)
|| U16(1 proof_abi_rules) || U32(262144 max_tx_bytes)
|| U16(16 max_inputs) || U16(16 max_outputs)
|| U32(4096 max_script_bytes) || U32(4096 max_payload_bytes)
```

`profile_id = H("Profile",ProfileRecord)`; its exact computed value is in
[profile.json](artifacts/profile.json). Rule ID 1 means the algorithms in this
draft, including native complete-message authorization, immutable global
spentness, forest anchors and the exact proof ABI below. Changing those rules
requires a new explicit reviewed profile, not just reusing its ID. The activated
domain/profile/capsule are fixed consensus data; a structurally valid arbitrary
capsule supplied by a transaction is never an authorized key.

## Capsule format KASPVK01, schema 1

All lengths/indices are U32, rotations I32, other integers explicitly below.
`vec(T)` is U32(count) followed by ordered T records. There are no platform-sized
integers, algebraic rewrites, unordered maps, padding, implicit defaults or
trailing bytes. The following exact sequence is normative for this draft:

1. ASCII `KASPVK01`[8]; four U16 values all 1: schema, Vesta curve,
   FixedPostNu6_2 circuit, existing Blake2b/Challenge255 compatibility profile.
2. Vesta base modulus q[32], scalar modulus p[32] as unsigned LE integers;
   scalar ROOT_OF_UNITY[32], DELTA[32], ZETA[32].
3. U32(parameter_bytes), full upstream `Params::write`: U32(k), G[2^k] points,
   G_lagrange[2^k] points, W point, U point; no additional inner array counts.
4. U32(k), U32(extended_k), omega[32], extended_omega[32], g_coset[32],
   U32(quotient_degree), U32(CS_degree), U32(blinding_factors), U32(minimum_rows),
   actual stored compatibility transcript scalar[32].
5. Four U32 counts: fixed, advice, instance, original selectors; vec(U32) advice
   query counts per advice column; minimum-degree option U8(0) or U8(1)+U32;
   vec(U32) constant-column indices.
6. Three vec(QueryLayout), in advice/fixed/instance order. Each query is U32
   column index + I32 rotation; its vector index is its query index.
7. vec(vec(Expression)) preserving gate-group and within-group polynomial order.
8. vec(Lookup), each vec(Expression) inputs then vec(Expression) tables, equal
   paired arities.
9. vec(PermutationColumn): U8 kind (0 advice,1 fixed,2 instance) + U32 column.
10. vec(VestaPoint) fixed commitments then vec(VestaPoint) permutation commitments.

Expression tags: U8(0)+scalar constant; U8(1)+U32 selector+U8 simple flag
(forbidden in this post-compression key); U8(2/3/4) fixed/advice/instance query
with U32 query index+U32 column+I32 rotation; U8(5)+negated child;
U8(6/7)+left+right for sum/product; U8(8)+scalar+child for scaling. No ordering,
normalization or common-subexpression rewrite is allowed. Query AST tuples
must match their typed layout. Gate labels, dev selector maps and redundant
inverse/precomputation caches are excluded; mathematical verification data and
its derived counts/domain are included and checked.

Vesta is y²=x³+5, with base q and scalar/group order p:

```text
q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
```

Scalars are exact 32-byte LE values <p, never reduced on input or native machine
limbs. Compressed Vesta point is canonical x[32] over q with y parity in bit
255; zero encodes identity. Validate canonical curve encoding/re-encoding;
allow identity where this mathematical role permits it. Do not apply Pallas
recipient-key rules to Vesta VK commitments. Pallas reverses these field roles.
The fixed identity check additionally authenticates prescribed generator arrays;
passing a point decoder does not authorize arbitrary parameters.

Actual key: K11/n2048, extended K14, quotient degree8, CS degree9, blinding5,
minimum rows8, fixed29/advice10/instance1, 56 original selectors, 55 gate groups/
193 polynomials, three lookups, query counts 25/29/1 and 15 permutation columns
with chunk length7. Embedded parameters are 131,140 bytes with SHA-256
`1eab6f93a080ce41b908d935c04bd2e3ed1ac23f277c15d11c499d56d28fa0f7`.

## Preserve the real proof transcript

The actual compatibility scalar, at capsule offset 131440, is:

```text
71522dd31238af3da22e6d9acbec2d03e0fedf2688553cf3be0bbe598fd4f70b
```

Upstream currently derives it by reducing BLAKE2b-512 personalized
`Halo2-Verify-Key` over `U64(debug_byte_length)||Debug(vk.pinned())` into p.
That derivation is **not** portable serialization. The capsule captures its
actual stored value as explicit fixed field data; another language uses those
bytes without reproducing Rust formatting. Never substitute key_id/profile_id
for this scalar. The [description text](artifacts/upstream-pinned-key-description.txt)
is provenance only, not the capsule or a native format.

Proof ABI 1 is the complete pinned Halo2 0.4.1/Orchard verifier schedule, with
exactly two ordered Action instances and canonical 7,264-byte proof. Each
instance is one column with anchor, cv.x, cv.y, nf, rk.x, rk.y, cmx,
enable-spends=1, enable-outputs=1, disable-cross-address=0. Use the source's
Lagrange instance commitment including `Blind::default()=1` times W; dropping
that term is incompatible. All public tuple components use their exact field
maps and order. Native b is enforced by binding authorization, not an extra
invented Halo2 public-input row.

Transcript uses the pinned Blake2b-512/Challenge255 schedule and personalization
`Halo2-Transcript`: common scalar absorbs tag2+canonical scalar32; common point
absorbs tag1+x32+y32 affine coordinates (identity rejects in that transcript
role), although proof-read points remain compressed32. Squeeze appends tag0,
finalizes a clone and reduces all 64 digest bytes into p; do not absorb the
derived challenge as if read from the proof. Preserve commitment/evaluation/
permutation/lookup/opening order, challenge powers and exact polynomial/IPA
equations from the pinned source. The [source review](../../../research/native-shielded-key-identity-sources-2026-11-04.md#exact-transcript-compatibility-obligations)
identifies those exact files. Single-proof/individual signature verification is
the reference; unspecified host-RNG batching is not consensus acceptance.

## Export and validation evidence

The [diagnostic exporter](key-export/README.md) applies a retained, feature-gated
read-only patch **only to copied pinned sources**. It exports actual key data,
checks scalar provenance and preserves the old diagnostic fingerprint. Two
processes produced identical bytes and reverified all three existing complete
synthetic bundles. Python independently checks full framing, field/curve roles,
domain/query/AST/degree relations and fixed identity, with negative controls.
Original interop source/lock/cache remain unchanged.

This is not a portable VK reader wired into Kaspa or an independent Halo2
implementation. A native backend must import this exact capsule or deterministically
rebuild and fail closed unless its actual exported mathematical identity equals
it; a formatting-dependent upstream rebuild may need an explicit scalar-aware
import path. Complete cross-backend proof verification and independent
cryptography review remain gates. The capsule schema and diagnostic IDs are
proposed research formats, not allocated network/opcode numbers.
