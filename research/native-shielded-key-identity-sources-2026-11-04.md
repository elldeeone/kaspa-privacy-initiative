# Portable identity for the repaired Orchard Halo2 verification key

**Reviewed:** 2026-11-04, from repository baseline
`3d17324e2145f2d7116a605502eb70a8151b0a2c`. **Scope:** internal AI primary-source
audit, diagnostic export and format conformance for the native specification.
This is not external cryptography approval, a native verifier implementation or
activation. No funds, RPC, new proof creation or proving-key ceremony was used.
The tracked interop crate, its lockfile and original dependency caches were not
modified. Diagnostic changes were applied only to copied sources outside Git.

## Recommended decision and computed identities

Use a **canonical structured capsule of the actual mathematical key,
parameters, constraint/query/permutation data and the existing transcript
scalar**. Pin its SHA-256 in the native profile/activation record. Do not call
the previous Rust Debug hash a portable VK, hash only source identifiers, or
replace the current Fiat–Shamir input with this new capsule hash.

The source-bound export is now concrete:

| Item | Value |
| --- | --- |
| Capsule schema | `KASPVK01`, schema 1; diagnostic research IDs, not allocated Kaspa consensus identifiers |
| Capsule bytes | 206,564 |
| `vk_id = SHA256(capsule_bytes)` | `743fa19c541fa2c7881c4ed0e3340c82d88780dbbc549cc2f3bfd982c2e517e0` |
| Embedded parameter bytes | 131,140 |
| `params_id = SHA256(params_bytes)` | `1eab6f93a080ce41b908d935c04bd2e3ed1ac23f277c15d11c499d56d28fa0f7` |
| Existing compatibility transcript scalar, canonical LE32 | `71522dd31238af3da22e6d9acbec2d03e0fedf2688553cf3be0bbe598fd4f70b` |
| Scalar offset in this capsule | 131,440 |
| Preserved previous Debug diagnostic hash | `eafbdf6694e6da29789e105a15ce9509b957dd9f5ca3a1fa4c468bb6546686af` |

Two fresh helper processes produced identical capsule bytes. The copied-source
verifier also accepted the three **existing synthetic** deposit, transfer and
withdrawal bundles, with the original diagnostic hash unchanged. An independent
Python decoder checked framing, canonical curve/field encodings, domain and
query/AST/degree consistency, and the captured scalar's provenance. This is
export/conformance evidence, not an independent implementation of Halo2.

## Exact source authority

| Component | Inspected identity |
| --- | --- |
| Orchard | `616a669df8c9a59c33d47064d3ce04b25d026b2e`, crate 0.16.0, `FixedPostNu6_2` |
| `halo2_proofs` | 0.4.1; crate checksum `d886268046f1ceedd464c95382a64c7e86520b029b18e02ee92bf94f5120817d`; crate VCS commit `8fa89d972dab7ee7314b5e1564e35edb5086f955` |
| `pasta_curves` | 0.6.1; crate checksum `a0ed53ba43531a06e1f82020907cf192fc3c25d7c0baf5c49c547b74e7103b62`; VCS commit `674bf82910d19fefdcad323d7dd05e8c77baa0bd` |

The two cached crate archives matched the existing interop lockfile checksums.
Thirteen critical Halo2 registry source files were compared byte-for-byte with
the official repository at the stated VCS commit. Source and archive checks are
recorded separately from exported key identity; source labels are provenance,
not a substitute for the actual mathematical capsule.

## The transcript scalar is an existing compatibility constant

Halo2 0.4.1 stores an internal `transcript_repr`. Construction hashes the compact
Rust Debug representation of `vk.pinned()`, prefixed by its byte length as
little-endian `u64`, using BLAKE2b-512 personalized `Halo2-Verify-Key`. The 512-bit
little-endian result is reduced to the Vesta scalar field. `hash_into` subsequently
absorbs that stored scalar. This is a real upstream protocol dependency, not just
the interop package's separate diagnostic fingerprint. [H-VK][P-REDUCE]

The portable capsule captures the **actual stored scalar** as a canonical field
value, and the diagnostic exporter checks its historical derivation. Another
language can use those fixed bytes without reproducing Rust formatting. The
upstream derivation itself is still Debug-based; this does not retroactively
make it a canonical language-independent serialization. The separate pinned-key
description file remains provenance text and is not the capsule.

Changing that scalar to a hash of a new encoding changes proof transcripts and
breaks compatibility with existing proofs. Any such change would require an
explicit new proof/profile version and fresh conformance evidence; it is outside
this specification's compatibility decision. A producer must not choose the
scalar independently of the activated complete capsule.

## Why the public API is insufficient

Orchard's public `VerifyingKey::build(version)` constructs the repaired key, but
its inner Halo2 `vk` and `params` fields are private. Halo2's `pinned()` returns
public types whose fields are private; it has no public complete VK byte writer
or reader. Returning or formatting `pinned()` therefore does not export the
mathematical fields through a stable public typed interface. [O-WRAPPER][H-VK]

Parameters have a usable public writer: `Params::write` emits `k`, coefficient
generators, Lagrange generators, `W` and `U` using canonical point encodings.
`Params::new(11)` is deterministic source-based parameter generation. The source
uses hash-to-curve domain `Halo2-Parameters`, messages `0 || LE32(i)` for `G_i`,
and messages `[1]` and `[2]` for `W` and `U`; the Lagrange generators follow the
specified inverse FFT. That is a parameter regeneration route, not an argument
for trusting arbitrary caller-supplied generators. [H-PARAMS]

Existing unstable fixture APIs are useful cross-checks, with limits:

- Constraint-system JSON/Lean helpers expose a projection; that alone omits the
  complete actual key, permutation commitments and parameters. [H-CS-FIXTURE]
- The full Vesta fixture exporter captures real key/URS/query/permutation data,
  challenges and an assembled MSM, and explicitly retains trust in the captured
  transcript/key serialization. A successful fingerprint capture is not proof
  acceptance. [H-FIXTURE]
- Orchard's checked-in capture entry point is test-only and selects
  `PostNu6_3`, not this repaired-V2 key. Its public availability must not be
  relabelled a direct FixedPostNu6_2 exporter. [O-FIXTURE]

## Canonical mathematical capsule schema

All integers below are little-endian; all lengths and indices are **u32**, never
Rust `usize`. `vec(T)` means count:u32 followed by that many ordered `T` records.
There are no maps, ignored padding bytes, implicit defaults or trailing bytes.
Every index, AST query reference, count and derived metadata value must agree
with the activated schema and its associated data. The exported constraint
system is the **post-selector-compression** key, not a pre-keygen configuration.
Key generation appends compressed selector polynomials before committing the
fixed columns. [H-KEYGEN][H-CS]

The normative field order for schema 1 is:

| Order | Encoding |
| --- | --- |
| 1 | Magic ASCII `KASPVK01` (8 bytes), then four u16 values, all `1`: schema, Vesta curve, FixedPostNu6_2 circuit label, existing Blake2b/Challenge255 transcript compatibility profile. |
| 2 | Vesta base modulus `q`[32], Vesta scalar modulus `p`[32], then scalar `ROOT_OF_UNITY`[32], `DELTA`[32], `ZETA`[32]. Moduli are unsigned integers; the following values are canonical scalar-field elements. |
| 3 | Parameter byte length:u32 and full `Params::write` bytes: `k:u32`, `G[2^k]`, `G_lagrange[2^k]`, `W`, `U`; every point is 32 bytes. The inner parameter format has no extra vector counts. |
| 4 | Actual domain `k:u32`, `extended_k:u32`, `omega`[32], `extended_omega`[32], `g_coset`[32], quotient degree:u32, CS degree:u32, blinding factors:u32, minimum rows:u32, existing transcript scalar[32]. |
| 5 | Fixed/advice/instance/original-selector counts (four u32); vec(u32) advice-query counts per advice column; minimum-degree option (`0:u8`, or `1:u8` followed by u32); vec(u32) constant-column indices. |
| 6 | Three vec(QueryLayout), in **advice, fixed, instance** order. QueryLayout = column:u32, rotation:i32; position in each vector is its query index. |
| 7 | vec(vec(Expression)) preserving gate-group order and each group's polynomial order. Names and annotations are excluded. |
| 8 | vec(Lookup), each containing vec(Expression) input expressions followed by vec(Expression) table expressions, with corresponding arities equal. |
| 9 | vec(PermutationColumn): kind:u8 (`0` advice, `1` fixed, `2` instance), index:u32. Preserve exact original order. |
| 10 | vec(VestaPoint) fixed commitments, followed by vec(VestaPoint) permutation commitments, in their actual key order; EOF. |

Expression uses prefix recursion with these exact tags:

| Tag | Remaining encoding |
| --- | --- |
| 0 | Constant scalar[32] |
| 1 | Selector index:u32, simple:u8 (`0` or `1`); **must be absent** from this post-compression profile |
| 2 / 3 / 4 | Fixed / advice / instance query: query-index:u32, column:u32, rotation:i32 |
| 5 | Negated child Expression |
| 6 / 7 | Sum / product: left Expression, right Expression |
| 8 | Scaled: scalar[32], child Expression |

Do not sort query or permutation columns, flatten/reorder arithmetic operations,
combine equal constants or canonicalize polynomial algebra. These orderings
control evaluation, challenge powers and proof parsing. Every AST query tuple
must match its typed query-layout entry. This captures the actual key even where
two algebraically equivalent programs would define a different encoding.
[H-CS][H-VERIFY][H-PERM]

The dev-only `selector_map`, gate labels and domain inverse/precomputation
caches are excluded explicitly. Query counts, degree, blinding factors and
domain metadata that affect verification are included and cross-checked against
their derivations. The original selector count remains recorded even though
the final AST contains no selector nodes. The capsule contains no proof-specific
instance commitment, proof element, challenge, witness, secret or proving key.

### Curve and role encodings

For Vesta, the curve is `y² = x³ + 5` over base field:

```text
q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
```

Its prime group order/scalar modulus is `p`. Pallas reverses these base/scalar
roles; do not decode Halo2's Vesta commitments as Orchard's Pallas spend or
encryption keys. Canonical scalars use 32-byte little-endian integers `< p`,
without reduction on input. They are not Montgomery limbs or Rust memory
representations. [P-FIELDS][P-FQ][P-CURVES]

Vesta compressed points encode canonical base-field `x` in little-endian bytes
and `y` parity in bit 255; all-zero is identity. Validate the curve/field encoding
and exact re-encoding. Identity is permitted for mathematical VK commitments
where the construction permits it; do not copy encryption-key restrictions
onto every commitment. The activated parameter arrays must equal the prescribed
fixed parameter identity; arbitrary structurally valid parameters are not
authorized by passing a decoder. [P-POINTS]

## Actual captured key and consistency conditions

The exported key has `k=11`, `n=2048`, `extended_k=14`, quotient degree `8`,
CS degree `9`, five blinding factors and minimum eight rows. There are 29 fixed,
ten advice and one instance columns, 56 original selectors, 55 gate groups /
193 polynomials, three lookup arguments, and 25 advice / 29 fixed / one instance
queries. `minimum_degree=None`; constant-column list is `[3]`.

There are 15 ordered permutation columns. The chunk length is `degree-2 = 7`,
so the product argument has three chunks; do not mistake 15 permutation-column
commitments for three product commitments. Advice-query counts per column are
`[2,3,2,2,2,2,3,3,3,3]`. The complete concrete layouts are in the manifest.
Permutation chunk/evaluation behavior follows the pinned verifier. [H-PERM]

The Python decoder independently checks these derivations: roots have the
required orders; domain roots agree with `k` and extended `k`; quotient and
extension sizes agree with degree; advice-query counts and AST references agree
with layouts; gate/lookup degree agrees with degree nine; blinding factors and
minimum rows agree with the source formulas. It rejects truncation, trailing
bytes, changed compatibility scalar and altered provenance. A valid reordered
point list changes the capsule hash and must fail the activated fixed identity;
structural validity alone is not source or activation authenticity.

## Exact transcript compatibility obligations

The actual Blake2b transcript starts with 64-byte output and personalization
`Halo2-Transcript`. Common scalar input is `0x02 || scalar_LE32`; common point
input is `0x01 || x_LE32 || y_LE32`, **not** its 32-byte compressed proof encoding.
An identity point cannot be absorbed through that point path. A squeeze appends
`0x00`, clones/finalizes the current state, and reduces all 64 little-endian
digest bytes modulo `p`; it does not truncate the digest or absorb that digest
as a fresh message. Consecutive squeezes append successive zero prefixes.
[H-TRANSCRIPT][P-REDUCE]

The protocol schedule is fixed by the pinned verifier:

1. Absorb the existing VK scalar, then per-proof/per-instance-column commitments
   derived from actual public instances. The inspected instance commitment path
   includes its deterministic `Blind::default() = 1` offset `W`; do not substitute
   an unblinded plain sum of Lagrange generators. [H-PARAMS][H-VERIFY]
2. Read advice commitments, squeeze theta; read permuted lookup commitments;
   squeeze beta and gamma; read permutation/lookup products and pre-y vanishing
   commitment; squeeze y; read quotient commitments; squeeze x. [H-VERIFY]
3. Read instance/advice/fixed evaluations and the ordered vanishing,
   permutation-common/product and lookup evaluations. Preserve the extra
   last-evaluation behavior for all but the last permutation chunk. [H-VERIFY][H-PERM]
4. Multi-opening squeezes x1/x2, reads the quotient commitment, squeezes x3,
   reads its evaluation vector, then squeezes x4. IPA opening reads its S point,
   squeezes xi/z, processes 11 ordered `(L,R,challenge)` rounds, and reads final
   c/f scalars. The final MSM must actually evaluate to identity; a capture-only
   fingerprint is not an accepted proof. [H-MULTI][H-IPA]

Native profile identity must bind this exact compatibility schedule, the
ten-row Orchard public-instance interpretation, both external RedPallas roles
and the native signing/effects digest. A portable Halo2 key is not the entire
private-payment protocol or an authorization to spend native KAS.

## Export patch, helper and reproducibility

Temporary public-source package:
`/var/tmp/kpi-native-key-export-20261104/`.

| Path | Purpose |
| --- | --- |
| `/var/tmp/native-key-export.patch` | Separately reviewable patch; SHA-256 `884d895adcf77851ee17270b28ef3081492419ffc57c4fb32ff35991a22c2fc3` |
| `sources/orchard/`, `sources/halo2_proofs/` | Exact source copies plus diagnostic patch; original caches unchanged |
| `helper/` | Minimal locked Cargo helper, using patched copies and the existing interop source read-only |
| `check_capsule.py` | Independent canonical decoder / provenance and consistency checker |
| `artifacts/fixed-post-nu6-2.vk-capsule.bin` | Actual mathematical capsule |
| `artifacts/params.bin`, `artifacts/portable-key-manifest.json` | Parameter bytes, concrete identity/role/layout metadata |
| `artifacts/export-result.json`, `artifacts/decoder-negative-checks.json` | Bounded conformance results |
| `upstream-source-checks.json`, `source-inputs.json` | Official-source/crate/archive identities and original-source preservation checks |

The patch adds a feature-gated read-only serializer inside Halo2's `plonk`
module, a diagnostic CS advice-query-count getter, a diagnostic domain getter,
and an Orchard wrapper delegate that rejects circuit versions other than
`FixedPostNu6_2`. It changes no proof generation, verification, key construction,
Fiat–Shamir calculation or stored mathematical field. It provides **no native
key importer or runtime scalar override**. The patch was checked against
pristine copied files and built with Rust 1.95.0 using the locked versions.

The helper and patch are ready for a finite reviewed retention step by the
parent task. They do not need to be installed into the existing interop package.
Reproduction commands are in the temporary package README; no proof creation
is required. The helper's interop source dependency path must be adjusted to
the retained checkout when packaging it elsewhere.

## Activation and remaining soundness limits

Bind `vk_id`, `params_id`, the fixed compatibility scalar/profile, proof shape,
instance map and the native authorization/state/codec identities into an
authenticated activation/profile record. The mathematical key capsule may be
shared across networks; the spending authorization and accepted state must
still bind network/genesis and immutable pool/creation domains. A transaction
cannot choose a new key by presenting a well-formed arbitrary capsule.

An independent backend can consume the fixed mathematical fields and scalar.
A source-regenerating backend must fail closed if its actual exported identity
differs. Public Rust APIs currently provide no complete VK import, so a native
loader/backend remains actual implementation work. Changing a verifier does
not create a new namespace in which old note nullifiers become unspent.

The capsule identifies what was captured; it does not prove that the constraint
system is sound, the repaired circuit meets every privacy requirement, the
parameter generation is independently implemented, or native effects/state are
authenticated. Existing complete proofs were reverified with the same upstream
implementation, not with the Python decoder. A full independent Halo2 verifier,
native integration, deterministic metering and specialist validation remain
separate requirements. This result resolves **portable computed identity and
diagnostic export feasibility**, not those larger claims.

[O-WRAPPER]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/circuit.rs#L1079-L1111
[O-FIXTURE]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/circuit/fingerprint/mod.rs#L100-L147
[H-VK]: https://github.com/zcash/halo2/blob/8fa89d972dab7ee7314b5e1564e35edb5086f955/halo2_proofs/src/plonk.rs#L42-L144
[H-PARAMS]: https://github.com/zcash/halo2/blob/8fa89d972dab7ee7314b5e1564e35edb5086f955/halo2_proofs/src/poly/commitment.rs#L28-L232
[H-KEYGEN]: https://github.com/zcash/halo2/blob/8fa89d972dab7ee7314b5e1564e35edb5086f955/halo2_proofs/src/plonk/keygen.rs#L186-L259
[H-CS]: https://github.com/zcash/halo2/blob/8fa89d972dab7ee7314b5e1564e35edb5086f955/halo2_proofs/src/plonk/circuit.rs#L930-L1053
[H-CS-FIXTURE]: https://github.com/zcash/halo2/blob/8fa89d972dab7ee7314b5e1564e35edb5086f955/halo2_proofs/src/plonk/circuit/fixture.rs#L160-L245
[H-FIXTURE]: https://github.com/zcash/halo2/blob/8fa89d972dab7ee7314b5e1564e35edb5086f955/halo2_proofs/src/plonk/fingerprint/vesta_lean.rs#L1-L40
[H-PERM]: https://github.com/zcash/halo2/blob/8fa89d972dab7ee7314b5e1564e35edb5086f955/halo2_proofs/src/plonk/permutation/verifier.rs#L37-L105
[H-VERIFY]: https://github.com/zcash/halo2/blob/8fa89d972dab7ee7314b5e1564e35edb5086f955/halo2_proofs/src/plonk/verifier.rs#L72-L240
[H-TRANSCRIPT]: https://github.com/zcash/halo2/blob/8fa89d972dab7ee7314b5e1564e35edb5086f955/halo2_proofs/src/transcript.rs#L14-L146
[H-MULTI]: https://github.com/zcash/halo2/blob/8fa89d972dab7ee7314b5e1564e35edb5086f955/halo2_proofs/src/poly/multiopen/verifier.rs#L15-L148
[H-IPA]: https://github.com/zcash/halo2/blob/8fa89d972dab7ee7314b5e1564e35edb5086f955/halo2_proofs/src/poly/commitment/verifier.rs#L79-L169
[P-FIELDS]: https://github.com/zcash/pasta_curves/blob/674bf82910d19fefdcad323d7dd05e8c77baa0bd/src/fields/fp.rs#L727-L746
[P-FQ]: https://github.com/zcash/pasta_curves/blob/674bf82910d19fefdcad323d7dd05e8c77baa0bd/src/fields/fq.rs#L720-L739
[P-CURVES]: https://github.com/zcash/pasta_curves/blob/674bf82910d19fefdcad323d7dd05e8c77baa0bd/src/curves.rs#L1066-L1094
[P-POINTS]: https://github.com/zcash/pasta_curves/blob/674bf82910d19fefdcad323d7dd05e8c77baa0bd/src/curves.rs#L743-L792
[P-REDUCE]: https://github.com/zcash/pasta_curves/blob/674bf82910d19fefdcad323d7dd05e8c77baa0bd/src/fields/fp.rs#L904-L921
