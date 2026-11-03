# BN254-native value commitment source review

**Reuse the stock arkworks 0.6 Pedersen commitment over `ark_ed_on_bn254::EdwardsProjective`, with one 64-bit window.** This matches the existing BN254/Groth16 version family. The exact native and gadget sources support `CV = v·V + r·R` for an eight-byte little-endian value. This is a source/design review, not a completed circuit or a privacy/security qualification.

Exact published-package checksums, VCS commits and selected source-file hashes are in `ARKWORKS-COMMITMENT-SOURCE-PINS-01.json` (SHA-256 `9f6758ad445dfee3fa7584bec78f585462019afaf6fa39d004f9143a8ce89aec`). The source archives are retained outside Git. No package was built or installed; no parameter setup, proof, backup read or fund operation ran.

The published `ark-r1cs-std` crate records `dirty: true` in its VCS metadata. Its package/file checksums identify the reviewed source. The selected Boolean comparator also matched its commit-pinned upstream file; no claim is made that the whole published crate equals that Git commit or a release tag.

## Curve and generator choice

The selected curve is the normalized Edwards model **a=1**, **d=168696/168700 mod P**, over BN254's scalar field:

| Quantity | Value |
|---|---|
| Base-field P | `21888242871839275222246405745257275088548364400416034343698204186575808495617` |
| Prime subgroup Q | `2736030358979909402780800718157159386076813972158567259200215660948447373041` |
| Cofactor | `8` |

The published curve source imports `ark_bn254::Fr` as its base field. Its [exact curve configuration](https://github.com/arkworks-rs/algebra/blob/bffa52711f225e888c1a91e1ec9fc59f2d9d5c94/curves/ed_on_bn254/src/curves/mod.rs) and scalar-field modulus agree with the published crate. Never insert circomlib's a=168700 coordinates into this a=1 model. Arithmetic validation also confirmed the normalized d and its nonsquare property.

[Projective random sampling](https://github.com/arkworks-rs/algebra/blob/bffa52711f225e888c1a91e1ec9fc59f2d9d5c94/ec/src/models/twisted_edwards/group.rs#L80-L92) samples a base-field y and sign, reconstructs a curve point and multiplies by the cofactor. It does **not** sample a public scalar and multiply the standard generator. [Stock Pedersen setup](https://github.com/arkworks-rs/crypto-primitives/blob/ba00127bf673d93d73a3e8bf969cb9eeced20d12/crypto-primitives/src/commitment/pedersen/mod.rs#L44-L60) draws R first, then V; `generator_powers` samples each base through that point sampler and forms successive doublings.

The candidate transparent parameter derivation is unchanged stock setup with pinned `rand_chacha=0.3.1::ChaCha20Rng`, seeded by SHA-256 of this exact UTF-8 string:

```text
KPI owner-private payments v1 / transparent Pedersen parameters / BN254 BabyJubjub
```

Seed: `bc05b21a635868b772c207e266b1bb5443ee2ddd5de3b108b0227c14fc795c87`. Freeze the seed, crate resolution, window and resulting parameters in the relation identity. Validate once that V and R are on-curve, in the prime subgroup, nonidentity, and neither equal nor negatives; halt on failure rather than retuning. This avoids introducing a known discrete-log relation by construction. The assumption remains discrete-log hardness and the pinned CSPRNG sampling model; this is not a new standardized hash-to-curve claim. `test_rng` is not the proposed CSPRNG.

## Encoding and circuit requirements

1. **Canonical CV:** exactly 64 bytes, `x32LE || y32LE`, using ark's validated uncompressed decoding, exact length/cursor exhaustion and roundtrip. The existing decoder checks canonical fields, curve membership and subgroup membership. It does not reject identity or trailing bytes. Apply an explicit identity policy for each role. Reject identity for parameters; the proposed note interface also rejects identity commitments. Never use unchecked decoding, modular byte reduction, decimal `FromStr`, or `from_random_bytes` for public CV validation.
2. **Fixed parameters:** Pedersen's `ParametersVar` stores native parameters and ignores allocation mode. It does not constrain a prover-supplied parameter choice. V/R and all powers must be frozen constants selected by the relation/VK identity.
3. **Commitment equality:** recompute every public CV from fixed subgroup bases and the witness opening, then constrain both coordinates equal. Public Edwards input allocation alone omits the prime-order check. The recomputation supplies subgroup membership by construction; native wire validation remains required.
4. **Canonical blinding:** stock `RandomnessVar` is a byte vector. Its commitment gadget zips bits with the 251 randomness powers and does not enforce Q-canonicality; high bits can be ignored. Constrain **all 256 bits** to `<= Q−1` using the existing [Boolean integer comparator](https://github.com/arkworks-rs/r1cs-std/blob/70a8298c82ef22b6ab81ee3a6cbf5138a3691aeb/src/boolean/cmp.rs#L41). `enforce_in_field_le` would use the constraint field P and is the wrong bound for r. Keep the same constrained bytes wherever r is bound. Blinding arithmetic is modulo Q; value arithmetic is bounded integer arithmetic.
5. **Values and conservation:** exactly eight LE bytes; constrain `1 <= v <= MAX` and input/output counts `<=64`. With `MAX=2,870,000,000,000,000,000` sompi and fee `<=MAX`, even `65·MAX = 186,550,000,000,000,000,000 < 2^68 < Q,P`. Thus the bounded value difference cannot hide a nonzero multiple of either modulus. Range and count checks are part of this argument; group equations alone do not establish those bounds. Validate exact input length before calling the native primitive, whose overlength path panics.

The separate source reviewer independently checked the canonical encoding, validated decoding and the selected 0.6 source identities. These checks establish the intended reuse seam. They do not prove note encryption correctness, membership/nullifier soundness, payment unlinkability or the complete private-payment relation.
