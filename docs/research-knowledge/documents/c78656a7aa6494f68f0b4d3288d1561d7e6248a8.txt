# Existing curve and generator API decision input

2026-10-24 UTC. Source inspection only for the owner-private prototype.
No commitment/proof, setup, build, container, private asset or native execution
was performed for this note. This is a source recommendation; the selected
relation and exact public parameter transcript belong to the prototype ADR.

**Version update:** the prototype author selects coherent **Arkworks 0.6.0**
to match its BN254/Groth16/exact-SHA code. The 0.5 source below is retained as
comparison, not the selected dependency. The published 0.6 crate verification
and canonical boundary findings are in the final section. Do not mix 0.5 and
0.6 gadgets, traits or package pins.

**Original 0.5 API recommendation, now a version comparison:** use the exact Arkworks 0.5 Edwards implementation and its
existing random-point sampler for independently reproducible public commitment
bases. Freeze a public, role-separated seed derivation and an explicitly pinned
CSPRNG; invoke `EdwardsProjective::rand` separately for V and R. Do not derive
either point by multiplying an existing generator by a public scalar. The
source sampler chooses a field coordinate and recovers a curve point, then
clears its cofactor; it does not disclose a discrete logarithm.

## Exact primary versions

- `arkworks-rs/algebra` tag `v0.5.0` resolves to
  `7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c`.
- `arkworks-rs/crypto-primitives` tag `v0.5.0` resolves to
  `b9414b6e89f541f40ee2489abcc2ee998821fc03`.
- `iden3/circomlibjs` `main` resolved during this pass to
  `48b3ab37013c5ed21e9ff8a80a5b010795c97094`.

All source links below use those immutable commits. The old archived
`arkworks-rs/curves` repository is not the 0.5 implementation source; the curve
has moved into `algebra/curves`.

## Curve, fields and R1CS seam

`ark_ed_on_bn254::EdwardsProjective` is the normalized Baby-Jubjub model
`x²+y²=1+(168696/168700)x²y²`, with cofactor 8. Its base field is exactly
`ark_bn254::Fr`, so its existing `EdwardsVar` runs over the same field as a
Groth16 BN254 circuit. This field identity does not permit mixing different
crate-version trait implementations.
[Curve model and configuration](https://github.com/arkworks-rs/algebra/blob/7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c/curves/ed_on_bn254/src/curves/mod.rs#L11-L50),
[base-field alias](https://github.com/arkworks-rs/algebra/blob/7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c/curves/ed_on_bn254/src/fields/fq.rs),
[existing constraint variable](https://github.com/arkworks-rs/algebra/blob/7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c/curves/ed_on_bn254/src/constraints/curves.rs).

```
Base field p = BN254 Fr
21888242871839275222246405745257275088548364400416034343698204186575808495617

Commitment scalar field q = ark_ed_on_bn254::Fr
2736030358979909402780800718157159386076813972158567259200215660948447373041
```

The scalar modulus is defined in the selected
[Fr source](https://github.com/arkworks-rs/algebra/blob/7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c/curves/ed_on_bn254/src/fields/fr.rs#L1-L7).
Use q for commitment blindings and any MPC blinding sum; the earlier Jubjub-Fr
sum experiment used a different prime. Its numeric field pin is not reusable.
Canonical scalar decoding and bounded integer-sompi arithmetic remain separate
checks; reduction in either field is not an amount-range check.

## What `UniformRand` actually does

For `EdwardsProjective`, the selected implementation repeatedly samples a
base-field **y** and a random sign, reconstructs x with
`Affine::get_point_from_y_unchecked`, and returns the point multiplied by the
cofactor. The affine sampler follows the same pattern. It is not random-x
sampling and not `random_scalar * GENERATOR`.
[Projective sampler, lines80–92](https://github.com/arkworks-rs/algebra/blob/7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c/ec/src/models/twisted_edwards/group.rs#L80-L92),
[affine sampler, lines270–282](https://github.com/arkworks-rs/algebra/blob/7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c/ec/src/models/twisted_edwards/affine.rs#L270-L282).

The prototype can therefore reuse this established sampler with publicly fixed
deterministic RNG bytes. Freeze exact curve/version, seed preimage framing,
role labels, RNG algorithm/version and output encoding before execution, then
publish the resulting points and the complete derivation transcript. An
explicit pinned `ChaCha20Rng::from_seed` is preferable to an unspecified
`StdRng` or test RNG for stable derivation. `rand_chacha 0.3.1` is already
present in the existing selected prover lockfile; adopting it here still
requires the new prototype's own exact lockfile/inventory.

Reject identity, malformed/noncanonical/off-curve/wrong-subgroup points and
accidental equal/opposite V/R. These checks do **not** prove that nobody knows
a discrete-log relation. The argument is that publicly fixed coordinate-based
sampling exposes no such relation, under the sampler/RNG and discrete-log
assumptions. No party may replace the transcript with chosen points.

## Existing Pedersen setup semantics

Arkworks' existing Pedersen commitment setup derives a randomness-generator
power table and message-generator power tables. Each table starts with
`C::rand(rng)` and repeatedly doubles that base. This directly uses the
coordinate-based sampler above for this C; setup does not first sample and
publish a scalar multiplying a known generator.
[Commitment setup, lines44–59](https://github.com/arkworks-rs/crypto-primitives/blob/b9414b6e89f541f40ee2489abcc2ee998821fc03/crypto-primitives/src/commitment/pedersen/mod.rs#L44-L59),
[generator powers, lines38–55](https://github.com/arkworks-rs/crypto-primitives/blob/b9414b6e89f541f40ee2489abcc2ee998821fc03/crypto-primitives/src/crh/pedersen/mod.rs#L38-L55).

For **one 64-bit window**, its little-endian bit evaluation of eight value
bytes plus scalar randomization has the intended form `CV = value*V + r*R`.
More independent message windows do not have this simple single-value-base
meaning. The exact window, byte encoding and scalar bit handling must be fixed
in the relation; do not use a generic byte-hash commitment as a value commitment
without checking those semantics.
[Bit evaluation](https://github.com/arkworks-rs/crypto-primitives/blob/b9414b6e89f541f40ee2489abcc2ee998821fc03/crypto-primitives/src/crh/pedersen/mod.rs#L111-L124),
[scalar randomization](https://github.com/arkworks-rs/crypto-primitives/blob/b9414b6e89f541f40ee2489abcc2ee998821fc03/crypto-primitives/src/commitment/pedersen/mod.rs#L85-L104).

The full setup consumes one RNG stream; alternatively, public role-separated
RNG streams can feed the same existing point/power-table APIs. That changes
public parameter derivation, not the commitment equation, and its exact choice
still needs the prototype's explicit source/parameter review.

## iden3 option and model mismatch

circomlibjs already derives Pedersen bases by hashing a fixed generator prefix,
index and retry counter, attempting point decoding, and multiplying by 8.
The selected code permits `blake` and `blake2b`; the ordinary hash path defaults
to `blake`. This is a genuine published hash/point-try derivation, not a
public-scalar multiple of Base8.
[Generator derivation](https://github.com/iden3/circomlibjs/blob/48b3ab37013c5ed21e9ff8a80a5b010795c97094/src/pedersen_hash.js#L79-L99),
[hash choice](https://github.com/iden3/circomlibjs/blob/48b3ab37013c5ed21e9ff8a80a5b010795c97094/src/pedersen_hash.js#L22-L32).

**Do not copy those coordinates directly into Arkworks.** circomlibjs uses
`A=168700,D=168696`; Arkworks uses `A=1,D=168696/168700`. Equal base field and
subgroup order do not make their affine coordinates or encodings identical.
Selecting that option would require an explicit reviewed model conversion and
cross-library vectors. The smaller Arkworks-only prototype avoids that extra
adapter by using its own existing sampler.
[circomlibjs curve parameters](https://github.com/iden3/circomlibjs/blob/48b3ab37013c5ed21e9ff8a80a5b010795c97094/src/babyjub.js#L8-L25).

## Fetched public source hashes

| Source | SHA256 |
| --- | --- |
| algebra `ec/src/models/twisted_edwards/affine.rs` | `b52ed820e359e98e805402724c84bdef7e840bf2e6a03a0102841eb06961e1bb` |
| algebra `ec/src/models/twisted_edwards/group.rs` | `5684cec2f0c9b871bfa626b5caeaa8e48e411e5b62cbdd50e7b2f381e1dcc684` |
| algebra `curves/ed_on_bn254/src/curves/mod.rs` | `4dbeebd29eed11303995716d523b1b9e9d5637154a2d6e899e1cbccb587163bc` |
| algebra `curves/ed_on_bn254/src/fields/fr.rs` | `ff0f7dc8b8285952d5046ce20de61fe93de673446d949ebb5212a834313dfa0a` |
| algebra `curves/ed_on_bn254/src/fields/fq.rs` | `754fe27aa1d02d7daa6f23612e92ca2c33edc7b7cd29a45044a115bab629db5f` |
| algebra `curves/ed_on_bn254/src/constraints/curves.rs` | `2a1b53d116efe204bfd70ba91a345e6828929ecdd94e075edc9bd58dfb7db2d8` |
| crypto-primitives `commitment/pedersen/mod.rs` | `690ef6d84511bfeb8313370d416cf5899ea1566a6924f4e5794a95f843fa1d41` |
| crypto-primitives `crh/pedersen/mod.rs` | `cde883c0798b9c3b82ad550a9f090017d8305ec4bdf9867452e67454c61c7a87` |
| circomlibjs `src/pedersen_hash.js` | `7367ac57302cfca052b5967570bc2f83457ff090ef728447a640ea74a0f1abf4` |
| circomlibjs `src/babyjub.js` | `68c3e5d2e3b2c5f4012b06df0a68829606bce8f5227dab64e43fbd7e675160c5` |

## Selected candidate version: published Arkworks 0.6.0 crates

The prototype author selected all-Arkworks 0.6.0 after the comparison above.
This source pass independently read crates.io's exact-version metadata and
whole-hashed the already acquired public archives; it did not fetch duplicate
archives, install, build or execute cryptography. The five-archive source
manifest supplied by the recovery-source lane has SHA256
`a6d43d40090e978d44b0368491df4a80e618d3d73042ebf8efac453a671d231b`.
The sixth archive, `ark-serialize`, was read from the existing public cache and
matched its selected prover lockfile as well as crates.io metadata.

| Published 0.6.0 package | Whole `.crate` SHA256 |
| --- | --- |
| `ark-ed-on-bn254` | `a4585ccc828ac1a1c0973a6d859b8cd9ae6055a0ee943139c8e254dfd87d6f38` |
| `ark-ec` | `8352a2b2aedf6ba2cc38f7520fc51191d518dde96175c729af19f2d059f191c4` |
| `ark-crypto-primitives` | `31b3409b1846fe459d19c95df039481575ac6d5842ae63858ad75cc31219bfc1` |
| `ark-r1cs-std` | `291f1c6628bfcac79b0dc2adbe401aa9100e2e96daa971645e0b18fc94de9a98` |
| `ark-ff` | `f7a806ac6c8307b929df4645776290a50ee2aac754ad09d8bdf73391309e43af` |
| `ark-serialize` | `a74dd304fd536fb95d0a328e72be759209cc496a9da094c5bc56e5fea4f9e86b` |

Authoritative exact-version metadata:
[curve](https://crates.io/api/v1/crates/ark-ed-on-bn254/0.6.0),
[EC](https://crates.io/api/v1/crates/ark-ec/0.6.0),
[crypto-primitives](https://crates.io/api/v1/crates/ark-crypto-primitives/0.6.0),
[R1CS](https://crates.io/api/v1/crates/ark-r1cs-std/0.6.0),
[fields](https://crates.io/api/v1/crates/ark-ff/0.6.0),
[serialization](https://crates.io/api/v1/crates/ark-serialize/0.6.0).
The six releases are dated 2026-04-26 in that metadata.

The curve and EC crates report algebra commit
`bffa52711f225e888c1a91e1ec9fc59f2d9d5c94`; crypto-primitives reports
`ba00127bf673d93d73a3e8bf969cb9eeced20d12`; fields/serialization report
`d168323a6c7adf25210030fdd2c0be734b52f85b`. R1CS reports commit
`70a8298c82ef22b6ab81ee3a6cbf5138a3691aeb` **with `dirty=true`**. These are
published `.cargo_vcs_info.json` claims. Exact published archive bytes, their
member hashes and the eventual lockfile take precedence over assuming a tag or
reported Git commit is byte-identical to the package.

The actual 0.6 curve model, q/p, Fq alias and `EdwardsVar` files have the same
whole hashes as their 0.5 counterparts listed above. The actual 0.6 projective
sampler remains random y/sign, point reconstruction and cofactor clearing;
the old no-public-scalar-DL finding therefore holds for the selected code too.
[`ark-ec` published group source](https://docs.rs/crate/ark-ec/0.6.0/source/src/models/twisted_edwards/group.rs),
[`ark-ed-on-bn254` published curve source](https://docs.rs/crate/ark-ed-on-bn254/0.6.0/source/src/curves/mod.rs).
Published 0.6 Pedersen setup still samples one base per table and doubles it;
the one-window/64-bit value semantics above remain the relevant stock API.
[`ark-crypto-primitives` published setup](https://docs.rs/crate/ark-crypto-primitives/0.6.0/source/src/commitment/pedersen/mod.rs),
[published generator powers](https://docs.rs/crate/ark-crypto-primitives/0.6.0/source/src/crh/pedersen/mod.rs).

### Actual canonical encoding and validation boundary

Selected EC `twisted_edwards/mod.rs` lines89–144 serializes an uncompressed
point as x then y; both base-field encodings are 32-byte little-endian, so the
prototype's declared uncompressed wire representation is **exactly 64 bytes**.
Default `CanonicalDeserialize::deserialize_uncompressed` selects
`Compress::No, Validate::Yes`. The EC path then calls `point.check()`, which
requires on-curve and correct prime-order subgroup membership.
[`ark-ec` published model decoder](https://docs.rs/crate/ark-ec/0.6.0/source/src/models/twisted_edwards/mod.rs),
[published affine validation](https://docs.rs/crate/ark-ec/0.6.0/source/src/models/twisted_edwards/affine.rs),
[`ark-serialize` defaults](https://docs.rs/crate/ark-serialize/0.6.0/source/src/lib.rs).

**Caller requirements remain:** enforce exact 64-byte input or complete cursor
consumption, use the validated method, and reserialize to the exact original
bytes. Deserialization of a value from a stream does not itself reject trailing
bytes. Identity is on-curve and in the subgroup, so define its permitted roles
explicitly; public generator bases must be nonidentity, while a zero aggregate
can legitimately be identity. Do not globally forbid an identity aggregate to
make parsing easier. The unchecked decoder and `from_random_bytes` are not
substitutes for the declared public point decoder.

Actual 0.6 field binary deserialization uses `from_bigint` and refuses integers
outside the field. In contrast, its decimal `FromStr` implementation reduces
modulo the prime. Thus `Fq::from_str`, `Fr::from_str` and mod-order constructors
must not silently serve as canonical public wire scalar/coordinate decoders.
[`ark-ff` published binary and decimal paths, lines605–675](https://docs.rs/crate/ark-ff/0.6.0/source/src/fields/models/fp/mod.rs).

| Checked selected 0.6 member | SHA256 |
| --- | --- |
| EC `src/models/twisted_edwards/group.rs` | `fd1137f2d271c71083014c01552004d671213b6f4752b78dff23e6c74e8318d4` |
| EC `src/models/twisted_edwards/affine.rs` | `555147132b94d3be9f2b1c326e546522f9eb849e8dc5a4b30c4803a4b00a87b3` |
| EC `src/models/twisted_edwards/mod.rs` | `be6f09902ef61258332832ce4e19ebbb173de355e15c8549fc7f7e98c9595420` |
| crypto-primitives `src/commitment/pedersen/mod.rs` | `4b7f3a0c55e26475ce2a76a46d924a06f63d13fda8206f1d8083529a7d719b77` |
| crypto-primitives `src/crh/pedersen/mod.rs` | `e7d419bb6d6f21771cb8e43a41d3c8cceee0c08857c1f7b75fc067189586ef1f` |
| serialize `src/lib.rs` | `e253b17896521de7958df388a0151c0824b24028a06ca46cfeb995f98d2a1d02` |

This is a source-level API/encoding assessment. Concrete generator derivation,
selected byte encodings, canonicality/subgroup controls and circuit bindings
still require the prototype's exact source freeze and actual verification.
