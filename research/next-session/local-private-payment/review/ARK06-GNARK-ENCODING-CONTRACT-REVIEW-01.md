# Arkworks 0.6 / gnark native-G16 adapter: independent source contract

2026-10-26. Source review and finite official-source capture only. No adapter implementation, compilation, constraint solve, setup, proof generation, proving-key read, actual owner data, RPC or financial/profile change was performed by this reviewer. This is implementation guidance, not an implementation GO or cryptographic correctness claim.

The selected gnark commit is `0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46`. The current Rust verifier is `verification/common/src/g16.rs`, SHA `c6ce48be94c702858b6a9a7093ae835cf4d2afd7808e56eb2a9a762c1d21b36a`. It requires exactly 128 bytes, checked Arkworks deserialization, byte-for-byte reserialization, no trailing bytes, and nonidentity A/B/C before evaluating the Groth16 equation. The current role statement code SHA is `bcd3f5f947904fe6fecc4e747b93e0f85a5c611390d0331651e3a1884004e123`.

## Exact wire representation

The proof is `A32 | B64 | C32`. Each base-field integer is canonical little-endian modulo

`q = 21888242871839275222246405745257275088696311157297823662689037894645226208583`.

| Proof bytes | Meaning | Flag location |
| --- | --- | --- |
| 0–31 | A.x, G1 | byte 31 |
| 32–63 | B.x.c0, G2 | none |
| 64–95 | B.x.c1, G2 | byte 95 |
| 96–127 | C.x, G1 | byte 127 |

The flag-bearing byte uses bit 6 for infinity and bit 7 for negative y. Positive is `0x00`, infinity `0x40`, negative `0x80`; `0xc0` is invalid. Nonidentity proof points require bit 6 to be zero. B.x.c0 has no flags: its high bits must follow canonical Fq range, rather than being masked away.

Arkworks sign is **not parity**. It is negative iff `y > -y` in the field's integer ordering. For Fq, equivalently `y > (q-1)/2`. For Fq2, comparison checks c1 first and c0 only on a tie. Since q is odd, the tie occurs at c1=0; the sign is therefore `c1 != 0 ? c1 > (q-1)/2 : c0 > (q-1)/2`. This comparison order differs from the c0-first wire order.

The Arkworks compressed decoder accepts an infinity flag without checking that the accompanying x is the unique serialized identity x. The existing verifier's reserialization check closes that ambiguity and its separate nonidentity check then rejects the point. The adapter must preserve both policies; host checked decoding alone is not the outer constraint.

## Smallest constrained adapter

Canonical **reencoding** of private point coordinates into public proof bytes avoids a square-root/decompression gadget. It is equivalent only when all of the following hold:

1. Every original private Fq coordinate element is width-constrained and `AssertIsInRange` is applied before bitwise use. Derive its LE bits with `ToBitsCanonical`; bind every public byte as an 8-bit value to the corresponding reencoded byte. Never pack an entire 254/256-bit Fq value into one native outer-Fr variable for equality or comparison.
2. Constrain the exact sign calculation above and all flag bits. Reject infinity explicitly as `(X,Y)=(0,0)` for G1 or all four zero Fq coefficients for G2, rather than rejecting every X=0 coordinate indiscriminately.
3. Verify A/C on G1 and B on G2/in the correct subgroup using the selected verifier's `WithSubgroupCheck`. BN254 G1 has cofactor one; G2 does not. Membership checks allow identity and do not replace the separate nonidentity policy.
4. Dynamic proof B must have `Lines == nil` in the compiled circuit. The selected Groth16 verifier calls `Pair`, not `PairingCheck`. `Pair` trusts supplied precomputed G2 lines and does not bind them to the point; subgroup-checking B does not repair unbound lines. Only fixed, selected compile-time VK points may use fixed precomputed lines.
5. Embed the selected Output VK as compile-time constants, including precomputed E and gamma/delta lines. A witness-supplied VK is a different predicate. Preserve IC3, exactly two public inputs, and empty commitment metadata. The selected Output VK SHA is `2839d491047edd5664db65af3fa92a7194d959e7f94f723eac982aa918c785e6`.

### Range API distinction

`AssertIsEqual` is modular equality. Ordinary `ToBits` and `Reduce` do not promise a canonical integer; the reduction API explicitly permits x+p. `ToBitsCanonical` invokes strict modular reduction, checks the reduced bits against q-1, and only then returns the 254-bit slice. Thus it does not merely truncate an unconstrained value.

For this strict adapter, asserting the original coordinate in range first is simpler: `AssertIsInRange` compares the original limb bit-vector against q-1 and marks it reduced, so subsequent canonical decomposition represents that same integer. This rejects raw x+q assignments rather than normalizing them. Mathematical reduction is otherwise legitimate only when the full emulated equality and canonical-output checks remain constrained; truncation is never a substitute.

Use `cmp.IsLessBinary` on equal-length, Boolean-constrained LE Fq bit-vectors. Native `cmp.IsLess` compares modulo the outer field and is unsuitable for comparing whole Fq coordinates. Original witness limbs must also retain their declared per-limb widths.

## Statement and scalar binding

Hash the exact Output168 bytes, with tag `KPXAOU01` and selected domain at their native offsets. SHA-256 produces the normal ordered 32 digest bytes. Interpret bytes 0–15 little-endian as input 0 and bytes 16–31 little-endian as input 1; both are below 2^128. Do not reverse digest bytes, swap halves, or reduce one 256-bit digest modulo Fr. Fr differs from Fq:

`r = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.

Construct the two emulated scalar inputs from those constrained 128-bit vectors, or constrain any separately supplied scalar witness equal to them. Host SHA, an unconstrained host verdict, or `ValueOfProof` conversion supplies no circuit binding. This one-proof adapter does not by itself implement the whole Output520/effects/state/encryption-delivery predicate or the frozen two-Spend/four-Output aggregate.

## Decisive negative assignments

Use a small encoding-only compiled constraint system first if full pairing compilation has not been resource-qualified. It needs no setup and can test the encoding contract independently; accepting a field/encoding boundary is not accepting a curve point or Groth16 proof.

| Assignment | Required classification |
| --- | --- |
| Flip an A, B.c0, B.c1 or C public proof byte while leaving all private coordinates and statement unchanged | Actual compiled constraints reject; construct the assignment directly, without reparsing the mutated public proof |
| Flip each flag sign bit with old coordinates; set infinity or `0xc0` flags | Actual encoding constraints reject; native parser outcome reported separately |
| Change private coordinate limbs while keeping public proof128 unchanged | Actual constraints reject; do not use a converter that silently restores the old coordinates |
| Raw x=q+1 with public x=1, or raw x=q with public x=0 | Original-coordinate range constraints reject, even though modular reduction would alias |
| Raw low limb `2^64+1` versus canonical limbs `[1,1,0,0]` for the same integer | Limb-width constraints reject the oversized limb |
| Public byte 256 or -1 | Actual byte constraints reject; host uint8 conversion must not normalize the test |
| Fq sign at `(q-1)/2` and `(q+1)/2`; Fq2 c1=0 with both c0 signs; nonzero c1 with the opposite c0 sign | Expected bits from the exact Ark order; wrong parity/c0-priority implementations reject or disagree visibly |
| Identity A/B/C using zero coordinates | Actual nonidentity constraint rejects, even if the pairing gadget permits infinity |
| Statement byte mutation with original proof and coordinates; reversed/swapped digest limbs if those are explicit witnesses | Actual full adapter constraints reject |
| Noncanonical field integer, wrong coefficient order, off-curve or non-subgroup G2 material | Separate native-parser and circuit outcomes; use direct assignments for any mandatory circuit claim |
| Proof length 127 or 129, malformed hex/JSON | Parser/shape rejection only; a fixed 128-element circuit array does not test a variable-length parser |

For mandatory compiled-constraint negatives, distinguish an unsatisfied compiled relation from host/parser rejection, panic or hint-generation failure. In particular, byte-mutation tests should keep the genuine private pairing coordinates intact so they can reach the equality constraints. Do not count an ignored struct field or mutation normalized by `ValueOf` as a tested adversarial assignment.

## Primary-source identities

All body reads used unchanged helper09. Nine finite official gnark source bodies were fetched at the exact commit above and then guarded-read; no dependency/tool build was performed. Their URL/path/length/SHA ledgers are:

- `/var/tmp/kpi-gnark-adapter-source-review-01/SOURCES-01.json`, SHA `201f9131837ee67fa19fa5c981443d1cb42d7e199706202fe4c1fca5efe371ae`: verifier, options, BN254 pairing/G2 and field binary APIs.
- `SOURCES-02.json`, SHA `97ed992ec6cccb409bb0c76a4c5e8f2bfaf847ad49654dd5bfa914a65a934e3d`: binary comparator and SHA-256 gadget.
- `SOURCES-03.json`, SHA `2503017d040417365ee2d020ce756d90778d09649946b1c408c907eeb82c336a`: field reduction and assertions.

Relevant exact gnark source positions: `verifier.go:289–322,547–549,603–624`; `opts.go:22–38`; `pairing.go:92–102,458–487,509–518,548–571`; `field_binary.go:66–104`; `field_reduce.go:16–54`; `field_assert.go:56–73,75–148`; `cmp/generic.go:38–59,108–112`; `sha2.go:52–94`.

Installed Arkworks 0.6 source hashes:

| Source | SHA256 |
| --- | --- |
| ark-ec short_weierstrass/serialization_flags.rs | `30f440a1d3a424e0e885981fd2e34f90771b8c1e7c3de078da5f72f49951ea3c` |
| ark-ec short_weierstrass/mod.rs | `975f3c9b4b041f23cdaa12144f4c61e8559a5b52def9244afc9956694a4c42b9` |
| ark-ec short_weierstrass/affine.rs | `d433d2e802ce603423341671d186fa1b5f9e637f07336eeae1cefc8ae24cf96e` |
| ark-ff fp/mod.rs | `da6cb3ab2dc07e63aa09ea10135adb4529b8f4840441aa575982faad2e9feb6e` |
| ark-ff const_helpers.rs | `b38f43fb2290d13cbef1432131abf9b0fd11217e02304826cd216ab6ed3b745e` |
| ark-ff quadratic_extension.rs | `43054f5dbab78253b55c3ac721504acc64c4cb7d3c02c62663baac113004728e` |
| ark-bn254 curves/g1.rs | `dabf1b825d366fd08b07c0dcb6dbed221c385cf202cca65d90bb069c15aa4ab0` |
| ark-bn254 curves/g2.rs | `d8423e33bc3aafb2511769ed946450d4d7454357908ba6de9a64fba48586fc02` |
| ark-bn254 fields/fq.rs | `7c65f9d074c6f807fb95b17b339487bc69a952d4741fc119a70436b3338c5ddb` |
| ark-bn254 fields/fr.rs | `05bd67486b5fc6ed6ed5e70e2e6673794797502e671aaf0e9108e8ebb7f18fbf` |

`const_helpers.rs:148–189` explicitly converts each u64 limb with `to_le_bytes` and writes them in order. The remaining trust includes correctness of the selected gnark emulation/pairing/SHA gadgets, the compiler/solver and fixed-key import. This source review is not a proof of those libraries or of the future complete privacy/financial relation. The actual implementation and its direct negative assignments remain to be reviewed.
