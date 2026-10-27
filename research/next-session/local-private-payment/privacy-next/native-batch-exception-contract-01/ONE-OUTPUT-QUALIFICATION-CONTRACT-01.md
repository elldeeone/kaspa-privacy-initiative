# One Output verifier: exceptional-arithmetic qualification contract

2026-10-27. Source assessment only. No circuit, compile, setup, proof, test,
RPC, financial action, wallet access or canary job ran. This note selects no
backend and changes no current financial predicate.

**Decision to make next:** retain the BN254 Circom verifier as a research
candidate, but do not treat its present top-level predicate as equivalent to
the native Output verifier. Its final IC accumulator loses its identity flag.
A first bounded experiment may explicitly reject a final identity accumulator
inside a separate circuit derivative; that is a documented completeness
restriction, not full native equivalence. Complete identity handling is the
other option. Neither option is implemented here.

This refines the [candidate assessment](../STANDARD-BN254-R1CS-CANDIDATES-SOURCE-01.md)
and [full native aggregate contract](../FULL-NATIVE-VALIDITY-AGGREGATE-CONTRACT-01.md).
All Yi Sun sources below use `107c316223a08ac577522c54edd81f0fc4c03130`.

## Exact predicate to preserve

The existing native verifier requires a canonical, checked 328-byte Output
key with exactly three IC points, and rejects identity in every key point and
every A/B/C proof point. Proofs are exactly 128 bytes, checked by deserialize
and exact reserialize. These are explicit local checks, not assumptions about
every caller of an Arkworks API: `relation/src/wire.rs:32–67,85–106`.

Output168 is `KPXAOU01 || DOMAIN32 || CM32 || CV64 || CFhash32`. Its exact
SHA256 becomes **two separately ranged little-endian 128-bit inputs**; do not
reduce one 256-bit hash modulo Fr. The outer relation must reconstruct the
bytes and these inputs rather than trust host-supplied hashes or coordinates.
`OutputStatement::validate` also checks DOMAIN and the selected CV encoding;
omitting that admission must be labelled a narrower Groth16-only experiment.
See `statements.rs:7–12,68–112` and `circuit.rs:174–183` at the hashes below.

Bind the exact public proof bytes to canonical private A/B/C coordinates,
including Fq ranges, Fq2 order, Ark sign/infinity flags and native nonidentity
requirements. Then constrain the candidate's **-A**, rather than accidentally
binding those public A bytes to -A. Fix IC, gamma, delta and
`e(-alpha,beta)` as authenticated constants from the selected key; enforce
`out === 1`. The candidate currently exposes those key/GT terms as signals.
Its equation is `e(-A,B) e(ICacc,gamma) e(C,delta) = e(-alpha,beta)`.
The Fq12 coefficient/basis conversion is an explicit obligation, not an
encoding convention to guess.
[Top-level source, lines 18–35,79–125](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/groth16.circom#L18-L125).

The already retained public fixture is the starting positive, not a new proof:

| Item | Bytes | SHA256 |
| --- | ---: | --- |
| `native-g16-adapter-01/FIXTURE.json` | 4642 | `3902034455441a53848ec5f516ba75d796373e7bb9a648fda53fcd97e545455b` |
| Output statement | 168 | `d3a607b2819b2b1585f5670ea1c31ffafc64386f1570b2f1ba94f3767db3a71a` |
| Output proof | 128 | `b49cd3145cb8a0d906addb0ca0be435c57d0836f15feb4d60002f6febb0937d7` |
| Selected Output VK | 328 | `2839d491047edd5664db65af3fa92a7194d959e7f94f723eac982aa918c785e6` |

The fixture receipt records existing native `verify-output` success and known
public seed provenance. This pass read that receipt, not those binaries or any
parameter blob, and did not reverify it. No Native Full, testnet, outer-R1CS or
privacy result follows from the receipt.

## 1. Final IC identity is lost at a real selected boundary

For the actual two-input case the selected components compute
`T0=[u0]IC1`, `S0=T0+IC0`, `T1=[u1]IC2`, `S1=T1+S0`.
Scalar and intermediate addition identity flags are connected, but the final
copy exports only `S1.out` as `VK`. The coordinate-only Miller interface has
no corresponding G1 identity selector.
[Groth16, lines 50–99](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/groth16.circom#L50-L99),
[Miller interface and evaluation, lines 1246–1339](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/pairing.circom#L1246-L1339).

The addition component intentionally uses finite proxy coordinates when its
flag means identity. Thus a final identity sum is passed into pairing as a
finite point rather than the identity contribution. This is a demonstrated
source-level predicate mismatch. It is **not established to be rejection-only**:
the substituted pairing term can change either side of an acceptance decision.
No reachable erroneous acceptance for the selected fixed key, two SHA limbs,
or a valid Output witness was constructed or established here. Do not assume
hash outputs exclude the case.
[Proxy selection, lines 343–361](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/curve.circom#L343-L361).

The first experiment must choose and freeze one of these predicates:

- **Native-equivalent target:** preserve and correctly handle identity through
  the pairing relation, using established checked group semantics.
- **Restricted research target:** constrain final `S1.isInfinity === 0` inside
  the derivative. A host blacklist or a success bit does not constrain a
  hostile assignment. Check the public fixture's accumulator with the selected
  complete reference before freezing the expected positive. Preserve any
  first failure; do not silently replace a fixture to erase it. Document that
  native-valid cases with an identity accumulator are excluded.

An unasserted flag, or only a positive ordinary fixture, closes neither target.

## 2. Selected G1 addition has guards that must not be overlooked

The selected general G1 adder masks the inverse case by
`(1-aIsInfinity)*(1-bIsInfinity)` before setting its result flag. Its source
therefore handles a tagged identity carrying proxy P plus finite -P correctly.
An initial hypothesis that this mask was missing was rejected by independent
review and direct rereading. The similar-looking **general Fp2** helper lacks
that mask, but it is not the helper selected by the G2 subgroup or optimized
Miller paths inspected here; do not transfer that observation into a claim
about the selected G1 path.
[G1, lines 343–361](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/curve.circom#L343-L361),
[different Fp2 helper, lines 484–498](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/curve_fp2.circom#L484-L498).

General G1 addition instantiates both doubling and unequal addition even when
one result is discarded. It changes the low x limb for equal-x dummy unequal
addition. The signal scalar multiplier also creates zero-coordinate dummy
addends for zero bits. Qualification must establish that these always-active
subblocks have satisfying, correctly bounded assignments, rather than assume
an unused branch is disabled. Do not indiscriminately demand that every dummy
addend is an actual curve point; trace the block's real equations and selection.
[General adder, lines 310–340](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/curve.circom#L310-L340),
[scalar loop, lines 24–79](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/curve.circom#L24-L79).

Two other negative findings narrow the investigation:

- `FpIsEqual` and `Fp2IsEqual` enforce their compared values below q; they do
  not merely compare arbitrary limb strings. A naive q-alias comparator bypass
  is not supported by these sources. The limb/carry/range assumptions of their
  transitive `BigLessThan` still belong in the frozen include closure.
  [Fp, lines 265–292](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/fp.circom#L265-L292),
  [Fp2, lines 509–540](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/fp2.circom#L509-L540).
- A 254-bit decomposition of an Fr scalar can have a representative differing
  by r. That alone is not a false-acceptance argument for multiplication of an
  r-order G1 point: the group result is the same. The separately constrained
  LE128 statement inputs and the exceptional behavior of the complete selected
  loop still need qualification.

## 3. G2 subgroup admission must justify its unequal arithmetic

`SubgroupCheckG2` first checks the twist equation, then compares
`psi(P)` with `[lambda]P`, `lambda=6*x*x`. It selects
`EllipticCurveScalarMultiplyUnequalFp2`, not the general tagged-infinity Fp2
routine. The subgroup admission cannot assume that a hostile on-curve input
already has prime order or order greater than lambda merely because the
scalar routine's comment states that assumption.
[Subgroup path, lines 64–97](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/subgroup_check.circom#L64-L97),
[selected scalar loop, lines 589–661](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/curve_fp2.circom#L589-L661).

There are real constraints behind that comment. Every unequal addition in this
subgroup loop explicitly constrains its two x coordinates to differ. Doubling
checks its output on the twist and tangent and asserts `xout != xin`.
The unequal-adder's denominator-cleared cubic and line equations determine
ordinary addition when dx is nonzero. At equal points (`dx=dy=0`) those
equations alone degenerate; the selected loop's explicit inequality must be
retained. With dx=0 and dy nonzero the cubic instead rejects under the intended
field semantics. A zero inverse in a witness hint is not automatically an
underconstrained accepted proof.
[Unequal addition, lines 243–350](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/curve_fp2.circom#L243-L350),
[doubling, lines 359–433](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/curve_fp2.circom#L359-L433).

Required argument: over the pinned coordinate/limb/carry bounds, every
accepted hostile path computes the actual `[lambda]P`, or rejects at an
explicit constraint; then the endomorphism comparison establishes the intended
subgroup predicate. Separately show that nonidentity r-order honest inputs
do not hit excluded intermediate cases for the pinned constants. Failed
generation, hint errors and constraint rejection are distinct outcomes.
This pass does not supply a transitive arithmetic soundness proof.

The optimized three-pair Miller path also invokes unequal Fp2 additions,
including Frobenius terminal additions. Its fixed signed loop coefficients
and every selected denominator/exception condition need their own argument;
the subgroup loop's guards do not automatically guard these other calls.
[Selected product loop, lines 1246–1426](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/pairing.circom#L1246-L1426).

## 4. Complete-source and first-run stop conditions

Freeze the complete include and hint-function closure, compiler version,
BN254 Fr/Fq parameters and exact constant conversion before a run. The current
14-file source capture omits `bigint_func.circom` and other referenced includes;
it is not a build closure. This pass cannot claim how `mod_inv(0)` behaves in
the missing witness generator. `Fp12Invert` does constrain input times inverse
to one, while cyclotomic decompression selects between two division paths;
these are different predicates and must not be conflated.
[Fp12 inversion, lines 480–512](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/fp12.circom#L480-L512),
[decompression, lines 59–126](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/final_exp.circom#L59-L126).

Freeze meaningful controls before the first complete one-Output R1CS run:

| Boundary | Required evidence |
| --- | --- |
| Genuine public fixture | Expected positive actually satisfies the complete compiled relation under the selected key and the declared identity policy. |
| Byte/coordinate binding | Changed public A/B/C byte with unchanged private coordinates fails actual constraints without reparsing the mutation into replacement coordinates. |
| Canonical encodings | Matched q/q+1 raw coordinates and public bytes, invalid flags, identity, off-curve and non-subgroup assignments reject at the recorded boundary. Parser refusal is separate from an R1CS residual. |
| Statement/authority | Wrong domain/tag/role or changed statement with old limbs/proof rejects; private-supplied VK/GT cannot replace constants; exact two LE128 ranges remain enforced. |
| MSM component | Separate public component controls cover zero/one/MAX128 scalars, intermediate cancellation, tagged identity/proxy cases and final identity. Do not pretend these are reachable genuine Output SHA fixtures. |
| Unequal/doubling components | Equal, inverse, zero-denominator and excluded intermediate cases have declared rejection/complete semantics and actual residual categories; do not count a generator crash as rejection evidence. |
| Final pairing path | Fixed-key/GT basis and signed-argument convention match the complete reference; every selected Miller/final-exponent exceptional branch is qualified or explicitly left unresolved. |

Stop at the first unexpected positive/negative result, missing source binding,
unconstrained acceptance bit, authority input, arbitrary hint override or
unresolved selected exception needed for the claimed predicate. Retain the
first result and source preimage. No random/debug challenge, suppressed
constraint, new setup or proof is needed for this first assignment check.

## Comparison and evidence boundary

The captured official Arkworks affine source keeps identity as part of the
group value, distinguishes checked and unchecked point construction, and
preserves identity in affine/projective conversion. Its short-Weierstrass API
also separates subgroup admission from cofactor clearing. Those are the
semantics to compare, not a reason to declare an unrelated circuit correct.
[Affine source at algebra pin 722284b, lines 63–103](https://github.com/arkworks-rs/algebra/blob/722284bc16aaf3eae2c49a28840477745b37ac46/ec/src/models/short_weierstrass/affine.rs#L63-L103),
[subgroup API, lines 73–108](https://github.com/arkworks-rs/algebra/blob/722284bc16aaf3eae2c49a28840477745b37ac46/ec/src/models/short_weierstrass/mod.rs#L73-L108).
This comparison does not assert that those library APIs reject identity in
every context; the selected native wrapper adds its explicit rejection policy.

Every body read used unchanged helper09. Independent source review confirmed
the selected G1 mask and final flag loss; it performed no execution. A helper
reader anomaly in that review's optional hash-recheck loop was not bypassed;
this author separately guarded-read the decisive sources against the captured
ledger pins. No ActualOriginal, private STATE/PLAN/truth, owner output/log or
actual runtime arguments/environment were read. No global document, source
implementation, publication candidate, source preimage or trial was changed.

The preceding 42 encoding controls are not a full 128-byte composition,
subgroup, Groth16, native batch, cost or privacy result. A passing one-Output
gate would still not establish the two-Spend/four-Output relation, state/value/
effects checks, malicious distributed proving, encryption delivery, lower fees
or coordinator blindness.

## Decisive source identities

The Yi Sun file hashes below were selected from the exact 14-file capture
ledger (`78eb57a4c714d7ff97a5b77d9e71c1dae46ba891bcbe62a2926ea0fd2689b3cd`)
and verified during guarded reads. Native sources are the exact fixture closure.

| File | SHA256 |
| --- | --- |
| Yi Sun `bn254/groth16.circom` | `9a3a89daa68c3a0a83d244590b862f0494272f57edd85835738f3503670c2af7` |
| Yi Sun `bn254/curve.circom` | `42149a75741f0bcf557ce7d7aa3af7456d920458584c6b22da170164add3bcf0` |
| Yi Sun `circuits/curve.circom` | `2977bff071a46efb5a663845a46266bbce72080639317888f48a76296ec07c33` |
| Yi Sun `bn254/curve_fp2.circom` | `83dc90d2e42e16eb96441ff6b6209f66eaa72506ce58bd2a62db4e5d5e857251` |
| Yi Sun `bn254/subgroup_check.circom` | `06a8392da7e0d828e1929947bf21612a54813bfa9acaa9035a8ad0e441c8333d` |
| Yi Sun `bn254/pairing.circom` | `c453e3a1eada832bbe7a4bdb707772c0b9424e682b42743727ef247bdfab7e4c` |
| Yi Sun `circuits/fp.circom` | `4aeb0ef9075503801f397f497b3ccff0bcbe99e4fbf7f1706415b2361fff8c2a` |
| Yi Sun `circuits/fp2.circom` | `a906cd9ffd2d07ad1faccac07826a98c243cf56087a6baae6ff31516755f7bca` |
| Yi Sun `bn254/fp12.circom` | `29e5c5db55bf2be12a88905b5faf616318c4b4994b450fc0d40ccb4f02130394` |
| Yi Sun `bn254/final_exp.circom` | `67a338ae1d9494e3cb57a23d591722c045ee7efbac9e34c03bdbbd3c87a65b44` |
| Native `relation/src/wire.rs` | `e47fc2e3e033b644f6099a2b2753c89d67eae7d999c975acf21475d92a32a3ef` |
| Native `relation/src/statements.rs` | `bcd3f5f947904fe6fecc4e747b93e0f85a5c611390d0331651e3a1884004e123` |
| Native `relation/src/circuit.rs` | `e13fa9bd6ba33bd01b71e824d10944b3d8561854b3c026f997b282cf57fde4b0` |
| Arkworks `affine.rs` | `d433d2e802ce603423341671d186fa1b5f9e637f07336eeae1cefc8ae24cf96e` |
| Arkworks short-Weierstrass `mod.rs` | `975f3c9b4b041f23cdaa12144f4c61e8559a5b52def9244afc9956694a4c42b9` |
