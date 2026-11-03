# Established C++ BN254 reuse for authenticated group wrappers

2026-10-27. Source-only candidate note. No installation, build, curve operation,
MPC, witness, proof, key, private input, RPC or financial execution. Nothing in the
frozen publication or current implementation was changed. The Fr scalar launcher
review retains priority over this separate follow-up.

**A concrete reuse path exists:** retain stock MP-SPDZ authenticated scalar/share
and checked-point-opening machinery, and investigate a thin G1/G2 value wrapper
using established **mcl BN_SNARK1** arithmetic. **Do not choose mcl BN254 by name**:
it is a different curve. libff alt_bn128 is another exact-parameter candidate.
Neither library supplies a qualified Native128 codec or MASCOT/Groth16 adapter.

## Exact candidate sources and APIs

| Library | Inspected official commit | Source compatibility and gap |
| --- | --- | --- |
| herumi/mcl | `9f49ba06593e2d426ab6fb9b0e17bc125a6f720c` (2026-10-18) | Explicit `mcl::initPairing(mcl::BN_SNARK1)`; G1/G2 provide established identity, addition, negation and scalar multiplication. Explicit order checks and field-modulus inspection are available. No executable was selected. |
| scipr-lab/libff | `a152abfcef21b7778cece96fe77f5e0f819ba79e` (2021-03-25) | `alt_bn128_pp::init_public_params()`, `Fp_type`, `G1_type`, `G2_type` expose the needed arithmetic types. Exact Fr/Fq literals match Native; its stream codecs and curve-only well-formedness are insufficient admission. No maintenance or security claim follows from the old commit. |

[mcl curve_type.hpp](https://github.com/herumi/mcl/blob/9f49ba06593e2d426ab6fb9b0e17bc125a6f720c/include/mcl/curve_type.hpp#L37-L44)
distinguishes BN254 with z=`-0x4080000000000001`, b=2, xi_a=1 from BN_SNARK1 with
z=`4965661367192848881`, b=3, xi_a=9, i²=-1. The latter is the actual Native
Ark BN254/alt_bn128 parameter family. `initPairing()` without a parameter defaults
to the different BN254 curve (`bn.hpp:105,155`): this is a real adapter footgun.
Require exact Fr/Fq checks after explicit initialization, not a 254-bit-size test.
The supported default field capacities cover these parameters, but no build or
binary acceptance was checked.

The exact libff
[alt_bn128 fields](https://github.com/scipr-lab/libff/blob/a152abfcef21b7778cece96fe77f5e0f819ba79e/libff/algebra/curves/alt_bn128/alt_bn128_fields.cpp#L20-L45)
are Fr=`21888242871839275222246405745257275088548364400416034343698204186575808495617`
and Fq=`21888242871839275222246405745257275088696311157297823662689037894645226208583`.
They are distinct fields; the authenticated MASCOT scalar field must be the first.

## Preserve strict group and wire admission

mcl's `EcT::set` verifies curve validity and conditionally group order;
`verifyOrder_` is configurable. Its generic `isValid()` accepts the identity,
and initialization/configuration affects subgroup checking. Explicitly require
on-curve plus correct-order predicates at untrusted group admission; do not trust
an unexamined default. Its addition code includes identity/equal/inverse branches.
This is source evidence about an established implementation, not a completeness
or constant-time audit of the whole selected closure. APIs named
`setLittleEndianMod`/`setBigEndianMod` reduce integers and cannot enforce strict
Native canonical-byte admission.

libff G2 `is_well_formed()` checks the curve equation and accepts identity; it is
not itself a prime-subgroup test. Its ordinary G1/G2 stream output includes a
separate zero marker and a least-significant-y-bit convention. In particular G2
uses y.c0 parity. That is **not** Native's compressed little-endian x/Fq2 ordering
and lexicographic-y flags. Do not pass Native128 to either library's ordinary
stream decoder or relabel a successful parse as Native canonical equivalence.

The unbuilt adapter must retain the exact Native codec contract: A32|B64|C32,
canonical Fq integers, Fq2 c0/c1 order, original-A sign before negation, strict
flags, exact reserialization, role/fixed-key checks and subgroup admission.
Nonidentity is mandatory for final Native proof/key points. Conversely, legitimate
authenticated **shares and intermediate group sums may be identity**; a blanket
identity ban there would break ordinary zero/cancellation behavior.

## Reuse the existing authenticated pattern, not the ECDSA application

At MP-SPDZ `113c4e47dd94bca9ecab029d2f0abe649bea5c52`, `P256Element.h` already
specifies the group value interface: Scalar=`gfp_<2,4>`, zero/value construction,
addition/subtraction, scalar multiplication, equality, checking and pack/unpack.
`preprocessing.hpp` uses `T<Scalar>`, `T<P256Element>` and point `Direct_MC`
initialized with the scalar MAC key; scalar/point openings are followed by their
MAC checks. `sign.hpp` performs the same checked public-point opening pattern.
Those are the concrete interfaces to adapt for established BN254 G1 and G2.

Do not copy ECDSA signing, nonce generation, hashes or diagnostics. Its optional
`check()` helper in preprocessing.hpp actually opens sk and inv_k for benchmark
checking; that is not a suitable private-prover operation. Benchmark options can
also disable checks. Preserve authentication and every required opening check;
never export bare value shares to a co-snarks half-share driver.

Still required: two reviewed group value wrappers; exact common Fr initialization
rather than OpenSSL/P256's scalar order; canonical scalar conversion without
reduction; fixed public base/matrix/key agreement; strict point serialization and
subgroup checks; separate G1/G2 transcript types; authenticated linear MSM and
opening integration; and the full prover/FFT/QAP driver contract. The original
P256 fixed-base conversion pattern is evidence of an established approach, not
an automatically available arbitrary-base Groth16 MSM adapter.

**Next source decision:** after the exact-Fr scalar gate, select one arithmetic
backend and review the minimal group-wrapper/codec contracts against Native
fixtures and stock MP-SPDZ checked group openings. First isolated component
controls should cover zero, one, cancellation, equal/inverse addition, scalar
boundaries and malformed/off-curve/non-subgroup encodings. This note authorizes
none of those executions and provides no malicious Groth16 or privacy verdict.

`SOURCE-LEDGER-01.json` pins the 11 selected mcl/libff source bodies by official
commit, URL, Git blob identity, length and SHA256. This is selected-source research,
not a complete transitive build closure. Every body was admitted with unchanged
helper09; public network responses were saved before inspection. MP-SPDZ pattern
sources are the exact already captured P256Element.h SHA 62d7d73c…, preprocessing.hpp
SHA 58d69c48…, and sign.hpp SHA aac0d109… in the active-MPC source directory.
