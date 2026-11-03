# Standard BN254 Groth16 outer proofs: candidate sources

2026-10-26. Source research only. No implementation, dependency installation,
compile, setup, proof, benchmark, RPC, private input or financial change ran.

**Finding:** an existing same-curve Circom verifier candidate was missed by the
earlier README-level assessment. The exact previously inspected
`yi-sun/circom-pairing` commit contains `circuits/bn254/groth16.circom`, not only
BLS12-381 circuits. It is a plausible ordinary-R1CS route around gnark's outer
commitment-protocol mismatch. It is explicitly unaudited demonstration code,
with concrete adapter and exceptional-arithmetic gaps. No maintained, drop-in,
fully compatible verifier is qualified by this pass.

This corrects the narrow Circom candidate description in the frozen
[earlier feasibility note](NATIVE-G16-AGGREGATE-BACKEND-FEASIBILITY-01.md)
(`e05b2682984f1f220dd808821c34b673c64ea1b38ae7eb730c4f3611ba211e40`).
That earlier note remains unchanged. The separate
[gnark outer-commitment assessment](GNARK-OUTER-COMMITMENT-COMPATIBILITY-01.md)
(`6db9301f0214d8bb8c2168fe9e8275adce3d7bceaeab5cccc9e7bc61357c4918`)
still applies: inner-proof mathematical compatibility does not remove required
outer commitment/PoK verification.

## The precise requirement

The present inner proofs use Arkworks0.6 BN254 Groth16: checked canonical
compressed A/B/C, exactly128 bytes, fixed328-byte role keys with IC3, and two
ranged little-endian128-bit SHA256 limbs. Their existing keys need not change
merely to verify these proofs inside another relation. A new outer circuit has
its own key and public statement; the current fixed inner key cannot be reused
as that new outer key.

An ordinary BN254 Groth16 outer proof requires a circuit over BN254 **Fr**.
Its inner BN254 coordinates live in the different prime field **Fq**. Therefore
native-Fq pairing gadgets, host BN254 verifiers, and generic prime-field
emulation are not sufficient evidence of a BN254-in-BN254-Fr verifier. Exact
Ark-byte binding, selected-key binding, subgroup/nonidentity semantics and the
two-SHA-limb statement remain requirements. This source pass does not select a
new financial profile or change the current1/2 parser's rejection of2/4 frames.

## Candidate comparison

| Inspected source | What exists | Boundary for this project |
| --- | --- | --- |
| **yi-sun/circom-pairing**, `107c316223a08ac577522c54edd81f0fc4c03130` | A BN254 Groth16 verification template with nonnative limb arithmetic, proof-point checks, MSM and pairing/final exponentiation. | Strongest ordinary-Circom/R1CS source candidate found. It needs a fixed-key, acceptance-enforcing, exact-byte/SHA wrapper and resolution of exceptional arithmetic. Its README disclaims audit/production use. No execution here. |
| **Official Arkworks r1cs-std0.6**, `70a8298c82ef22b6ab81ee3a6cbf5138a3691aeb`; Groth16 `8f0904a7d7a2c8945bf770bdd3c2081e0be1941a` | Standard A/B/C outer proofs; native pairing verifier gadgets and general emulated prime-field arithmetic. | The inspected pairing API binds the circuit to the inner base field and supplies BLS12/MNT4/MNT6 modules. No ready BN254-Fr self-recursive verifier is supplied. |
| **Axiom halo2-lib**, `4d3bceaf235178d1daf63da2c936acf3165c997c` | Actual BN254 pairing gadgets over a larger-coordinate field, with an active Halo2 library and audit references for specified older releases. | Halo2/PLONKish/KZG construction, not an ordinary-R1CS/standard-Groth16 backend. No R1CS exporter or native proof adapter was qualified here. |
| **gnark**, `0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46` | Existing BN254 emulated verification and actual outer commitment protocol. | The previously recorded Bsb22 checks cannot be omitted to fit the present standard128/IC3 verifier. No supported no-commitment full-verifier mode was qualified by the accompanying investigation. |

These are source-level distinctions. No candidate has an executed six-proof
cost, fee, memory, GPU, native acceptance or malicious-MPC result in this note.

## Circom: the useful discovery and required gates

At the exact pin above,
[`verifyProof(publicInputCount)`](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/groth16.circom#L8-L125)
sets six43-bit limbs for BN254 Fq. It checks proof `-A`, B and C through subgroup
components, computes the IC/public-input MSM, evaluates three Miller terms and
the final exponentiation, then compares against a precomputed pairing.
`publicInputCount=2` structurally gives IC3. This is actual BN254 source, despite
the README concentrating on BLS12-381 demonstrations.

The template is not a complete current-native adapter:

1. **Constrain acceptance and key authority.** It returns `out`; a caller must
   assert `out === 1`. Gamma, delta, IC and the precomputed
   `e(-alpha,beta)` are input signals, not authenticated constants. A research
   wrapper must bind the exact validated current role key and its correct Fp12
   representation. Allowing the prover to choose those terms is a different
   predicate. See the input declarations and final assignment in the
   [same template](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/groth16.circom#L18-L28).
2. **Bind native bytes and statements.** The input is affine coordinates, not
   Ark's compressed128 bytes. A wrapper must constrain canonical Fq values,
   Ark flags/sign, Fp2 order, negation of A, and conversion to six43-bit limbs.
   It must reconstruct the exact Output168 or Spend200 SHA and its separately
   ranged LE128 halves. Host decoding, a verification bit or unconstrained
   coordinate conversion supplies no such binding. The Fp12 basis is described
   in [`bn254_func.circom`](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/bn254_func.circom#L35-L56);
   its coefficient mapping to Ark's tower must be checked, not assumed.
3. **Qualify point and exceptional-case semantics.**
   [G1 checks](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/subgroup_check.circom#L37-L53)
   use the curve equation and cofactor one. The
   [G2 check](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/subgroup_check.circom#L64-L97)
   uses the twist equation and `psi(P)=[6x²]P`. Its chosen scalar routine has
   documented unequal-add/intermediate-exception assumptions
   ([source](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/curve_fp2.circom#L590-L645)).
   The IC MSM tracks infinity internally, but the top-level verifier forwards
   only VK coordinates into its Miller loop; its infinity flag is lost
   ([source](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/circuits/bn254/groth16.circom#L52-L99)).
   Thus VK=identity is an identified compatibility gap. Complete canonical
   coordinate ranges, all native nonidentity requirements and the transitive
   arithmetic constraints are not qualified by this inspection.

The repository's own
[README](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/README.md#L16-L20)
labels its circuits unaudited and intended for demonstrations. Its published
BLS benchmarks are not measurements of this BN254 template. The inspected
HEAD is the same2023 commit; repository metadata or the existence of tests does
not establish current cryptographic review.

**Why this addresses the outer-protocol question:** Circom exports ordinary
R1CS and C++/Wasm witness programs
([compiler2.2.3 README](https://github.com/iden3/circom/blob/ad44e915a12bb047b05745c2884aad9cc8326bc6/README.md#L16)).
The inspected snarkjs0.7.6 Groth16 prover constructs the standard A/B/C proof
([prover](https://github.com/iden3/snarkjs/blob/9a8f1c0083d18b9b5e18f526cfd729e7259423be/src/groth16_prove.js#L85-L135));
its verifier uses the ordinary pairing equation
([verifier](https://github.com/iden3/snarkjs/blob/9a8f1c0083d18b9b5e18f526cfd729e7259423be/src/groth16_verify.js#L40-L79)).
The candidate source introduces no gnark Bsb22 commitment interface. This
supports an ordinary-R1CS route; it does not prove that the candidate compiles,
is sound, exports an interoperable witness, or produces an Ark-compatible final
proof without a checked encoding/key adapter and circuit-specific outer setup.

## Why the other inspected routes do not supply a drop-in

**Arkworks:**
[`PairingVar`](https://github.com/arkworks-rs/r1cs-std/blob/70a8298c82ef22b6ab81ee3a6cbf5138a3691aeb/src/pairing/mod.rs#L6-L28)
uses `BasePrimeField<E>` for its group and target variables. The
[Groth16 verifier gadget](https://github.com/arkworks-rs/groth16/blob/8f0904a7d7a2c8945bf770bdd3c2081e0be1941a/src/constraints.rs#L142-L151)
retains that field. For BN254 this would be Fq, not the outer BN254 Fr. The
general
[emulated field](https://github.com/arkworks-rs/r1cs-std/blob/70a8298c82ef22b6ab81ee3a6cbf5138a3691aeb/src/fields/emulated_fp/mod.rs#L3-L24)
is not an implemented pairing adapter. The standard
[A/B/C proof structure](https://github.com/arkworks-rs/groth16/blob/8f0904a7d7a2c8945bf770bdd3c2081e0be1941a/src/data_structures.rs#L7-L16)
remains useful if an appropriate circuit exists. Typed proof points also do not
bind compressed source bytes; `new_proof_unchecked` explicitly omits subgroup
checks, so it is not an admission shortcut.

**Halo2:** its
[README](https://github.com/axiom-crypto/halo2-lib/blob/4d3bceaf235178d1daf63da2c936acf3165c997c/README.md#L81-L114)
and actual
[PairingChip](https://github.com/axiom-crypto/halo2-lib/blob/4d3bceaf235178d1daf63da2c936acf3165c997c/halo2-ecc/src/bn254/pairing.rs#L448-L523)
show a real BN254 pairing implementation for the Halo2 proving stack. Its
private loaders are explicitly unchecked; they do not establish canonical
byte, subgroup or nonidentity admission for our wrapper. This source pass
does not qualify a Halo2-to-standard-R1CS conversion. README audit references
belong to their stated releases, not automatic review of this exact commit or
a future Kaspa adapter.

Two older search hits do not fill the gap: Ariel Gabizon's inspected
[repository tree](https://github.com/arielgabizon/Groth16-BatchVerifierCircuit/tree/2542451c7f11380994b891d69a6268259f1fcfbc)
contains a paper and style files, not an implemented circuit; Matter Labs'
[BatchVerifier.sol](https://github.com/matter-labs-archive/Groth16BatchVerifier/blob/76ec31af62359dee8e519fce98f91654c441080a/BatchedSnarkVerifier/contracts/BatchVerifier.sol#L174-L227)
performs on-chain batching with additional pairings, not an ordinary-R1CS
recursive verifier. Neither is selected.

## Smallest useful next gate

Treat the Circom source as a **new research candidate**, not a repair already
qualified by the Go encoding controls. First settle its exceptional-arithmetic
and canonical-input contract. Then freeze one fixed-Output wrapper using the
existing explicitly public native fixture: exact role key/GT constants,
`out===1`, Ark128 byte/coordinate binding, exact statement SHA and two LE128
inputs. Compile and check the complete assignment without generating new
outer parameters or proofs.

Require the genuine fixture to accept and direct inconsistent assignments to
fail actual R1CS checks. Include changed public proof bytes with unchanged
private points, matched noncanonical Fq bytes/limbs, wrong keys/statements,
identity/off-curve/non-subgroup points and exceptional MSM/pairing cases.
Distinguish parser, generator/assertion, hint and constraint failures. A valid
one-proof fixture is not a complete two-Spend/four-Output relation.

The existing exact-byte Rust/RISC Zero verifier remains the independent
reference alternative described in the frozen feasibility note. Neither an
ordinary central prover nor a plain R1CS export hides the witness/mapping from
that prover. A compatible malicious distributed prover, complete witness
checking, encryption/delivery, state/value/effects conservation, native2/4
acceptance and independent exits remain separate obligations. No source here
supplies automatic coCircom interoperability, a fee reduction or general privacy.

## Exact source identities and evidence boundary

Every captured file body and digest input was read through unchanged helper09.
Finite source captures are under `/var/tmp/kpi-standard-pairing-backend-source-01/`
and `/var/tmp/kpi-standard-arkworks-source-01/`. The main decisive bodies are:

| Repository / path (commits fixed above) | Bytes | SHA256 |
| --- | ---: | --- |
| yi-sun `circuits/bn254/groth16.circom` |4325|`9a3a89daa68c3a0a83d244590b862f0494272f57edd85835738f3503670c2af7`|
| yi-sun `circuits/bn254/subgroup_check.circom` |3108|`06a8392da7e0d828e1929947bf21612a54813bfa9acaa9035a8ad0e441c8333d`|
| yi-sun `circuits/bn254/curve_fp2.circom` |25894|`83dc90d2e42e16eb96441ff6b6209f66eaa72506ce58bd2a62db4e5d5e857251`|
| yi-sun `circuits/curve.circom` |18847|`2977bff071a46efb5a663845a46266bbce72080639317888f48a76296ec07c33`|
| yi-sun `circuits/bn254/pairing.circom` |65754|`c453e3a1eada832bbe7a4bdb707772c0b9424e682b42743727ef247bdfab7e4c`|
| yi-sun `README.md` |6323|`1feb5aa430a7e457fa163eebfaa43b032d85a2d741e1f60a55600f288e334d21`|
| Ark r1cs-std `src/pairing/mod.rs` |3027|`d955483db237ebc3d81f163ca28dd62d8b898e4e3cb258581fb1fff33c2735d0`|
| Ark r1cs-std `src/fields/emulated_fp/mod.rs` |8781|`88a8d92810ec85ab7ba6fde72c853e786fe7d61ccd026ff913c9396049b6a2b5`|
| Ark Groth16 `src/constraints.rs` |20158|`ebbe7740aa8950edcbe41e3a146da7d309d6958f959b404887aaa056cce14b27`|
| Ark Groth16 `src/data_structures.rs` |4783|`b4f55d91a20107d51a9f93dcd1cfb56d184a9b99ff962057675ca2c9ec49ec08`|
| Axiom `halo2-ecc/src/bn254/pairing.rs` |19124|`ab1254b89cc787d2d5edbe1e6299b20b19d6365c0d5ebe681514f4f8d8bf5736`|
| Axiom `README.md` |19254|`03fb0d9dad69b06f64be00ae582f54986c3e3579e0ed3b9a60bc2aa91209b3c8`|
| snarkjs0.7.6 `src/groth16_prove.js` |13477|`36b58c6b524596c009cad1afda4342c4e779965c875ff3b5ad5a0c687cce01f6`|
| snarkjs0.7.6 `src/groth16_verify.js` |3568|`983d0eec8a5f23c85efaec276c7ee47e7e9edc72c15814b1850f8874270ee6bd`|
| Circom2.2.3 `README.md` |4935|`55fbd0ebdd89d9228c92b47e2e18b3bb4cc5cd1fce393c390b901c8e770b6a65`|

The independent Arkworks21-entry ledger is9285 bytes,
SHA`56beaba5990f6de1e2bb7d7981e8ac95f5b7ac94a6525bec1e27a16c98df4fd1`.
The separate14-file Circom arithmetic ledger is6332 bytes,
SHA`78eb57a4c714d7ff97a5b77d9e71c1dae46ba891bcbe62a2926ea0fd2689b3cd`.
These record source inspection, not a transitive security audit or executed
compatibility. No ActualOriginal, private STATE/PLAN/truth, owner/controller
log or runtime argv/environment was read. Existing notes, source profiles,
trial artifacts and publication candidates were not modified.
