# Native BN254 Groth16 aggregation: source evidence

Date: 2026-10-26. Source research only; no circuit, build, setup, benchmark, install, RPC, or activation.

**Finding:** gnark supports BN254-in-BN254 verification. The main blocker is an **unbuilt exact-byte adapter**, not curve compatibility: each public wholeOutput520 tuple includes its 128-byte Ark proof in the effects digest. The outer circuit must bind those exact canonical bytes to the pairing witness. Host parsing or a checksum alone is insufficient. The plan also requires canonical encoding of private Spend proofs. Malicious-secure full-witness MPC remains **unqualified**.

## Pins

Main evidence pin: [gnark `0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46`](https://github.com/Consensys-Incorporated/gnark/commit/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46). Its [go.mod, lines 1–9](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/go.mod#L1-L9) requires Go 1.26.8 and gnark-crypto `v0.22.1-0.20261009142911-8911ee45d22b`. Findings use this exact pin, not floating HEAD.

Latest stable observed: [v0.16.4](https://github.com/Consensys-Incorporated/gnark/releases/tag/v0.16.4), October 7, at [`e974abb44722dd201a7f1949baeabca0fef5866e`](https://github.com/Consensys-Incorporated/gnark/commit/e974abb44722dd201a7f1949baeabca0fef5866e). It fixes emulated scalar-multiplication soundness and recursive-verifier zero-input correctness. The project's reviewed pin already contains complete addition for the latter case; no pin change is proposed.

## Native contract and evidence ledger

The parent reviewer independently read and hash-checked these public files under `poc/local-private-payment/`:

| Source | SHA-256 | Lines |
| --- | --- | --- |
| `verification/common/src/g16.rs` | `c6ce48be94c702858b6a9a7093ae835cf4d2afd7808e56eb2a9a762c1d21b36a` | 9–21 integers; 31–39 G2 coefficients; 66–95 checked proof/equation |
| `verification/common/src/lib.rs` | `949452a43d9db837067a818e09f9660bf5f6ff9a3adac82094120e532aca6d5d` | 83–105 VK; 164–170 digest inputs |
| `relation/src/statements.rs` | `bcd3f5f947904fe6fecc4e747b93e0f85a5c611390d0331651e3a1884004e123` | 7–12 limbs; 33–40 Spend encoding |
| `verification/common/src/wire.rs` | `136f7b1115a64d08e9789114be04d0fa3de90b05da5aa2216bd686effc7b6562` | 119–127 Output tuple/proof offsets |

Arkworks 0.6 BN254 admission requires exact 128-byte compressed proofs, checked decoding, canonical re-encoding, and nonidentity A/B/C. The 328-byte VK has IC3 and two public inputs. SHA-256 of exact statement bytes supplies two little-endian 128-bit halves. Spend200 and Output168 are parent/root-reviewed statement sizes. `wire.rs` locates each 520-byte output row and its proof at bytes 392–520. Root's separate effects-source review confirms those complete tuples, including proof bytes, enter the public effects digest.

The current one-Spend/two-Output codec remains immutable and cannot accept a two-Spend/four-Output aggregate packet. That six-verification aggregate is a research candidate, with target cost unknown.

Root-reviewed VK SHA-256: Spend `b02bbf6a31a57c6132ae1ecaa680e1e955946fc1076fbe4f7e58142407b57203`; Output `2839d491047edd5664db65af3fa92a7194d959e7f94f723eac982aa918c785e6`.

## Supported API and fixed-key binding

The official [example, lines 69–146](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/recursion/groth16/nonnative_doc_test.go#L69-L146) uses `NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]`, `AssertProof(vk, proof, witness)`, and outer `ecc.BN254.ScalarField()`. This uses field emulation.

Proof and inner public witness may remain outer-secret: untagged fields default to secret. Fixed VK identity instead requires populated compile-time circuit constants, for example a field tagged `gnark:"-"`. Witness assignment alone does not bind VK identity. [Schema, lines 184–205](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/frontend/schema/schema.go#L184-L205).

[`ValueOfVerifyingKeyFixed`, lines 279–320](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/recursion/groth16/verifier.go#L279-L320) explicitly requires constant embedding: precomputed G2 lines are not constrained to witness coordinates. It computes alpha/beta pairing E and negative gamma/delta. Map A→Ar, B→Bs, C→Krs, IC→K. The [input-count rule, lines 530–532](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/recursion/groth16/verifier.go#L530-L532) is `len(K)-len(PublicAndCommitmentCommitted)-1`: IC3 without commitments means exactly two inputs, excluding the implicit one-wire.

## Unbuilt adapter gates

1. **Exact encoding:** bind public Output proof bytes to canonical Ark decoding and the pairing coordinates inside the outer relation, or a separately reviewed exact-byte-verifier composition. Preserve canonical Spend encoding too. Checked host decoding only supplies assignments; a malicious outer prover can bypass it. No established gnark Ark-compressed decoding circuit was identified. Proposed future synthetic control: mutate public Output tuple row[392..520] while fixing coordinate witnesses; require outer rejection.

2. **Coordinate and point checks:** reject noncanonical integers before conversion; never guess serialization order. G2 maps c0→A0, c1→A1 in [g2.go, lines 40–49](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/algebra/emulated/sw_bn254/g2.go#L40-L49); gnark-crypto encoding is big-endian A1||A0 with different flags, [marshal.go, lines 1014–1041](https://github.com/Consensys-Incorporated/gnark-crypto/blob/8911ee45d22b/ecc/bn254/marshal.go#L1014-L1041). Enforce curve/subgroup checks and the native nonidentity policy in-circuit. Pairing checks permit infinity; supplied G2 lines are trusted. [Pairing, lines 431–487](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/algebra/emulated/sw_bn254/pairing.go#L431-L487).

3. **Statement/state binding:** constrain exact Spend/Output bytes, SHA-256, half ordering, both 128-bit ranges, and the intended aggregate/state relation. Host verification verdicts supply no circuit authority. BN254Fr uses four internal 64-bit limbs, distinct from the two application digest halves. [Parameters](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/math/emulated/emparams/emparams.go#L137-L148); [canonical little-endian bits/FromBits, lines 59–94](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/math/emulated/field_binary.go#L59-L94).

[`WithCompleteArithmetic`, lines 20–35](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/recursion/groth16/opts.go#L20-L35) is a deprecated no-op: scalar multiplication is complete by default. [`WithSubgroupCheck` checks proof A/C/B](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/recursion/groth16/verifier.go#L591-L595), but does not establish byte binding or nonidentity policy.

## Evidence boundary

No target constraint count, proving-time, memory, or distributed-prover evidence was produced. Official [circuit documentation](https://docs.gnark.consensys.com/Concepts/circuits) explains emulation costs and requires representative profiling before budget claims. A new outer Groth16 circuit needs its own circuit-specific setup; existing inner setup is unchanged. Setup MPC is separate from malicious-secure online full-witness MPC. API presence establishes neither active privacy nor permissionless exits.
