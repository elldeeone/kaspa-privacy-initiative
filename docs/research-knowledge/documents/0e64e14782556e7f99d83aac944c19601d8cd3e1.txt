# Gnark outer commitments and native Groth16 compatibility

2026-10-26. Exact-source assessment plus retained public experiment evidence.
This note creates no circuit, setup, proof, build, or new run.

**Finding:** existing Arkworks BN254/IC3 proofs are mathematically compatible
with the recursive verifier. An **outer** gnark Groth16 proof with BSB22
commitments additionally requires commitment, PoK, derived-input and VK metadata
verification. Those checks cannot be discarded to fit the current standard
Ark128/IC3 verifier. The full outer system and its commitment count remain
uncompiled and unqualified.

## Correction established by the first positive run

Our earlier source assessments omitted the emulated rangechecker/logderiv
integration's commitment-hook dependency. That omission left the proposed direct
compiled-system `Solve` path unqualified. The frozen assessments remain unchanged:
[backend feasibility](NATIVE-G16-AGGREGATE-BACKEND-FEASIBILITY-01.md), SHA
`e05b2682984f1f220dd808821c34b673c64ea1b38ae7eb730c4f3611ba211e40`,
and [gnark source assessment](GNARK-NATIVE-G16-AGGREGATE-SOURCE-01.md), SHA
`b255eac3d31467c8c8710cbb5496e2f14463eb19c8aa7895a46f3c08db946e7b`.

Run `codec-02` built successfully and compiled the G1 encoding R1CS: 5,148
constraints, 33 public variables including ONE, eight secret variables, serialized
size 208,817 bytes, SHA
`4da8a6ebe30a53d41936ed41ad1dcc60e73a997de00d277807ad77e404d3842b`.
Its initial generator assignment expected ACCEPT but returned
`HINT_OR_SOLVER_ERROR`: `placeholder function: to be replaced by commitment computation`.
There was **no successful positive solve, typed constraint unsatisfaction,
negative case, or encoder verdict**. This also establishes no encoding bug.

| Retained public evidence | Bytes | SHA256 |
| --- | ---: | --- |
| [Solve stdout](/dev/shm/kpi-native-g16-adapter-01/run-codec-02/SOLVE-STDOUT.txt) | 1013 | `3b6ec6afd6d3f891072d19ac5f794384b564aaf6f66ac88fccdec786c7a463dd` |
| [Execution record](/dev/shm/kpi-native-g16-adapter-01/run-codec-02/EXECUTION.json) | 4650 | `c7940c6193a9a472fad29612491011645fe349417b0d8c10f8f34ccd249cef23` |
| [Independent source diagnosis](../review/GNARK-CODEC-02-COMMITMENT-SOURCE-DIAGNOSIS-01.json) | 5752 | `8af1f23f8763eb8c52d965926a870b58517fa8bee308f2615392ad78c98d8da6` |

The diagnosis traces `NewField` through commitment-based rangechecking,
logderiv, deferred multicommit and the R1CS commitment placeholder. Normally
that placeholder errors. Its testing/debug branch instead uses a random
nonzero field value and warns that resulting proofs are unsound and fail
verification. It is not a qualified replacement here.
[Placeholder, lines 14–27](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/frontend/cs/commitment.go#L14-L27).
No random/zero challenge override or omitted deferred check is authorized.

## Exact outer proof, key and input changes

All gnark references below use commit
`0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46`; its crypto dependency is
`8911ee45d22bdf9d1c6ab4affe2d4f7ffaedd557`.

1. **Proof protocol and bytes.** `Proof` contains A/B/C plus
   `Commitments []G1Affine` and a batched `CommitmentPok`. The prover replaces
   the placeholder with an actual Pedersen commitment and hash-to-field
   computation, then constructs/folds its PoKs.
   [Prove, lines 36–40, 158–227](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/backend/groth16/bn254/prove.go#L158-L227).
   `WriteTo` actually writes `Ar | Bs | Krs | Commitments[] | CommitmentPok`;
   its introductory order comment is stale.
   [Implementation, lines 33–55](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/backend/groth16/bn254/marshal.go#L33-L55).
   The compressed G1/G2 sizes are 32/64 bytes and the G1 slice has a four-byte
   big-endian length prefix. Therefore this native gnark serialization is
   **164+32m bytes**, where m is the commitment count, including its trailer
   when m=0. This is a source-derived format formula, not a target fee result.
   [Crypto encoder, lines 540–552, 778, 1024](https://github.com/Consensys-Incorporated/gnark-crypto/blob/8911ee45d22bdf9d1c6ab4affe2d4f7ffaedd557/ecc/bn254/marshal.go#L540-L552).

2. **VK and public inputs.** The VK includes `CommitmentKeys` and
   `PublicAndCommitmentCommitted`. Setup makes commitment-output wires public
   at the Groth16 level and creates the corresponding commitment keys.
   [Setup, lines 54–102, 280–293](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/backend/groth16/bn254/setup.go#L54-L102).
   VK serialization includes the committed-index matrix, commitment-key count
   and serialized keys.
   [Marshal, lines 113–140](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/backend/groth16/bn254/marshal.go#L113-L140).

3. **Required verifier work.** `Verify` checks commitment/key counts and caller
   witness arity `len(K)-m-1`; it derives/appends m hash scalars, verifies the
   Pedersen PoK and adds commitment points to the public-input accumulator.
   [Verify, lines 47–58, 85–123](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/backend/groth16/bn254/verify.go#L47-L123).
   Dropping those fields/checks changes the predicate. The current exact
   Ark128 proof admission and IC3/two-input verifier have no such interface.

4. **Deferred challenge dependency.** Multicommit collects committed variables,
   schedules a deferred callback, obtains the root through `Commit`, and derives
   callback challenges from it. The R1CS builder records commitment metadata
   and the placeholder's output wire. These are part of the compiled checking
   path, not optional logging.
   [Multicommit, lines 43–63, 105–127](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/multicommit/nativecommit.go#L105-L127),
   [R1CS Commit, lines 896–925](https://github.com/Consensys-Incorporated/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/frontend/cs/r1cs/api.go#L896-L925).

## Compatibility boundary and unfinished work

**Inner:** the existing Ark128 proof and selected IC3 VK have no commitment
metadata. Their A/B/C equation, after the checked canonical byte/coordinate
bridge, remains compatible with the BN254 recursive verifier. Nothing here
requires changing or regenerating those inner proofs/keys.

**Outer m=0:** gnark's own serialization still differs from Ark128 in layout,
flags and byte order. A checked standard A/B/C encoding bridge can address the
format difference when the mathematical VK and statement interface match.
This does not establish that any new outer key matches the current fixed role
key or its two-input interface.

**Outer m>0:** the additional commitment/PoK protocol above requires a compatible
verifier and key/input metadata. It cannot be replaced by an Ark128 byte
projection. No full outer system has been compiled here, so its m, key size,
complete proof shape and native acceptance remain unknown.

The experimental full wrapper exposes **296 explicit public byte variables**
(Statement168+Proof128). A future compact public interface would be a separate
statement/constraint design and must preserve exact byte/effects binding. It
must not be conflated with the inner proof's two SHA-derived LE128 scalars.

The separately authored full wrapper remains **uncompiled and unfinished**:
[circuit.go](native-g16-adapter-01/adapter/output/circuit.go), 4893 bytes, SHA
`e68fcab1836e5a4be52a821ef0f0ed75f5dc4065688663e496be8ba192193f1a`;
[assignment.go](native-g16-adapter-01/adapter/output/assignment.go), 2037 bytes, SHA
`f64d2e234a1dd40432ae5fb55dd2ec4dc312e88e458076a7e16463292ffb488a`.
No full harness with a qualified setup-free commitment path was completed.
This note does not assess the separate prospective bits-only encoding run.

There is no full-recursion cost, fee, outer-proof soundness, current native 2/4
acceptance or malicious full-witness MPC qualification. The ordinary constructor
still sees its witness. Current financial codecs/profiles remain unchanged.

## Exact official-source ledger

Paths in the first six rows are relative to gnark commit 0be5c2 above; the last
row is relative to its exact crypto commit 8911ee above. All bodies were read
through unchanged helper09 from the sum-verified owned source cache.

| Source | Bytes | SHA256 |
| --- | ---: | --- |
| `backend/groth16/bn254/marshal.go` | 14495 | `01bd3c3ba6fcbc02af3aaeb79aa5dfdfa6396254123a084f45c8080f4f128521` |
| `backend/groth16/bn254/prove.go` | 14995 | `cce9ea860b690391750ffed573db1dd00f1f34ca9047b88d298139e4c5c9b46e` |
| `backend/groth16/bn254/verify.go` | 7785 | `0c7f2407ff79f6b16511acc6f91e6ba777ee637c3dface00d6cbfc49fb7662b3` |
| `backend/groth16/bn254/setup.go` | 19624 | `5842791928849d33cd34b39c6b6e48d4e97e40aca10ccd547a1c06994dcc46c0` |
| `std/multicommit/nativecommit.go` | 6374 | `9343ff7a46afb1380c0772cbcdafda6b9afbf776a6a5103a1845a77f7afcd48b` |
| `frontend/cs/commitment.go` | 890 | `892907423e1557255deae0e38f68cd65feb5a0a840b9f4d37b8efb43152e8b95` |
| `ecc/bn254/marshal.go` | 33576 | `d479596a362f12e4bd2dd4f9ed60fe562e34932ac1a9bc74eabf07e9d172b1ec` |

The R1CS commitment source additionally cited above is
`frontend/cs/r1cs/api.go`, 28392 bytes, SHA
`09f8100795a959229c9cb47f66389742b6b5d0f78a8ff4cb03d80c5b0bdf0d5d`.
No arbitrary challenge override, setup/proof generation, compile, RPC, private
input read, or financial-source change was performed for this companion note.
