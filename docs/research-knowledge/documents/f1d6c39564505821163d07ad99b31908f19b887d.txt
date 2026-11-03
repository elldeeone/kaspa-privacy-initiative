# Construction gate: actual API failures and real-curve certificate

**The bounded ADR0061 experiment passes.** It rejects two unsupported
construction shortcuts using the actual upstream APIs and curve, while
retaining a positive component-assembly/binding seam. This is not a valid KAS
transaction, a ValueShuffle implementation or a privacy qualification.

The frozen Rust source is
`5647600c8471e4c4e0281b555ae066af8a97705891e4b5677ffe971b1f85afa3`;
Cargo.lock is `008537b42e950ae75e016f322be9b7b76be6ff49771aca6e9592745d986875ac`.
All nine reviewed API files match their exact official Sapling Git blobs at
`88a7946b4a3066787776e11f0a502654167e022d`. The lock identifies 86 packages,
including 84 registry packages. Actual results:
[RESULTS-01.json](RESULTS-01.json), SHA256
`8736aec390fc09ff11ea6ea1f518168d0d2cf0ded0b73ac948dcc0f858dbf02d`.

## Observed controls

| Control | Actual outcome |
| --- | --- |
| Proof-bearing redacted records passed to the real high-level prover | `MissingProofGenerationKey`, before the panic-on-use prover backend or RNG |
| Same records passed to the real IO finalizer | `MissingValueCommitTrapdoor`, before RNG |
| Noncanonical external binding scalar | `InvalidBindingSignatureSigningKey` |
| Exposed per-owner blinding difference on actual Jubjub points | Each of three owners' exact two-output group recovered among all 15 pairs |
| Fixed permutation | Same output IDs recovered |
| Wrong blinding contribution or fee | No matching pairs |
| Missing blinding contribution | Missing attack input, never an anonymity pass |
| Redacted records with the correct externally supplied aggregate key | Extraction/signing and actual commitment-derived RedJubjub Binding verification pass |
| Incorrect aggregate key | Extraction/signing still succeeds, but actual Binding verification rejects |
| Wrong public value balance or digest | Binding verification rejects; wrong digest also rejects the extractor's SpendAuth check |

The separate amount-only oracle has nine eligible pairs. It is calibration,
not an argument to the point-equation attacker. The matcher receives public
commitments, fee, opaque IDs and beta*R only; no note openings or true pair.
The public fixture is not a statistical sample or hidden-truth privacy study.

All Groth16 fields are explicit non-genuine placeholders. The positive boundary
is actual parser/extractor/SpendAuth/Binding behavior only. A full Sapling proof
verifier would reject these records. No proof, setup, VM, GPU, accepted state,
native reserve or real wallet secret is part of this experiment.

## Execution and retained failure

Public dependency acquisition took 3.881 seconds. The first offline build
failed before the harness compiled because `/usr/bin/cc` resolves through an
unmounted `/etc/alternatives` path. That failure and its source/command remain
in [build-failure-01](build-failure-01/CAUSE.md). Explicitly selecting the already
installed GCC linker fixed the operational cause; Rust source, fixture,
expected controls and dependency lock did not change.

The successful offline build took 21.494 seconds, with an end-of-work cgroup
peak of 420,372,480 bytes and zero swap. The actual experiment ran in
0.01354 seconds; the whole run cgroup peaked at 8,441,856 bytes, including its
Python wrapper. These are cgroup observations, not wrapper-only Rust usage.
Caps were two CPUs/four GiB/swap zero. The namespace had no original home or
financial-parameter source; the environment was cleared, source was read-only,
and build/run used an unshared network. Compiler, OS and selected upstream
dependencies remain trusted premises.

[Source/execution joins](SOURCE-AND-EXECUTION-01.json),
[locked dependencies](LOCK-SELECTION-01.json) and
[unit cleanup observations](CLEANUP-01.json) retain the exact boundaries.
All four owned units are collected/inactive with no resident worker. No
unrelated service was changed. The first failure is not a failed privacy claim.

## Decision consequence

An all-witness builder, individual blinding-share disclosure and output
permutation do not meet the proposed construction observer. Low-level Sapling
component reassembly plus a correct aggregate binding key is a real API seam;
it does not supply anonymous message transport or private aggregation.

The established ValueShuffle family remains the strongest identified candidate
for that missing construction. Complete output-tuple carriage, masked blinding
aggregation, compatible final binding semantics and a reviewed native-KAS
adapter remain open. The original price-prior, singleton ancestry and heldout
failures remain unchanged. No new cryptographic primitive or KAS relation is
selected by this result.

The finite publication packet deliberately excludes `REVIEW.md`, whose final
independent result/inventory join is performed separately after this worker
releases its agent slot. Source/fixture/launcher reviews preceded execution.
