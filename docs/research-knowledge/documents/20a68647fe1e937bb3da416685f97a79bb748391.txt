# Low-memory W1 aggregate prover design (2026-10-29)

Status: source-grounded design; no proof has been launched.

## Problem

The exact aggregate relation is admitted at 13,093,029 constraints,
12,949,821 variables, three instance variables and matrix fingerprint
`c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab`.
Its independently scanned standard R1CS is 2,840,345,392 bytes with SHA-256
`cc76d603d0cb184f4e43b99d3af9f215274c0a67bdbec28ed435046c2b9c42bc`.

The retained stock-Ark public-invalid probe entered the prover after decoding
the historical proving key, then hit its exact 12 GiB cgroup limit without
returning or serializing a proof. Current available memory is too close to that
negative, and swap is exhausted. This is a hard hold on the stock path, not an
arithmetic or privacy result.

## Pinned source observations

1. Ark Groth16 0.6.0 `create_proof_with_reduction()` synthesizes with
   `construct_matrices: true`, retains the constraint system, constructs the
   QAP witness and then creates additional full-length bigint assignment
   vectors. The reviewed source is
   `/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ark-groth16-0.6.0/src/prover.rs`,
   SHA-256 `2747321418043a0d362b95075b14141056b327b27266232c7fdbf6de018fc3bd`.
2. The same crate exposes the exact reduction formula. Its witness map uses two
   domain vectors `a,b`, an `ab` vector and then a `c` vector, dropping `a,b`
   before allocating `c`. The reviewed source is `r1cs_to_qap.rs`, SHA-256
   `cb024c922c9c406a8ed0f549b4dbfa85a1a924511ea47446a990a6ef7d2a1b78`.
3. Ark EC 0.6.0 already supplies `ChunkedPippenger`, which bounds MSM base and
   scalar buffers and accumulates exact group results. The reviewed source is
   `stream_pippenger.rs`, SHA-256
   `bf90c0a93abad26f2da10624ded3c37204ed6d35905afcd22333685601bfbc4a`.
4. This relation already has exercised matrix-free synthesis using
   `SynthesisMode::Prove { construct_matrices: false,
   generate_lc_assignments: false }`; `examples/partition_core.rs` has SHA-256
   `9afc87f7a9fb7e3714a06ec5066f68241a191ed87fbcc79f1295e016e4b1ff78`.
5. The exact stock negative is implemented by
   `examples/probe_public_invalid_proof.rs`, SHA-256
   `8c7be87731f0291b7c2fba51ed9728cf1fdc1cf13d4de82198ac66bd7c5af70d`.
   It is deliberately ineligible for W1 proving.

These are source observations, not a successful resource measurement.

## Selected design

Build a nondefault, no-setup W1 prover with five fixed phases:

1. Revalidate the canonical seven W1 checkpoints and reconstruct exactly one
   selected round. Reverify its six Output proofs, three signature relations
   and cross-round history before reading the proving key.
2. Synthesize the exact aggregate circuit in matrix-free prove mode. Retain
   only the canonical instance and witness assignments. Require three instance
   variables, exact variable and witness counts and the effects-digest-derived
   public inputs. Arkworks 0.6 does not record constraint rows in this mode, so
   `num_constraints()` is required to be zero here; the assignment stage does
   not claim current constraint-row construction or satisfaction.
3. Stream the sealed standard R1CS constraint section once. For each row,
   canonically decode every `(wire, coefficient)`, reject aliases/out-of-range
   wires, and evaluate A, B and C against the assignment into domain-sized
   field vectors. In the same pass, require every row's `A * B == C`. Recheck
   the historical 13,093,029-row count, section sizes, term counts, wire map and
   exact EOF. This is the stage that establishes constraint satisfaction. Never
   materialize Ark matrices.
4. Apply Ark's exact domain operations in place to derive H. Consume the
   historical PK's canonical Ark 0.6 compressed serialization in field order.
   Check every vector length before its points, subgroup-validate each point,
   and fold it immediately into bounded `ChunkedPippenger` buffers for H, L,
   A, B1 and B2. Never retain an expanded query vector or full bigint clone.
   Sample fresh nonzero-capable Groth16 `r,s` from the OS RNG and use Ark's
   unchanged proof formula.
5. Verify in-process with the independently opened exact pinned VK and public
   inputs, require wrong-input and mutated-proof rejection, then serialize only
   the canonical proof receipt to its create-new mode-0400 private target and
   fsync it. The existing independent W1 verifier must rerun before stage 08 can
   exist.

The circuit, assignment order, R1CS, proving key, verifying key, public inputs,
Groth16 randomness and verification equation are unchanged. This is an
implementation of established Ark formulas with a different storage schedule,
not a new cryptographic primitive.

## Implemented controls

The default crate exposes only a non-authorizing status. Its raw geometry,
identity, assignment, H and fixed-`r,s` interfaces exist only under the
nondefault `algebraic-controls` feature. That control crate
`poc/local-private-payment/private_batch_trial/low_memory_w1_prover` now has:

- two-pass standard-R1CS authentication before domain allocation or secret row
  evaluation, followed by an in-use rehash;
- two-pass decoded-PK authentication before point decode or secret MSM,
  followed by an in-use rehash and independent canonical VK identity check;
- canonical field order, exact query lengths, per-point subgroup validation,
  fallible local vector/MSM reservations and a source-fixed 65,536-pair buffer;
- exact H equality against Ark across six deterministic randomized
  domain-boundary cases;
- exact proof-element equality against stock Ark for fixed `r,s` across the
  original circuit and three deterministic randomized domain-boundary cases;
- wrong-input, mutated-proof, container, field, row, wire-map, artifact
  identity, independent-VK, every PK field/query length/point, truncation,
  trailing-byte, preallocation and second-pass substitution controls.

The all-feature suite is 13/13 green, plus the default-surface compile-fail
doctest. This is small public synthetic
equivalence evidence, not W1 proof evidence.

The exact Ark serialization arithmetic also closes without padding or an
unidentified suffix: fixed VK/scalars contribute 392 bytes; A and B1 each
contribute 414,394,280; B2 contributes 828,788,552; H contributes
536,870,888; and L contributes 414,394,184. Their sum is exactly the pinned
decoded PK size, 2,608,842,576 bytes. The streamer still must authenticate the
complete decoded SHA-256 and gzip process outcome at runtime.

The standalone low-memory crate remains deliberately non-launchable: its
feature-gated algebraic control accepts raw assignments, H, identity contracts
and fixed test `r,s`, and its test still returns the parsed VK. By itself that
crate remains source-only equivalence evidence; none of those caller-controlled
surfaces is an admissible proof authority.

The relation crate now implements that nondefault fixed source interface. It
calls private `prepare::<1>()`, directly consumes its vectors in the streamed
R1CS/low-memory engine, then opens the proof parameter descriptors for the
decoded/compressed PK, decode receipt and independent fixed VK only after exact
satisfaction. Assignment preparation itself earlier authenticates and
deserializes the historical source aggregate VK inside `load_frozen_sources()`;
it is not covered by the later scoped phase claim. The receipt therefore says
both `historical_source_vk_opened_during_assignment_preparation=true` and
`proof_parameter_descriptors_opened_after_satisfaction=true`. The entry samples
nonzero `r,s` from `OsRng` and verifies against the separately pinned VK. Wrong
public inputs and a mutated proof must both reject.
The only caller input is a create-new receipt path in an existing owner-only
directory; no assignment, artifact path, descriptor, round, public input or
randomness enters. The private receipt contains only the 128-byte compressed
proof, two derived public inputs and public boundary facts, and explicitly says
full secret zeroization is false.

The independently pinned VK now crosses authentication as an owned exact
`[u8; 328]` snapshot: exact read, EOF, SHA-256 and stable metadata checks occur
before `Cursor` deserialization over those same bytes. No authenticated live VK
file survives into verification. The proof writer returns the SHA-256 of the
exact canonical bytes handed to the create-new private writer, and only after
file and directory fsync/final checks complete. Its example emits one fixed
lowercase commitment line and never rereads the output path.

The same nondefault source also has a verification-only API/example. It accepts
only a bounded (4,096-byte maximum), unique-key, exact-canonical proof receipt
on stdin, deserializes its 128-byte proof and exactly two canonical `Fr` inputs,
opens only the fixed VK into the owned snapshot, and requires valid-proof,
wrong-input and mutated-proof outcomes. It has no assignment, R1CS, PK, prover,
output-file, network or funds path and emits only the exact input-byte SHA-256
commitment on success.

This is source-interface evidence only. No combined build has been frozen and
no proof binary, external verifier or host supervisor has run; every launch,
privacy, financial, Testnet and production authority remains false.

## Memory model and measured scaling

One full W1 assignment is roughly 0.39 GiB at 32 bytes per field element.
Three `2^24` field vectors are roughly 1.5 GiB. The 2.61 GB canonical
compressed PK is read sequentially; expanded query payload is not resident.
Bounded MSM buffers add a selected constant.

Two public synthetic row controls passed with zero swap:

| Domain | R1CS bytes | Peak RSS | Receipt SHA-256 |
| ---: | ---: | ---: | --- |
| 262,144 | 33,554,184 | 40,476 KiB | `7f9f29029862ebdda4bd31c834de5f4d9cd2aba46fff8dc67a477df0fa4dd570` |
| 1,048,576 | 134,217,480 | 151,144 KiB | `2db1e43572000912d64a503e15fb11d86bb1ef8d1143ce2cab046252c394e7a8` |

The sealed local receipts are under
`.local/low-memory-w1-scaling-20261029-02/`. They demonstrate the expected
absence of retained matrices at these sizes. They do not measure exact W1
assignment synthesis, 2^24 FFTs, historical-PK streaming time, or total proof
RSS. No real proof may launch from an extrapolation. Admission still requires
an exact preparation measurement and a safe host cap.

A public synthetic control compared one million G1 and G2 pairs:

| Group | Buffer | Elapsed | Peak RSS | Swap |
| --- | ---: | ---: | ---: | ---: |
| G1 | 1,024 | 0.507 s | 4,168 KiB | 0 |
| G1 | 65,536 | 0.142 s | 16,280 KiB | 0 |
| G1 | 262,144 | 0.146 s | 54,636 KiB | 0 |
| G2 | 1,024 | 1.008 s | 4,268 KiB | 0 |
| G2 | 65,536 | 0.355 s | 26,220 KiB | 0 |
| G2 | 262,144 | 0.345 s | 94,440 KiB | 0 |

The fixed 65,536-pair buffer is effectively as fast as 262,144 in this control
while using roughly one quarter to one third of its RSS. The sealed receipt is
`.local/low-memory-w1-msm-buffer-20261029-01/receipt.json`, SHA-256
`3fb6affa67b68fc3e8103ed1e1eb683137f52d7e5d3a704571f99fcf33b7718c`.
The benchmark excludes point decoding and does not predict exact W1 wall time.
Ark's internal MSM bucket allocation remains fail-stop even though the local
base/scalar buffers reserve fallibly.

The exact public c023 R1CS was then exercised without any private assignment,
PK, proof or network input. The control first authenticated all
2,840,345,392 bytes to `cc76d603...`, then allocated an internal public-invalid
assignment (`wire0=1`, every other wire zero), parsed all 13,093,029 rows and
executed the complete 16,777,216-domain H schedule. It retained 40,934
unsatisfied rows as expected and returned only the H digest
`637365bce70975baa6db7c396757ee73acd4471294e5f9852402ecc993996eee`.
Under a 12 GiB address-space cap it completed in 24.83 seconds wall with
2,246,860 KiB peak RSS and zero swap. The sealed receipt is
`.local/low-memory-w1-exact-r1cs-resource-20261029-01/receipt.json`, SHA-256
`499c761cf4fddd169a4f19feac2a22282de910ddb8b2be008c62a734f55579a8`;
the source/binary/time evidence SHA-256 is
`6e16b97fc5fc1d8071cbdfb64b2dfe508f7012372da6c57ea2f90e41574a3696`.
This is resource-control evidence only. In particular, the assignment is
deliberately invalid, so it is not satisfaction, proof, launch or privacy
evidence.

The exact historical decoded PK is separately retained locally as a read-only
2,608,842,576-byte file with SHA-256
`170431eee45f57ff6a3dc278d96f8a824145b8ca9ded04088a662983a449e945`.
This is pre-secret evidence, not a sealed same-inode gzip/decoded-PK authority.

## Alternatives rejected for this attempt

- Raising the cgroup limit or adding swap: risks unrelated processes and has no
  successful bound.
- Retrying stock Ark: the retained 12 GiB OOM is decisive negative evidence.
- New setup or a smaller relation: changes the trusted parameters or research
  question.
- Converting to another prover/key format: adds an unreviewed parameter
  conversion boundary.
- GPU proving: no selected compatible GPU prover/key path exists, and the
  available 8 GiB device does not remove host-side synthesis/QAP obligations.

## Required controls before a real proof

1. Hostile standard-R1CS parser controls: bad magic/version/prime, duplicate or
   missing sections, noncanonical field aliases, wire overflow, row/term
   truncation, trailing bytes and map substitution.
2. Deterministic randomized small circuits: streamed row evaluations and H now
   equal Ark's in-memory matrices/witness map across six domain-boundary cases.
3. Same small PK, same assignment and fixed `r,s`: low-memory and stock Ark
   proofs must both verify and all three proof group elements must match
   exactly. This control now passes.
4. Wrong assignment, wrong R1CS, wrong PK/VK, wrong public input, mutated proof
   and accepted-invalid sentinels must fail closed. PK/VK field, query, identity,
   truncation and second-pass substitution controls pass. The fixed source entry
   owns the assignment/public inputs and requires wrong-input and mutated-proof
   rejection at run time; exact-proof execution remains separately admitted.
5. Medium R1CS/H scaling must retain wall/RSS/swap/IO evidence and demonstrate
   that memory growth excludes matrix storage. The first two sizes pass;
   historical-PK and exact-assignment scaling remain required.
6. The exact round-1 preparation must prove satisfaction and geometry before
   PK decode. Proof launch remains a separately admitted one-use action.

Any discrepancy is a retained negative. Do not retune the relation, witness,
public inputs or privacy thresholds to make this path pass.

## Evidence boundary

A successful proof would establish only that the exact offline synthetic W1
assignment satisfies the exact admitted relation and can be proven under the
historical key. It would not establish setup privacy, cryptographic security,
observer completeness, financial privacy, Testnet settlement or production
safety.
