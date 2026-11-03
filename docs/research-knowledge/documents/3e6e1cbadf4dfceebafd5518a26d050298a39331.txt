# ADR-0099: Low-memory no-setup W1 aggregate prover

**Status:** Accepted for bounded offline algebra controls. A fixed nondefault
private-receipt entry exists; a frozen combined build and host launch remain
blocked until separately reviewed.

## Context

The stock Ark Groth16 path for the exact 13,093,029-constraint aggregate
relation was killed at a 12 GiB memory cap after proving-key decode and prover
entry. The host does not currently have a qualified safe stock-prover window.
The exact standard R1CS has independently passed a complete row/term/section
scan, and the relation already supports matrix-free assignment synthesis.

## Decision

Implement a feature-gated offline prover that:

- performs matrix-free assignment synthesis;
- streams the sealed standard R1CS to evaluate and satisfy every row;
- applies Ark 0.6.0's unchanged R1CS-to-QAP domain operations;
- streams Ark's canonical compressed proving key, subgroup-validating each
  point and using bounded chunked Pippenger for every proving-key MSM;
- uses the historical proving/verifying key without setup or conversion; and
- publishes a proof only after exact in-process and independent verification.

Arkworks 0.6 deliberately records no predicate rows when
`construct_matrices:false`; its `num_constraints()` is therefore zero during
the assignment-only phase. That phase checks exact instance/witness/variable
shape and derived public inputs, and explicitly reports that current constraint
rows and satisfaction were not checked. The sealed historical row count is
reference evidence until the next phase streams all 13,093,029 exact R1CS rows
and checks satisfaction before the proving key is opened.

Assignment preparation is not key-free: `load_frozen_sources()` authenticates
and deserializes the historical source aggregate VK before exact R1CS
satisfaction so it can validate the retained source material. The later phase
claim is therefore deliberately narrower and applies only to proof parameter
descriptors, not to every VK read by preparation.

No real W1 proof is authorized until parser, equivalence, hostile-input and
resource-scaling controls pass and a separate host admission succeeds.

The raw geometry, identity, assignment, H and fixed-`r,s` interfaces exist only
behind the nondefault `algebraic-controls` feature. They are test seams, not
proof authority. The default build exposes only a private-field status value
whose source-owned assignment, historical PK, independent VK, OS randomness,
sealed gzip and launch gates are all false.
The low-level algebraic control API is not a production entry: raw
assignment/H/identity/fixed-randomness inputs and the VK parsed from the same
test PK are ineligible for launch. The fixed relation entry therefore does not
expose those surfaces: it owns the W1 assignment and historical PK/VK
authorities, samples internally with `OsRng`, and independently verifies with
the pinned VK.

The relation crate now contains the one-way integration under the nondefault
`offline-w1-prover` feature. Its fixed entry privately calls `prepare::<1>()`,
streams the exact pinned R1CS and requires satisfaction, opens fixed parameter
descriptors for the decoded/compressed PK, decode receipt and independent fixed
VK only afterward, draws nonzero `r,s` internally from `OsRng`, and
verifies in-process against the independently opened pinned VK, including
wrong-input and mutated-proof rejection. The caller supplies only a create-new
receipt path in an existing owner-only directory. No callback, assignment,
artifact path, round, public input, randomness, setup or authority crosses the
API. Only the 128-byte compressed proof, its two derived public inputs and
honest public boundary facts enter the private receipt; full secret zeroization
remains false. The receipt records both scoped facts explicitly:
`historical_source_vk_opened_during_assignment_preparation=true` and
`proof_parameter_descriptors_opened_after_satisfaction=true`.

The independent VK is read, length/EOF/hash/metadata checked, and retained as
one owned `[u8; 328]` snapshot before a `Cursor` deserializes those same bytes;
verification never consumes an authenticated-then-live VK file. After the
canonical receipt bytes are create-new written and fsynced, the writer returns
their exact SHA-256 commitment. The fixed example emits only
`FROZEN_W1_PROOF_RECEIPT_SHA256=<64 lowercase hex>` on success and never rereads
the receipt path.

A separate verification-only example accepts at most 4,096 bytes on stdin,
requires the exact unique-key canonical receipt schema, deserializes its
128-byte proof and exactly two canonical field inputs, snapshots only the fixed
VK, and performs valid-proof, wrong-input and mutated-proof checks. It writes no
file and emits only
`FROZEN_W1_VERIFIED_PROOF_RECEIPT_SHA256=<64 lowercase hex>` on success.

These source interfaces are not proof evidence or launch authority. The combined
source/binary closure, same-inode host admission, external verifier process and
one-shot supervisor still require separate freezing and review before any exact
proof run.

## Invariants

1. Exact circuit source, c023 R1CS, assignment order, PK/VK, public inputs and
   Groth16 proof equation remain unchanged.
2. No caller-supplied path, digest, public input or boolean can select proof
   authority. Only the canonical seven-checkpoint W1 source may enter.
3. Relation satisfaction and geometry are established before PK decode.
4. `r,s` are fresh OS randomness; no retry reuses an attempt identity.
5. OOM, signal, nonzero exit, parser discrepancy or verification error
   quarantines the attempt and publishes no stage 08.
6. Setup, ceremony, network and funds remain forbidden.
7. The decoded PK byte identity, canonical field order, exact query lengths and
   per-point subgroup checks are mandatory; no converted key is eligible.
8. A generic `Read + Seek` two-pass check is algebraic evidence only. Production
   binds the fixed historical gzip identity and the decoded PK's read-only inode
   identity after assignment synthesis and exact R1CS satisfaction, but before
   decoded-PK deserialization or any secret-dependent MSM.

## Alternatives

- More RAM/swap for the stock path: rejected without a safe measured bound.
- Retry the identical stock path: rejected by the retained OOM.
- New setup, reduced relation or alternative key format: rejected because each
  changes the experiment or trust boundary.
- GPU path: deferred; no compatible selected implementation exists.

## Security and privacy implications

Streaming removes retained matrices; it does not weaken constraint checks. The
PK streamer additionally removes expanded query vectors; it does not alter the
key. The main new risks are parser disagreement, variable-order mismatch, QAP
schedule drift, serialized-key field-order drift, invalid points and
MSM/formula mistakes. Exact equivalence controls, canonical byte identity and
independent verification are mandatory. Passing them is implementation
evidence only, not proof of cryptographic security or privacy.

The algebra controls now preauthenticate complete R1CS and decoded-PK bytes,
rewind, and rehash during use. Local domain, query and MSM buffers reserve
fallibly. Ark's internal MSM bucket allocation can still fail-stop, so exact
host admission remains mandatory. The fixed source entry now owns fresh
`OsRng` sampling; proof execution and every production authority remain absent.

## Evidence and reconsideration

See
[`research/low-memory-w1-aggregate-prover-2026-10-29.md`](../../research/low-memory-w1-aggregate-prover-2026-10-29.md)
and sealed preflight SHA-256
`87b3ab338d30bbfecfd0dcabfdbd56c1263245f2cc5a0e7c5d0160d32113fdd0`.
The public synthetic MSM-buffer receipt is
`.local/low-memory-w1-msm-buffer-20261029-01/receipt.json`, SHA-256
`3fb6affa67b68fc3e8103ed1e1eb683137f52d7e5d3a704571f99fcf33b7718c`.

An exact public-R1CS-only resource rehearsal authenticated the full
2,840,345,392-byte `cc76d603...` file before allocation, scanned all
13,093,029 rows with the fixed public-invalid assignment
`wire0=1, all others=0`, and ran the 16,777,216-domain H schedule. It found
40,934 unsatisfied rows, used 2,246,860 KiB peak RSS and zero swap, and
completed in 24.83 seconds wall under a 12 GiB address-space cap. It opened no
PK or assignment artifact and executed no proof or network path. Receipt
SHA-256 is `499c761cf4fddd169a4f19feac2a22282de910ddb8b2be008c62a734f55579a8`;
the source/binary/time evidence SHA-256 is
`6e16b97fc5fc1d8071cbdfb64b2dfe508f7012372da6c57ea2f90e41574a3696`.
This establishes parser/QAP resource feasibility only, not relation
satisfaction, proving feasibility, cryptographic correctness or privacy.

Reconsider if a reviewed upstream prover demonstrates a lower measured bound
with the exact Ark key format, or if equivalence controls find any divergence.
