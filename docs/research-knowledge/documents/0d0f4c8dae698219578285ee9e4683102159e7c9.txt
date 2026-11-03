# Same-relation prover memory investigation

Classification: read-only source investigation, 2026-10-23 UTC. No build,
setup, proof, native validation, key loading or measurement was performed here.
The closed exact-SHA run remains unchanged. HMAC circuit work is a separate
candidate with a separate relation construction and fresh parameter selection.

**The strongest allocation opportunity is to release the synthesized constraint
system after the official witness map returns, before the official MSMs.**
The existing prover retains it until every MSM completes. A proving-only exact
witness reservation is much smaller and easier, but its RSS benefit is unknown.
Do not claim that reducing unused capacity by 22.4 MiB reduces RSS by 22.4 MiB.

## Existing observation

The closed [observed targets](../exact-sha-proof/OBSERVED-TARGETS.json) record
4,204,012 KiB whole-process peak RSS, or 4,304,908,288 bytes. This exceeds the
unchanged 4 GiB target by 9,940,992 bytes, approximately 9.48 MiB. The resident
proof took 11.16959634 seconds under a four-CPU quota; the ten-second target
also missed. This is one observation, with no p95 or whole-wallet qualification.

The [report](../exact-sha-proof/run-01/report.json) establishes 3,459,641
witness variables, three instances including one, and FFT domain 4,194,304.
It does **not** record the witness vector's actual capacity. The proposed
capacity 2^22 is an inference from incremental vector growth, not a measurement.
The external cgroup samples place the largest observed memory increase during
the broad proof phase. They do not distinguish witness-map, H-MSM, or G2-MSM
subphases, so they do not identify the exact allocating call.

## Source identity and lifetime

These are the resolved local Arkworks 0.6.0 sources, not assumptions about a
different release. File hashes are retained in [SOURCE-PINS.json](SOURCE-PINS.json).
The package VCS metadata identifies Groth16 commit
`0bb3e604c534bd118ed477eaf1231f591d6fc40f`, relations commit
`d027f19d699d3af459ae4924366d71159231bc82`, and algebra commit
`bffa52711f225e888c1a91e1ec9fc59f2d9d5c94`.

| Pinned source | Lines | Allocation or lifetime |
| --- | --- | --- |
| [Groth16 prover](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/src/prover.rs#L187-L220) | 187-220 | Creates CS, synthesizes, finalizes, computes QAP witness, then retains CS while proof MSMs borrow assignment slices. |
| [QAP reduction](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/src/r1cs_to_qap.rs#L85-L107) | 85-107 | Materializes all matrices and concatenates assignment slices into another full-assignment vector. Both temporaries die when the witness map returns. |
| [QAP buffers](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/src/r1cs_to_qap.rs#L178-L240) | 178-240 | Allocates domain-sized A/B arrays, then AB, drops A/B, allocates C, and returns AB. Each Fr domain buffer is 128 MiB for this domain. |
| `relations/constraint_system.rs` | 76-92, 120-123, 606-615 | CS owns public assignments, compact LC map, predicates; witness assignments start as `Vec::new()` and receive individual pushes. |
| `relations/assignment.rs` | 11-20 | The three assignment vectors are public. Direct borrowed slices avoid the cloning reference accessor. |
| `relations/constraint_system_ref.rs` | 107-118 | The convenience instance/witness accessors return cloned vectors. The normal Groth16 path borrows inner CS instead and does not make these clones. |
| `relations/constraint_system.rs` | 717-757 | Finalization can temporarily own old and inlined LC maps together. Both old-map and new-map storage are not retained through the whole proof. |
| `relations/predicate/mod.rs` | 81-100, 207-216 | Three R1CS argument vectors are retained in CS; `to_matrices` builds expanded rows by pushing into three new outer vectors. |
| `relations/lc_map.rs` | 51-55, 69-109 | Compact LC representation has separate variable, interned coefficient and offset vectors. Its backing fields are private; no public shrink method exists. |
| `groth16/prover.rs` | 65-89, 113-118 | Proof MSM stage materializes bigint H/aux/input assignments and an additional concatenated assignment; H bigints are explicitly dropped before aux conversion. |
| `ec/scalar_mul/variable_base/mod.rs` | 153-170, 240-302 | The signed MSM groups scalars, then copies selected bases/scalars into group-specific vectors. |
| `poly/domain/radix2/fft.rs` | 129-151, 252-253 | FFT helpers allocate a roots table of half the domain: 64 MiB of Fr here, besides small recursion scratch. |

The official matrix-input proving API, `create_proof_with_reduction_and_matrices`
(`prover.rs:29-53`), is public. It retains the caller's borrowed matrices through
all MSMs. The normal path drops expanded matrices after the witness map but
retains compact CS storage. Switching APIs alone therefore has no proven peak
benefit; it could increase the later MSM peak.

## Layout reasoning

BN254 `Fr` is `Fp256<MontBackend<FrConfig,4>>`: a four-limb `BigInt<4>` and
zero-sized phantom data. On the selected x86-64 target this is 32 bytes.
`Variable` wraps u64, `InternedField` wraps u32, and a materialized matrix term
is `(Fr,usize)`, 40 bytes on that target. Source definitions are pinned below;
a future experiment should assert actual `size_of` values in its report.

The original witness values occupy 110,708,512 bytes, approximately 105.58 MiB.
An inferred capacity of 4,194,304 would reserve 134,217,728 bytes, leaving
23,509,216 reserved bytes unused. Those unused bytes are not automatically
resident pages. They cannot be treated as measured RSS savings.

Three predicate argument vectors contain one eight-byte `Variable` per
constraint: at least 83,949,432 bytes of initialized payload for 3,497,893
constraints, before capacity, traces, LC map or allocator overhead. These are
real populated objects that are no longer consulted after the witness map.
Their deallocation may still interact with allocator retention, so even this
payload count is not a promised RSS delta.

Expanded matrix outer-vector slack, inferred from ordinary doubling, could
reserve another 50,141,592 bytes of unused Vec metadata slots. That capacity
also remains unmeasured. Changing it requires changing the upstream matrix
materializer or replacing it; it is not the smallest local change.

## Candidate A: exact witness reservation

Smallest local candidate: wrap the selected `TransferCircuit` in a
`ConstraintSynthesizer<Fr>` which, **only in proving mode**, calls
`cs.borrow_mut().assignments.witness_assignment.reserve_exact(3_459_641)`
before delegating to the unchanged circuit. Do not reserve in setup mode,
which intentionally carries no witness assignment. Record length/capacity
before and after synthesis, and reject a dimension mismatch. Release the
mutable borrow before calling the inner synthesizer.

This is a public field and standard Vec API; it changes neither variable order,
assignment values, constraints, randomness, parameters, nor transcript format.
The current `payment::prove` accepts a concrete circuit, so a separate experiment
must mirror its public validation, serialization and original checked
verification while invoking official Groth16 with the wrapper. Do not edit the
closed library to accommodate the experiment.

This is low implementation risk but **low-confidence RSS impact**. The exact
reserve may reduce reallocation/copies and allocator fragmentation. It does not
remove the duplicate full assignment or retained constraint objects. Do not
spend a new setup merely to try this; allocation alone does not require a new
relation or key.

## Candidate B: release constraint storage after the witness map

The public `R1CSToQAP` trait is an extension seam. A separate, tightly pinned
adapter can delegate every algebraic method to the official `LibsnarkReduction`.
Its `witness_map` delegates first, lets the official temporary matrices and
full assignment drop, then releases constraint-only CS storage before returning
the unchanged H vector to official Groth16.

After `prover.rs:209`, that caller reads only inner instance/witness assignment
slices at lines 218-219. It never consults matrices, LCs, predicates, traces or
gadgets again. Thus freeing those objects at this point changes allocation
lifetime, not the calculated relation. Keep both assignment vectors and counts
exact. Keep original randomized proof creation and checked verification.

Important limit: this uses a public reduction trait, but eagerly discarding
constraint structures is not an upstream documented lifecycle operation. Some
candidate fields are public but doc-hidden, and LC internals are private. It
therefore requires an independent review against these exact source pins,
explicit naming as a local lifetime adapter, and tiny conformance tests before
one measured proof. Prefer a minimal upstream lifecycle API if generalizing it.
Do not present an unreviewed CS reset as a drop-in supported optimization.

At minimum, the delegate must preserve the assignments byte-for-byte and avoid
double finalization, witness reordering, constraint changes, reused randomness,
or any bypass of authentication/verification checks. Do not implement a new
MSM or Groth16 formula merely to gain access to a private helper.

## Candidate C: move, rather than duplicate, the full assignment

A separate adapter can instead implement `witness_map` with the official
`witness_map_from_matrices`, temporarily moving the public witness vector out
of CS. Append the three instance elements, rotate them to the front, call the
unchanged official reduction, then restore the original witness ordering and
length before restoring it to CS. This avoids the official `.concat()` copy of
approximately 105.58 MiB during QAP work. Restoration must happen on every
ordinary error path before returning. It must be tested against direct
concatenation and original instance/witness bytes on a tiny fixture.

This is more invasive than A, changes assignment lifetimes, and may not address
the largest late MSM peak. It should not be combined silently with B in the
first comparison. No claim is made that either adapter currently exists.

## Proposed next experiment

1. First complete the independent HMAC candidate already underway. Its
   constraint reduction is separate and may supply enough real headroom.
2. If allocation work remains useful, choose **one** candidate and a new
   experiment identity. Preserve the closed 4.009 GiB / 11.17 second miss.
   Pin unchanged relation source, key, fixture, transcript and checks; pin the
   new wrapper/adapter separately. Do not change trial identity or native code.
3. For A, log exact capacities and layout. For B/C, first run a tiny
   same-parameters conformance test proving that official checked verification
   succeeds and assignments/H values match. For B, independently verify that
   no caller reads discarded data after return under the selected version.
4. Run one complete proof with the same four-CPU quota, swap disabled, external
   aggregate RSS/cgroup sampling, and unchanged thresholds. Report synthesis,
   finalization, witness map and MSM phase markers where the adapter exposes
   them. Include setup/key handling and serialization when those belong to
   the measured wallet path. No kill-on-target limit, trimming, excluded child
   process, or sample reset may manufacture a pass.

An isolated peak below 4 GiB would still be a performance observation, not a
whole-wallet or p95 qualification. There is no new cryptographic/security claim.
