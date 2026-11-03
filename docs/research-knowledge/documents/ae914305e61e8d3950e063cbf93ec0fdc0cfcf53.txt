# Direct combined Groth16: feasible research candidate

**2026-10-25. Recommend design review of one owner-local combined circuit with a
compact statement and native public-state checks.** It would remove zkVM
verification of three component proofs. This is a source-based feasibility memo,
not an accepted architecture, implemented circuit or measured speedup.

The owner-reported new R0 proof took about 17 minutes / 271.75 million cycles, versus
about 33 minutes / 514 million for the older 3-input/6-output batch. Different useful-payment
counts prevent a per-payment speed claim. No proof, setup, synthesis, key, native
policy or live-trial change was performed for this memo.

## Exact baseline and cost estimate

Fresh manifests for compiled source
`82cf9c59c17c006f79faf2b7689d09690ad505b776f9ce6409f4d1f9ccc79e5c`
give these counts, also retained in [SOURCE-01.json](../../../../poc/local-private-payment/relation/SOURCE-01.json):

| Existing relation | Constraints | Witness variables | Uncompressed PK bytes |
| --- | ---: | ---: | ---: |
| Spend | 1,476,992 | 1,461,143 | 601,785,008 |
| Output | 217,807 | 214,998 | 85,578,096 |
| **Spend + two Outputs** | **1,912,606** | **1,891,139** | **Not yet a combined key** |

The sum is a retained-gadget baseline. Removing three statement hashes, sharing
variables and adding conservation/new binding changes it. With two public digest
limbs and the constant (`I=3`), the baseline FFT domain is 2²¹, with 184,543 rows
before doubling. For the current uncompressed BN254 query layout,
`PK_bytes = 320*W + 64*D + 1520`; this matches all three existing manifests.
At baseline it predicts 739,383,728 bytes, about 705 MiB. It is larger than the
current distinct Spend+Output key files together (about 656 MiB); the Output key is
already reused for both outputs. [Version-pinned generator](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/src/generator.rs#L78-L89),
[queries](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/src/generator.rs#L138-L187),
[radix-two domain](https://github.com/arkworks-rs/algebra/blob/a5460be2d98e709133f3947eae535d3d67ca3355/poly/src/domain/radix2/mod.rs#L46-L57).

Identified key, assignment and three FFT-vector payloads already approach 1 GiB at
that domain, **before** sparse matrices, linear combinations, MSM buckets,
allocator and parallel overhead. Plan for multiple GiB of host RAM; peak RSS and
proving time remain unmeasured. A domain doubling adds 128 MiB to the H-query and
doubles each 64 MiB FFT vector. This does not establish an 8 GiB GPU fit: the selected
arkworks prover uses CPU/Rayon, not the current R0 CUDA backend.
[Witness-map allocation](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/src/r1cs_to_qap.rs#L164-L222),
[prover MSMs](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/src/prover.rs#L52-L117).

## Sound composition contract

Reuse the established Note168, positioned HMAC NF, ownership/key hashes,
depth16 membership, exact SHA gadget, canonical scalar/CV encodings and existing
value limits. Refactor [the predicates](../../../../poc/local-private-payment/relation/src/circuit.rs#L129-L183)
to consume one canonical allocation of each note, value, blinding and public
field. **Equal host values allocated twice are different unconstrained variables.**
Reuse the same variable handles, or enforce equality explicitly, including paths
reused for old/new roots. The existing `value_cv` privately reallocates its
blinding, so its interface must change or those copies must be equated.
[Allocation behavior](https://github.com/arkworks-rs/r1cs-std/blob/70a8298c82ef22b6ab81ee3a6cbf5138a3691aeb/src/alloc.rs#L70-L77),
[explicit equality](https://github.com/arkworks-rs/r1cs-std/blob/70a8298c82ef22b6ab81ee3a6cbf5138a3691aeb/src/eq.rs#L43-L51).

Enforce `v_in = v_0 + v_1 + fee` using those same bounded unsigned value bits.
Enforce `r_in + c*q = r_0 + r_1 + Delta`, with every scalar canonical in `[0,q)`
and `c` constrained to 0, 1, 2. Here q is the existing Baby-Jubjub subgroup order;
`3q < BN254_Fr`, so the bounded equation cannot wrap in the constraint field.
Zero blinds/Delta remain valid. Both real output values retain the 60,000,000-sompi
floor; no dummy/zero-change or field-reduction shortcut is introduced.

One illustrative 496-byte statement is:

`role8 | D32 | effects32 | old_CMroot32 | NF32 | CVin64 | 2*(CM32|CV64|CFhash32) | feeLE8 | Delta32`.

Hash it inside the circuit into two exact 128-bit public limbs. Native Script
must independently extract **every** field from the actual transaction/body and
reconstruct the complete effects digest, including current outpoint/state,
reserve, immutable successor tail, ciphertext tuples, paths and fee. An opaque
effects hash supplied to an otherwise detached circuit is insufficient. The
wallet must reconstruct and consent to those same bytes, authenticated invoice
and recoverable change before proving. Groth16 proves the encoded relation;
it does not supply missing financial wiring. [Groth16 primary paper](https://eprint.iacr.org/2016/260).

## Where the public checks belong

| Design | Source-based planning estimate; not synthesized |
| --- | --- |
| Compact statement, native public updates | About the 1.9 million baseline; 8 statement SHA compression blocks replace 10. A 2²¹ domain remains plausible, not established. |
| Whole proof-excluded body hashed in CS, native updates | Illustrative new core of 3500 B gives a 3701 B effects preimage / 58 SHA blocks. Roughly 1.4–1.6 million extra constraints versus old statement hashes; likely 2²² domain. |
| NF/CM updates also in CS |132 tagged 72 B node hashes plus 3 NF leaves: about 270 additional SHA compression blocks. A coarse existing-gadget calibration suggests roughly 8 million extra constraints and likely 2²⁴ domain; not a measured count or RSS estimate. |

These SHA estimates use 49 blocks in Spend and 7 in each Output, approximately 30,000
constraints/block averaged with other work. Constants and shared allocations
prevent treating that average as an exact gadget price.

**Native public updates are new work.** The [current mixed branch](../../../../poc/local-private-payment/verification/native/src/policy.rs#L295-L310)
delegates them to R0; only direct Exit has native NF insertion. Reuse its
predecessor/empty-append logic and add two ordered CM appends, preserving sorted
256-bit NF intervals, shared paths, occupied-prefix genesis, canonical indices,
capacities, current roots and exact successor counts. No host acceptance flag
may replace [the current transition predicates](../../../../poc/local-private-payment/verification/common/src/wire.rs#L229-L280).
Native must also check `CFhash=SHA256(CF)`, distinct/nonempty CMs, exact framing
and amounts. Hashing body bytes alone proves none of these predicates. Moving
CF hashing into CS adds another 10 SHA blocks; ciphertext correctness still
requires recipient decryption/validation.
The input note's private CM membership path stays inside CS; exposing it to
native Script would reveal which public note is spent.

## Required review gate

1. Record an ADR/RFC with a fresh domain, combined role/VK, native profile and
   proof-excluded codec. Never hash the combined proof into its own statement.
   Removing per-output proofs changes Output520 to a 392-byte row; scanner and
   recovery must verify retained complete transitions/combined seals. A fresh
   note domain also requires a fresh Exit key; old notes/keys are not migrated.
2. Keep combined proving inside the owner boundary: it receives owner/NF secrets
   and all note/blind openings. The public-only outer prover cannot receive this
   witness. Preserve private output ordering, invoice consent, original-seed
   recovery, independent exits and current-head/reorg reconciliation.
3. Only after review, synthesize and adversarially test equality omissions,
   inflation/blind wrap, stale/wrong roots, double spends, cross-lane/profile
   replay and malformed codecs; then measure real proof time/RSS and complete
   native acceptance. No implementation or setup is authorized by this memo.

The current final on-chain R0 seal is already one Groth16 proof. Replacing it
does not automatically remove the roughly 14 million native Script-unit floor or yield
a fee saving; new native path checks also cost units. Privacy and the 2% fee
target receive no pass from this prover comparison. The live 6-payment/9-payout
campaign and frozen evidence remain unchanged.
