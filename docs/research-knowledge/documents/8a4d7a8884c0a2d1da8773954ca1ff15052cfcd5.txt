# Financial witness construction

This is the source implementation of the ADR-0074 private batch relation and
its authenticated witness recipes. It does not select an aggregate key, prove
financial acceptance or qualify privacy by itself.

The final joined model keeps only ONE and two effect-digest limbs public. The
three native intent digests and AK byte edges are internal, joined to three
complete selected EdDSA matrices. The selected Output producer is the wallet's
new-profile producer; the proved public R0 wrapper must verify all six genuine
Output proofs, indexed NF/CM updates and native transaction projection.

1. Each isolated owner computes only its native auxiliaries and complete real
   signature WTNS, using its own note/openings and authenticated public old
   context. Source-owned invalid filler fills unavailable other-owner slots.
   Every local auxiliary was checked for independence from unrelated filler.
   The private input order is source-bound, as described in `OWNER-LOCAL.md`.
2. `joint_trace::construct` privately sorts complete NF/CV rows, creates 768
   fresh authenticated `RANDOM_BIT` instructions for 128-bit output sort keys,
   sorts complete 520-byte output tuples, and derives one-hot route selectors.
   Fixed original indices break random-key ties; their statistical bias is
   bounded by the collision probability at most 15/2^128. No owner provides
   shuffle keys, the final permutation or arbitrary effect bytes.
3. Shared bit arithmetic derives fees, new reserve, unselected reserve
   remainder, canonical public Delta and quotient 0..2. `state_trace` derives
   all three NF witnesses, six CM append paths and new roots from authenticated
   public prefix history and the private sorted rows. The complete 10,364-byte
   effect body then feeds the global SHA-256.
4. `JointArk` records every actual initial/final Ark Boolean, Fp and SHA
   auxiliary at its physical model column. It preserves the retained normal
   matrices and witness recipes. Fp equality's inverse auxiliary uses the
   public fixed exponent P-2, with Ark's equal-case multiplier 1. It never reads
   sample witness values to choose recipes. All model columns must be assigned.

Native input CV uses the recovered CM-bound note value with a fresh owner-local
blinding. Neither the state history nor the shared construction links this CV
to its historical output CV. Seed recovery does not require the creator's old
Output blinding. Current Output CVs remain bound to their authorized complete
tuples and the local value-conservation equations.

The typed IR has canonical `LINEAR`, `MULADD`, bit-only full-width `ADD_BITS`,
`RANDOM_BIT`, and private `ASSERT_ZERO` operations. The active C++ consumer
checks source/model/trace/layout identities and authenticated owner-role
routing. Shared assertions and every actual R1CS row must enter one private
validity boundary before any effect, proof or prefix-related opening. Individual
residuals are never opened. Scratch registers never become public outputs.

Ark's matrix-free synthesis must retain LC definitions when generating typed
recipes (`generate_lc_assignments:true`), while still suppressing row matrices.
Without those definitions symbolic LC expansion fails. The first retained
wholegraph attempt demonstrated that failure; the corrected mode passed.

Retained local evidence on October 28:

| Control | Result | Scope |
| --- | --- | --- |
| Three held-owner partition comparisons | All 2,625,295 local auxiliaries and 66 edges each unchanged | Public invalid filler; no satisfaction/proof |
| Owner CLI with genuine signatures | Three isolated workers; 10,065 signature rows and 66 edges each accepted | Unfunded component inputs; no aggregate proof |
| Joint Ark differential | Exact retained/adapted/traced matrices and every auxiliary equal | Two public synthetic assignments |
| Private NF/CM construction | Complete roots/paths agree with independent Python | Two public variable assignments; same IR |
| Full joint construction | All 10,364 effect bytes/selectors/remainder/k agree with Python; actual 768 random instructions | Two public oracle tapes; same IR |
| Complete final model-column graph | All 12,949,821 columns assigned; 31,326,437 total wires; 15,474,590 ops | Structure only; no matrices/setup/MPC |
| Complete core value comparison | Every 12,919,677 instance/auxiliary value matches normal synthesis; identical graph across changed NF/output ordering | Public invalid fixtures; no private owner body |
| Full finalized matrices | 13,093,029 actual rows; all terms retained in 242,839,916-byte lossless gzip axes | Unassigned stock source; no proof |
| Fresh stock Ark parameters | Canonical PK 2,608,842,576 bytes and VK328; independent complete hash/CRC/readback | Local research setup; no ceremony or financial acceptance |

The wholegraph control took 34.8 seconds and 1,592,432 KiB maximum RSS. Its
canonical operation body is 2,514,104,547 bytes, excluding the input header and
owner layout. Count-only mode retains no operation body or values. These
measurements do not estimate setup or authenticated execution memory/time.

Exact source/results are under `.local/private-batch-partition-20261028-01`,
`.local/private-owner-parser-controls-20261028-01`,
`.local/private-joint-ark-controls-20261028-01`,
`.local/private-state-trace-dynamic-20261028-01`,
`.local/private-joint-trace-dynamic-20261028-03`, and
`.local/private-batch-joint-qualification-20261028-02`. The genuine isolated
owner receipts belong to the public unfunded component run
`/run/user/1000/kpb-unfunded-batch-components-20261028-05`.

Full finalized matrices and fresh stock parameters are now retained under
`.local/private-batch-full-matrix-probe-20261028-01` and
`.local/private-batch-stock-setup-20261028-02`. Stock setup checked the complete
canonical row fingerprint before QAP generation, then streamed standard PK
serialization through one gzip member to durable storage. The first setup's
temporary-filesystem quota failure is preserved separately. Complete setup and
serialization took 97.5 seconds with 10,384,760 KiB maximum RSS.

The direct source/setup constructor accepts only public Context and pinned
public signature matrices. It creates all invalid filler internally; callers
cannot pass three owner records or a clear signature assignment. Per-row term
sorting is an explicit bijection into stock Ark's finalized representation;
the original signature matrix/map hashes remain pinned and the new canonical
matrix identity is distinct from the raw order-sensitive identity.

The final program is exported against actual mode2 model identity
`f3ca3c18f17ed8175fa420364e9aa2824a12af4320ca1dc00ba2508f60ba28ff`.
Count-first/header-first streaming retained its 2,576,450,912 canonical bytes as
one 357,524,936-byte gzip member, without a plaintext spool. Compressed owner
layout and the actual two SHA limb LC recipe were prepared before selecting
the model root, avoiding a model/trace identity cycle. Those layout, recipe and
complete operation-graph hashes matched the final export exactly. Public
program/source metadata lives under
`.local/private-batch-financial-trace-20261028-01`; it contains no actual owner
record or WTNS. Its full authenticated execution remains a separate gate.

The financial shared execution/proof, final compact model admission, selected
three-role public wrapper and native lifecycle remain integration work.
Passing these bounded controls is not cryptographic proof or production-safety
evidence. No actual private owner body was used as a clear combined witness or
dealer by these controls.
