# Constraint diagnostic cache change

**Source/equivalence-probe ACK for another shape/control attempt.** This does not
release setup or claim wide feasibility.

The build02 `main.rs` SHA256
`682a8866285e46d4695af466825b5f60c4540fb06be291fb0b93775a93af7f4c`
changes shape diagnostics from `generate_lc_assignments:false` to `true`, adds
public phase timings, and adds a direct finalized `ActionCircuit.check()` command
without cloning/hashing matrices for every negative assignment. Relation modules
and final SAT/UNSAT checks are unchanged. It makes no per-negative matrix claim.

Official local ark-relations0.6.0 `gr1cs/constraint_system.rs` sets this cache
flag true by default. `new_lc_add_helper` stores evaluated LC assignments when
it is enabled; it does not replace or omit matrix construction. The change is
to assignment evaluation/cache, not accepted relation constraints.

The public [cache probe](../prover/cache-probe-01/report.json), SHA256
`58e433c493ceb3d032c13c0a740b7269b79e483e7ab8dceadf1bab048d241316`,
reports both settings SAT with identical actual dimensions/matrix hashes for a
one-constraint LC example and a39,770-constraint SHA256 example. Probe source
SHA256 is `d1f32d97e96e1b2e6e23b63d86ca0b5679583594fc4b98c6fe2ccfcb93f1c58a`.
This small equivalence evidence does not bound a full role's performance.

The preserved build01 compact reports are both SAT with3,284,767 constraints,
3,248,304 witnesses,3 instances, FFTdomain4,194,304 and identical matrix
`98c92c77b48028768456068b950ea65c019bf72931cab1b6174b9545fad6514a`.
They establish compact mode0/2 identity for that build. The first wide attempt
was deliberately stopped for diagnosis; it is neither UNSAT nor a measured
resource-limit failure. Its direct kernel process observation is null.

The next attempt must retain the same compact matrix identity and obtain actual
wide dimensions/SAT plus the frozen coherent direct-constraint controls before
setup review. Phase timers should separate synthesis, finalize, satisfaction and
matrix hashing from proving cost. No financial check, budget or safety invariant
was relaxed. This reviewer ran no build, setup, proof or native operation.
