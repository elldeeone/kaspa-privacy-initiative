# ADR-0076: Batched private validation of a complete authenticated assignment

Date: 2026-10-28 UTC.

Status: **Accepted for isolated research implementation after root and
independent adversarial design review.** Implementation review and actual
controls remain required before financial use. The exact two-row experiment in [ADR-0075](0075-authenticated-groth16-functional-experiment.md)
and its per-residual Fermat checks remain unchanged. No financial readiness,
privacy qualification or production architecture is selected here.

## Problem

[ADR-0074](0074-private-batch-construction.md) requires validation of the same
complete authenticated extended assignment used by the prover before any
proof-related opening. The existing implementation evaluates every actual
R1CS row and exactly zero-tests each residual with authenticated exponentiation
by `P-1`. For BN254 Fr, its present square-and-multiply loop costs 353
authenticated multiplications per residual. Thirteen million residuals would
cost 4,589,000,000 such multiplications, excluding row products and aggregation.
This is an arithmetic estimate, not an executed financial benchmark.

The required replacement must still compute all actual rows, private state
assertions, ONE and promised public-prefix conditions. It must not open raw
residuals, use a host validity Boolean, substitute sample rows, or rely on a
later rejected SNARK to undo an earlier disclosure.

## Existing design and proposed choice

The [source review](../../poc/local-private-payment/private-batch-relation/BATCHED-VALIDATION-RESEARCH.md)
records the maintained MP-SPDZ pin, original SPDZ Appendix A.3, MASCOT's
authenticated execution, stock field-coin/rejection-sampling functions and
the limits of existing `CheckFor`/`zero_check` interfaces. This adapts established
polynomial batching and retains the existing exact full-field zero-test. It
does not introduce a new cryptographic primitive.

Select the following method for the **new private batch construction path and
separately selected SHA controls**, leaving the qualified two-row toy unchanged:

1. Finish private input and witness construction. Own and freeze the entire
   authenticated assignment, independently derived promised prefix and every
   private trace assertion. Evaluate and freeze every residual in a canonical
   order. Complete pending field/protocol and broadcast checks before any
   challenge contribution is committed or revealed.
2. Agree one public validation binding and a fresh attempt identity. Generate
   a fresh public Fr challenge using stock `Create_Random<T>(P)` with a
   canonical checked field-contribution adapter, then check
   broadcast consistency and agree the canonical challenge and binding. The
   API must generate the coin internally; a caller cannot supply `r`.
3. Compute the authenticated scalar
   `Z = e[0] + r*e[1] + ... + r^(m-1)*e[m-1]` using public field powers and
   local linear share/MAC operations. Evaluate `b = 1 - Z^(P-1)` with checked
   authenticated multiplications. Open only `b`, with pending checks before
   and after its opening. Proceed only if its checked canonical value is ONE.
4. Issue a typed immutable validation capability for the same owned assignment,
   context, epoch and identities. Every subsequent witness map and proof
   release consumes that capability; no Boolean skip-validation argument is
   allowed. Independent normal SNARK, mandatory R0 and native verification
   remain required.

The exact mode remains available as a separately named policy for small controls.
The policy and its parameters are public agreed inputs, never a fallback after
a failure. All row products and witness computations still require their normal
MASCOT checks; the batched zero-test does not replace authentication.

## Soundness statement and comparison

Let `P = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.
For a fixed nonzero vector of `m` residuals with `1 <= m < P`, its polynomial
has degree at most `m-1`. With a uniform independent `r` over all Fr, false
acceptance is at most `(m-1)/P`; for `m=1` it is zero. Zero is a permitted
challenge. There is no special zero retry. For `m=13,000,000`, the ideal bound
is about `5.94e-70`, or `2^-229.96`. Every actual trace/prefix residual must be
included when determining `m`; thirteen million is an example, not a fixed cap.

| Method | Zero-check cost after all residuals exist | Error for fixed nonzero residuals, with ideal coins |
| --- | --- | --- |
| Exact per-residual Fermat | Present implementation: `353*m` multiplications plus AND aggregation | Zero arithmetic error |
| One public scalar and powers | Present exact Fermat on one scalar: 353 multiplications; `O(m)` local linear work | At most `(m-1)/P` |
| Independent public Fr coefficient per residual | One exact Fermat; `O(m)` coefficients and local linear work | `1/P` |

The selected ideal bound is a statistical batching error, **not** a claim of
230-bit security for the whole system. Real execution additionally depends on
the existing CSPRNG, commitments, MACs, OT, groups and SNARK assumptions. The
pinned local PRNG uses a 128-bit AES seed. No claim beyond that computational
security level follows from the larger field. With at most `q` fresh attempts,
the ideal union bound is at most `q*(m_max-1)/P`; cryptographic and protocol
failure terms must also be included. Unbounded retry grinding has no fixed bound.

Independent Fr coefficients have the tighter ideal bound, but producing a
joint field coin for each residual would add millions of coin invocations.
Expanding a jointly exposed PRG seed is the established computational
alternative; it needs an explicit PRG security argument and different error
accounting. This proposal selects the simpler one-field-coin protocol whose
ideal degree bound is already below the system's computational limit.

## Coin and commitment boundary

Reuse stock `Create_Random<T>(P)` from MP-SPDZ `Tools/Subroutines.hpp` at
`113c4e47dd94bca9ecab029d2f0abe649bea5c52`. Each role privately reseeds a local
PRNG, calls `Fr::randomize` (rejection sampling through `randomBnd`), commits its
canonical field contribution, broadcasts commitments, opens contributions and
sums them in Fr. Its local PRNG seed is not disclosed. At least one honest role
with fresh unpredictable randomness and hiding/binding commitments is required.
The stock raw `Fr::unpack` does not validate canonical peer contributions before
addition, so **calling unchanged `Create_Random<Fr>` is not admitted**. The
proposed `T` adapter delegates sampling and field addition to Fr but encodes
fixed canonical field bytes and rejects wrong length, trailing bytes or values
outside `[0,P)` during `unpack`, before aggregation. Reuse the existing strict
scalar codec where suitable; do not invent a commitment or coin exchange.
This adapter is a reviewed implementation requirement, not completed code.
Apply `Player::Check_Broadcast()` after the stock exchange and agree role/phase.

In the ideal random-stream model, an honest field contribution is uniform; the
real implementation requires a CSPRNG replacement argument. Commitment opening
failures, inconsistent broadcasts, entropy failures and insecure/zero-seed
options abort the attempt before proof openings. The existing trusted-host
assumption remains; this does not protect a role whose process or entropy source
is controlled by its operator beyond the stated corruption model.

Do **not** use the exposed 16-byte joint seed from `GlobalPRNG(P)` as if it
were a uniform Fr challenge. Its deterministic Fr image has at most `2^128`
possible values, so the field-size degree bound does not apply directly. An
arbitrary degree-`d` polynomial can target `d` computable image points; roughly
`d/2^128` is the relevant support-size warning, not `d/P`. For thirteen million
points this is only about `2^-104.37`. This is a generic bound warning, not a
demonstrated feasible financial-witness exploit. Also do not use
`SeedGlobally(P, false)`, `almost_randomize`, a hash of a caller seed, or a
challenge reused from the MAC-check protocol.

The agreed validation binding includes a versioned domain, session/attempt and
service/history identity, source/dependency identity, field, complete model and
matrix identity, trace/layout/input-map hashes, actual variable/instance/row/
assertion counts, promised-prefix policy, public context/head, validation mode
and context/MAC-check epoch. Bind any already public statement exactly; bind
the derivation and frozen authenticated values of a still-private public prefix
without opening it. Agree the canonical challenge with this binding after the
coin. Do not hash the fresh field coin to another field value.

Public hashes identify the program and public context. They do **not** commit
the secret assignment. That commitment comes from completed authenticated input
and execution plus immutable ownership and the protocol ordering below.

## Required stage machine and ownership

`Building -> FrozenResiduals -> PendingChecksPassed -> CoinAgreed ->
PrivateZeroTestPassed -> Validated -> Proof -> Released`, with an absorbing
`Aborted` state from every stage. A phase error, failed check, exception,
disconnect or crash consumes the attempt; there is no resume with a fresh
challenge under the old attempt identity.

`FrozenResiduals` owns the complete authenticated assignment and canonical
residual sequence. It cannot export a mutable span, pointer or share accessor.
The builder must not retain an alias capable of changing that storage: merely
moving a vector whose elements were exposed earlier is insufficient. All R1CS
rows come first, followed by all private `ASSERT_ZERO` conditions, ONE and every
promised-prefix equality. Shape/count and unused-input checks precede the coin.
Expected prefix values must be independently derived, not aliases compared
against themselves and not clear zero placeholders for secret-derived values.

`ValidatedAssignment` has a private constructor and noncopyable ownership. It
contains the immutable assignment, validation binding, challenge receipt and
context identity/check epoch. Public APIs cannot construct it from a `bool`.
The financial prover/witness-map entry points accept this type, not a mutable
assignment plus `already_validated`. They reject a different context, epoch,
model, trace, prefix, attempt or policy and prevent capability reuse. Internal
proof code may access a const view while ownership remains sealed. The exact
toy API is separate and retains its current full check.

The future implementation must define epoch invalidation precisely. A MAC
failure poisons the context and all capabilities; a healthy later proof-stage
check may advance a check counter without changing the sealed assignment.
Every later multiplication/group opening still has its own required checks.
This capability prevents repeated *assignment* validation from being bypassed
or inconsistently repeated; it is not permission to omit protocol checks.

## Abort, retry and disclosure limits

A last opener can learn the candidate coin and abort selectively. Commit/reveal
provides unpredictability before commitments, not fairness or guaranteed output.
The root bound is per initiated fixed-vector attempt in the ideal coin model;
it must not be advertised as a bound conditional on adversarially selected
successful completion. Record the coin/phase when available, consume fresh
randomness and a fresh attempt identity after any abort, and count attempts in
the security accounting. Durable retry/history enforcement is still required.

An attacker must not replace an assignment/residual after seeing `r`, retry
the same validation until a favorable coin appears, rewind an honest role to
replay its contribution, or move a capability across a context/restart. Lost
or rolled-back service history/checkpoints remain explicit barriers. A fresh
trial identity does not override ADR-0074's restriction on changed overlapping
cohorts/effects after preparation. This proposal does not repair the known
active changed-cohort intersection attack or establish liveness after an Exit.

Only the aggregate checked validity bit may be opened on invalid input. It is
still a protocol observation subject to the existing leakage/retry model.
Opening `Z`, individual residuals, a masked residual or failed-row numbers is
outside the selected contract. A final verifier rejecting an invalid proof
cannot undo a preceding leak. SNARK/R0/native acceptance remains the separate
financial safety boundary under I-1 through I-16.

## Implementation gate and required evidence

The design review accepted the direct field-coin choice, ideal/real error
statement, canonical contribution decoding, exact residual coverage,
derived-prefix contract and immutable ownership/check epochs described above.
The implementation must satisfy those requirements under second-pass review.
Durable abort/retry handling remains an integration requirement; a research
control cannot qualify it by assertion. Approval does not imply qualification.

Implementation controls must include cancelling nonzero residuals at a fixed
coin; exact-versus-batched results on valid/invalid fixtures; zero/extreme Fr
coins; malformed/noncanonical contributions; wrong model/layout/source/epoch;
mutation and capability reuse attempts; skipped/extra rows and private
assertions; prefix aliasing; bad MAC/commitment/broadcast refusal before any
proof opening; and crash/retry cases with retained attempt records. An injected
fixed coin is allowed only in a separately compiled public-fixture control,
never in the production-facing validation API.

Measure the actual financial row/trace workload, memory and all mandatory
checks before claiming the scalability issue is resolved. Small controls and
the degree calculation do not establish complete MPC, cryptographic correctness,
native settlement, original-seed recovery or payment privacy. No frozen source,
financial key, invariant, mainnet code or funding policy changes in this ADR.
