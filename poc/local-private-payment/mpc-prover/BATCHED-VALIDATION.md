# Separate batched public-prefix research path

[ADR-0076](../../../docs/adr/0076-batched-private-assignment-validation.md)
selects this policy separately from the qualified exact two-row toy. There is
no automatic fallback or caller-provided challenge.

`validate_batched_public_prefix` re-parses the selected model's pinned bytes,
checks its expected model/source/matrix identities, and deep-copies the complete
authenticated assignment and trace assertions. Its residual order is every
actual R1CS row, the ordered trace assertions, ONE, then each independently
public model-prefix equality. Trace drivers bind the inspected assertion count,
trace/layout/owner map, fresh attempt, history, public context and dependency
identities before coin generation.

Pending protocol/MAC and broadcast checks finish before stock
`Create_Random<CheckedFrContribution>` commits or opens a contribution. The
adapter samples with stock Fr rejection sampling and accepts only canonical
32-byte little-endian contributions below P, with no trailing bytes. The
agreed public coin and binding are persisted before the private polynomial
combination is exactly Fermat-zero-tested. Only one authenticated validity bit
is opened. Zero is a permitted coin and is never retried specially.

The resulting `ValidatedAssignment` has a private constructor, owns immutable
storage, and exposes no assignment/share accessor, mutable span, copy, move or
serialization. `prove_validated` consumes that exact instance once, checks the
context pointer, monotonic context generation, poison epoch and expected
binding, and privately maps the same assignment to H. It admits proving-key
queries from its own immutable model. A mutable caller model or key cannot
substitute new queries after validation. Healthy later checks advance a check
counter while leaving the poison epoch intact. Any failed operation consumes
the attempt and poisons the context; there is no public reset or success flag.

Every subsequent scalar and group MAC check, canonical Native128 encoding and
independent selected Ark verification remains mandatory. The driver treats a
proof as a candidate until that independent verification succeeds. Source
review and public parser/API controls are recorded separately from actual
multiparty runtime evidence.

The present factory is explicitly for independently known PUBLIC prefixes,
such as the selected abc SHA-256 digest. It cannot issue a financial private-
prefix capability from arbitrary caller-provided expected values. A financial
entry needs a trusted sealed witness-construction result that owns its actual
trace assertions and independently derives the promised secret prefix. Durable
history, crash/retry enforcement, NativeAuth/R0, recovery, exits and payout are
separate unfinished integration boundaries. This module alone does not qualify
payment privacy or a complete private payment system.
