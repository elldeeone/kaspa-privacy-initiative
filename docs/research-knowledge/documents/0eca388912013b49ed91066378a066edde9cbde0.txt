# ADR-0075: one complete authenticated Groth16 functional experiment

Date: 2026-10-28

Status: Accepted for an isolated, unfunded research implementation. This does
not select a production architecture or qualify native payment privacy.

## Problem

The completed BN254-Fr MASCOT scalar check does not establish a complete
authenticated Groth16 prover. The retained
[implementation plan](../../research/next-session/local-private-payment/source-checkpoint-2026-10-27/groth16-integration/INTEGRATION-IMPLEMENTATION-PLAN-03.md)
identifies missing external-owner input, field/group authentication, witness-map,
FFT, proof construction, encoding and independent verification components.
An integrated functional experiment is a dependency of the private payment
work, with a deliberately smaller statement and explicit evidence boundary.

## Decision

Implement the retained C++ MP-SPDZ/MASCOT path using established BN254 group
arithmetic and the selected Groth16 reduction/formula. Preserve the retained
source pins and method contracts. The isolated experiment has two external
clients and three computing servers. Its synthetic inputs are `x=3`, `y=5`;
the public input is `t=128`, and the actual constraints are:

```text
z = x*y
(z+1)*(x+y) = t
assignment order: ONE, t, x, y, z
```

Use the real external private-input route, fresh preprocessing and proof
randomness, and one ordered authenticated protocol context. Public constants
must retain private MAC-key shares. Linear transforms act on value and MAC
lanes. Multiplication and group openings must retain their required checks.
Use the exact BN254-Fr domain and curve, canonical point/scalar encodings,
and role-specific subgroup/identity policies. Unsupported predicates, shapes
or serialization forms are rejected explicitly.

The public Arkworks exporter and independent verifier must agree on every
constraint, variable order, public prefix, domain/reduction and setup identity.
The auxiliary witness is constructed within the selected protocol. No clear
combined witness dealer, semi-honest fallback, unauthenticated multiplication
or disabled check may make the experiment pass.

Check every actual constraint on the same authenticated extended assignment
before releasing any proof-related group opening. Invalid assignments may
release only the selected aggregate validity result, never raw residuals.
The two-row experiment may use an exact full-Fr zero test; a bit-length-bounded
integer equality operation is not an equivalent test on arbitrary Fr elements.

## Alternatives

Retaining the old scalar gate alone does not exercise the missing composition.
Reusing a semi-honest co-snarks entry under a new driver name does not supply
MASCOT authentication. A Rust authenticated trait port remains an alternative
research route, but implementing both paths would duplicate an unqualified
surface. This finite experiment follows the already documented C++ candidate.

## Acceptance and retained failures

All three servers must agree on the complete canonical proof. Required MAC
checks must pass, and the independent Arkworks verifier must accept against
the frozen VK and `[128]`. The same proof must reject with `[129]`.
Wrong field, curve, source/job/arity, malformed points and unsupported model
features must fail at their actual boundaries. Bad shares/assignments must
not produce an accepted proof. Preserve failed attempts under distinct
identities and retain their exact source/input/error classifications.

## Limits and trust assumptions

The participants use public synthetic fixtures. Fixed client slots, public
instances and TLS endpoints do not demonstrate ownership anonymity. A valid
proof does not establish active privacy of augmented server transcripts.
The selected masked auxiliary group opening remains part of that review.
Trusted setup, source/dependency integrity and trusted-host execution remain
explicit assumptions; no production cryptographic review is implied.

There is no KAS, deposit, delivered note, accepted native transaction, withdrawal,
seed recovery or fee result in this experiment. The proposed private batch
profile must separately solve restricted owner consent, private witness/public
prefix construction, hidden input/output correspondence, every-path owner
authorization, native current-state validation, output delivery and independent
exits. Known changed-cohort retry linkage is retained. The existing financial
profiles, reserves, verification keys and invariants are unchanged.
