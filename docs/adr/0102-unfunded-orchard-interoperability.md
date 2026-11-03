# ADR-0102: Unfunded complete-Orchard interoperability package

**Status:** Accepted for the local interoperability experiment only.
**Date:** 2026-11-04 (Australia/Sydney).
**Origin:** [RFC-0004](../rfc/0004-native-kas-private-payment-boundary.md).

## Problem and authorization

ADR-0101 selected a research construction but supplied no runnable full Halo2
bundle verifier or exact economic-effects codec. The owner now explicitly asks
to build that unfunded package, commit in stages and finish it. This authorizes
local upstream key construction and genuine synthetic Halo2 proof generation
for interoperability, rather than merely another relation or host-only check.
It does not authorize funds, broadcasts, a native pool, MPC, zkVM/prover-service
campaigns or a change to security invariants/privacy requirements.

## Decision

Build an isolated Rust package at [poc/orchard-interop](../../poc/orchard-interop/README.md),
using the exact repaired Orchard V2 source selected in ADR-0101, two complete
Actions, its standard builder/encryption/decryption, Halo2 verifier and both
individual RedPallas signature checks. Commit its dependency lockfile and
public synthetic vectors. Never import old live wallet material or proof keys.

Define an explicitly experimental format and standard BLAKE2b-256 personalized
effects digest. Bind every modeled ordinary input/output, domain/context,
amount, fee, sequence/lock/mass/payload field, anchor, Action public field and
delivery byte. Exclude proof and signatures to avoid signing fixed points.
This is not Kaspa serialization, SIGHASH, an allocated transaction version or a
new cryptographic primitive. Native integration must map every real field and
verify ordinary authorization separately; the package cannot authenticate an
input value or a caller-provided accepted context.

Keep cryptographic checks separable from supplied-context checks so each
negative has an identifiable failure layer. No randomized batch acceptance;
use single-proof and individual signature verification. Current nullifier/pool/
anchor checks against supplied context demonstrate API obligations only.

Fingerprint exact dependencies/source and the actual constructed verifier.
The public Orchard API has no portable verification-key serializer; use an
explicitly diagnostic SHA-256 of its public Rust Debug representation under
the locked profile, compare independent constructions/processes, and retain
that limitation. Do not relabel it a consensus key encoding.

## Alternatives and objections

- Another custom note relation or reexecuted guest would miss full-Halo2
  interoperability; retain those old experiments as comparators.
- A new wrapper backend adds unneeded dependencies to this bounded question.
- Patching upstream to expose private key serialization would alter the
  reviewed dependency. Diagnostic fingerprints plus genuine cross-process
  verification answer the current question without that patch.
- Synthetic context cannot establish native backing, ancestry, acceptance or
  recovery. Returning success must state the local scope explicitly.

## Outcome and reconsideration

Results, commands and negative coverage belong in the package README and
verification receipt. The RFC stays Open. I-1/I-2 adoption, exact native state/
header/bootstrap, consensus integration, independent specialist review and
complete privacy/cost/recovery qualification remain separate gates. Reconsider
the adapter if upstream changes invalidate its pinned construction/API or if
native integration requires a different complete reviewed profile.
