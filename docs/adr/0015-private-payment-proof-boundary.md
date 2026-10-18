# ADR-0015: Full private-payment specification and proof qualification boundary

Status: Accepted **only for the owner-authorized research split**, 2026-10-18.
The [private-payment specification](../rfc/0003-private-payment-proof-and-settlement.md)
remains Open. No production cryptographic suite or native deployment is accepted.

## Context

R01–R16 now have bounded offline model work. Real R13 requires a complete proved
valid/invalid/valid transition with the full private monetary relation and actual
ordered data. Real R16 additionally requires independent restoration, real
proofs and confirmed native payouts. Neither follows from the model's ideal
oracle, small preimage/sum circuit, segment receipts or GPU availability.

The owner authorized GPU qualification and the complete private-payment
specification in parallel, with no mainnet or real funds. Fresh selected
[primary-source review](../../research/private-payment-source-review-2026-10-18.md)
supports studying existing constructions rather than inventing a primitive or
expanding the public application runtime.

## Decision

1. Keep **computation qualification** separate from **private relation correctness**.
   The current classifier/proxy can qualify a proving backend only for its exact
   statement. Its speed or successful proof does not qualify the full note
   circuit, native settlement or privacy.
2. Put the complete proposed relation, wire/intent responsibilities, persistent
   economic state, receiver acceptance, native payout/final-drain obligations
   and R13/R16 acceptance gates in RFC-0003. Study Orchard-derived two-action
   semantics with constrained delivery as the leading concrete candidate;
   independent review of the exact primitive/version/parameter composition
   precedes substantial cryptographic implementation.
3. Preserve one immutable economic nullifier domain across permitted versions,
   current-state credit/refund and paid-claim consumption, separate rent/fees,
   and a noncircular proof-free wallet intent bound to authenticated actual
   native operations by the outer adapter. These are existing invariants made
   explicit, not exemptions or a selected production circuit.
4. Keep fresh source pins, rights and trust assumptions visible. Historical
   insecure Orchard circuit variants, restricted circuit code, model hash/HMAC
   identifiers and the one-party proxy setup are not implementation shortcuts.

## Consequences and limits

RFC-0003 makes the intended positive and negative behavior reviewable before
funding or implementing a new note system. It deliberately leaves exact reviewed
crypto suite artifacts/encoding vectors, the full wallet circuit, complete outer
classification proof, native private-state binding and independently recoverable
confirmed payouts as separate named deliverables. No assertion of security,
strong anonymity, seed-only recovery, post-quantum privacy or readiness follows.

No invariant, user asset, admin authority, native deployment or testnet trial
identity is changed by this decision. Existing recovery evidence stays labelled
offline. The separate GPU experiment documents its own hardware and proof scope.
