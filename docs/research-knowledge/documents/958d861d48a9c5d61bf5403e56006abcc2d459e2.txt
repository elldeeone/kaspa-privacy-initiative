# ADR-0034: Test public v6 proof composition without settlement

**Status:** Accepted — bounded local research experiment; implementation gates
and uncompleted evidence remain explicit.

**Date:** 2026-10-22 Australia/Sydney.

The owner authorized an intensive local engineering window to advance native-KAS
privacy research. We will test whether two existing v6 ownership/value proofs
can be verified and bound to an exact public projection in a pinned guest,
without changing the v6 private relation or authorizing reserve settlement.
This isolates proof-verification and byte-binding feasibility from the larger
privacy, accepted-state and independent-exit questions.

## Decision

1. **Complete the ordinary-host gate first.** Reuse the established checked
   Groth16 verifier. Require two narrow zero-payout SPEND statements with the
   same domain, key, anchor and count; four distinct nonzero nullifiers; bounded
   individual fees and exact aggregate fee; and original ciphertext binding.
   Two bijections bind all nullifiers and complete commitment/ciphertext records
   to the public projection. Preserve record multiplicity. Acceptance means an
   existential partition into those two valid statements; it authenticates
   neither a submitting user nor transaction order.
2. **Keep experimental instances distinct.** The default gate remains fixed to
   the retained public rehearsal domain and exact verification key. Its two
   retained SPEND bundles have different count/anchor values and do not provide
   a compatible positive pair. A new, openly identified test-only setup may
   supply development fixtures through a separate configured gate. Its key,
   domain, source, generation and setup assumptions must be pinned separately;
   its success cannot qualify the original rehearsal instance.
   The single-party experimental setup has no reviewed setup-integrity claim;
   key hashes identify it without proving trapdoor erasure. Disclosed development
   keys remain unfunded fixture material.
3. **Separate checked parameter preparation from guest execution.** A guest may
   compile immutable key bytes/domain into its image after a host preflight
   fully checks those exact bytes, canonical encoding, subgroup membership,
   nonidentity and arity. The private static-parameter path accepts no
   witness-selected key or identity. Submitted proofs retain checked decoding
   and verification; the generic caller-configured checked-key path stays
   checked. Freeze source, key, tools, ELF and image, and independently pin the
   expected image in the execution host. A program plus a neighboring
   self-declared image file is insufficient authentication.
4. **Bind complete public bytes.** Each source bundle is exactly 875 bytes.
   The public projection `P` is exactly 1,088 bytes; the complete private
   composition input is 2,846 bytes. The two-proof journal is exactly
   `J = "KPI2V6J1" || u16le(1) || SHA256(P)`, 42 bytes. `SHA256(J)` is a
   separate digest from `SHA256(P)` and from the journal bytes. Publication
   checks require complete P/J consistency, not only a supplied digest.
   The collector sees the complete input and grouping; this experiment grants
   it no settlement authority or demonstrated privacy protection.
   Common count/anchor are checked inside the private composition input but
   omitted from P/J. This receipt therefore cannot authenticate an additional
   host-supplied count/anchor or its history path.
5. **Reconstruct native public observations independently.** Regenerate the
   existing public state roots and all 4,368 settlement-witness bytes from a
   selected public prefix. Keep descriptor trust, native transaction identity,
   proof/VM checks, funding ancestry and chain acceptance as separate claims.
   Offline native replay under supplied UTXOs does not authenticate an accepted
   chain or the missing input ancestry of funding parents.

The [results register](../../research/intensive-2026-10-22/RESULTS.md) records
which host, fixture, guest, receipt and native gates have actually completed.
A one-proof compatibility execution has a different 40-byte diagnostic journal;
it is not evidence of the two-proof 42-byte journal or an outer receipt.

## Consequences and limits

This is a composition experiment using existing primitives, not a new
cryptographic construction, architecture selection, reserve upgrade or runtime
adoption. No accepted-anchor authentication, current spentness check, native
reserve transition, correct-encryption guarantee, delivery, recovery or
independent-exit mechanism is supplied by the host gate or guest execution.
This experiment establishes no native reserve settlement or funded-trial
readiness. Mainnet activity, real funds and external publication remain outside
the local engineering scope.

All [security invariants](../../SECURITY-INVARIANTS.md) and
[adopted privacy targets](../rfc/0012-useful-privacy-requirements.md) remain
unchanged. Preserve [ADR-0033](0033-price-baseline-evaluation.md), the completed
512-ledger result and all earlier rejected policies. The common-price prior's
21.0977% approximate success already exceeds the unchanged 20% absolute cap;
proof composition does not resolve that workload's information limit.
No privacy benefit, production security or permissionless-exit qualification
follows from successful composition.

Any later settlement or architecture proposal requires its own explicit design
decision, synchronized threat model and invariant-preserving evidence. Local
execution measurements close only their named experimental gate.
