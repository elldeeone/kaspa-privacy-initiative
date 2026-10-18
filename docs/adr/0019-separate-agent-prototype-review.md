# ADR-0019: Separate-agent review for the offline private-payment prototype

Status: Accepted review method and reviewed offline design corrections.
Owner instruction, 2026-10-18: use a separate agent for the crypto review and
assess whether that unblocks the research prototype. No mainnet or real funds.

## Scope and provenance

Use a fresh-context reviewer distinct from the implementation author. Record
the exact input snapshot, reviewer identity, source checks, findings, fixes and
focused re-review. Reviewer `/root/crypto_composition_review` shares the same
model/platform/host as the author; this is a separate-agent AI design review,
not an independent human/external audit or proof of cryptographic soundness.
The full P1 checklist and actual native qualification are not automatically
complete because an agent report exists.

The owner selects this route for bounded offline research implementation.
Proceed only after implementation-blocking findings are explicitly resolved
and re-reviewed. Native descriptor/ordering/settlement/payout and independently
operated recovery remain later actual qualification gates. Do not add an
operator exit or accept a placeholder artifact ID to proceed. External audit
status remains unavailable and must be reported separately from AI review.

The previous external/human-only interpretation of P1 is not a requirement
stated by the owner. This decision makes the selected research review method
explicit; it does not label AI work as independent expert assurance.

## Required corrections under review

1. Bind exact canonical public recovery authorization bytes into the wallet
   journal using `authorization_digest = SHA256(raw ASCII
   "KPI/private-payment/authorization/v1" || auth_bytes)`. CREDIT uses exactly
   flag 1 + signature64; TRANSFER/EXIT use exactly flag 0. The signature still
   signs the complete intent via G_hash and intent_id. The outer compares the
   complete expected journal, including the digest of its actual public
   envelope. No signature/proof/native-ID self-reference is introduced.
2. Make the wallet guest a generic fixed-algorithm relation. It binds supplied
   IDs but does not authenticate pool admission, its own image or native
   backing. The proved outer verifier must compare G_hash, D, network genesis,
   pool ID, lane ID, statement ID, suite ID and the actual verified wallet
   image with the authenticated immutable policy before effects. Offline
   fixtures use an explicitly synthetic policy. Actual native descriptor and
   bootstrap identity binding remain unavailable until qualified.
3. Initialize allowed anchors to exactly the published depth-32 empty Orchard
   root at genesis; thereafter admit canonical post-operation roots. Omitting
   the genesis anchor would deadlock the first credit.
4. Define expiry inclusively against the zero-based canonical accepted native
   lane transaction ordinal. Every accepted lane entry, including rejected
   operations, advances it. The single-operation profile does not permit a
   payload to create extra ordinals. Authenticate cursor state, increment
   checked u64, and halt atomically before overflow. The wallet only binds
   expiry bytes; the ordered outer transition decides expiry.
5. Explicitly clarify I-2 for native entry/exit boundaries. Proposed wording:
   closed private transfers retain `private_in = private_out + private_fee`.
   Native boundary transitions additionally require
   `private_in + credited_pending_native_principal = private_out +
   new_exit_principal + private_fee`. CREDIT consumes one authenticated,
   still-pending backed deposit; it does not add reserve a second time. EXIT
   creates a fully backed unpaid claim and releases no reserve by itself.
   Native fees/rent stay separately accounted. This is an explicit invariant
   scope clarification for review, not permission to mint unbacked value or
   weaken backing, authorization or single consumption.

The invariant clarification must receive explicit reviewer disposition before
it is applied to SECURITY-INVARIANTS.md or used for implementation. An author
cannot silently reinterpret the old private-only equation to justify credit.

## Alternatives and remaining limits

Continuing to wait for an unspecified external reviewer would not exercise the
owner's selected prototype review route. Automatically declaring P1 passed
because a second agent ran would discard real design findings. Use a recorded
review/fix/re-review cycle with separate offline and native readiness decisions.

Library/vector/VM interoperability and a separate-agent report are different
evidence. Full wallet proofs, total outer invalid-proof classification,
accepted native transactions, exact terminal payouts and independent recovery
must each be produced and verified. No passing design review substitutes for
those results. Reconsider the profile if implementation or later expert review
finds a soundness, privacy, reserve or native-binding defect.

## Recorded disposition, 2026-10-18

The separate agent's [initial review](../../poc/private-payment/reviews/2026-10-18/initial-review.md)
identified four offline design blockers. Its
[focused re-review](../../poc/private-payment/reviews/2026-10-18/focused-rereview.md)
closed C1–C3 at design level and explicitly approved the exact I-2 proposal.
That proposal was applied unchanged to SECURITY-INVARIANTS.md, SHA-256
`35e180449636d24abe40a117fc291f6b897d1592fcdaa43ba795a40a4ca55331`;
the [application record](../../poc/private-payment/reviews/2026-10-18/invariant-application.json)
records its previous and applied identities. C4 is therefore closed at design
level. No other invariant was changed.

Unfunded offline P2 implementation may proceed using synthetic policy/deposit
fixtures. Public auth/journal byte tooling corroborates the corrected format;
it does not implement guest verification or outer admission. Full P1 native
binding/bootstrap, code-level proof review, actual images, native settlement
and independent recovery remain open. The
[review result](../../poc/private-payment/REVIEW-RESULTS.md) separates those gates
and retains frozen before/fix inputs and reviewer-produced outputs.
