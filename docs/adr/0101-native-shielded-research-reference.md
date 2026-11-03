# ADR-0101: Native shielded-value research reference

**Status:** Accepted for technical research reference only.
**Date:** 2026-11-03. **Origin:** [RFC-0004](../rfc/0004-native-kas-private-payment-boundary.md).

## Problem and constraints

The owner requested concrete answers to all ten RFC questions, using the
consolidated prior learnings. Another list of unnamed primitives and reviewers
would leave the next research task undefined. Current Kaspa ordinary outputs
remain transparent, and its current verifier tags do not accept Orchard directly.
No production architecture, consensus activation or security-invariant amendment
has been approved. Preserve native KAS, owner authority and all existing safety
and privacy requirements; do not silently import a whole historical runtime.

## Decision

Use the complete **repaired Orchard V2** construction at
`616a669df8c9a59c33d47064d3ce04b25d026b2e` as the first native-pool research
reference: `orchard_v2()`, `FixedPostNu6_2`, note V2, exactly two complete Actions
and unrestricted cross-address use. Preserve proof, note/key/tree/nullifier,
encryption, spend authorization and binding signature together. Prefer direct
native Halo2/RedPallas verification over adding a second proof backend to the
first reference. The exact source/format and alternatives are in the
[cryptographic review](../../research/rfc0004-cryptographic-profile-review-2026-11-03.md).

For research specifications, use authentic empty pool genesis, current all-slot
spentness, serial native effects in consensus accepted order, complete atomic
undo, full retained recovery data and owner rebuilding/re-authorizing fees.
Use the complete-construction/zero-genesis induction route for the smaller KAS
monetary bound; do not claim an upstream hidden `MAX_SOMPI` range gadget.
Exact native codec, new header/state commitments, eligibility/activation,
storage/mass and integration remain open in the
[consensus/accounting review](../../research/rfc0004-consensus-accounting-review-2026-11-03.md).

Keep Q1's information limits and prior-only benchmark failure explicit. The
strong privacy requirement is unchanged. Keep RFC-0004 Open and I-1/I-2 unchanged;
the proposed boundary wording is review input, not an adopted invariant.

## Alternatives, objections and tradeoffs

| Alternative | Disposition |
| --- | --- |
| Unspecified latest Orchard | Reject: `orchard_v3` restricts cross-address use; versions are substantive. |
| Complete Ironwood V3 | Retain optional recovery-preparation comparison. Proposed ZIP 2005 is not end-to-end PQ safety or a requirement for classical repaired-V2 transfers. |
| Full-verifier RISC0 wrapper | Retain secondary engineering option; complete compiled guest/image, compatibility and cost evidence are absent. |
| Existing Orchard-derived guest or custom v6 BN254 relation | Valuable source lessons, different relation/identity; neither is a ready complete Halo2 wrapper or native consensus pool. |
| Confidential UTXOs | Credible other native-value design, with different public-spend graph. Retained alternative; not the first note-pool reference. |
| Pruned self-authenticated server snapshot | Reject as a bootstrap shortcut; no authenticated native-state coverage exists by assertion. |
| Keep all choices unresolved | Avoids commitment but prevents a concrete next interoperability study; narrowed reversible research choices are more useful. |

Two Actions and full retention deliberately bound the first specification's
complexity. They do not establish useful capacity, fees, storage sustainability
or production readiness. Repaired source selection is not independent proof of
cryptographic correctness. The direct verifier requires actual consensus work.

## Outcome and security implications

This records reversible research choices and the review's remaining obligations,
not adoption of a runnable protocol. No runtime, key derivation, verifier,
reserve, invariant, funded trial or network rule changes. Independent human
cryptography/consensus approval remains outstanding. Internal review and model
checks cannot supply it. No MPC, proof/setup campaign or funded trial resumes.

The concrete next optional study is unfunded codec/verifier interoperability;
native implementation additionally needs exact state/codec/bootstrap and reviewed
invariant/accounting decisions. Qualification still needs a feasible explicit
claim/population and fresh complete privacy/cost/recovery evidence.

Reconsider this reference if source defects, native verifier cost, recovery or
storage limits defeat it; if a complete wrapper has better supported tradeoffs;
or if the owner explicitly changes the fixed requirements. Retain failed evidence
and compare complete profiles rather than swapping individual primitives.
