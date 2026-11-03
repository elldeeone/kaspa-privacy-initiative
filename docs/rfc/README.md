# Requests for Comments

RFCs are open technical proposals used while a significant design question is still unresolved. They capture context, constraints, alternatives, evidence, objections, and open questions so contributors can discuss and test a proposed direction.

Use `NNNN-short-title.md` and the [RFC template](0000-template.md). Start with **Open** status. An RFC can conclude as **Accepted**, **Rejected**, **Superseded**, or **Withdrawn**; record the outcome and its scope.

When a durable architecture or design decision is reached, record its rationale and outcome in an [ADR](../adr/README.md) that links back to the RFC. Link the RFC's outcome to that ADR.

## Proposals

- [RFC-0001: State architecture for the first native-KAS privacy PoC](0001-state-architecture.md) — Open; no architecture selected.
- [RFC-0002: Shielded payment protocol](0002-shielded-payment.md) — Open; proposed protocol and unresolved security choices.
- [RFC-0003: Depth-four multi-user TN10 trial profile](0003-depth-four-multi-user-tn10-profile.md) — Accepted for one bounded experiment by ADR-0019; execution evidence remains separate.
- [RFC-0004: Native-KAS private payments and the transparent-exit boundary](0004-native-kas-private-payment-boundary.md) — Open; Q1–Q10 review and unfunded complete-Orchard codec/verifier interoperability package complete under ADR-0101/0102. Exact native mapping/bootstrap/key identity, invariant adoption, consensus integration and qualification remain open; no independent specialist approval or production adoption.
