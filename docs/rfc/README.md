# Requests for Comments

RFCs are open technical proposals used while a significant design question is still unresolved. They capture context, constraints, alternatives, evidence, objections, and open questions so contributors can discuss and test a proposed direction.

Use `NNNN-short-title.md` and the [RFC template](0000-template.md). Start with **Open** status. An RFC can conclude as **Accepted**, **Rejected**, **Superseded**, or **Withdrawn**; record the outcome and its scope.

When a durable architecture or design decision is reached, record its rationale and outcome in an [ADR](../adr/README.md) that links back to the RFC. Link the RFC's outcome to that ADR.

## Proposals

- [RFC-0001: State architecture for the first native-KAS privacy PoC](0001-state-architecture.md) — Open; no architecture selected.
- [RFC-0006: Reusable private authorization](0006-reusable-private-authorization.md) — Bounded experiment completed; broader scale, privacy and liveness questions remain open.
- [RFC-0010: Independent deposits without replacing saved exit proofs](0010-compact-independent-deposits.md) — Bounded v5 offline and TN10 experiment passed; broader privacy remains open.
- [RFC-0011: Two-input payments, private change and partial withdrawals](0011-two-input-private-payments.md) — Open; bounded H13 mechanics passed offline. Broader qualification and practical privacy remain open.
- [RFC-0012: Useful privacy requirements for native KAS payments](0012-useful-privacy-requirements.md) — Accepted requirements; milestone 1 complete. Adopted qualification targets do not establish implementation privacy, security or performance.
