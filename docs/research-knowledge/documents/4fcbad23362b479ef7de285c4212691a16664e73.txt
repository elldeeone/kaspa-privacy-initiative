# Requests for Comments

RFCs are open technical proposals used while a significant design question is still unresolved. They capture context, constraints, alternatives, evidence, objections, and open questions so contributors can discuss and test a proposed direction.

Use `NNNN-short-title.md` and the [RFC template](0000-template.md). Start with **Open** status. An RFC can conclude as **Accepted**, **Rejected**, **Superseded**, or **Withdrawn**; record the outcome and its scope.

When a durable architecture or design decision is reached, record its rationale and outcome in an [ADR](../adr/README.md) that links back to the RFC. Link the RFC's outcome to that ADR.

## Proposals

- [RFC-0027: Owner-private native KAS lifecycle](0027-owner-private-native-kas-lifecycle.md) — Open; one new GN3-backed profile joins repeated multiparty payments, seed recovery, direct independent exits and actual confirmed testnet payouts.
- [RFC-0026: Owner-private multiparty construction](0026-owner-private-multiparty-construction.md) — Open; exact builder/knowledge/binding feasibility under the public and assembler observer, with bounded API falsification under ADR0061.
- [RFC-0025: Four-wallet testnet funding and accepted recovery](0025-four-wallet-testnet-funding-and-accepted-recovery.md) — Open; strict GN2, actual accepted heads and all four confirmed payouts under ADR0060, with separate privacy and independent-retention outcomes.
- [RFC-0024: Independent private payments, settlement and recovery](0024-independent-private-payment-settlement-and-recovery.md) — Open; four parallel execution tracks, with separate settlement, privacy, availability and full-capacity exit gates.
- [RFC-0001: State architecture for the first native-KAS privacy PoC](0001-state-architecture.md) — Open; no architecture selected.
- [RFC-0006: Reusable private authorization](0006-reusable-private-authorization.md) — Bounded experiment completed; broader scale, privacy and liveness questions remain open.
- [RFC-0010: Independent deposits without replacing saved exit proofs](0010-compact-independent-deposits.md) — Bounded v5 offline and TN10 experiment passed; broader privacy remains open.
- [RFC-0011: Two-input payments, private change and partial withdrawals](0011-two-input-private-payments.md) — Open; bounded H13 mechanics passed offline. Broader qualification and practical privacy remain open.
- [RFC-0012: Useful privacy requirements for native KAS payments](0012-useful-privacy-requirements.md) — Accepted requirements; milestone 1 complete. Adopted qualification targets do not establish implementation privacy, security or performance.
- [RFC-0013: One current-version native-KAS payment lifecycle](0013-coherent-v6-lifecycle.md) — Accepted for bounded offline integration; own-key admission, backup recovery, payment/change and fresh terminal exit pass. Live qualification remains open.
- [RFC-0014: Owner-aware evaluation of the 32-user privacy claim](0014-owner-aware-privacy-evaluation.md) — Open; first-stage falsification design, with statistical qualification still separate.
- [RFC-0015: Native transaction privacy under varied usage](0015-native-usage-privacy-screen.md) — Completed with finite-case amount-privacy warnings; no privacy qualification.
- [RFC-0016: Requested withdrawals with a working private balance](0016-working-balance-withdrawals.md) — Evaluated; arithmetic gate failed despite benefit in one scenario. Wallet policy not adopted; native continuation stopped.
- [RFC-0017: Separate price priors from transaction information](0017-price-priors-and-transaction-leakage.md) — Evaluated; frozen attack did not outperform the price prior across 512 ledgers. Broader information/privacy questions remain open.
