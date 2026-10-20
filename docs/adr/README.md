# Architecture Decision Records

Architecture Decision Records (ADRs) record actual architecture/design decisions, their rationale, and their outcomes so the project does not depend on memory, personality, or social authority. Use [RFCs](../rfc/README.md) for open proposals, alternatives, evidence gathering, and unresolved design questions.

The RFC/ADR separation was introduced after the initial repository structure. Some early experimental records may not perfectly follow the newer convention. ADR-0002 and ADR-0003 retain their existing names, statuses, and experimental scope for now.

## File naming

```text
NNNN-short-title.md
```

## Status values

- Accepted
- Superseded
- Rejected

Early experimental records retain their existing status terminology under the transition note above.

## Rules

An ADR should:

- state the problem;
- list constraints;
- compare credible alternatives;
- identify security/privacy implications;
- cite evidence;
- record objections;
- explain why the decision was made;
- record its outcome and link to the originating RFC, when applicable;
- state what evidence would cause reconsideration.

Use [0000-template.md](0000-template.md).

## Records

- [ADR-0002: A0 terminal reserve-release experiment](0002-a0-reserve-release-experiment.md)
- [ADR-0003: A1 finite successor reserve and independent terminal exit](0003-a1-successor-reserve.md)
- [ADR-0007: bounded local proof-byte classification experiment](0007-local-proof-classification.md)
- [ADR-0008: specialized BN254/Groth16 comparison](0008-specialized-groth16-comparison.md)
- [ADR-0009: bounded accelerated BN254 qualification](0009-accelerated-bn254-qualification.md)
- [ADR-0010: approved 128M outer classification proof](0010-approved-128m-outer-proof.md)

The open state architecture comparison is [RFC-0001](../rfc/0001-state-architecture.md).

- [ADR-0011: local private-note wallet and economic transitions](0011-local-private-note-wallet.md)

- [ADR-0012: bounded private-note state/native integration](0012-private-note-state-integration.md)
- [ADR-0013: fixed private-note proof and join-native preparation](0013-private-note-proof-package.md)
- [ADR-0014: authenticated private/native lifecycle preparation](0014-private-native-lifecycle.md)
- [ADR-0018: reusable private authorization and current native settlement](0018-reusable-private-authorization.md)
- [ADR-0022: scope two-note deposits into a new compact pool](0022-compact-two-note-deposits.md) — Research scope only; no implementation or protocol adoption.
- [ADR-0023: test equal net credits as a wallet funding policy](0023-equal-net-deposit-policy.md) — Bounded candidate policy; general privacy unestablished.
- [ADR-0024: specify two-input private payments before further experiments](0024-two-input-private-payment-scope.md) — Accepted scope, followed by authorized offline implementation; bounded H13 passed, RFC-0011 remains Open.
- [ADR-0025: screen common partial payouts without changing the protocol](0025-common-payout-offline-screen.md) — Owner-authorized offline policy comparison; preserve independent exits and count complete drainage.
- [ADR-0026: independently scheduled common payouts](0026-scheduled-common-payout-screen.md) — Offline privacy gate failed; short-delay policy rejected and conditional native/TN10 step not triggered.

- [ADR-0027: adopt shielded-payment qualification targets](0027-shielded-payment-targets.md) — Accepted requirements; milestone 1 complete, implementation qualification remains open.
- [ADR-0028: begin lifecycle integration with public funding replay](0028-public-funding-replay.md) — Bounded offline component on the unchanged v6 relation; full wallet integration remains open.
