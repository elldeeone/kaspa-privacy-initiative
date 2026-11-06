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

- [ADR-0109: complete costs and genuine batched payouts](0109-complete-cost-and-batched-payout-test.md)
- [ADR-0108: actual-wallet common-set integration and cost test](0108-real-wallet-common-set-integration.md)
  ([ownership benefit and negative direct-cost result](../../research/payment-set-withdrawal-2026-11-05/RESULT.md)).

- [ADR-0107: finite common-set withdrawal diagnostic](0107-finite-common-set-withdrawal-diagnostic.md)
  ([bounded result](../../research/common-set-withdrawal-2026-11-05/RESULT.md)).

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

- [ADR-0015: staged TN10 inputs and one-way native initialization](0015-tn10-private-native-preparation.md)
- [ADR-0016: user-held recovery and terminal reserve exit experiment](0016-user-held-recovery-and-terminal-exit.md)
- [ADR-0017: integrated partial and exact-reserve recovery guest](0017-integrated-recovery-native-guest.md)
- [ADR-0018: depth-four local continued-private-spend profile](0018-depth-four-private-spend-experiment.md)
- [ADR-0019: opt-in depth-four multi-user TN10 trial](0019-depth-four-multi-user-tn10-trial.md)

- [ADR-0100: research consolidation and the transparent-exit boundary](0100-research-consolidation-and-privacy-boundary.md)
- [ADR-0101: native shielded-value research reference](0101-native-shielded-research-reference.md)
- [ADR-0102: unfunded complete-Orchard interoperability package](0102-unfunded-orchard-interoperability.md)
- [ADR-0103: native shielded-value consensus specification draft](0103-native-shielded-consensus-specification.md)
