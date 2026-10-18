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
- [ADR-0011: bounded offline model recovery formats and R01–R04](0011-offline-model-recovery.md)
- [ADR-0012: offline restored transitions and pending refund claims](0012-offline-restored-transitions.md)
- [ADR-0013: offline paid-claim recovery and terminal reserve drain](0013-offline-paid-claim-recovery.md)
- [ADR-0014: offline R08–R16 recovery failure programme](0014-offline-recovery-failure-programme.md)
- [ADR-0015: private-payment specification and proof qualification boundary](0015-private-payment-proof-boundary.md)
- [ADR-0016: separate local RTX 3070 CUDA qualification](0016-local-cuda-qualification.md)
- [ADR-0017: smaller proof segments on the RTX 3070](0017-rtx3070-smaller-segments.md)
- [ADR-0018: private-payment implementation package and testnet preflight](0018-private-payment-implementation-package.md)
- [ADR-0019: owner-selected separate-agent review for the offline prototype](0019-separate-agent-prototype-review.md)

The open state architecture comparison is [RFC-0001](../rfc/0001-state-architecture.md).

- [ADR-0020: Full offline wallet relation and receipt-backed restore harness](0020-offline-wallet-relation.md)
