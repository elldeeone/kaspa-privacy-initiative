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

- [ADR-0099: Low-memory no-setup W1 aggregate prover](0099-low-memory-no-setup-w1-prover.md) — Stream the sealed c023 R1CS and canonical historical PK with matrix-free synthesis and bounded MSMs; small exact equivalence passes, while the real proof remains blocked on exact-assignment/PK scaling and host admission.
- [ADR-0098: Observe the actual unbounded P1 transcript](0098-observe-unbounded-p1-transcript.md) — Stream the actual selected P1 transcript without a guessed operational cap, while requiring separate direct capture or exact replay of every P1-known internal random/state family before the passive view can qualify.
- [ADR-0097: All-branch fresh-trial history owner](0097-all-branch-fresh-trial-history-owner.md) — Acquire the ledger, reserve both C03 objects and pin pidfds before trial identity use; only complete failed views may continue, while unavailable capture seals a typed run-invalidating terminal; factories, no-drop outcome, sink and selected callsite remain blocked.
- [ADR-0096: Feasibility-aware Observer v4 acceptance](0096-feasibility-aware-observer-v4-acceptance.md) — Keep Observer v3 open and add a new live-authority-only v4 join for distinct S4/S12, conjunctive S5+S6A, joint S6A+S7, narrow S14+S12, same-instance Full-W1/Close feasibility, all-fresh-trial history and source/runtime freshness; all production minters remain blocked.
- [ADR-0095: Pre-setup-only bounded CRS plan](0095-pre-setup-only-bounded-crs-plan.md) — Bind local setup only to a predeclared trial/run/attempt/cohort skeleton and exact circuit closures; exclude post-setup selections, capture plans, projections and unresolved manifests, with production selection and all setup runs still blocked.
- [ADR-0094: Source-owned selected-parent artifact table](0094-source-owned-selected-parent-artifact-table.md) — Require an immutable exact 10x6 final-artifact table and same-descriptor child execution before parent manifest authority; all 60 production rows are currently machine-reported MISSING and launch stays `CONFIGURED0`.
- [ADR-0093: Phase-scope pre-network private coverage](0093-pre-network-private-coverage-phase-scope.md) — Keep accepted-chain rows explicitly deferred and Observer-v3 Step-2 rows explicitly open; one opaque native join retains the sole sealed output plus empirical residual but mints no prediction, phase, barrier or Step-2 permit.
- [ADR-0091: Sealed measurement input and output data planes](0091-sealed-measurement-data-planes.md) — Retain the exact ten sole-reader wire streams in sealed objects, admit only their private authority to FD40, and derive barriers/scores from authenticated fixed-size sealed worker outputs; all selected callsites remain `CONFIGURED0`.
- [ADR-0090: Owner-local hidden-candidate truth release](0090-owner-local-candidate-truth-release.md) — Release genuine owner-local R1/R2 truth only after a one-shot frozen hidden-run barrier and private pending-batch join; per-owner score consent remains separate and selected launch stays `CONFIGURED0`.
- [ADR-0088: Passive pinned-P1 empirical observer scope](0088-passive-pinned-p1-empirical-observer-scope.md) — Bound the frozen empirical gate to the complete admitted view of the exact pinned passive P1 process plus C1; ADR-0098 clarifies that P1-known random/state families are required, while active malicious-host, physical-host, and covert-channel privacy remain unqualified.
- [ADR-0087: No-raw-B1 collaborative Groth16 completion](0087-no-raw-b1-mixed-beaver-groth16-completion.md) — Construct the two secret scalar/G1 products from fresh authenticated field triples, open only masked differences, and expose only final `(A,B2,C)`; bounded research evidence does not qualify privacy or production.
- [ADR-0086: Complete DDNNT external-owner input supply](0086-complete-ddnnt-external-owner-input.md) — Replace the unqualified three-value `x+a` adapter with exact five-value DDNNT delivery and common `d=x-s`; old formats fail closed and registered launch remains `CONFIGURED0`.
- [ADR-0085: Staged registered payment-capture authority](0085-staged-registered-payment-capture-authority.md) — A live parent must join six party capabilities, ten exact streams, ordered baseline/candidate measurement and a finite recomputed manifest before a bounded `BatchPrivacyPassAuthority`; all production adapters and launch remain false.
- [ADR-0084: Two-phase Testnet trial authorization](0084-two-phase-testnet-trial-authorization.md) — Split same-trial launch preflight from post-terminal completion; the private offline native/ten-stream join and first-RPC ordering are source-implemented, while actual lifecycle/global-capture callsites and every network adapter remain fail-closed.
- [ADR-0083: Parent-owned fresh-attempt authority](0083-parent-owned-fresh-attempt-authority.md) — One supervisor owns the durable registry and issues role-bound linear approvals after all-three direct-head agreement; process integration and an external monotonic anchor remain required at `CONFIGURED=0`.
- [ADR-0064: Owner-private native KAS lifecycle](0064-owner-private-native-kas-lifecycle.md) — New TN10-only GN3, repeated private rounds, seed recovery and direct one-owner exits; actual integrated execution remains required.
- [ADR-0063: Owner-private payments prototype](0063-owner-private-payments-prototype.md) — Separate Spend/Output proofs and malicious MPC construction; genuine unfunded local verification and a bounded grouping study, no inherited testnet lifecycle.
- [ADR-0062: exercise an existing checked private field-sum API](0062-existing-engine-private-field-sum.md) — Public synthetic component gate; no KAS construction or privacy qualification.
- [ADR-0061: Construction API and partition falsification](0061-construction-api-and-partition-falsification.md) — Accepted bounded existing-API/curve controls; no new KAS relation, setup, proof or privacy qualification.
- [ADR-0060: Four-wallet GN2 testnet rehearsal](0060-four-wallet-gn2-testnet-rehearsal.md) — Accepted bounded contract; fresh testnet profile, owner-local two-input funding, strict accepted-history recovery and four independent exits.
- [ADR-0059: Scheduled private actions with public settlement proofs](0059-scheduled-private-actions-with-public-settlement-proofs.md) — Accepted for a new unfunded two-action R0/native prototype; exact fee/body semantics and direct private fallback remain required gates.
- [ADR-0058: Private full-note exits without commitment appends](0058-private-full-note-exits-without-commitment-appends.md) — Accepted for a separate unfunded capacity experiment; fresh parameters and proof/native validation required, old instances unchanged.
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
- [ADR-0029: own-key admission and backup recovery](0029-own-key-admission-and-recovery.md) — Bounded offline wallet integration and complete recovery/spend/exit test on unchanged v6 parameters.
- [ADR-0030: separate funding and exit keys](0030-separate-funding-and-exit-keys.md) — Fresh backup v2 uses a funding-specific derivation; explicit v1 recovery remains compatible and retains its known reuse risk.
- [ADR-0031: screen working-balance withdrawals with arithmetic first](0031-arithmetic-working-balance-screen.md) — Bounded comparison complete; frozen gate failed and conditional native continuation stopped. No wallet policy adopted.
- [ADR-0032: diagnose sparse guesses before selecting another mitigation](0032-sparse-diagnosis-and-privacy-evaluation.md) — Retain direct-L1 mechanics, stop general cashout tuning, and audit priors/public information before a new mitigation; old privacy failure remains unchanged.
- [ADR-0033: evaluate transcript advantage against price guessing](0033-price-baseline-evaluation.md) — Completed fixed-attack test; all comparisons support below-five-point advantage, none establishes positive advantage. Retain mechanics and improve evaluation before a new mitigation; no protocol change.
