# Architecture lessons

[Knowledge guide](README.md) · [Component decisions](reuse.md)

## Current decision boundary

The owner's 5 November direction in
[ADR-0105](../adr/0105-maximize-privacy-without-consensus-changes.md) excludes
consensus changes. The current-rule confidential-claim reference and
[comparative source review](../../research/current-rules-privacy-options-2026-11-05.md)
govern active work. Later native consensus formats/Halo2/key artifacts described
below are preserved research outside active implementation scope.

The project has demonstrated native test-KAS deposit/payment/withdrawal
components. Strong financial privacy, the complete cost target and complete
independent recovery remain open. The current [architecture](../ARCHITECTURE.md),
[RFC-0001](../rfc/0001-state-architecture.md) and
[transparent-exit RFC](../rfc/0004-native-kas-private-payment-boundary.md) govern
the proposal; no historical Accepted ADR selects production architecture.

| Research line | Reusable lesson | Boundary to retain |
| --- | --- | --- |
| A0 proof-gated release | Real proof authorization can gate native reserve release; fee/storage-mass/header checks matter. | One release is not an authenticated ongoing reserve or independent N-user recovery. |
| A1 successor reserve | Authenticate the successor, exact actual input context and recovery artifacts; rollback scanner accounting on reorg. | The physical-loss recovery trial is a bounded profile, not complete disappearance of all infrastructure. |
| Based App bridge and recursive replay | Explicit native backing/fee domains, input completeness, public replay and recursive checkpoints can be tested. | The [scoped conclusion](../based-app-feasibility-2026-10-17.md) completes that public-account milestone, not shielded-system selection. |
| Direct self-funded compact pool | A sponsor is not mechanically necessary for the selected native deposit/exit layout. | [self-funded native trial](documents/014b5ea21d0f081ff7d490033d77095a57e44930.txt) does not establish general anonymity, arbitrary repricing or sustained contention fairness. |
| Paired/compressed state transition | Bind the exact public records, historical anchors, current nullifiers, predecessor and successor. | A synthetic supplied root/outpoint is not accepted ancestry, backing or live settlement. See [paired proof/compression results](documents/832da77252bdfb3f3b56bd920b236442143f8c2e.txt) and [state-aware journal proposal](documents/b6002dff3bc25e9b1b89aee3c42682d34946d20b.txt). |
| Wallet-local private spending | Private receiving, re-spending and owner recovery are useful current reference mechanisms. | Ordinary transparent withdrawals reveal values/scripts and can expose earlier payments. |
| Private construction/MPC | One bounded construction hid an explicit map from its coordinator. | The distinct registered aggregate path remains incomplete and constructor-visible; [paused handoff](documents/8afbd3d859a68dc4d80194cbdc3f0cc36e5e9961.txt) remains paused. |

## Bind economic authority where it is enforced

A private proof must bind the actual native payout amount and destination,
current reserve context and immutable successor policy. A host verdict or a
valid proof about unrelated supplied state cannot release reserve KAS. Preserve
checked integer narrowing, exact fee/principal separation, pending liabilities
and treasury/reserve isolation. See [research journal](documents/a99d0c7618070857506be9bfaa31780dadf32d56.txt).

The frozen feasibility and offline-wallet lines contain explicit alternative
I-2 formulations. The [historical payout accounting statement](documents/96c60f39f1f07ec42377662e2080cf158e1001d7.txt) accounts for authorized native payouts in
addition to private outputs/fees. This is valuable design input, **not an amendment
to current SECURITY-INVARIANTS.md**. A future transition/exit specification must
resolve that boundary explicitly rather than silently importing another branch's
conservation statement.

## Reuse existing protocols before another subsystem

The current RFC/source reviews compare mature shielded systems, note delivery,
nullifiers, authenticated state, discovery and exits. Their reference mechanisms
are design inputs, not evidence that those systems' assumptions hold on Kaspa.
[privacy surface source review](documents/abe50a0f21b547dab4131289e3f69a791a93e526.txt) and the local historical RFCs preserve the earlier comparisons.
Refresh exact Kaspa/Toccata/vProgs upstream identities before new semantic work.

The [extended native-value proposal](../rfc/0004-native-kas-private-payment-boundary.md#reviewable-native-shielded-value-proposal)
now records the source-bound requirements, accounting and prior-learning
constraints. The completed [Q1–Q10 internal review](../rfc/0004-native-kas-private-payment-boundary.md#review-questions-and-stop-conditions)
and [ADR-0101](../adr/0101-native-shielded-research-reference.md) select a complete
repaired Orchard V2/native-verifier research reference. Exact native codecs,
authenticated bootstrap, reviewed invariant/accounting adoption and actual
consensus integration remain open. Application proofs, a different prover or a
larger runtime cannot conceal ordinary transparent-output fields. This review
establishes no independent specialist approval or implementation/privacy result.

The later [unfunded interoperability result](../../poc/orchard-interop/README.md)
demonstrates the complete repaired-V2 verifier and experimental codec locally.
It closes that compatibility question while leaving native field/state/header
mapping, portable key identity, bootstrap, invariant adoption and actual
consensus integration open. Carry its exact public vectors and limitations;
do not treat synthetic ordinary inputs as native backing.

The [native specification draft](../spec/native-shielded/README.md) supplies
proposed exact formats/algorithms and a portable mathematical key identity.
It addresses the old single-tree capacity trap through rollover/global
spentness and scopes first funding/payouts to standard key scripts. It records
accounting/invariant review and full replay/retention explicitly; adoption,
actual consensus integration, activation/pricing and qualification remain open.
