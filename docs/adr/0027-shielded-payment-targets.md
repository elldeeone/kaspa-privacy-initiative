# ADR-0027: Adopt the shielded-payment qualification targets

**Status:** Accepted — requirements decision for research/testnet only.

**Date:** 2026-10-20

**Related RFC:** [RFC-0012](../rfc/0012-useful-privacy-requirements.md)

## Context and decision

The earlier experiments demonstrate bounded native payment and exit mechanics.
They do not establish useful privacy, an independently operated current-version
wallet or acceptable user costs. A declared finish line is needed before further
integration is judged.

The owner adopted the proposed targets and directed closing milestone 1.
RFC-0012 is the authoritative numerical profile: payment sizes, complete fees,
reference hardware, proving/payment/startup/exit/recovery latency, observer models,
relationship and amount inference, selective attacks, observation horizons and
fee-stress cases. Milestone 1 is complete as a requirements decision. No later
milestone is marked passed.

The primary use case is repeated payments from a retained shielded balance.
Native ingress/egress remains public, and an urgent exit can disclose more.
Exit authority cannot depend on meeting a privacy threshold or waiting for others.
No new token, consensus change, deployed protocol change or privileged withdrawal
route is selected.

## Alternatives considered

- **Continue relative improvements over old anchors:** retains existing screens,
  but does not establish an acceptable absolute privacy outcome.
- **Fit requirements to current prototype costs and fixtures:** makes continuation
  easier, but can hide small-payment, recovery and participation limitations.
- **Adopt user-oriented targets and report gaps:** selected. Current v6 can miss
  targets; that evidence guides optimization, architecture selection or an explicit
  reconsideration of the use case.

The existing source-transaction screens remain historical evidence with their
own frozen criteria. They are not rescored under the new owner-level targets.

## Security, privacy and operational consequences

All [invariants](../../SECURITY-INVARIANTS.md) remain unchanged. Safety violations
cannot be traded against fees, latency or privacy. Unpaid claims remain liabilities,
including when a performance target fails. Numerical performance gates are not
operational timeouts that abandon a funded testnet payout.

The privacy percentages are empirical acceptance criteria under specified
observations, not cryptographic security parameters. Simulated roles do not
establish independent ownership; public values and legitimate counterparty
knowledge are not hidden. Witness confidentiality remains required, while network
anonymity needs separate evidence.

The source-grounded verification cost already challenges the small-payment fee
endpoint. That justifies investigating amortization or alternatives; it does not
adopt batching or vProgs without a design and evidence. Setup integrity, general
recovery, contention, admission and cryptographic composition remain unresolved.

## Evidence and next work

- [Requirements and capability map](../rfc/0012-useful-privacy-requirements.md)
- [Pinned source review](../../research/shielded-kas-privacy-requirements-2026-10-20.md)
- [H13 native testnet result and limitations](../../poc/shared-pool/TWO-INPUT-TN10.md)
- [H18 negative privacy result](../../poc/shared-pool/SCHEDULED-PAYOUT.md)
- [Branch milestones](../SHARED-POOL-PLAN.md)

The owner authorized this documentation commit/push followed by starting
milestone 2. That work consolidates one candidate lifecycle and its enforcement
obligations. A complete experiment still needs a frozen workload/analysis manifest.
No new funded trial or upstream publication is initiated by this decision.

## Revisit if

The intended use case changes, evidence reveals an unachievable or misleading
requirement, or verified upstream changes alter the cost/security constraints.
Record the rationale and preserve the previous profile and failed evidence.
