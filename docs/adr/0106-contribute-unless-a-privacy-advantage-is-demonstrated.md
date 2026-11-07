# ADR-0106: Contribute to KPI unless an alternative earns its privacy advantage

**Status:** Accepted owner work-selection rule; no production architecture adopted.
**Date:** 5 November 2026.

## Decision

The owner requires either a solution that demonstrates better privacy than
Olaf's current direction, or focused contributions to that shared direction.
No alternative has demonstrated that advantage. **Contributing to the existing
KPI effort is therefore the default active path.** Preserve independent
criticism and previous negative evidence; do not create a competing runtime or
continue open-ended alternative-architecture work merely because it is possible.

The reference is the shared upstream implementation at
`7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1`, verified against upstream main on
5 November. Its [open RFC-0001](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/docs/rfc/0001-state-architecture.md)
prioritizes investigating one Based App while keeping direct covenants as a
control. Supporting that effort does not mean declaring its architecture,
privacy, scaling, cost or complete operator-loss recovery qualified.

This supersedes ADR-0105's preference for starting a separate direct-inline-ZK
comparison. Its hard **no consensus changes** constraint and all fund/authority/
privacy requirements remain. Native-consensus work and paused MPC stay outside
active scope. Historical plans, evidence, prototypes and archive tags remain.

## Conditions for pursuing an alternative

A short candidate investigation needs all of the following before it expands:

1. A concrete privacy mechanism and named fact it should protect better than a
   fixed upstream baseline. It must fit existing Kaspa rules and the retained
   custody, exit, accounting and recovery requirements.
2. A matched complete-lifecycle comparison with fixed observers, truthful
   counterparty knowledge, workload, metrics, success criteria and stop rule.
   Stronger guarantees require correspondingly stronger evidence; source review
   or passing verifier tests cannot establish a measured privacy advantage.
3. A bounded falsification step. Stop or return to contributing if it fails;
   do not respond by changing the observer, counting hidden labels, weakening
   requirements or building another subsystem without a demonstrated need.

No candidate currently clears the demonstrated-advantage gate. This decision
starts no new comparison, proof campaign, trial or runtime implementation.

## Immediate useful contribution

Use upstream [P13: practical privacy leakage](https://github.com/olafweller/kaspa-privacy-initiative/issues/13)
to turn our retained findings into narrow, reviewable shared-project evidence.
The [local contribution draft](../../research/upstream-p13-contribution-2026-11-05.md)
identifies full-withdrawal amount correlation, the private-change/common-reserve
failures, and scorer controls that retain execution truth. It asks for no new
runtime, consensus interface or cryptographic primitive. The first deliverable
is a focused evidence/test-requirements contribution, not another architecture.

Follow [CONTRIBUTING.md](../../CONTRIBUTING.md): align scope through the relevant
issue before substantial implementation, preserve existing evidence and keep
changes small. Recording this 5 November decision sent no external message.
The later [focused P13 timing finding](https://github.com/olafweller/kaspa-privacy-initiative/issues/13#issuecomment-6706287130)
was posted on 7 November. The broader local draft remains unposted; the comment
is neither a PR nor maintainer agreement.

All SECURITY-INVARIANTS.md requirements remain unchanged. No owner knowledge,
privacy/cost threshold or independent-exit requirement is relaxed. No real funds,
mainnet deployment, new trial broadcast or provider infrastructure follows.
