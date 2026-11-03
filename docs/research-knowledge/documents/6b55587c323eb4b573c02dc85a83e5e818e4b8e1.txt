# RFC-0024: Independent private payments, settlement and recovery

**Status:** Open; parallel experiments authorized, architecture selection gated.
**Date:** 2026-10-23 UTC. Baseline `5aaf99532d8714e510d421102df719f60f54d073`.

## Problem

ADR-0057 completes a locally validated single-issuer batch with 32 independent
recipient exits. It does not close separate-sender fees, financial privacy,
private exits at state capacity or independent durable recovery. The owner now
requests completion of those four workstreams. The
[execution plan](../../research/next-session/independent-payments/PLAN.md)
defines separate, falsifiable completion gates.

## Fixed requirements

Preserve SECURITY-INVARIANTS I-1 through I-16, native KAS backing, exact integer
sompi and user-controlled private exits. No operator signature, hosted private
witness collection, real funds, mainnet experiment or new cryptographic
primitive is an acceptable shortcut. Existing trial/setup identities are not
upgraded in place. Passing code/proof/native controls is bounded implementation
evidence, not a proof of soundness, anonymity or production safety.

## Settlement alternatives

Compare unchanged ordered native transactions, a minimal native shared
settlement/intent policy, and established proof composition or a Based App.
Do not presume vProgs is required or unnecessary. First check the two-action
public transcript required by the
[compatibility memo](../../research/next-session/compact-batch/fees/AGGREGATION-COMPATIBILITY-01.md).
Verification of individual proofs does not establish current state, update
witnesses, exact native payout effects or a combined fee authorization.

Any selected aggregate must bind one actual final L1 body to the current start
and the complete ordered changes. Decide explicitly whether exact-transition
Auth528 authorizations suffice or a new reviewed intent relation is required.
Price complete entry, payment, delivery, settlement, private withdrawal and
operator-missing fallback at the same stated fee rate. Cooperative averages do
not qualify an expensive isolated private exit.

## Privacy alternatives

Address actual payment/settlement behavior, including co-output invoice facts,
one-funder sparse periods, amount priors and complete native cashout. Compare
established multiparty transaction/intent and anonymity mechanisms only with
their authority, witness privacy, delivery, fee, delay and fallback obligations
explicit. More SMT coverage cannot erase an already demonstrated leak.

New frozen measurements must distinguish funding ancestry, modeled payer role,
commitment-to-payout linkage, exact value and human identity. Paired views do
not create independent populations. Preserve original thresholds and failed
studies; an unmet threshold is a rejection or open blocker, not a reason to
weaken the observer or replace unknowns with anonymity claims.

## Recovery and exit alternatives

Separate public byte identity, independent distribution/retention, executable
authority, semantic replay and fresh accepted-head/current-UTXO reconciliation.
Demonstrate cold restoration from own backup and public material; additional
local paths/processes are not separately controlled providers.

The existing compact relation equates no-append mode with terminal reserve.
A new-instance full-note private cashout without a commitment append is a
candidate for capacity liveness. It needs a separate reviewed relation,
parameters, program/domain and proof/native evidence. Prove that remaining
nullifier capacity suffices across every valid admitted branch; otherwise
select a reviewed scalable state alternative. Carrying a root or deleting
spentness without authenticated membership/uniqueness is not a resolution.

## Open decisions

- Can a genuinely cheaper shared-settlement design retain private unilateral
  exits with complete data and bounded delay during low demand/operator loss?
- Which concrete behavior removes invoice/co-output and sparse-funding linkage
  without another party receiving a user's private spend witness?
- Does a no-append full-note exit close commitment and nullifier capacity for
  every reachable state of the selected bounded experiment?
- Which separately controlled providers retain the exact public parameters,
  history and reproducible software, and how is loss detected and repaired?
- Which new-instance design passes a complete fresh accepted-testnet rehearsal
  through confirmed terminal payouts after original-service loss?

Record resolved architecture decisions in a new ADR before implementation;
retain rejected candidates and new trust assumptions with their evidence.

## Execution decisions and evidence

[ADR-0058](../adr/0058-private-full-note-exits-without-commitment-appends.md)
selects and completes a separate no-append capacity experiment with genuine
proof/native closure and the all-branch NF reservation argument. It resolves
that bounded dependency, not full-tree change or accepted history. The public
recovery release, exact clean source build and full HTTPS restoration/private
terminal proof also pass in supplied contexts; separately administered
retention and fresh accepted-state reconciliation remain open.

[ADR-0059](../adr/0059-scheduled-private-actions-with-public-settlement-proofs.md)
now selects an unfunded scheduled two-P0-action/R0/native prototype. Virtual
authorization, acyclic exact financial projection, sumFi=actualF and a direct
private fallback are mandatory. No old pool upgrade or fee/privacy target
qualification follows. Track current results in the
[execution checkpoint](../../research/next-session/independent-payments/RESULTS.md).
