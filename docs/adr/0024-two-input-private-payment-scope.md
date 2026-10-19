# ADR-0024: Specify two-input private payments before further experiments

**Status:** Accepted — research/documentation scope only.
**Date:** 2026-10-20 (Australia/Sydney).
**Branch:** `shared-pool-four-wallet`; inspected baseline `228e5d0`.
**Proposal:** [RFC-0011](../rfc/0011-two-input-private-payments.md), still Open.

## Problem

The compact candidate can independently settle funded claims, but its normal
payment relation consumes one note and splits it into two positive notes.
Withdrawals consume a whole note. It cannot combine receipts or keep private
change on withdrawal. Those restrictions are unsuitable for general varied
payments and strengthen public amount/ancestry constraints.

H11's fresh proofs and H12's equal net deposits improved inference outcomes in
their declared workloads. Those results do not establish strong privacy for
varied, interleaved payments. Repeating the same policy experiments would not
resolve whether the payment relation itself is an adequate foundation.

## Decision and authority

Write a concrete two-input/two-output proposal and its observer review before
building or running more tests. The owner authorized documentation only. This
ADR accepts that scope, **not cryptographic correctness, protocol adoption,
implementation, parameter generation, new experiments or publication**.

Retain direct covenant settlement as the candidate because it already separates
private ownership authorization from publicly rebuildable current settlement.
No current-L1 primitive has been identified as missing for a two-input relation.
This remains an architectural inference until the actual larger layout is
qualified. No consensus change or mandatory runtime is part of this decision.

The proposal must contain:

- Two private input and two private output slots, with constrained zero padding
  on the normal path; a payment can combine receipts and retain private change.
- Partial native withdrawal with private change, exact claim-funded fees,
  explicit value conservation, and direct current double-spend enforcement.
- A full-exit fallback that appends no commitments, remains possible at the
  commitment capacity limit, and needs no privileged signature or secret.
- Historical proof preservation within a new immutable pool, private saved
  fallback bundles, local recovery requirements and explicit fee/data limits.
- A chain-only observer review that includes amounts, topology, anchors,
  padding, later exits and complete-drain inference without an anonymity score.

Use a new relation, setup, VK and pool version. Do not retrofit deployed v4/v5
pools, reuse their proofs across domains, modify their artifacts, or describe
previous test outcomes as execution of this proposal. Keep all
[security invariants](../../SECURITY-INVARIANTS.md) unchanged.

## Alternatives considered

| Alternative | Decision and reason |
| --- | --- |
| More equal-deposit/delay policy work on the existing relation | Keep existing results, but defer more runs. Policies cannot add merging or private withdrawal change and depend on compatible traffic. |
| Add partial withdrawals but retain one input | Too narrow for varied payments funded by several receipts; leaves split-only ancestry. Include two inputs in the specification. |
| Publicly variable one/two-input and output counts | Simpler padding rules, but reveals shape explicitly. Specify fixed normal slots and review the additional dummy-NF/capacity obligations before implementation. |
| Force every exit to append two output slots | Reject as the only exit path: a filled commitment tree could block withdrawal. Keep a separately visible no-append fallback and enough NF capacity. |
| Adopt Olaf's integrated outer-proof/runtime approach now | Defer. The inspected wallet circuit has the same one-input/full-note-exit restriction. A runtime change alone does not repair the payment relation; batching may become justified by measured costs or contention. |
| Add bounded mutable fees, a mandatory relayer or sponsor | Defer. Retain exact authorization fees and disclose repricing limits; these mechanisms introduce separate authorization or service assumptions. |
| Enforced denominations, a new token or new L1 consensus | Outside this decision. Varied native-KAS payments and permissionless exits remain the target. |

## Consequences and objections

The larger relation requires new setup material and review. Fixed slots cost
extra constraints and public NF updates even when only one note is consumed.
Dummy commitments/nullifiers are not users or balances; terminal accounting and
capacity rules cannot reuse the old count-based interpretation.

The RFC proposes depth-17 NF state with depth-16 commitment/history state so
every positive note can still use a one-note fallback at capacity. Its induction
and dummy-NF derivation need independent scrutiny. A full pool can force a more
revealing exit. Saved exact-fee proofs remain conditional on fee adequacy,
unused NFs, public-data availability and accepted history; no guaranteed
confirmation time or protection from every future fee rate is claimed.

Private change hides an internal remainder, not the native payout or all
relationships. A thin or distinctive history may still permit unique inference.
The new relation must be evaluated using an observer that permits merging and
padding; the old one-deposit-per-note model is no longer valid.

## Reconsideration and outcome

Stop before implementation if the proposed relation can mint, double spend,
invalidate another user's note through dummy inputs, release excess reserve,
strand an otherwise valid claim at capacity, or require operator-only recovery
data. Revisit settlement architecture if a separately authorized qualification
finds unacceptable native limits, proving cost or contention. Revisit the
privacy claim if varied/interleaved public traces remain reconstructable.

Current outcome: the RFC and
[privacy/adversarial review](../../poc/shared-pool/TWO-INPUT-PRIVACY-REVIEW.md)
record the candidate and outstanding obligations. No new result, setup,
implementation or test is produced by this decision. Stage 2 remains open for
general payment privacy.
