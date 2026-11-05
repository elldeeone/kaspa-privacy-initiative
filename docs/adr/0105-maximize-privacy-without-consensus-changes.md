# ADR-0105: Maximize native-KAS privacy without consensus changes

**Status:** Accepted owner constraint and research direction; no production design selected.
**Date:** 5 November 2026.

**Subsequent owner direction:** [ADR-0106](0106-contribute-unless-a-privacy-advantage-is-demonstrated.md)
supersedes this document's direct-settlement-first work priority. Contribute to
the shared KPI direction by default; alternatives need a concrete comparative
privacy case. The no-consensus-change constraint and safety requirements remain.

## Owner direction

The owner explicitly requires the highest available privacy **without any
consensus changes**. Optimize the complete native-KAS payment lifecycle within
existing rules. A new native transaction/header type or verifier precompile is
not an acceptable implementation dependency.

This supersedes the forward plan in ADR-0100 and the consensus-native direction
in ADR-0101/0103/0104. Their completed specifications, complete Orchard verifier,
portable artifacts and negative findings remain preserved as research. They
are not current-network features or the next implementation task. RFC-0004 stays
open; its consensus-design sections are retained background, outside active scope.

## Active direction

1. Start from the existing wallet-held confidential-claim/direct-inline-ZK
   covenant reference and its executed testnet lessons. Native KAS remains the
   backing; no issued asset, operator withdrawal key or custodian is introduced.
   Use only existing verification interfaces. Full native Orchard/Halo2
   verification cannot be assumed available through the current Groth16/RISC0
   tags; a wrapper is a distinct unqualified engineering candidate.
2. Compare complete designs using the [current-rules source review](../../research/current-rules-privacy-options-2026-11-05.md):
   confidential on-domain payments, metadata-resistant construction/scanning/fee
   payment, cooperative unlinking of transparent boundaries, and channels where
   justified. The first candidate to measure is the minimum-trust covenant
   reference with avoidable metadata links removed. A mixing/cooperative exit
   layer is a separate hypothesis, not an assumed cure.
3. Preserve wallet spending authority, independent exit eligibility, integer
   native backing/accounting and all SECURITY-INVARIANTS.md. No forced retention
   of principal, protocol withdrawal wait, privileged rescue, mandatory service,
   new token or consensus extension. Optional cooperative privacy must have an
   independently usable fallback, whose weaker privacy is reported explicitly.
4. Measure the entire deposit/payment/re-spend/withdrawal lifecycle against
   chain-only, known-owner/counterparty and service/network views separately.
   Do not remove truthful auxiliary information or full-drainage cases to make
   the result look private. Compare sender, receiver, amount and graph leakage,
   cost, anonymity-set availability and exit/recovery reliability separately.

## Meaning of highest privacy

There is no demonstrated globally strongest design across all workloads,
observers, liquidity, latency, cost and trust models. Produce a measured frontier
of feasible designs under the owner's constraints. Rank a candidate above another
only for the tested observer/workload, disclose its tradeoffs, and report failures.
More peers, unknown output ownership, network cover or voluntary batching are
assumptions, not free protocol guarantees or evidence that peers exist.

Ordinary outputs still publish amounts/scripts. Hiding internal payments and
reducing links to those outputs are legitimate current-rule research targets.
No algorithm can erase a published value or defeat an equation whose inputs
the admitted observer actually knows. That is a bound on a particular claim,
not a reason to abandon improving practical privacy within current rules.

The old known-owner/full-drainage failures and 21.10% prior floor versus the
retained 20% ceiling remain unqualified evidence. This direction changes the
allowed architecture, not historical scores, owner knowledge, thresholds or
security invariants. No privacy qualification is adopted by this ADR.

## Next decisive work and stop conditions

Use the [comparative study plan](../../research/current-rules-privacy-study-2026-11-05.md).
Freeze observer knowledge and workload before a fresh comparison; reuse corrected
role-conditioned scoring and coupled truth checks. Improve useful payment privacy,
not just the number of opaque commitment assignments. State actual-chain,
synthetic and cryptographic evidence separately.

Reject a candidate if its benefit depends on custody, a new consensus rule,
hidden participant/owner knowledge, forced waiting/remaining principal, an
unqualified proof/exit path, or accounting/authentication bypass. A failed
privacy result remains a failure even if proofs pass. No additional verifier
microbenchmark is justified without a specific lifecycle dependency.

This decision does not resume paused MPC, change an invariant, deploy to mainnet,
use real funds, fund/broadcast a trial or authorize new provider infrastructure.
