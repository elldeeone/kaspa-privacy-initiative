# ADR-0039: Test exit liabilities and native claim costs

**Status:** Accepted for bounded offline research only. No production architecture
or requirement change. **Date:** 2026-10-23 Australia/Sydney. DO_NOT_FUND.

## Decision and purpose

Continue from `8d7d719` on the fee and independent-exit blockers in
[RFC-0019](../rfc/0019-fees-and-independent-exit-obligations.md). A successful
native claim after accepted authorization is different from a unilateral exit
of an unconsumed private note. We need executable evidence of that boundary,
correct unpaid-liability accounting and the actual native fee contract before
expanding proofs or choosing a future note format.

Select two parallel workstreams:

1. Implement the RFC's finite abstract liability/service-loss model. Freeze its
   exact state/action schema and initial cases before execution; use exhaustive
   search and independent value/authority checks. Retain expected stranded-user
   traces and deliberately unsafe mutation counterexamples. Ideal proof/hash/
   signature oracles are assumptions, not cryptographic or native validation.
2. Prepare a separately named native permission-claim diagnostic using the
   existing vProgs `f9b84a863a7c7c20586a9cf947550475e894f72e` emitter/delegate
   and official Kaspa validator. Pin the emitter/native dependency boundary,
   preserve all source adaptations and freeze positive/negative inputs before
   runtime. Use public synthetic UTXOs only. Measure real mass/fees and whether
   the exact upstream payout/change constraints permit fees from claim principal.

Source inspection and comparison are documented in the
[research directory](../../research/next-session/exit-fee/). Existing current
Toccata and mature protocol research is reused. Any suspected missing state or
path binding is a review concern, not an upstream exploit or permission to
mutate live infrastructure. No external report/message is authorized here.

## Boundaries

All security invariants, numerical fee/privacy targets and the historical failed
results remain unchanged. No new privacy token, mainnet, real funds, admin exit,
funding, broadcast, new paid compute or silent cryptographic construction.
Existing immutable notes/covenants retain their old format. A hypothetical
revealing exit must not expose the credential that authorizes a competing
private spend; no such format is selected or implemented by this ADR.

The old tool-rejected S7 owner/replay/DRAIN and restored-proving workflow remains
parked. Neither workstream recreates it. No unchanged GPU proof is needed to
measure native storage/compute fees or explore finite exit states. Use available
Forge CPU cores for independent source/build/model work; operational resource
limits must not be confused with product acceptance thresholds. Incomplete or
resource-limited exploration remains incomplete evidence.

Before recording results, conduct an independent adversarial pass for inflation,
double release, missing liabilities, incorrect payouts, stale/cross-lane state,
data withholding, service loss, reorg assumptions and hidden sponsorship. Report
what became feasible and what remains unimplemented separately. These experiments
cannot establish the complete deposit-to-confirmed-private-payment lifecycle.
