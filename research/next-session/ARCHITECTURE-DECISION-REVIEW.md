# Architecture decision review: useful private native-KAS payments

**Recommendation:** measure whether the existing B=2 proving path can approach
the adopted time/hardware envelope before paying for larger aggregate proofs.
In parallel, qualify the small ordinary-budget seam against existing public
cases. Treat these as bounded resource experiments, not privacy or independent-
exit qualification. Source arithmetic for B=2/4/8/12 is useful now; a B=12 proof
is not the default next experiment.

Review inputs are the pushed integration snapshot
`85e39398fd97ff0299e07fad8899cd3f4cc454ac` and separate lifecycle snapshot
`68d7b039f606bd42b39d8d1317c0bfd76c277ae0`, being combined in this continuation
checkout. This note authorizes no implementation, setup, proof or funded job.
The actual tool-safety-rejected S7 public replay/owner CLI/DRAIN workflow remains
parked: no retry, recreation, reassignment or rephrasing is proposed.

## The two decisive limitations

1. **The common-price workload cannot meet the current absolute amount cap.**
   Permitted prior knowledge alone succeeds with probability
   `21103/100025 = 21.09772557%`, above the adopted 20% cap. An observer can ignore
   the entire payment transcript, so hiding more transaction data cannot repair
   that workload's qualification. This is not a cipher/runtime defect or proof
   that every native-KAS use case is impossible. Preserve the failed workload
   and requirements. A different prospective claim/workload or changed target
   needs an explicit decision before a new qualifying evaluation; neither is
   selected here. [Requirement and prior rule](../../docs/rfc/0012-useful-privacy-requirements.md),
   [analytic review](../privacy-target-consistency-2026-10-22.md).
2. **The current fresh-Groth16 singleton-exit route cannot fund its minimum
   claim at rate 500.** Its 147,500-mass proof floor costs 73,750,000 sompi before
   other work, above the supported 60,000,000-sompi claim. Aggregating ordinary
   payments does not remove this independently arriving claimant. Extra owner
   money or a sponsor changes the cost/dependency and is not economic recovery
   of that claim. Do not erase the liability, raise the minimum retrospectively
   or make another user's arrival an exit condition. This is a bound on the
   named route, not a universal Kaspa impossibility result.
   [Value/exit analysis](../value-relation-review-2026-10-22.md),
   [ADR0036](../../docs/adr/0036-v6-native-budget-1600.md),
   [R7/R8](../../docs/rfc/0012-useful-privacy-requirements.md).

The [conditional fee frontier](fee-frontier/README.md) adds a second R8 limit:
if a 10-KAS lifecycle must pay for one unamortized v6 ADMIT verifier and one
fresh direct exit verifier, their reference-rate floor is 29.5M sompi, above
the complete-lifecycle 2% budget of 20M even with a free private transfer.
The same proof-only bound requires principal at least 14.75 KAS before any
overhead. This is route/fee-allocation specific; receiver-only histories,
shared admissions or previously authorized claims need different accounting.
It is not permission to change the supported payment range or allocate fees
to a larger unrelated deposit. At higher rates, percentage comparisons remain
diagnostic; the adopted 1%/2% caps apply to the reference-rate workload, while
independent supported exits remain required at all three scenarios.

## Critical path; what the evidence still does not establish

| Obligation | Current evidence and remaining gate |
| --- | --- |
| Useful privacy, R3–R6/I16 | Genuine proof composition alone does not establish useful privacy. The collector receives source bundles/grouping; current public test fixtures disclose their inputs intentionally. Neither the completed 512-ledger study nor the new receipts qualify financial privacy. Resolve the prior/claim question and native/service observation boundary before another qualification claim. |
| Accepted backing and spendable receipts, R1/R2/I1–I7/I14 | The fresh S7 prefix and pair pass official Full under supplied synthetic UTXOs. Accepted-chain lineage/backing and independently recognized spendable receipts are absent. Decryption/delivery checks and valid supplied-context native bodies are narrower evidence. |
| Independent exit and data survival, R7/I8–I11 | Post-pair owner DRAIN, service-shutdown independence and the complete owner lifecycle are unproven. The retained public PK has an integrity/VK-prefix check; restored proving is not established. The previously rejected owner/replay workflow stays parked; this note proposes no substitute implementation or PK-recovery job. |
| Affordable, timely operation, R8 | Actual selected fees, all per-user lifecycle costs, small-claim exits, CPU-only wallet resources, cold start and real acceptance latency remain unqualified. A native quote, a proof-only timer and an aggregate average each cover only part of this row. |

These are gates for a useful payment system, not reasons to weaken safety.
Safe halting is required but is not a successful exit. Sources:
[invariants](../../SECURITY-INVARIANTS.md),
[requirements](../../docs/rfc/0012-useful-privacy-requirements.md),
[ADR0037](../../docs/adr/0037-offline-continuing-s7-owner-lifecycle.md),
[closed checkpoint](../intensive-2026-10-22/FINAL-CHECKPOINT.md).

## What an aggregate-arity experiment can answer

Let B count independently useful private payments, each represented by one
two-input/two-output authorization. Its 2B output records include recipient and
change outputs; they are not 2B payments. Freeze the intended payment/change
assignment and use the payment amount once as the fee denominator. Self-
transfers, reserve principal and recycled balances cannot enlarge that divisor.

For 10-KAS payments the reference-rate ordinary fee cap is 10,000,000 sompi per
payment. Normalizing the actual B2 mining mass of 196,484 gives a rate-100 quote
of 19,648,400 total, or 9,824,200 per payment. This is a mass-only comparison
with the 10-KAS endpoint, **not an actual qualifying 10-KAS payment result**:
the fresh fixture pays 4 and 5 KAS, and changed values can change storage mass.
The genuine frozen authorizations actually pay 80,000,000 total: 40,000,000 per
payment, which would still be 4% even on hypothetical 10-KAS payments. Lower
mass does not reprice them. A newly priced experiment needs new genuine
authorizations and exact value/output accounting; preserve the existing 80M
result and count all additional attributable costs.
[Actual checkpoint](../intensive-2026-10-22/FINAL-CHECKPOINT.md),
[payment fee contract](../../docs/rfc/0012-useful-privacy-requirements.md).

Larger B can quantify fixed native verification amortization. It does not by
itself reduce the work of verifying each inner proof, fill a batch on demand,
prove privacy, or qualify a lone exit. Do not duplicate the genuine B2 pair as
a larger positive: repeated nullifiers must reject. Every proposed arity needs
its own fixed image/framing, genuine disjoint inner statements, common
anchor/count, complete sequential current-NF/CM/history updates, exact aggregate
fee and checked native successor. History records each two-CM prefix; an
intermediate prefix is not another accepted reserve UTXO. See
[RFC0018](../../docs/rfc/0018-paired-native-settlement-experiment.md) and
[ADR0037](../../docs/adr/0037-offline-continuing-s7-owner-lifecycle.md).

Source/cost arithmetic for all four arities is a cheap decision aid. First use
the smallest B2/B4 comparison that can falsify a proposed operating point.
Proceed to B8/B12 heavy proofs only if the smaller results leave a specific
unanswered cost/resource decision. Do not present a linear extrapolation of
B2's measured 302.926-second GPU proof as an actual B12 measurement or a
universal lower bound. [B2 actual proof results](../../poc/s7-owner-lifecycle/proof/RESULTS.md).

## Minimal next experiment: B2 proving-resource decision

**Question:** can an established implementation/backend setting materially
change the current proving bottleneck, without new arithmetic, a new private
relation, reduced verification or a different claim?

1. Freeze the retained genuine B2 input, selected image/J, SDK/control identity,
   hardware, memory accounting and one justified alternative setting. Review
   supported segment-size modes such as po2=19/18 or an existing multicore
   backend before selecting one; their suitability is not asserted here.
   Keep development mode off and verify the same successful statement.
2. Profile/measure the unchanged B2 outer path first, separating execution,
   proof generation, same-claim compression and verification. Current execution
   is 1.517s for 77,752,334 cycles/170 segments; proof generation is 302.926s and
   compression 4.444s. Fast guest execution is not a fast proof. Do not start a
   larger-arity proving job merely to reproduce this known timing problem.
   [Selected results](../../poc/s7-owner-lifecycle/proof/RESULTS.md).
3. If a wallet inner-proof resource test is required, use a separately named
   standalone public development performance fixture, not owner/recovery work.
   Separate fresh setup from one initial/SPEND proof stage and report both;
   do not hide setup cost inside a warm timer or describe setup peak as proof
   peak. No restored-PK, backup, owner CLI, DRAIN or ledger-replay task is
   proposed. Existing v6 evidence is already 20–22s warm, 201–204s cold and 6.44GiB
   peak; repeating it unchanged supplies no improvement hypothesis.
   [Existing baseline](../../docs/rfc/0012-useful-privacy-requirements.md).

Freeze necessary falsifiers before runtime:

| Metric | Required interpretation |
| --- | --- |
| Correctness | Same checked image/J/claim and genuine proof; no security setting weakened to obtain speed. Keep failed/resource-limited attempts. |
| Wallet hardware | Four physical CPU cores, 16GB host RAM, SSD, CPU-only; aggregate required wallet/prover peak ≤4GiB. Account for every actor/worker and subprocess, including host RAM and separate GPU VRAM; a single worker's VRAM is not aggregate memory. A GPU/service result cannot be reported as CPU-wallet qualification. |
| Warm/cold | Warm local proof p95 ≤10s; cold-ready p95 ≤60s with files already downloaded. Report cache state and setup/download separately. A small diagnostic is not a p95 qualification sample. |
| Payment latency | Authorization→independent recognition ≤60s p95, including batch fill, inner/outer proving, compression, submission and recognition. A proof+compression duration above 60s fails the diagnostic operation screen and is a reason to stop arity scaling; one sample does not establish a p95 distribution. Below 60s is necessary headroom, not an end-to-end pass. |
| Cost | All actual per-payment fees plus attributable proving/service/retry/change costs ≤1% at reference; complete per-user lifecycle ≤2%. Count subsidies explicitly. Recompute 100/200/500 scenarios; supported exits remain required at all three. |

If an external aggregate prover is studied, label its hardware, queueing, price,
availability and observed bundle/grouping separately. It cannot become exit
authority; the unproven independent-exit gate cannot be assumed away by calling
the service optional. Operational run ceilings must be distinct from target
thresholds; a cap failure is not a relation failure or an anonymity success.

## Parallel small experiment: ordinary1600, paired1700

This is useful bounded economics work, not the main architecture answer.
Derive a new charge bound for the emitted S7 ordinary branch; the old fixed-v6
bound does not transfer. Exercise existing genuine public bootstrap/ADMIT/SPEND
cases and typed underbudget/fee/mass controls with their actual supplied UTXOs,
without building a public ledger replayer or owner workflow. Preserve scripts,
authorizations, signatures, fees and IDs; record changed budgets/full hashes.

At 1700, actual bootstrap/ADMIT compute masses 200,511/201,631 imply rate 200
quotes 40,102,200/40,326,200, above their 40M actual fees. A 100-budget reduction
would remove 10,000 compute mass, so it could close these small rate-200 gaps if
the complete new source/VM/mass checks agree. It cannot lower the actual 40M fee,
repair the 73.75M singleton floor at 500 or qualify unexecuted DRAIN. Keep paired
1700 unless independently requalified; absent DRAIN coverage must stay explicit
before any all-modes default claim.
[Initial native evidence](../intensive-2026-10-22/INITIAL-FOUR-AND-NATIVE-PREFIX.md),
[source-only provisional bound](../intensive-2026-10-22/S7-PROVISIONAL-FEE-BOUND.md).

## Decision after these measurements

Continue aggregation only for an explicitly identified resource benefit with
unchanged correctness and honest per-user accounting. If the measured route
still misses the necessary time/memory gates, record that configuration's
failure and compare established proof/backend architectures before scaling B.
An accepted-settlement/cheap-terminal-claim design is a separate architectural
research choice: it relocates authorization cost and needs new state, liability,
privacy and liveness arguments; it does not erase an unaccepted singleton's
cost. For example, the pinned [Aztec Outbox](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/l1-contracts/src/core/messagebridge/Outbox.sol#L95-L156)
accepts roots only from its rollup, then checks recipient/chain, membership and
nullification at message consumption. That is not a free route for a KAS note
without earlier authenticated settlement. The separate
[primary-source alternatives review](native-kas-singleton-fee-alternatives-2026-10-22.md)
records the cost/dependency distinctions. No such mechanism or requirements
change is adopted by this note.

Regardless of aggregate success, the existing prior information limit and
independent-exit/economic gap remain. No new token, admin withdrawal path,
funding, broadcast, production-security claim or privacy pass follows.
