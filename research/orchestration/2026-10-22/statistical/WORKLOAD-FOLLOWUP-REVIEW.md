> Imported documentation snapshot. [Canonical status and ownership](../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Review of the proposed matched cash-demand workload follow-up

Date: 2026-10-22, Australia/Sydney. Source/design review on Forge only. No experiments, sampling, scoring, private evaluation reads, source edits or system changes. The active frozen price-baseline test and its eventual verdict remain untouched.

## Decision: defer the proposed 128-master study

**No-go as the next compute lane.** The proposal can estimate an additional synthetic sensitivity, but it does not yet name a still-open decision that either result would change. Its advertised action is already in force.

The workload report proposes q=0 versus eight of 32 receipt-coupled cash-request slots, each replayed with whole and partial policies. It says a harmful result means not pursuing partial withdrawals as a general privacy policy, while a favorable result cannot revive the old rejection (`workload-review/REPORT.md:30,43-47`). However:

- The completed screen already rejected that policy: sparse independent demand failed, and fully receipt-correlated cases worsened amount guessing to 21/42 and 22/36 ([docs/rfc/0016-working-balance-withdrawals.md:134-154](../../../../docs/rfc/0016-working-balance-withdrawals.md); [poc/shared-pool/WORKING-BALANCE-PRIVACY.md:32-59](../../../../poc/shared-pool/WORKING-BALANCE-PRIVACY.md)). Those few development histories do not estimate population effects precisely, but the research decision was explicitly to stop this candidate, not to qualify it from a population estimate.
- ADR-0032 explicitly closes general cashout-policy tuning and retains partial-payment/change mechanics without advancing the rejected policy (`docs/adr/0032-sparse-diagnosis-and-privacy-evaluation.md:28-47,55-60`). It calls for independently justified assumptions, a named public feature and opposing predictions before a new mitigation.
- Eight coupled slots is a declared benchmark, not measured demand prevalence. An eight-slot mixture also changes request owners, amounts and repeated demand. The report correctly calls this regime sensitivity rather than a scalar causal correlation effect (`workload-review/REPORT.md:17,30,43`). Matching payments removes one earlier confound; it does not make this chosen mixture representative.
- The unchanged marginal price prior still exceeds the 20% absolute cap. No amount of replication of this comparison closes that gap or the other adopted gates.

Thus a harmful result reinforces an existing stop decision; a favorable or unresolved result leaves that decision unchanged. The useful new quantity would be the size of sensitivity at this synthetic mixture, not evidence for a new policy, supported user population, or causal field redesign. More precision about a known failure can be educational, but that alone does not justify making it the next substantial experiment.

## Smallest decisive next step

Use **zero new histories and zero observer jobs** for this proposal now. After the current frozen result, require a short decision contract naming a still-open choice with different actions for opposing outcomes. It must explain why the already retained failure evidence cannot settle that choice, and why the selected cash-demand condition matters independently of attack accuracy. If no such branch in the decision exists, archive this as an optional sensitivity study rather than scheduling it.

This does not request another policy sweep, a more favorable mixture, or a change to any adopted threshold.

## Statistical requirements only if a new decision later justifies revival

These are corrections/conditions, not approval of 128 or a new execution contract.

1. **Unit and matching.** One independently seeded master economic history is one unit. Four dependent replays do not turn 128 masters into 512 independent observations. Pair eligible *economic payment obligations*, not replay-specific event IDs. Freeze the same honest-to-honest set, denominators, missing-case handling, clock and urgent-exit obligations across the compared replays. Keep all four replays together for uncertainty; never resample one failed cell or score its absence as protection.
2. **Specify the estimand.** Let A(i,q,p,v) be master i's within-10% amount accuracy for regime q, policy p and view v, using one frozen attack. The policy effect in regime q is B(i,q,v)=A(i,q,partial,v)-A(i,q,whole,v), where a negative value favors partial. The regime-by-policy interaction is H(i,v)=B(i,8,v)-B(i,0,v); positive H means coupling worsens partial relative to whole. H is in [-2,2], not [-1,1]. The direct partial-policy regime effect A(i,8,partial,v)-A(i,0,partial,v) answers a different question. Select the primary contrast before sampling instead of reporting whichever one looks decisive. Matched price-only baselines cancel in H when targets and actual prices are identical; reporting them remains necessary for absolute and prior-advantage context.
3. **Views and horizons.** Preserve separately labeled C+D and eight-pooled inputs; legitimate disclosed records vary with each replay. Inferential claims about both views count in the family. Named-participant or creation/next-payout results must either have their own frozen multiplicity treatment or remain descriptive. A final-horizon result does not validate durable privacy or retained-prefix attacks.
4. **Attack selection.** Either select a single fixed strategy using development evidence or use simultaneous bounds over the entire frozen strategy family. A strongest-policy claim cannot be based on choosing the correct strategy separately for each master using truth. Final descriptive winners must not be silently promoted to confirmatory claims.
5. **Uncertainty.** Use master-level paired differences and an explicitly sized family covering every claimed view, contrast, endpoint and horizon. If using bounded-mean e-values, the current [-1,1] factors cannot be copied onto H: with H=-2 and lambda=.9 the factor 1+lambda*H is negative. Rescale H/2 and its scientific margin together, or derive valid factors for the actual range. Existing threshold 180 covers exactly the current nine tests; it is not transferable by default. Simultaneous intervals are another valid option with the true range and multiplicity. Neither method supplies missing power or permits optional extension. The adopted 20% absolute, five-point advantage, identity, selected-coverage and forced-disclosure requirements remain unchanged; a diagnostic interaction is not a replacement gate.
6. **Sample size is unresolved.** 128 was explicitly an operational proposal, not a power calculation (`workload-review/REPORT.md:44`). Do not ratify it. First freeze the actual question, smallest decision-relevant contrast, inferential family and desired precision/power. Use transparent analytic planning and, only if necessary and separately authorized, public development evidence that will not enter evaluation. Correlation between matched arms may improve precision but cannot be assumed. The current fixed-bet test already warns of weak power for small high-variance excesses; fewer independent units and a wider-range interaction make automatic reuse particularly unjustified.

## Honest runtime and resource budget

No compute is scheduled or recommended here. For comparison only, the proposal's final horizon has 128 masters × 4 replays × 2 views = **1,024 observer jobs**.

- At the parent-provided current throughput of about 10.4 jobs/minute with 12 workers, those jobs alone imply about **98.5 minutes** of observer wall time.
- Using the parent-provided historical 38–74 seconds per public job gives about **10.8–21.0 worker-hours**, or **54–105 minutes** at perfectly occupied 12-worker concurrency. These public-job timings are not validated pooled/coupled/whole-arm forecasts; contention, tail complexity and load imbalance can change them.
- Generation, accounting, controls, sealing, scoring, recount and export are extra. Creation/next-payout diagnostics and named-participant views have no frozen roster, so there is no honest total-job or end-to-end-runtime estimate yet. Prefix observations can be more numerous than simply three fixed horizons.
- Do not overlap another 12-worker workload with the active experiment or use these estimates as abort timers. There is no defensible approved statistical N or complete runtime budget for this proposal today.

## Sources and provenance

Project references above are relative to `/home/luke/projects/kaspa-privacy-shared-pool` on Forge. The proposal reference is relative to `/home/luke/projects/kpi-orchestration/2026-10-22`. Timing inputs came from the parent's task message; this review did not read current run artifacts or independently benchmark them. Existing statistical details are also documented in this lane's [REPORT.md](REPORT.md).

SHA-256 at report creation:

Captured UTC: 2026-10-22T07:29:56.420221+00:00

```text
9b71e1c2a839ba0ad4d3dbfbd53d311c596bf874cb69438474e54e77ffda75eb  /home/luke/projects/kpi-orchestration/2026-10-22/workload-review/REPORT.md
3a321db2d137e4360abe5ab7cc699e6faf0584c47b1ce5a083d21149fd514948  /home/luke/projects/kaspa-privacy-shared-pool/docs/adr/0032-sparse-diagnosis-and-privacy-evaluation.md
4ed4331b623010320618639e55f5a7e290c32ce4eb37156619035383a6df6bc4  /home/luke/projects/kaspa-privacy-shared-pool/docs/rfc/0016-working-balance-withdrawals.md
9f62faaca50dca456a2337cbe8ac9598e3b3c16d1a550748395485a08c93dc2c  /home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/WORKING-BALANCE-PRIVACY.md
```
