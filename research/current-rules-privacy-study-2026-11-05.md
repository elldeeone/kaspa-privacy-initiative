# Next privacy comparison under unchanged Kaspa rules

**Status:** prospective comparative study design; not executed or qualified.
**Date:** 5 November 2026.
**Authority:** [ADR-0105](../docs/adr/0105-maximize-privacy-without-consensus-changes.md).
**Sources:** [current-rule options](current-rules-privacy-options-2026-11-05.md).

**Subsequent work-selection rule:** [ADR-0106](../docs/adr/0106-contribute-unless-a-privacy-advantage-is-demonstrated.md)
makes contribution to the shared upstream effort the default. This prospective
comparison remains reference material; do not start it as an open-ended new
programme. A specific challenger needs a privacy hypothesis, fixed baseline,
bounded test and stop rule before it earns further work.

## Question and starting evidence

Which feasible, noncustodial current-rule design best protects sender,
recipient, amount and payment relationships over a complete native-KAS lifecycle,
while keeping independent exits and reporting cost/recovery limits?

The starting implementation family is the executed wallet-local/direct-inline-ZK
reference, not the synthetic native-v2 prototype. Its
[corrected actual-chain result](full-drainage-executed-lifecycle-2026-11-01/CORRECTION.md)
retains two gross histories while disclosing some payment facts. Its older
[private-change result](wallet-local-private-change-2026-11-01/RESULT.md)
loses target amount protection when the remainder later exits. The
[common-reserve mitigation](full-drainage-executed-lifecycle-2026-11-01/NEXT-PRIVACY-RESULT.md)
removed a funding-origin link without improving direct-payment inference.
Do not present any of these as a new candidate privacy pass.

## Candidate screen before building

| Candidate | Falsifiable benefit | Required failure/tradeoff check |
| --- | --- | --- |
| Existing direct-inline-ZK baseline | Reproduce its useful lifecycle and known leaks. | Corrected truth-retaining observer; complete costs; same known identities. |
| Baseline with avoidable metadata links removed | Reduce identifying fee ancestry, key reuse, selected-note queries and role/size/timing signals. | Give the observer all remaining public fields and legitimate counterparty facts; removing one leak must not be scored as whole-payment privacy. |
| Above plus opt-in cooperative exits / unlinkable output registration | Reduce input-to-output or withdrawal-request-to-output attribution when a real cohort exists. | Coordinator transcript/collusion, unequal amounts/change, low liquidity, aborts, censorship, and users independently exiting immediately. Equal outputs do not hide values. No wait or cohort may become an exit requirement. |
| Channels/state channels | Reduce public per-payment records for repeated payments. | Counterparty/router knowledge, open/close balance inference, forced-close privacy, liquidity, timelocks and enforceability under existing Kaspa. Reject if it violates the owner's independent-exit constraints. |
| Based-app execution of the same private state | Potential shared-state batching/throughput benefit. | Same boundary analysis plus operator loss, data availability, settlement latency and actual complete proof cost. Runtime choice alone is no privacy gain. |

Do not invent a custom blind-signature protocol, declare a Bitcoin protocol a
Kaspa port, or port full Orchard/Halo2 as if its verifier already exists on L1.
Reuse reviewed protocols only after checking exact transaction/proof bindings,
fund conservation, fee semantics, covenant output authorization and failure paths.

## Observers and controls to freeze

1. **Public chain:** complete actual transaction/DAG history, deposits/outputs,
   values/scripts, covenant ancestry, roots/anchors, nullifiers, payload sizes,
   native fee inputs, timestamps/order and publicly documented wallet policy.
2. **Known owners/counterparties:** the same history plus truthful payout-owner
   mappings and specified receipts/contact edges. Include full withdrawal of all
   participating user principal, isolated activity and sparse/linked workloads.
3. **Services/network:** coordinator/relayer/prover/query transcripts and the
   declared network observation capabilities. Do not equate Tor use or absent
   logging with resistance to timing correlation or a global observer.

Use matched baseline/candidate workloads and independently sealed hidden truth.
No private truth enters prediction; every complete candidate history must retain
the execution truth. Hidden-label renaming must leave financial scores unchanged.
Anonymity sets contain plausible independently controlled honest participants,
not extra transaction positions, self-churn or assumed cover traffic.

The exact workload, availability/collusion model, amount grid/prior, sample size,
statistical comparison, uncertainty and stop rule must be frozen before running
a new candidate. They are not selected by this high-level plan. Preserve the
existing adopted absolute privacy/cost requirements and report them separately;
do not replace them with a favorable relative score. In particular, the retained
common-price population's 21.10% prior floor cannot qualify its 20% cap.

## Evidence required before a claim

- Report financial-fact reconstruction/guessing under each observer and prior,
  before cashout, after partial exits, later change withdrawal and full drainage.
  Include metadata ablations and malicious/cooperating-party controls.
- Report complete useful lifecycle costs, preparation/proving/confirmation,
  liquidity/cohort dependence, abort/retry costs and fallback privacy. No
  estimate or synthetic fee field counts as a paid testnet lifecycle result.
- Verify deposit -> recipient-spendable private transfer -> re-spend -> duplicate
  rejection -> authorized payout; then remove default services and recover/exit
  with wallet-held secrets and independently available public data/software.
- Confirm exact released/current-rule native validation before claiming on-chain
  compatibility. A source-backed design or offline screen is not a successful
  rehearsal or a funded trial. Do not start one automatically from this plan.

Select the smallest candidate that survives the screen, or report no candidate
meets the retained requirement. This task changes active research direction and
records the comparison; it executes no new workload, protocol or network trial.
