# P13 contribution draft: withdrawal correlation and observer-validation controls

**Date:** 5 November 2026. **Status:** local draft, not posted or submitted upstream.
**Target:** [P13: practical privacy leakage](https://github.com/olafweller/kaspa-privacy-initiative/issues/13).
**Working rule:** [ADR-0106](../docs/adr/0106-contribute-unless-a-privacy-advantage-is-demonstrated.md).

## Proposed contribution

Add the following retained findings and test requirements to KPI's current
private-payment investigation. They apply to direct covenant and Based App
settlement. They propose no competing runtime or production architecture and
make no claim to have achieved better privacy than the shared upstream design.

The reviewed upstream baseline is
`7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1`. Its
[RFC-0001](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/docs/rfc/0001-state-architecture.md)
already distinguishes internal confidentiality from public deposit/withdrawal
boundaries. These results sharpen the tests for that existing scope.

## 6 November local follow-up

The [complete offline batching comparison](batched-payment-costs-2026-11-06/RESULT.md)
now uses genuine private receiving/re-spending, full wallet relations, complete
compressed receipts and native Full validation. Matched named/common-set batches
have identical native fees; the latter retains six payout-key assignments while
still revealing identified withdrawal amounts. This is narrow optional exit
work to contribute to the shared path. It is not an overall privacy win over an
executed current upstream implementation. Fee/prover models, cohort/state-race
limits and recovery controls are retained separately. This draft remains local;
no comment, message or pull request has been posted.

Upstream `main` was read again through GitHub on 6 November and still resolves to
`7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1`; the baseline above is current for that
ref. This does not turn our matched wallet-path experiment into an execution of
all upstream deployment/runtime behavior.

## Retained findings

| Finding | Evidence and exact limit |
| --- | --- |
| Full transparent withdrawal can disclose earlier payments despite valid proofs. | The [corrected actual-chain assessment][live] retains two complete gross histories under its finite known-owner/contact model. B's payment to M is 20,000,000 sompi in both; A's is 30,000,000 or 40,000,000. This is conditional leakage, not universal reconstruction or an assumption that every observer knows output owners. |
| Interim private change is not durable protection if later withdrawal reintroduces the equation. | The [offline private-change comparison][change] shows interim amount ambiguity followed by reconstruction after the remainder exits. It uses genuine wallet proofs but synthetic native boundaries; it is not a new testnet result or atomic exit-with-change. |
| Removing exact funding ancestry is a narrower benefit than improving payment privacy. | The [common-reserve counterfactual][reserve] changed each payout's funding-origin candidates from one to two, while complete gross histories remained two. That proposed mitigation was rejected as a direct-payment fix; it was not implemented on-chain. |
| A unique prediction can be wrong because the observer excluded the executed history. | The [live correction][live] retains the original wrong-contact-edge result as a negative control and checks coupled execution-truth retention. Counting a single wrong history as successful reconstruction would misstate the privacy result. |

## Proposed minimum leakage controls

1. Use separate chain-only, known-owner/counterparty and infrastructure/network
   views. Declare acquisition of owner mappings/contact facts; do not infer IP
   resistance from unused logs, relays or local service tokens.
2. Score actual financial facts through payment, re-spend, partial withdrawal,
   later change withdrawal and full drainage. Use the same truth-preserving
   observer against baseline and candidate; keep commitment-position uncertainty
   separate from payment amount/relationship uncertainty.
3. Require the prediction set to retain one complete executed history before
   interpreting its size. Rename hidden labels and require unchanged scores.
   Include truthful and deliberately contradictory contact-edge controls.
4. Run the simple public-information control: A deposits 100, withdraws 59,
   pays known fee 1, has no remaining balance or other flows, and makes one
   unknown outgoing payment. That payment is 40. It tests honest handling of
   admitted information; no internal witness encryption can remove the equation.
5. Compare to a specified prior-only predictor as well as the retained absolute
   qualification gates. The [prior review][prior] derives 21.0977% success for
   one retained population against its unchanged 20% ceiling. Keep that case
   unqualified; do not substitute a relative-improvement score for its target.
6. Report payment privacy, full paid lifecycle cost and independent recovery as
   separate results. Valid proofs and completed payouts do not imply anonymity;
   a new privacy mechanism must disclose liquidity, delay, collusion and fallback
   assumptions without silently changing the independent-exit requirement.

## Review and reproducibility limits

The source links below pin already-public reports at fork commit `75121f21`.
Public reports summarize retained observations; private wallet material, execution
truth and full owner-specific captures stay excluded. Reproducing the actual
run's complete scoring requires its retained private evidence. Do not represent
the published summary as a self-contained independent replay or propose copying
owner secrets/captures into the upstream repository.

The arithmetic control above is directly checkable from its declared public
inputs. It is not a new protocol experiment. No new workload, proof, network
request to a node, trial, infrastructure or privacy qualification was executed
for this contribution draft. An upstream patch should carry only the narrow
agreed evidence/control scope, rather than bulk-merge this research branch.

[live]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/75121f218dd9f36a9e31c0d911560660849642f0/research/full-drainage-executed-lifecycle-2026-11-01/CORRECTION.md
[change]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/75121f218dd9f36a9e31c0d911560660849642f0/research/wallet-local-private-change-2026-11-01/RESULT.md
[reserve]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/75121f218dd9f36a9e31c0d911560660849642f0/research/full-drainage-executed-lifecycle-2026-11-01/NEXT-PRIVACY-RESULT.md
[prior]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/75121f218dd9f36a9e31c0d911560660849642f0/research/rfc0004-privacy-feasibility-review-2026-11-03.md
