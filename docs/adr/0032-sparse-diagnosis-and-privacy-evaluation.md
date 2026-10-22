# ADR-0032: Diagnose sparse guesses before selecting another mitigation

**Status:** Accepted research direction; no protocol or privacy target changed.

**Date:** 2026-10-22 Australia/Sydney.

## Context

The partial-withdrawal screen failed. Its sparse pooled final attack guessed
11/37 amounts within ten percent, against 9/37 for its price prior. Equal
11/37 whole/partial totals left unclear whether partial tails reconstructed the
same actual payments. The owner authorized investigating and documenting the
mechanism through a clear next-direction decision.

The [completed diagnosis](../../poc/shared-pool/WORKING-BALANCE-SPARSE-DIAGNOSIS.md)
reproduces every old final sparse-case prediction before reading truth. Of eleven successful
partial-pooled guesses, eight have unrelated selected payout supports and three
touch actual ancestry without a closed value path. Both exact matches are
unrelated-support hits. None of the 1,074 selected constructions matches the
actual payment input set or closes the actual receipt/change flows. All scores
and the original rejection remain unchanged. No absence-of-leakage conclusion
follows from a bounded heuristic's wrong explanations.

The prior comparison contains six gains and four losses; the equal whole/partial
totals contain eight gains, eight losses and only three shared hits. This count
does not itself identify a transaction field whose redesign would fix privacy.

## Decision

Retain the direct-L1 research platform, native backing, private payment/change,
recovery and independent exits. Keep persistent private spending as an
unqualified hypothesis. Close general cashout-policy tuning as the immediate
work item; the rejected partial policy and H18 schedule do not advance.

The next bounded research task is an **evaluation-design and public-information
audit**, using existing genuine-native usage evidence as development material:

1. Separate prior predictability, incremental transaction information, exact
   matching and logically forced disclosure. Preserve the adopted absolute and
   prior-advantage caps. State the common-price workload's information limit.
2. Justify cash-demand and activity assumptions independently of favorable
   scores. Keep sparse activity, collusion, all tails and urgent exits visible.
3. Identify a named public feature and opposing predictions before testing a
   new mitigation. Any later held-out test freezes attacks, workloads, horizons,
   sample/power rules and costs before fresh data. A structural change needs
   causal evidence or robust incremental inference and an invariant-preserving
   alternative; switching runtimes or batching is not selected by this score.

No new histories, native integration, wallet command, proof relation, setup,
operator role, trusted rescue path or consensus change is adopted here. A later
architecture change requires its own RFC/ADR and synchronized threat model.

## Consequences and limits

The original screen remains failed and its native continuation stopped.
Milestone 3 and the broader privacy qualification gate remain open. The known
price prior's expected 21.10% success exceeds the unchanged 20% absolute cap;
the workload remains unqualified, without excluding guessable cases or silently
changing a target. Receipt-correlated stress behavior is a model, not empirical
user behavior. Current fee/resource and recovery/liveness gaps remain.

The [source review](../../research/shielded-kas-sparse-withdrawal-design-2026-10-22.md)
records established-design comparisons and current source identities. This
decision protects all security invariants and changes no trust assumption.
