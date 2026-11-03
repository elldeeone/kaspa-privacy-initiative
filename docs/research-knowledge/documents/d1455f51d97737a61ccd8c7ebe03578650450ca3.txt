# RFC-0017: Separate price priors from transaction information

**Status:** Evaluated — fixed attack did not outperform price guessing; privacy unqualified.

**Date:** 2026-10-22 Australia/Sydney.

## Question and evidence

The [sparse diagnosis](../../poc/shared-pool/WORKING-BALANCE-SPARSE-DIAGNOSIS.md)
found successful numerical guesses without matching complete payment flows.
It did not determine whether the guesses gain incremental information from the
transcript. The common-price prior already exceeds the unchanged absolute
privacy target. Neither equal prices nor false guessed supports remove old hits.

Compare the unchanged `split_tail` heuristic with optimal marginal price guesses
on 512 fresh independent sparse partial-withdrawal ledgers. Report public
transcript and added colluder-record contrasts separately. Keep the old failed
screen, activity/cash model, immediate exits and complete drainage intact.

## Alternatives and assumptions

Native proof/transaction regeneration tests a different, more expensive
question; the model already exposes the arithmetic fields this inference test
uses. Individual-field deletion risks leaving deterministic substitutes such
as reserve differences and bridge amounts. A donor permutation needs an
additional exchangeability model. Neither is selected here. Broader attacks,
protocol privacy, real behavior and empirical cash demand remain open.

The [source review](../../research/shielded-kas-price-baseline-test-2026-10-22.md)
documents marginal Bayes actions, independent-ledger scoring and finite-sample
betting evidence. The [frozen contract](../../poc/shared-pool/PRICE-LEAKAGE-SPEC.md)
controls exact sampling, attacks, nine tests, thresholds, disclosures and stop
rules. Passing implementation checks is not cryptographic or privacy proof.

## Decision and open questions

[ADR-0033](../adr/0033-price-baseline-evaluation.md) selects this bounded
evaluation method without changing settlement, backing, notes or exit authority.
Do public observations add material value-prediction success beyond the modeled
price distribution? What additional effect do the permitted participant records
have on this fixed heuristic? Any five-point result is scoped to this workload
and attack; it cannot qualify the absolute target or decide a runtime alone.

## Completed outcome

The [frozen experiment](../../poc/shared-pool/PRICE-LEAKAGE.md) completed all
512 ledgers and 1,024 observer jobs, with 18,192 eligible payments and both
independent recounts passing. Equal-ledger approximate accuracy was 20.88% for
the price baseline, 13.53% for public-plus-directory `split_tail`, and 14.47%
with pooled records. All three comparisons support mean advantage below five
points; none establishes positive advantage under the nine frozen tests.

This closes the bounded evaluation, not the general information question.
The next direction is better attack calibration and native observation mapping,
including selective exposure. No next experiment is released here. Preserve
the absolute target, old policy rejection and direct-L1 mechanics; no runtime
or payout-policy change follows from these scores.
