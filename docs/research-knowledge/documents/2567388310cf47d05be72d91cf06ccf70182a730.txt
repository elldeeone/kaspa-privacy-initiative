# Privacy target consistency review — 2026-10-22

**Finding:** the declared common-price workload cannot satisfy the adopted 20%
absolute amount-guessing cap in population, even if the payment transcript hides
everything. The permitted price prior alone succeeds with probability
`21103/100025 = 21.09772557%`. This is a workload/requirement information limit,
not evidence that a different payout policy or runtime would repair privacy.

The requirements already anticipate this outcome. This review proposes clearer
qualification bookkeeping; it changes no adopted target, failed result, observer,
workload, protocol or execution authorization.

## Scope and evidence

Reviewed integration source `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`:

- [RFC-0012](../docs/rfc/0012-useful-privacy-requirements.md), especially its
  measurement contract, amount gate, public-prior rule and forced-disclosure gate.
- [ADR-0032](../docs/adr/0032-sparse-diagnosis-and-privacy-evaluation.md),
  [ADR-0033](../docs/adr/0033-price-baseline-evaluation.md), and the
  [prospective contract](../poc/shared-pool/PRICE-LEAKAGE-SPEC.md).
- The [completed public report](../poc/shared-pool/PRICE-LEAKAGE.md), public
  aggregate summary and interpretation-review receipt, and source definitions in
  [the model](../poc/shared-pool/working_balance_model.py) and
  [the scorer](../poc/shared-pool/price_leakage_score.py).

No evaluation seeds, raw truth, private predictions, honest target masks or
truth-joined records were accessed. No histories, observers, new inference or
recounts were run. The only calculation executed was standard-library rational
arithmetic for the formulas and illustrative weighting example below.

## 1. The absolute cap has an unavoidable prior floor

Let `X` be an undisclosed payment amount, `g(a,x)` the adopted within-10% success
indicator, and `V0 = max_a E[g(a,X)]` the best permitted price-only success rate.
An observer receiving any transcript `O` can always ignore it. Therefore

```text
V(O) = sup_f E[g(f(O),X)] >= V0.
```

The unchanged model uses 60% uniform mass on 10, 20, 25, 40 and 50 tKAS,
plus 40% uniform mass on the 4,001 cent amounts from 10 through 50. This is the
declared ideal-draw model, not empirical purchasing behavior. Honest amount
sampling is separate from the activity/capital/cash schedules; the scorer's
honest-to-honest eligibility is based on endpoints, not amount correctness.

For the already declared 45-tKAS price action, the tolerance accepts amounts in
`[450/11, 50]` tKAS. It covers the 50-tKAS invoice mode and 910 grid values,
40.91 through 50.00 inclusive. Hence

```text
P(success at 45) = 3/25 + (2/5)*(910/4001)
                 = 21103/100025
                 = 21.0977255686% > 20%.
```

This lower bound alone proves infeasibility; optimality is not needed. The
declared marginal optimum also follows directly: the five invoice modes have
disjoint successful-guess intervals `[.9*x,1.1*x]`, so a guess covers at most one
invoice mode. A tolerance window covers at most 910 cent-grid values in the
bounded support, attained at 45. No public transaction fact is needed.

More generally, absolute cap `c` and prior-advantage cap `delta` allow an optimal
observer's accuracy only in

```text
[V0, min(c, V0 + delta)].
```

This interval is empty when `V0 > c`. Here the contradiction is between a claim
of qualification for this workload and the adopted cap. RFC-0012 itself is
consistent as a rejection rule: it explicitly says to retain prior-predictable
cases and record the information limit. The workload remains unqualified.

Finite samples may fluctuate below their population prior. That cannot remove
the analytic floor; a chance favorable sample is not a mechanism that makes the
population target attainable. No post-result filtering, distribution replacement
or threshold change follows from this observation.

## 2. Different metrics need different baselines

For exact equality the modal price probabilities are

```text
3/25 + 2/(5*4001) = 12013/100025 = 12.0099975006%.
```

All five invoice modes tie; the specified 10-tKAS baseline selects the smallest.
The approximate-optimal 45-tKAS action has only the irregular-grid exact mass,
`2/(5*4001)`, about 0.0100%. Using it as the exact baseline would greatly
understate public price knowledge. The completed report correctly uses separate
baselines and keeps exact endpoints descriptive.

An exact guess being correct does not establish a logically forced disclosure.
Forced disclosure requires that every world consistent with the declared
observations and assumptions agrees on the protected fact. A price guess can be
right in one world while alternatives remain. Conversely, the adopted zero
forced-disclosure target is not a statistical promise of zero exact guesses.

The selective relationship-precision gate is expressly about relationships.
It must not silently become a selective amount-precision threshold. Amount
selectivity can be reported as a diagnostic; any additional quantitative gate
needs an explicit prospective requirements decision. A full-coverage average
alone does not bound accuracy on a small selected subset: even an average of
20% is mathematically compatible with perfect success on one fifth of targets
and zero elsewhere. This is a limitation of that metric, not a finding about
these ledgers.

## 3. A fixed heuristic's gain does not bound available information

For nested information `O` and `(O,R)`, every decision available from `O` remains
available with `R`. Optimal success is therefore monotone:

```text
V(O,R) >= V(O) >= V0.
```

This does not require a particular heuristic to improve. As a generic
counterexample, a fair binary secret can be revealed completely while a fixed
predictor deliberately chooses its opposite. That predictor has zero accuracy;
the best informed predictor has accuracy one. A poor selected predictor cannot
upper-bound the information channel.

Likewise, counting new correct guesses without losses does not identify
incremental information. If an alternative guess `A` is independent of `X`,
its expected success is `E[q(A)] <= V0`, where `q(a)=E[g(a,X)]`, even though it
may hit targets missed by the best fixed action. The paired net estimand is
appropriate for the narrow question actually frozen.

The completed report correctly states that the selected heuristic's mean
approximate accuracies were 13.53% for C+D and 14.47% for pooled records,
versus a 20.88% equal-ledger price baseline. It does not claim negative
transaction information or zero leakage. All three below-five-point tests
crossed; the positive tests did not. This supports the frozen heuristic's mean
gain being below five points under the declared model, rather than qualifying
the protocol, all possible observers, selective exposure or the absolute cap.

The fixed strategy family includes the price action itself. Its strongest
approximate predictor cannot be less successful than that included action,
whatever the selected `split_tail` predictor does. A below-five result for one
heuristic does not make the strongest-evaluated absolute gate pass.

## 4. Keep the population and information boundary explicit

For ledger `i`, let `N_i` be its eligible targets and `A_i` its accuracy. The two
reported rates estimate different populations:

```text
Equal-ledger:   E[A_i]
Pooled-target: E[N_i*A_i] / E[N_i]
Difference:    Cov(N_i,A_i) / E[N_i].
```

The identity is for the population estimands; corresponding empirical formulas
hold using empirical averages/covariance. Equal-ledger weighting samples a
ledger first, then a target uniformly within it. Pooling weights ledgers by
eligible target count. For illustration, perfect accuracy on a one-target
ledger and zero on a nine-target ledger yields 50% equal-ledger accuracy and
10% pooled accuracy. Cluster dependence remains even when the desired estimand
is pooled; target weighting never justifies independent-target uncertainty.

The frozen experiment chose equal-ledger differences and the completed report
labels pooled counts separately. This is consistent, not an arithmetic defect.
The observed 20.88% and 20.94% baseline rates must not be swapped to improve an
inferential comparison. The analytic prior floor is about the declared amount
model, not either sample rounding.

The nine fixed e-tests also have the stated narrow coverage. Under independent
ledgers and a fixed heuristic, each nonnegative wealth product has expectation
at most one under its null. The fixed mixture retains this property, and the
union bound gives `9/180 = .05` without requiring independent contrasts. The
reverse null is mean gain at least five points; rejecting it supports gain below
five points. These tests are not the full set of one-sided rate/advantage upper
bounds required for qualification in RFC-0012. This completed experiment expressly
does not attempt that qualification, so there is no procedural contradiction.

C+D includes an externally supplied initial-funding owner directory; pooled
also includes eight colluders' permitted records. Neither comparison identifies
one transaction field's effect or proves that the same observation exists in
native bytes. Marginal price optimality does not imply conditional optimality
after permitted disclosures, transcript selection or other known covariates.
Later observations must retain prior observations and keep the same historical
target; a public final zero balance is not a historical private-balance result.

## Reviewable clarifications, with all adopted gates preserved

1. **Make the information-limit status explicit.** For every proposed
   qualification workload, record the protected target, gain function, permitted
   prior inputs and analytically established prior floor before execution. If
   that floor exceeds an absolute cap, mark the workload unqualified under the
   current requirements. Incremental-information research can still answer its
   narrower question, but it cannot close qualification. This operationalizes
   RFC-0012's existing public-prior rule without changing a threshold.
2. **Name the qualification population.** A prospective qualification manifest
   should state whether each absolute and advantage gate concerns an average
   ledger/session or an average eligible payment, and specify the clustered
   uncertainty method. Preserve equal-ledger inference for the completed study;
   do not reinterpret its published counts.
3. **List which gates an evidence artifact addresses.** Separate approximate
   full-coverage success, exact guessing, logically forced disclosure,
   relationship selectivity and any amount-selectivity diagnostic. Also name
   C+D versus C, pooled records and native/service coverage. This prevents a
   below-five heuristic finding from being promoted into overall privacy.

No new requirement adoption is proposed by implication. Whether the product
must resist high public price predictability is an owner-level use-case decision;
any future revision must explicitly preserve this workload, prior floor and
failed outcomes as historical evidence. No protocol rewrite, privacy claim or
new experiment is released by this review.
