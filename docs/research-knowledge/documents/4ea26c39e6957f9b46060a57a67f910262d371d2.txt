# Separate price predictability from transaction information

Reviewed 2026-10-22 (Australia/Sydney), against research source
`9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`. This is a source and evaluation-design
note supporting [ADR-0032](../docs/adr/0032-sparse-diagnosis-and-privacy-evaluation.md).
It selects no mitigation, changes no privacy threshold or protocol rule, and
uses no private truth, seeds, generated histories or funded activity.

**Selected first test:** 512 fresh sparse-independent, partial-policy ledgers
from the unchanged rejected workload, with fixed `split_tail` inference and
three paired contrasts: C+D minus price-only, pooled minus price-only, and
pooled minus C+D. Freeze attacks, sample size and nine betting tests before
generation. Keep all other strategies descriptive and preserve the workload's
existing absolute privacy failure. This measures bounded additional prediction;
it is neither a new payout-policy comparison nor privacy qualification.

## What the baseline must optimize

[Generalized gain functions][gain], definitions in Section III, explicitly model
approximate guessing. The relevant prior action maximizes expected success for
the adopted scoring rule; it need not be the most frequent exact amount. A
bounded heuristic's measured gain is not the optimal channel vulnerability.
Wrong explanations for successful guesses therefore do not establish zero
signal. An optimal observer can ignore additional information; a fixed heuristic
may perform worse when given it. These are different claims.

For this experiment, use integer sompi and gain
`g(guess, amount) = 1[10 * abs(guess - amount) <= amount]`. For each possible
amount `a`, its successful integer guesses occupy
`[ceil(9*a/10), floor(11*a/10)]`. Sum the exact probability weights over these
intervals and choose the smallest maximizing guess. This is a direct application
of the gain-function definition, not a new cryptographic construction.

The existing [observer](../poc/shared-pool/working_balance_observer.py) already
implements that interval sweep. Its public mixture has 60% uniform mass on
10/20/25/40/50 tKAS and 40% uniform mass on 4,001 cent values in [10,50].
It yields `45 * 100_000_000` sompi and expected success `21103/100025`, about
21.10%. Preserve that information limit against the unchanged 20% absolute cap.
Do not optimize an exact-match prior and present it as the within-10% baseline.
For descriptive exact matching, the smallest modal support value is 10 tKAS,
with probability `3/25 + 2/(5*4001)`. This is a different scoring baseline.

Distinguish these views explicitly:

| View | Available information | Interpretation |
| --- | --- | --- |
| Price-only | Frozen workload distribution and declared scenario labels; opaque target references needed for scoring | Prior price predictability |
| C+D | Public history plus initial-funding owner directory | Transcript and directory information beyond price-only |
| Pooled | C+D plus the eight colluders' own authored/receipt records | Adds participant knowledge; total gain is not chain-only leakage |

The primary contrasts use identical eligible targets within each ledger. The
price-only baseline is the optimal marginal price action, not an optimal
conditional inference engine given every colluder fact. Pooled-minus-C+D
separates the bounded attack's added participant knowledge. Neither contrast
isolates an individual public field or establishes a causal protocol effect.

Freeze target eligibility and disclosure rules before generation. Do not remove
easy targets after scoring or credit an already disclosed receipt as newly
inferred public information. Report any predeclared known/protected-target
strata separately. An optimum under the marginal price distribution is not
automatically optimum after conditioning on extra selection or transcript
metadata. Optional descriptive `q(guess)` can report each guess's expected
success against the marginal price distribution; it is not a conditional
posterior, an independence test, or an additional inferential endpoint.

## Independent units and frozen inference

Use one ledger's mean target accuracy as one observation. For each frozen
comparison let `D_i = accuracy_i(attack/view) - accuracy_i(baseline)`, in [-1,1].
Different ledgers must be independent draws; targets and alternative supports
inside a ledger are not independent samples. Pair views of the same ledger.
Keep fee, payout-policy, activity and cash-demand cells separate, or freeze
explicit weights for any mixture. Never choose those weights after results.
Mean ledger accuracy weights ledgers equally; pooled target accuracy instead
weights ledgers by target count. Freeze that estimand and any empty-stratum
handling. Neither permits silently discarding inconvenient histories.

### Selected test: finite-sample betting evidence

[Waudby-Smith and Ramdas][betting], Section 4 equation (23) and Propositions
2–3, give the bounded-mean capital-process construction. It supports the
following direct application; the paper does not validate this simulator.

For each of the three frozen contrasts use exactly 512 ledger differences,
`D_i` in [-1,1], and the fixed set `L = {1/8, 1/4, 1/2, 9/10}`:

```text
E_plus(theta) = (1/4) * sum_lambda product_i [1 + lambda*(D_i-theta)]
E_minus(.05)  = (1/4) * sum_lambda product_i [1 - lambda*(D_i-.05)]
```

Compute `E_plus(0)`, `E_plus(.05)` and `E_minus(.05)` once after all predictions
and scores are sealed. Each contrast therefore has three tests, nine in total.
The nulls are respectively `mean(D)<=0`, `mean(D)<=.05`, and `mean(D)>=.05`.
Reject a null only if its e-value is at least 180. Bets and mixture weights are
frozen; selecting the largest component without correction would be different.

**Direct proof.** Under each null, every factor is nonnegative and has
conditional expectation at most one. Independence and the fixed attack make the
next ledger's conditional mean equal its population mean. Iterated expectation
therefore bounds each product's expectation by one; its fixed average retains
that bound. Worst-case factors are .1 for `E_plus(0)`, .055 for
`E_plus(.05)`, and .145 for `E_minus(.05)`. Markov's inequality gives probability
at most `1/180` of each false rejection. A union bound gives at most
`9/180=.05` over all nine tests, without independence between contrasts.
The paper's [0,1] representation follows by setting `X=(D+1)/2`,
`m=(theta+1)/2` and its bet to `+/-2*lambda`.

The 512-ledger budget was selected before any new seed or history to reduce
the earlier small-study power problem. As analytic motivation, with only 256
values all equal to `D_i-theta=.025`, `E_plus(theta)` is about 82.23, below
180 despite zero variance; constant excess must reach about .0286271. With
512 values, that same constant case yields about 22,311.32 and the constant
crossing falls to about .0142239. These are deterministic formula checks, not
simulated histories or evidence about unknown variance. The selected budget
still does not guarantee a resolved five-point margin; variability can reduce
power and fixed positive bets need not gain wealth against every small,
high-variance excess. No held-out outcome was used to choose 512.

Rejecting the reverse null supports mean advantage below five percentage points
for that fixed contrast, attack and generator. It does not show zero leakage,
qualify the absolute target, or bound every attack in the descriptive family.
Failure to reject remains inconclusive. Do not add ledgers, tune bets or promote
a descriptive winner after observing results. No field-redaction or donor
permutation experiment is selected for this first test.

### Alternative retained for a later, separately frozen test

[Maurer and Pontil, Theorem 4][bernstein] supplies a finite-sample empirical
Bernstein bound. Range scaling gives the following radius for each side:

```text
r = sqrt(2 * s_D_squared * ln(2/delta) / N)
    + 14 * ln(2/delta) / (3 * (N - 1))
```

Here `s_D_squared` is the usual sample variance with denominator `N-1`.
For `K` predeclared comparisons, set `delta = alpha/(2*K)` and apply a union
bound to obtain simultaneous two-sided intervals `mean(D) +/- r`. Count every
inferentially claimed cell, attack, view and endpoint in `K`. A family maximum
can use the maximum simultaneous lower bound and maximum simultaneous upper
bound. It cannot select each ledger's best attack using private correctness.
Freeze fixed `N`, family, endpoints and thresholds first; do not stop when a
preferred interval appears. This recommendation applies the theorem to paired
ledger scores; the paper does not validate this simulator or its independence.

Precision planning below is arithmetic, not a pilot or a claim about unknown
held-out variance. For illustration with `alpha=.05` and `s_D_squared=.01`:

| Comparisons K | Histories N | Radius |
| ---: | ---: | ---: |
| 16 | 1,024 | 0.04446 |
| 100 | 1,024 | 0.05425 |
| 100 | 2,048 | 0.02986 |

A smaller variance can make this much tighter than a range-only Hoeffding
bound. Unknown variance means no fixed budget guarantees a five-point decision.
An interval above a predeclared margin supports excess prediction; one wholly
below it bounds these frozen attacks under this generator. An interval crossing
the margin is inconclusive. A bound below five points does not establish zero
leakage, satisfy the absolute cap, or cover stronger attacks.

Do not assume paired sign-flip tests are exact merely because mean advantage
is zero: exchangeability/invariance is an additional assumption. [Chung and
Romano][permutation] distinguish equality of parameters from the stronger
distributional null needed for ordinary exact permutation tests.

## If later investigating fields, remove their substitutes too

The local public model exposes reserve, deposit, payout and fees, and enforces
`reserve_after = reserve_before + deposit - payout - fee`. Thus deleting only
`payout` leaves it recoverable by subtraction. Native bridge source/input/change
amounts can supply further deterministic substitutes. A later field diagnostic
must freeze its direct and derived amount channels and use hand-built controls
showing that each purportedly hidden value cannot be trivially recovered from
the surviving fields. Preserve genuine observer disclosures in every arm and
report that they can retain information even after public amount redaction.

[Strobl et al.][dependent] demonstrate that importance estimates can change
when correlated predictors and their permutation scheme change. The applicable
lesson here is narrow: dependent fields require an explicit joint information
model. A diagnostic view is a deterministic projection of the same ledger; it is
not a second valid transaction system, random assignment of a protocol, or proof
that hiding one field in a deployed design would produce the same outcome.

The [existing source review](shielded-kas-sparse-withdrawal-design-2026-10-22.md)
pins Kaspa transaction outputs, Toccata, vProgs, Orchard and MWEB. This statistical
test changes none of those structures. No source reviewed here supplies measured
user cash-demand distributions, production anonymity or a privacy guarantee for
the prototype. Keep independent-demand cases as models and receipt-correlated
cases as declared stresses; retain final drainage and immediate exits.

## Primary sources

- [Alvim, Chatzikokolakis, Palamidessi and Smith (2012), CSF][gain],
  DOI `10.1109/CSF.2012.26`, author-hosted paper, Section III.
- [Waudby-Smith and Ramdas, fixed arXiv version 7][betting], Section 4
  equation (23), Propositions 2–3; journal DOI `10.1093/jrsssb/qkad009`.
- [Maurer and Pontil (2009), COLT][bernstein], Theorem 4; also
  [arXiv:0907.3740v1](https://arxiv.org/abs/0907.3740v1).
- [Chung and Romano (2013), Annals of Statistics][permutation],
  DOI `10.1214/13-AOS1090`, fixed arXiv version 1.
- [Strobl et al. (2008), author/institutional deposit][dependent],
  DOI `10.5282/ubm/epub.2821`, technical report dated 2008-03-28.

The retrieved COLT PDF has SHA-256
`4b06ea7eb3a832347df493948deb06a7053aa36d22eba6793d2a4e48ab3935c1`;
the retrieved Chung/Romano version-1 PDF has SHA-256
`11d8b4c5a4eb994a18b1bb4e8e17b636936dfbdf8e705b7f5d716dff3933b195`.
The retrieved Waudby-Smith/Ramdas version-7 PDF has SHA-256
`d783b1200025fbdf89b0edf718c19712c1e7acfec263a4b07a68609b4d7ac4ef`.
Source links were read on the review date; the note's recommendations are
applications to this evaluation, not claims made by those papers about Kaspa.

[gain]: https://homepages.dcc.ufmg.br/~msalvim/publications/2012-CSF.pdf
[betting]: https://arxiv.org/html/2010.09686v7#S4
[bernstein]: https://www.cs.mcgill.ca/~colt2009/papers/012.pdf
[permutation]: https://arxiv.org/abs/1304.5939v1
[dependent]: https://epub.ub.uni-muenchen.de/2821/
