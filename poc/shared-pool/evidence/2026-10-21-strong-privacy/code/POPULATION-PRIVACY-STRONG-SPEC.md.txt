# Stronger practical privacy screen: prospective specification

Date: 2026-10-21. Native wallet candidate: `52c209296184d880221432fcbf56bb20d3f64d10`.
Requirements remain [RFC-0012](../../docs/rfc/0012-useful-privacy-requirements.md).
This extends [RFC-0014](../../docs/rfc/0014-owner-aware-privacy-evaluation.md)
without changing protocol, wallet, invariants or earlier evidence.

The owner authorized freezing attacks and criteria, then generating fresh
32-role/eight-adversary histories and running through a result. The runner must
copy/hash this specification, executable sources, dependencies and source review
before sampling any hidden seeds. Development fixtures have explicit public
seeds and are never evaluation samples. No decisions may be tuned after held-out
predictions or truth scoring. Failed attempts and original seeds are retained.

## Question and scope

After separating native funding and exit keys, can practical observers infer
ordinary internal payments using known deposits, wallet selection assumptions,
tagged receipts, payment timing and later cashouts? Predict sender, recipient
and integer amount; rank guesses about both parties for selective targeting.

This first slice is a **bounded failure screen**, not privacy qualification.
It uses 16 independent modeled persistent-balance histories, each with 32 roles
and eight colluding active roles. It starts with the pooled final-history view.
An absence of a successful tested attack cannot certify real-world anonymity,
cryptographic privacy or the complete native byte surface. No new native proofs,
funded activity, broadcasts, setup or network observations are generated.

The [source review](../../research/shielded-kas-strong-privacy-screen-2026-10-21.md)
records the native calibration and model limits. Fresh v2 removed a tested script
alias; this model represents funding identities and payout destinations with
independent opaque labels. It neither repeats that derivation test nor assumes
all other correlations absent. Actual wallet users select their inputs; the
automatic selection policy below is an explicit workload assumption.

## Fixed workload

Generate exactly 16 fresh independent seed bundles, each with independent
32-byte request and opaque-label seeds, sampled only after source freeze and
controls. Cases 01–08 overlap; 09–16 are sparse. There are no matched duplicates
or prompt-cashout held-out arms. Each history is one statistical sampling unit.

Reuse the earlier Ledger, independent accounting, integer sompi, fees, floors,
public schema, complete participant-record convention and opaque labels. Roles
0–7 belong to one adversary. Roles 8–31 are modeled honest users, not verified
independent people. The founder is role 0. The declared public directory maps
funding identities and receive contacts to roles; it does not label hidden
payment authors or cashout owners. That directory is assumed side information.

Each role makes four payments: 128 ordinary payments, 32 attacker-authored and
96 honest-authored. Initial balances are independently uniform over 5,000,
10,000, 20,000 and 40,000 tKAS. Honest requests select uniformly among other
currently admitted roles; amounts use the existing discrete log-uniform
10–1,000 tKAS sampler at sompi precision. No denomination rounding is added.

First admit roles 0–3 and 8–19, execute one shuffled payment from each, admit
the remaining roles, and execute their shuffled first payments. Three subsequent
rounds each contain one shuffled payment per role. Modeled time advances by one
minute per payment. Sparse cases additionally insert 60 minutes before each of
the three subsequent rounds. Hidden order is freshly sampled; phase boundaries,
distributions and scheduling rules are available to the observer from frozen
source. A quiet gap does not assert a smaller actual owner set.

In zero-based round `r`, each active role `a` sends an honest admitted recipient
`(r+1)*100*100_000_000 + (a+1)*1000` sompi. Recipients are selected independently.
These nonadaptive tags actually affect the workload. The adversary cannot see
future honest requests, force reactions, censor or reorder them. Capital,
operation and value shares are measured, not all labeled 25%.

The modeled selector chooses a one/two-note owned unspent combination covering
the payment and 0.4-tKAS fee, leaving zero or at least 0.6 tKAS change. Minimize
excess, then input count, then lexicographic positions. Persistent recipients
retain receipts. Complete final drainage visits owners in a hidden shuffled
order and consumes one/two remaining notes in position order. Do not silently
drop requests, erase small claims, subsidize or resample an unaffordable history.

The larger minimum capital protects feasibility before testing: each original
capital/change chain loses at most 1,000.4 tKAS per authored payment, even when
received fragments are selected. Before the fourth payment it retains at least
1,998.8 tKAS, leaving valid change after a maximum payment. Every accepted history
still undergoes independent accounting and exact schedule/selector checks.

## Observer and fixed attacks

Each isolated observer receives exactly its history's `public.json`, pooled
records of roles 0–7 and the frozen public `policy.json`, plus public
source/dependencies. It receives no
other history, hidden seeds, truth, eligibility mask or private wallet data.
All ordinary payments are predicted at final history, including already-known
and startup targets. Scoring applies exclusions later.

Four variants are fixed: `prior`, `cashout_residual`, `split_balance`, and
`tag_split`. They produce deterministic full-coverage guesses and a relationship
ranking, not calibrated probabilities or forced-disclosure certificates.

The prior uses the published amount distribution and admission/round/complete
participant information, including author-count exclusions available from the
one-payment-per-role phase rule. It is stronger than the earlier hash-only role
baseline but is not asserted to be an optimal posterior for the complete ledger.
Directly known facts are preserved. Ties and all matching/ranking/fallback rules
are part of `population_privacy_strong.py`, frozen byte-for-byte with this spec.
The amount fallback is 100 tKAS: an interior relative-error window under the
published log-uniform prior. This is not asserted to maximize the exact discrete
posterior conditioned on the entire history. Uniform-prior role ties use hashes
of public event IDs and roles; the hash itself supplies no behavioral inference.

`cashout_residual` ranks later public payout-plus-fee totals, optionally subtracting
known note values, with chronology, ownership and known-spent filters.
`split_balance` matches known same-owner one/two-note inputs minus the payment
fee against later possible payment and change values. Positive change ownership
helps guess the sender. `tag_split` applies the same reasoning to known
attacker-authored notes delivered to honest owners. The target's intended
recipient is not attacker-controlled merely because it received a tag.

Known notes come only from the initial/self-bootstrap convention, public
admissions, disclosed receipts and authored outputs, plus equal commitments.
Guessed matches never become new known notes. A candidate input must precede
the target and fit its anchor; a position with an explicitly disclosed spend
at any different event is rejected, including a spend learned later. A possible
exit residual is its payout plus fee, optionally less one known coinput. Reject
disclosed exits, foreign coinput ownership, target-output reuse, double use of
the same known coinput, and a proposed payment/change split using one exit twice.
Unknown intermediate spends can still invalidate a guessed match.

Join candidates exhaustively within these local rules, without truncation.
Rank by explicit endpoint evidence, fixed attack tier, distinct supporting joins,
then shorter modeled time distance. Break remaining candidate ties by smaller
amount, sender and recipient. Rank selected relationships using that four-integer
evidence tuple, then payment event ordinal. Empty matches retain the prior.
These attacks use the one/two-input/common-owner/change rules; they do not enforce
the complete greedy selector or reconstruct every intermediate hidden state.

Exact numerical equality alone does not prove that a cashout consumed the
proposed note or that a proposed input was still available. Record matching
diagnostics and fixed fallbacks; never reinterpret guesses as logical proofs.
Any bounded candidate omission must be explicit in the frozen source/report.

## Eligibility and metrics

The primary target predicate is unchanged: both endpoints are honest and outside
the disclosed member set, and all 32 roles were admitted by payment creation.
Eligibility never depends on attack success, match confidence or future exposure.
Keep startup, adversary-endpoint and all-undisclosed diagnostics separately;
overlapping strata are not added together.

Already-known facts are excluded field by field: authors know sender; authors
or receiving participants know recipient and amount. A joint relationship is
already known only if both endpoints are known. Recipient-only knowledge is
not silently upgraded to sender knowledge. The observer gets no private mask.

Report correct/eligible counts for sender, recipient, joint relationship,
exact amount and amount within `10*abs(guess-actual) <= actual`. Report every
variant separately, with no truth-selected per-target best attack. For each
history, select the top `ceil(q*N)` eligible relationship guesses at q=5%,10%,25%
using the frozen confidence/tie ordering; publish the resulting actual rounded
coverage and both-endpoints-correct precision. Do not rank using correctness.

## Fixed uncertainty and decision rules

The unchanged RFC caps are 10% identity accuracy, 20% within-10% amount accuracy,
five percentage points advantage over the frozen prior, and 50% relationship
precision at each declared coverage. Exact amount and full-coverage joint
relationship rates are additional descriptive diagnostics.

Use equal-history means and paired per-history attack-minus-prior differences.
Report pooled payment counts descriptively, without treating all payments as
independent. The fixed family has 99 comparisons across three scopes (all 16,
eight overlap, eight sparse): four variants times three absolute metrics, four
variants times three selective coverages, and three attacks times three paired
advantages per scope. Use Bonferroni with alpha=0.05 over both tails, 198 tails
in total. A bounded mean of width W has radius
`W*sqrt(log(198/0.05)/(2*n))`; W=1 for rates and W=2 for paired differences.
Clip intervals to their respective valid ranges. This is deliberately
conservative, assumes independent histories and makes no within-history
independence claim. Empty primary-history cells make the relevant family
incomplete; never silently remove such a history.

At n=16 the rate radius is about 0.509, so this screen cannot establish a
qualification pass or resolve modest advantage changes. Raw cap exceedances
are exploratory signals, distinct from certified breaches. The sample count
is a practical attack-screen budget, not a power calculation for RFC acceptance.

- **Certified screen failure:** a valid completed comparison has its simultaneous
  lower bound strictly above an unchanged cap. Review the evidence, then stop
  expansion of the affected candidate/claim and select a redesign or explicit
  scope decision. Preserve all cases and failed attacks.
- **Completed bounded screen without a certified breach:** all cases, controls,
  seals and scoring checks finish, with no such lower-bound breach. Report raw
  rates, uncertainty and any cap-exceedance signals. This is not a privacy pass.
- **Incomplete/invalid evidence:** missing cases, failed controls, source/input
  drift, truth inconsistency, contaminated observer inputs, unresolved checks or
  post-unblinding tuning prevent the corresponding conclusion. Retain the
  attempt and identify the exact failure; do not retune it into success.

The heuristic variants issue no logically forced claims. Any later proposed
forced disclosure requires separate independent validation against the supported
model and private truth; absence of such a certificate is not a zero-leak proof.
All sixteen predictions are sealed before any scoring; finish the frozen batch
without selecting histories after observing outcomes. `qualification_pass` is
always false. Public-only/separate-participant views, earlier horizons, stronger
adaptive attacks, adequate qualification power, real native bytes and independent
users remain open. Milestone 3 remains behind the complete early privacy gate.

## Reproduction and controls

`population_privacy_strong_trial.py prepare OUT` copies/hashes source/spec/notes,
candidate sources, native-calibration identity and dependency bytes. `controls`
runs model, workload, attack and scorer controls in isolation. `generate` samples
fresh seeds outside Git and generates exactly the declared histories. `run`
isolates predictions, seals the whole batch, validates truth in separate scorers
and aggregates the fixed metrics. At most two scorer processes run concurrently,
only after the complete prediction barrier. Existing files cannot be overwritten.

Controls cover complete records, known and ambiguous matches, wrong plausible
matches, prior conditioning, sompi boundaries, chronology and spentness, genuine
prompt-cashout development positives, schema contamination, exact eligibility,
ranking/ties/coverage, aggregate-family count and incomplete-history rejection.
Fixed-truth validation checks the concrete ledger and exact generating policy;
it is not a search for unknown alternative histories or a security proof.

Export only approved public inputs, predictions, aggregate scores, source pins,
process/seal attestations and public-source snapshots. Keep seeds, full truth,
private records outside the declared participant view and raw operational logs
outside the public evidence. Source hashes identify bytes, not independent audit.
