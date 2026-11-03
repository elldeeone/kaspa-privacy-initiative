# Method 05: deterministic public cashout guesses

This preregisters a small practical guessing measurement on the **same eight
frozen histories**, before any method-05 predictions or scores are inspected.
It changes neither requests nor seeds. It is independent of whether the exact
or slice solver finishes. No solver is used to predict; original full-model
truth checks run only in the separate scorer after all predictions are sealed.

## Inputs and coverage

The observer receives exactly one existing public history and participant view.
It receives no truth, seed, arm, regime, eligibility mask or private wallet data.
Predict every ordinary SPEND except self-bootstrap, at the final public horizon.
Run all eight histories with the pooled view first. Preserve other views and
earlier horizons as unexecuted, not as passing cases.

All amounts are integer sompi: `L=1_000_000_000`, `U=100_000_000_000`, and the
constant baseline/fallback is `10_000_000_000` (100 tKAS). A DRAIN's total input
is exactly its public `payout + fee`, whether it consumes one or two notes.
Every variant predicts every target, including when it must use a fallback.

## Fixed baselines

For each endpoint, use an explicitly disclosed author/recipient identity if
available. Otherwise start with roles admitted by the target, removing disclosed
members excluded by the complete-record convention. Sort the remaining roles.
Select index `int(SHA256(canonical_json({domain,field,event_id})),16) mod count`,
where `domain` is `kpi-population-heuristic-role-v1`, `field` is `sender` or
`recipient`, and canonical JSON sorts keys with separators `(',', ':')`.
The amount baseline is always 100 tKAS. No private eligibility mask reaches this
calculation.

This role baseline is a **limited diagnostic prior**, not the strongest prior
required by RFC-0012: it omits cohort/round scheduling, conditional recipient
priors and inference from other disclosures. The constant amount is at the
log-uniform distribution's geometric midpoint; its continuous-prior chance of
being within the required tolerance is about 4.36%. Neither value is an observed
accuracy. Low attack rates or low improvement over this baseline cannot qualify
privacy.

## Three fixed attacks

1. **`cashout_total`:** inspect DRAINs strictly after the target in event order.
   Use the first with `L <= payout + fee <= U` as the amount guess. Endpoints
   remain their baseline guesses.
2. **`cashout_half`:** inspect the same DRAINs, independently. Use the first with
   `L <= (payout + fee) // 2 <= U`; guess that integer half. Endpoints remain
   their baseline guesses. Odd totals round down by one sompi, never to KAS.
3. **`known_note_residual`:** seeds are positive outputs explicitly recorded in
   this view's authored transactions, sent to an owner outside the disclosed
   member set. Public initial/admission balances and recipient-only receipts
   do not supply seeds. For each later DRAIN, consider seeds created strictly
   before it; exclude the target's own payment output and any seed explicitly
   spent in a disclosed authored event strictly before that DRAIN. Keep residuals
   `payout + fee - seed_value` in `[L,U]`. Rank candidates by
   `(DRAIN_event - target_event, abs(seed_birth_event - target_event), seed_position)`.
   Choose the minimum tuple, guess its residual as amount and seed owner as
   recipient. Sender remains baseline. Empty candidate sets use both baselines.

These are guesses, not conservation proofs or confirmed note-spend links. A
two-input cashout need not contain the seeded note or the target payment. In a
valid current complete-P view, an undisclosed owner's note cannot actually be
spent by a disclosed author. The spent-record filter is defensive; it does not
give senders the recipient's future nullifier or general spending visibility.
The candidate may use a seed created after the target but before the cashout.
Tie rules are public and fixed. No confidence ranking or selective-coverage
measurement is introduced here.

## Scoring and interpretation

Seal **all eight histories' predictions before any scoring**. The isolated scorer
checks input identities, complete ordered target/variant coverage, concrete
workload accounting and truth inclusion in both original full CP-SAT/Z3 models.
It applies the original primary predicate privately: all roles admitted, both
endpoints honest and outside the disclosed member set. Known facts are excluded
per field: author knows sender; author or recipient knows recipient and amount.

Report each variant and baseline separately, with correct/eligible counts for
sender, recipient, exact amount and amount within the RFC-0012 tolerance:

```text
10 * abs(guess - actual_amount) <= actual_amount
```

Primary amount measurement is that tolerance, not exact equality. Also report
all undisclosed targets, startup and adversary-endpoint diagnostics separately.
The latter strata may overlap; do not add their denominators. Never select the
best variant per target using truth. A strongest-variant aggregate may be shown
separately with the evaluated family named. These measurements issue no forced
disclosure certificate and cannot trigger the exact-forced-counterexample rule.

Prompt-cashout amount matching is an expected positive control. Persistent-arm
outcomes are the substantive comparison. Four independent request sets and their
paired arms cannot qualify the rate/advantage gates; paired histories are not
independent samples. Results are finite, modeled observations, not real-world
anonymity or a statistical privacy pass. `qualification_pass` is always false.

Before inference, hand-checked fixtures cover total/half/residual guesses,
fallbacks, odd-sompi division, range/tolerance endpoints, seed chronology,
disclosed-owner exclusion, target-output exclusion, defensive spent timing,
schema poisoning and scorer known-fact exclusions. Freeze this file, executable
source and reused dependency identities before running predictions.
