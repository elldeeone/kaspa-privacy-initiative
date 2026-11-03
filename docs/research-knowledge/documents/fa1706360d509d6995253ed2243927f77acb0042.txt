# Scheduled common payouts: frozen offline decision (H18)

Date: 2026-10-20 UTC. Branch: `shared-pool-four-wallet`.
Baseline: `e063e0d`. Commit this document and `scheduled-payout-freeze.json`
before generating or observing the new workloads.

The owner authorized a policy freeze, new offline timing-aware comparison and,
only if its gate passes, native calibration and TN10 validation. No push or
upstream posting. Preserve every earlier run, parameter set and branch.

## Decision and policy

Does a common partial payout retain a material inference benefit when users
withdraw independently on a bounded schedule, including all final remainders?
Keep the existing v6 relation, 200,000,000-sompi payout, 40,000,000-sompi fee,
60,000,000-sompi positive-note floor and 10,000,000-sompi payout floor.

The wallet offers an optional split for an explicitly selected note:

1. A full-withdrawal request can instead pay Q now, retaining private change
   when `value >= Q + fee + note_floor`. Otherwise use the ordinary full exit.
2. After the partial is accepted, save the change's independent exit. Schedule
   its full withdrawal after a private random delay of 5–15 whole minutes.
   The eleven weights are `1,2,3,4,5,6,5,4,3,2,1` (sum 36). This bounded
   triangular distribution is a declared experimental policy, not a privacy
   guarantee or a claim about how users already behave.
3. Never split that change again. An immediate exit always overrides the
   optional schedule. An old full exit and the partial spend the same note;
   after the partial succeeds, use the replacement change exit.

There is no shared withdrawal round, coordinator, extra deposit, cover payment,
subsidy, minimum population or required cooperation. The trial workload selects
the oldest eligible live note of each wallet for this optional treatment.
Selection is a declared fixture preference, not a consensus condition or a
global bound on the observer's possible owners. Other live notes fully exit.
The wallet never needs another participant's identity or request time.

Compare with immediate fresh full exits on the same original claims and
requests. Use fresh authorizations for primary privacy. Saved exits remain
private fallbacks; the immediate-exit control deliberately publishes one.
This is a scheduling test of one policy, not a search over denominations.

## New workloads, randomness and timing

Generate 12 independent paired ledgers in each of two regimes, plus singleton
and immediate-exit controls. The private master seed's SHA-256 is in the freeze.
Derive each case stream with HMAC-SHA256 and a stable case name. Never mount
the seed, generator, case/regime labels, request times or true graph in an
observer. These are new amounts, legal operation orders and request schedules;
the six-payment/four-wallet topology is reused and is an explicit limitation.

The original activity is H14's bootstrap, three independent deposits, six
private payments and two varied partial withdrawals. Generate deposits between
15 and 25 tKAS in integer 0.01-tKAS units. The bootstrap splits its net value
using a uniformly drawn 35–65% integer percentage. For each payment, choose
its recipient value uniformly in integer sompi between 35% and 65% of the
available value, subject to both positive-note floors. Earlier partial
withdrawals take a uniformly drawn 15–30% of their input less the fee, retaining
positive change; avoid accidentally choosing Q. Select each next legal
operation uniformly from the sorted dependency-ready operations. Bootstrap
comes first. There is no rejection based on privacy or attack scores.

Prefix events have independent 2–8 minute spacings. After that activity:

- **Overlapping low activity:** seven original claim requests independently
  arrive 0–30 minutes after the final prefix event.
- **Sparse low activity:** first wait 120 minutes with no new activity, then
  request the seven claims in a random order, with independent 20–45 minute
  gaps. No invented traffic fills those gaps.

Use a serial, work-conserving pool queue with two modeled minutes per
operation in both arms. This is a declared allowance for proving/acceptance,
not measured Kaspa confirmation time. Tie order uses private random tickets;
tail requests enter only after their actual partial acceptance plus the draw.
Full exits may occur between partials. Recompute anchors, note positions,
balances and participant records for that actual event order.

Count complete cashout from each original request, matching the same economic
claim across arms. Include queueing, every extra fee and every tail, until
reserve zero. The synthetic initial funding UTXOs omit live allocation/genesis;
a conditional TN10 run must count those too. Do not relabel modeled delay as
measured operating latency.

Singleton control: one funded owner, a bootstrap split, one optional common
payout and full drainage, with no other deposits or private payments.
Immediate control: a fresh generated four-wallet ledger with wallet 0 opting
out of shaping and using its saved full exits immediately on request. Controls
must remain feasible and expose their limitations; they are excluded from the
primary improvement and cost comparison.

## Observer and attacks

Five separate views per primary arm: chain-only and each participant's own
complete records, under H16's known-client rules. Do not pool disclosures.
Reuse the public v6 projection and ownership constraints; amounts are integer
sompi, cryptographic fields opaque. Public accepted-event time is available.
There is no RPC/IP/mempool observation, hidden request time, real wallet count,
case label, secret leg association or unused exit capability.

Compute complete-history source candidates twice:

- The existing integer conservation, note, anchor and participant relation,
  with single-input common payouts and inherited original-source provenance.
- Add the declared timing policy: common change is spent by a full exit,
  not another partial/payment. Its final acceptance must be compatible with
  a 5–15 minute delay and two-minute service, allowing intervening queue work.
  With k intervening accepted operations, delay d can explain the pair only
  if `d + 2 <= tail_time - partial_time <= d + 2*(k+1)`.
  These are necessary client-model constraints, not consensus rules or a
  complete probabilistic model of the queue. Include the old relation as an
  ablation so any gain from these assumptions is visible.

Ask for all feasible source transactions for cashout legs and all feasible
source-transaction sets for original private payments. Collapse a common
change's provenance recursively; do not count it as a new independent source.
Unknown solver status is an error, never evidence of ambiguity. Every positive
search graph must pass the separate unchanged integer relation, and every
actual amount/input graph must satisfy both models after predictions finish.

Freeze three full-coverage attacks:

1. Uniform feasible-source reference, with a public-hash tie selection.
2. Most recent feasible original source (for source sets, oldest member first).
3. A globally consistent integer graph maximizing the sum of log timing
   compatibility weights of common-to-tail pairs. A pair's weight sums the
   declared delay weights compatible with its visible gap and queue bound.
   Round `1000*ln(weight)` to an integer; break equal objectives using a
   smaller public-hash selector score. This is a maximum-score heuristic,
   **not** a posterior or a claim of an optimal adversary.

Apply all three to the timing-aware candidates; report the first two on the
untimed relation too. Report singleton precision/coverage, abstentions,
candidate counts, all three guess accuracies and the uniform reference.
The primary attack-family score is the largest aggregate accuracy of the
three fixed attacks in each arm/regime/profile. The scorer does not choose
the best attack separately for each target or use hidden leg grouping to
help the observer. This conservative family comparison is predeclared.

For a split economic claim, any correctly guessed leg counts as a successful
link. This intentionally counts both opportunities exposed by the policy.
Report early Q legs separately, but decide the result after full drainage.
The target is its original note-creating transaction, not a person, total
deposit ancestry or a percentage of privacy.

## Gate, controls and stopping

Use the existing Stage 2 screening limits: at least 25% relative reduction
in full-coverage correct cashout-source guesses in **each** regime for both
chain-only and separate-participant aggregate profiles. Report a paired
95% bootstrap interval over the 12 whole ledgers per regime (2,000 draws,
fixed public statistics seed 180018); its improvement interval must exclude
zero. Views/claims within a ledger are not independent samples. If baseline
success is zero, no relative benefit is established and that clause fails.
Also require no new uniquely linked original private payment for any matched
eligible participant/chain target, <=25% extra pool fees per primary case,
and <=30 minutes p95 added complete-cashout delay in each regime.

A small sample can be inconclusive. Keep the verdict negative/inconclusive
without replacing failed seeds, broadening limits or trying another delay.
The gate is a conservative decision to spend effort on live qualification,
not proof of practical anonymity or closure of all Stage 2 requirements.

Before the full run, controls must cover independent tiny graph enumeration,
timing boundary/queue cases, genuine integer graph checks, hidden-data
isolation, parser/range/floor rejection, exact fees/backing, all-claim drainage,
paired prefix/request identity, source collapse, and immediate override.
Commit source/input hashes before observations; finish the full observation
matrix before scoring hidden truth. Preserve interrupted/failed attempts.

If privacy, costs or truth fail, stop before funding and report what failed.
Do not build a live adapter merely to repeat a failed privacy policy.
Existing genuine H17 exit evidence remains prior evidence, not a new H18 run.

## Conditional native and TN10 validation

Only after the offline gate passes: calibrate one preselected overlapping
case (index 0) with genuine existing v6 proofs, the same interleaved order,
all four saved exits and old/partial mutual exclusion. No new circuit/setup.
Use the existing TN10 node and transport, a fresh one-command unfunded identity,
complete funded rehearsal then a fresh measured trial. Never rebroadcast
within a used trial identity.

Each owner must rebuild its current public settlement witness independently,
preserving its saved proof; no other wallet keys, proving key or operator
state may be supplied to an exit process. Stop the original prover first.
Verify every accepted transaction and native payout, including terminal
drainage. Count actual proving/queue/confirmation time and allocation, genesis,
pool and funding-reuse fees. A privacy score does not qualify relayability.
Keep secrets and unused capabilities outside Git; export allowlisted evidence.
