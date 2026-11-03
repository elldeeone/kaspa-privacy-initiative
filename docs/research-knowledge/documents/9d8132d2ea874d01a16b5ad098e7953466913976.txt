# Common-size partial cashouts: frozen offline test (H17)

Date: 2026-10-20 UTC. Branch: `shared-pool-four-wallet`.
Baseline: `498a66a`. Authorization: build/run offline, preserve independent
exits, retain code/results/journal. No TN10, publication or parameter changes.
This document and `common-payout-freeze.json` must be committed before coding
or observing the new workload. Do not tune the size after results.

## Question and decision

Does one common-size partial withdrawal per wallet reduce reconstruction of
the original cashout sources after every remainder has exited, without
revealing additional original payment relationships? If not, reject this
specific policy as a useful mitigation. Do not retry denominations until one
looks good. A positive screen would justify a separate practical scheduling
design, not adoption or an anonymity claim.

**Freeze Q = 200,000,000 sompi (2 test KAS).** This is an intentionally round
amount compatible with the existing fixture's positive-change floor. It was
chosen before new observer runs, with the original workload already known.
It is not a statistically independent holdout selection.

Reuse all four H14 amount/schedule cases. Keep the first twelve operations,
all deposits, six private payments and two varied partial withdrawals exactly
unchanged. Before final drainage, append four ordinary partial withdrawals,
one for each wallet, in wallet order 0,1,2,3. Their explicitly requested inputs
are `bootstrap:1`, `W1:0`, `W2:0`, `P4:1`, respectively. Input selection is a
fixture request, not an asserted automatic coin-selection algorithm.

Each consumes one note, pays Q, deducts the existing 40,000,000-sompi fee,
returns the positive remainder in slot 0, and pads slot 1 with zero. Reject
the case if the remainder is below 60,000,000 sompi. No merging, replenishment,
extra deposit, background participant, subsidy or extra private payment.
Drain the same seven economic claims in their original order (reversed in
schedule 1), replacing the four consumed notes with their change notes.
Use fresh latest-root authorizations for the main privacy comparison.

Baseline fees are 760,000,000 sompi for 19 transactions; candidate fees are
920,000,000 for 23 (+21.05%). Each wallet's total payout declines by exactly
one additional 40,000,000-sompi fee. Count all original and new partial payouts,
all seven final payouts, and every fee. Initial funding equals these payouts
plus fees, with zero residual reserve. Fixed ten-minute inter-event spacing
adds 40 minutes to final completion. Report per-claim first and complete
cashout timing. This exceeds the branch's existing 30-minute p95 completion
delay target; that target is not relaxed. This diagnostic cannot close Stage 2.

## Observer and hidden data

Reuse the H15 known-client chain observer and the H16 known-client participant
observer. Run each of four participant views separately; never pool records.
The main observer knows public amounts, fees, destinations, ordering, state
counts, anchors, fixed padding, normal change slots, single-input full exits,
and (for this policy) single-input Q partial withdrawals with positive change.
The chain-only profile has no ownership records. The participant profile has
only that participant's complete receipts/authored operations and local
recipient aliases, under H16's explicit ownership assumptions.

The observer does not receive the plan, true note graph, original cashout
mapping, wallet count, schedule/amount/case labels, other participant views,
keys, unused saved proofs, RPC/network records, or the generator. A Q payout
is recognizable by its public amount; the observer is not told which wallet
made it or which final payout belongs to it. Roots/ciphertexts/NFs are treated
as opaque except for previously documented count/anchor/spentness constraints.
Use H16's corrected metadata-isolated sandbox, with no `/proc`, host home or
network access. Prefix views must exclude future participant records.

No protocol constraint is added. The v6 relation permits two real inputs;
the new one-input rule is knowledge of this client policy, not consensus.
Use integer-sompi feasibility. Every accepted relaxed-SMT graph must have an
integer CP-SAT certificate. Unknown/incomplete search is inconclusive, never
evidence of privacy.

## Metrics that cannot be improved by adding change

The primary target remains each of the original seven cashout claims per case
(28 distinct claims; 84 eligible separate participant/claim observations).
Recursively collapse the output of a Q partial into its single input's creating
transaction. Other note outputs retain their own creating transaction as their
source. This provenance is inferred within each feasible graph, not supplied
from ground truth. Source transaction is not a person or ultimate deposit.

For a split claim, score both its Q payout and final remainder separately.
Count the original claim as linked if **any** of its legs has exactly one
feasible original source. The scorer may match legs to assess the same
economic claim; the observer may not intersect their candidate sets using that
hidden matching. Report every leg's candidates, singleton coverage, correct
singleton inference and abstention; a minimum leg count is only a scorer
summary, not an observer clustering method. Also report original payment
input/source sets so change churn cannot inflate their ambiguity.

Compare against immutable H15 chain-only and H16 single-participant fresh
full-drain predictions. H17 has two horizons: immediately after the four Q
payouts and after all seven drains. The first is diagnostic only, without
pretending it has the same payout completion as baseline. Only the complete
history decides the primary result. Full exits are scored only when present.
Exclude participant-owned inputs or positive outputs as in H16.

Falsifiable privacy screen: reduce the seven baseline distinct claims linked
by at least one separate eligible participant to at most five (at least 25%
relative reduction), with no case/participant increase in linked claims and
no newly forced original payment source set in any case/participant. A distinct
union is a robustness summary over separate views, not a colluding observer.
Report chain-only results separately even if already zero at baseline.
The cost/mechanics screen additionally requires <=25% extra native fees,
the unchanged 30-minute p95 completion-delay target, integer truth survival,
exact backing, and independent exits. Distinguish the privacy and overall
verdicts. Four fixed synthetic cases do not support population confidence
intervals, real-world anonymity or a percentage of "privacy."

## Smallest genuine calibration and controls

Run one new genuine v6 calibration, `a0-s0`, using the existing parameters and
pinned native implementation. The other three cases remain arithmetic models.
Keep the existing circuit/covenant/state formats. Add only an opt-in study
harness mode and analysis code.

Save a full-exit fallback when each of the four selected original notes is
received. Before its optional Q withdrawal, independently rebuild that saved
exit without wallet keys or proving parameters; test both winner orders:
full exit rejects the partial, and partial rejects the old full exit. Save
new change exits at receipt. After subsequent activity, all four wallets must
drain all seven notes using those unchanged saved proofs in isolated workers.
Run a separate fresh-proof drainage branch and reject the alternative/replay.
Validate native proof/covenant acceptance, malformed mutations, public-body
revalidation, exact accounting and equality of the model/native projection.
No controller secret may be needed by an exit worker; supplying authenticated
public state is an explicit fixture assumption, not general recovery proof.

Controls: original-prefix identity; one extra fee per wallet; note/payout
floor rejection; all-claim drainage; source-collapse correctness including a
tiny independently enumerated integer example; participant facts and future
view exclusion; truth graph feasibility; no secret leg intersections;
single-input rule conditionality; saved/normal mutual exclusion.
Pin source/input hashes before observations, finish observations before
scoring, preserve failed attempts, and perform an adversarial second review.
Export allowlisted aggregates/predictions/calibration receipts only: no keys,
proving parameters, note openings, raw participant records or unused exits.

Stop with an honest negative/inconclusive report if tails remove any apparent
benefit, eligible truth is rejected, exact inference cannot finish, costs fail
the frozen budget, or calibration requires privileged help. No further
denominations or funded run are authorized by this test.
