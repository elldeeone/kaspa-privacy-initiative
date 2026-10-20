# H14: blinded reconstruction of two-input payments

Frozen before generation or scoring, 2026-10-20 UTC. Baseline: `4630617` on
`shared-pool-four-wallet`. This is an offline Stage 2 screen, not a protocol
change, a user study, or a claim of real-world anonymity.

## Hypothesis and decision

H14: fresh normal-path exit authorizations, with saved fallbacks kept private,
leave more than one feasible **set of source transactions** for at least half
of the six private payments after full drainage, in every frozen four-wallet
case. They must also leave strictly more such alternatives than saved exits in
at least one case, without losing any wallet's independent exit capability.
This is a deliberately modest necessary screen, not a definition of strong
privacy. Failure pauses wallet expansion and identifies the dominant public
constraint to address. Passing warrants a larger adversarial study, not a
privacy claim. A sound singleton on a target falsifies ambiguity for that target.
A solver failure, missing case, invalid calibration, or excluded ground truth
makes the affected comparison inconclusive; it is never counted as privacy.

## Freeze and workloads

Commit this file and `two-input-privacy-workloads.json` before running the
new generator or observer. Do not discard, redraw, or change cases after seeing
results. Record implementation corrections separately, retaining failed runs.
Four economic ledgers: two explicit amount rows crossed with two schedules.
Each has four deposits, six varied private payments, two partial withdrawals,
and seven final one-note exits. Every ledger is run in two exit-policy arms.
All money is integer sompi. Fees are exactly 40,000,000 per operation, the
positive-note floor is 60,000,000, and payout floor 10,000,000. Zero output
slots are allowed; they are not extra owners or positive notes.

The manifest specifies private recipients and input handles for generation
only. `bootstrap` spends Alice's sole genesis note into two Alice notes.
P2 combines Bob's receipt from Alice with Bob's independent deposit. P4 and P5
also merge different receipts. W1 and W2 are partial withdrawals with private
change. The public observer receives neither this manifest nor its path,
wallet names, input handles, private values, RNG state, arm labels, or truth.
Opaque identifiers are generated independently of ownership. No random economic
workload selection is used. The same economic events, ordering, destinations,
fees and payout amounts are compared within each pair.

Schedule times are synthetic: one operation every 10 minutes, starting at
minute 0; first final exit 10 minutes after the last payment and then every
10 minutes. They are not block timestamps or measured waiting times. Schedule
1 changes deposit interleaving and reverses the drain order. There are no
background users, external payments, exchange labels, or compromised wallets.
Assume distinct unrelated funding sources and fresh payout addresses. Separately
report common-funder sensitivity: collapsing all deposit labels yields one
funding cluster, not four independent people. Four wallets are controlled by
this experiment; participant independence is an assumption, not evidence.

## Paired policies and genuine calibration

All private payments and partial withdrawals use current anchors in both arms.
Only final DRAIN authorizations differ: `fresh` proves against the current
commitment tree at exit; `saved` uses the tree immediately after the note was
created. Saved fallbacks remain private during the fresh branch. Partial
withdrawals are not relabelled as saved full exits. After every final exit,
compare the whole visible prefix; after terminal zero reserve, compare again.
The first amount row/schedule is also realized with genuine v6 Groth16 proofs
and the unchanged covenant/verification key, using synthetic native UTXOs.
Both branches must drain completely; exactly the same saved proof bytes must
settle after intervening operations. Validate native transactions and fees,
check fresh-first and saved-first mutual exclusion, and project actual public
bytes back to the model. New proofs use the existing experimental parameters;
no setup or circuit change is part of H14. Keep unused authorization material
outside Git. The other cases are explicitly model executions, not proof runs.

## Observer and exact inference target

Input is a public-only projection decoded from v6 fields: genesis value;
transaction order/time; mode; historical anchor count; two output positions for
ADMIT/SPEND; public deposit, payout and fee; reserve balance; funding and payout
identifiers. Real native calibration additionally validates framing, anchors,
commitments, ciphertext hash, nullifier uniqueness and native accounting from
transaction bytes. The observer does not see keys, openings, positive/dummy
flags, private input positions, wallet names or payment intentions. Proofs,
commitments, ciphertexts and nullifiers are assumed hiding/unlinkable except
for their public equality and structural constraints. This does not test that
cryptographic assumption. RPC queries, IP addresses, mempool timing and delivery
channels are outside the model, not declared private.

Use one integer amount variable per output, with value zero or at least the
protocol floor, and initial value fixed to genesis funding. Every spend selects
one or two distinct positive notes created before its public anchor. Each note
can be consumed at most once. Admission outputs sum to deposit minus fee;
spend inputs sum to outputs plus public payout plus fee. DRAIN creates no notes.
At each prefix, native reserve equals remaining positive private value; terminal
zero reserve consumes all positive notes, never padding. Do not impose the
hidden wallet ownership or a guessed one-input policy on alternatives.

Enumerate feasible **unordered real-input position sets**, including both
singletons and pairs. Deduplicate those into unordered sets of their creating
transaction IDs (a pair from one transaction is one source set). Report both;
never treat slot permutations, zero notes, or repeated source labels as more
people. A merged note has no protocol-defined single deposit ancestor: do not
reuse the H11 deposit-origin metric or arbitrarily assign its sompi to ancestors.
The targets are each of the six payment events, scored immediately when seen
and using the final drained transcript. Also analyze both partial withdrawals
and all final exits, and re-evaluate payments after each drain step.

## Attacks, controls and metrics

1. Public structural baseline: eligible unordered input sets under anchor/age,
   one/two-input shape and no use of hidden values. A latest-source heuristic
   ranks these sets by newest oldest input, then newest next input, then the
   position tuple. The baseline is an opportunity set, not a uniform posterior.
2. Public amount baseline: remove combinations unable to cover visible payout
   plus fee using public creation upper bounds. Bounds propagate public value
   conservation and anchors, without using true private splits.
3. Joint exact integer constraints over the complete observed history: query
   every candidate combination, recording SAT/UNSAT. Unknown is inconclusive.
   Rank surviving sets by the same fixed recency rule. Report correctness,
   singleton coverage/precision and candidate counts, paired changes, and
   retroactive collapse. Accuracy is a property of this workload/heuristic,
   not a probability that a payment is private. No attack selection by truth.

Controls must pass before reporting the screen: a single-note source is
reconstructed; a symmetric two-source fixture retains its alternatives; tiny
integer fixtures agree with independent exhaustive enumeration; all true input
sets survive; invalid conservation, impossible anchors, duplicate spends and
zero-note spending are rejected. Test model parsing and native decoder mutations.
Run the observer in a filesystem/network sandbox with only observer code,
public input and solver libraries mounted. Ground truth is scored by a separate
process after predictions are written. Record hashes and denied-access probes.

Record each target's before/after candidates, ranked correctness and exact
identifiability, plus each arm's operation count, public fee total, payout,
zero reserve, and simulated waiting times. Measure genuine calibration proof
count/time, loading time, peak memory if available and native fee/mass. Offline
execution spends zero tKAS; 19 pool operations imply 7.6 tKAS hypothetical fees
per economic branch at the chosen fixed fee. Setup/funding fees and congestion
are excluded. Fresh exits add seven proofs to the saved-exit work in this
calibration; they do not remove the private fallback requirement.

## Completion and limitations

Deliver one reproducible offline runner, frozen manifest, public results with
per-event candidate sets, genuine first-case calibration, adversarial review,
and journal/plan update. Finish when all four paired cases and controls are
accounted for, calibration matches, and the frozen decision is evaluated.
Do not add cases merely to obtain a favorable result. A small exact model can
falsify privacy against its attacks; surviving alternatives do not establish
strong privacy, equally likely histories, user anonymity or production safety.
No network experiment, consensus change, parameter setup, push or public post.

Sources: current v6 `mod.rs`, `circuit.rs`, `covenant.rs`, RFC-0011 and H13
transaction evidence; [prior source review](../../research/compact-policy-study-sources-2026-10-20.md).
[ZIP 315](https://zips.z.cash/zip-0315) motivates explicit funding, balance,
anchor and shape leakage; [ZIP 224](https://zips.z.cash/zip-0224) provides the
established real/dummy distinction. Neither transfers Orchard security to this
prototype. The mature-protocol comparisons in the source review remain
applicable: this adds an observer, not a cryptographic subsystem.
