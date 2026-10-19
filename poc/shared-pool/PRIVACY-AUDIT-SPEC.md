# Stage 2: compact transaction privacy audit

Recorded 2026-10-19, before running the new observer. Baseline `af9bae8`.
This is the plan's initial audit/stop gate, not a blind preregistration of the
already documented H6/H7 experiments. Their workload and old-anchor limitation
are already known. No new traffic experiment, private proof or broadcast is
authorized by this document itself.

## Question and decision

Can bounded withdrawal delay, while preserving an existing authorization,
remove deterministic identification of the transaction that created its input
note? If an early anchor fixes that source even after intervening payments,
reject delay with frozen authorization as the candidate privacy remedy. Retain
reusable authorization as an exit/liveness feature. Check a newer anchor only
as an abstract sensitivity control; do not call edited public inputs a valid
proof or a measured mitigation.

Falsifiable audit prediction: the first full withdrawal in each retained H6
sequence has exactly one possible creation transaction under public membership
and single-spend constraints, despite multiple note commitments. The same
conclusion need not hold for H7's newly proved exits. Failure of this prediction
requires reconsidering the audit argument, not redefining the target.

## Inputs and observer boundary

Use all accepted transaction bodies and block headers from H6's two-payment
rehearsal, H6's 100-payment trial and H7's three-wallet recovery trial. Project
only `transaction` and `header` from `chain-confirmed.json`; discard experiment
labels, local timestamps, RPC URLs, wallet reports, descriptors and manifests.
Derive order from reserve input ancestry. Give the observer every serialized
transaction field, including proofs, redeem scripts, payloads, public payouts
and fees. It may use block timestamps but the initial attack needs order only.
Do not interpret RPC arrival time as chain time.

The first funding transaction's reserve value and the first spend's state/count
identify a single initial claim. Its opening/commitment preimage is not needed.
Subsequent commitment positions and their creating transactions are public.
The observer knows the published circuit's rules: one input per operation,
two positive outputs per transfer, full-note exits, no later deposits, integer
sompi, 60,000,000-sompi note floor and conservation. It assumes valid accepted
proofs, the intended immutable covenant and correct retained chain history.
No cryptographic break, active malicious participant, IP/RPC access or external
identity information is modeled. Note positions are not people.

Primary target: creating transaction of each withdrawal's consumed note.
Secondary: consumed note position and funding transaction ancestry. Actual owner,
sender/recipient labels and secret note values are unavailable. The attack must
run in a filesystem/network sandbox containing only software and the projected
chain input. The scorer, separately, may use prior experiment records for the
preselected first H6 withdrawal; no private keys or note openings are exported.

## Methods, controls and measurements

1. For every withdrawal, enumerate positions eligible under its historical count
   and existence before the spend. Apply joint single-spend matching over the
   whole observed prefix; report source sets separately from position sets.
   A singleton source is a logical certificate under these assumptions, not a
   fitted posterior. Abstain otherwise. Report all-withdrawal coverage.
2. On the small H6 rehearsal and H7 trace, also enforce joint integer value
   conservation, note floors, exact public fees/payouts and complete drain.
   Query each possible input position. Solver `unknown`/inconsistency is an
   error, never evidence of ambiguity. A conservative candidate set is an upper
   bound on ambiguity, not proof of cryptographic anonymity.
3. Compare each withdrawal at its own prefix and at complete drain. Include
   source-order recency and public-candidate uniform-prior baselines, with ties
   declared. Do not invent a probability distribution over feasible histories.
4. Controls: singleton; multiple genuinely feasible sources; future-note
   exclusion; jointly impossible reuse; malformed count/state/ancestry;
   commitment relabeling; sat-model conservation; same-anchor delay invariance;
   and a newer-anchor sensitivity for the first H6 rehearsal withdrawal.
   The last changes only the abstract model, not recorded transaction bytes.

Report source/note candidate counts, singleton precision/coverage when separate
truth is available, abstentions, exact input-value exposure, native fees and
transaction counts. Existing full payouts disclose `payout + fee` exactly.
Source labels can be scored for the first H6 exit from its separately documented
workload; no unsupported all-wallet identity score. Do not attach confidence
intervals or a population anonymity score to these three selected old traces.

## Stop condition and deferred comparison

A deterministic H6 source certificate activates Stage 2's documented old-anchor
stop/redesign condition. Do not build a traffic simulator or fund another trial
to demonstrate it again. Bounded randomized delay adds time but changes no
membership constraint for an identical proof. Equal public payouts with private
change is the other planned established policy; compact state does not implement
it. Its circuit/covenant/fee changes require separate design work, and it cannot
enlarge a fixed historical membership universe by itself.

If this gate does not stop the study, preregister the planned singleton/two
low-activity regimes, seeds, independent/shared funding controls, matched eventual
withdrawals, timing and amount attacks, and the 25% inference/25% fee/30-minute
thresholds before generating/evaluating those workloads. No such statistical
comparison is claimed here. Independent later deposits into this same compact
pool are unsupported; separate pools are not a substitute for that control.

Completion here means a reproducible public-only counterexample and an explicit
retain/redesign decision, including the cost and limits of the suggested next
test. It does not mean the candidate passed practical privacy or that all of
Stage 2's conditional comparative criteria were exercised.
