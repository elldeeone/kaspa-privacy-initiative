# Four-view actual privacy-improvement gate

Status: **frozen before any new private input, prediction, truth scoring or
network trial.** This gate does not authorize execution. Root's immutable
selection must bind this file, the acceptance and bundle-producer sources,
observer/capture sources, workload, both fresh run selections, all eight sealed
view capsules, their pre-truth barriers, and both complete capture receipts.
Legacy v1 or hand-authored bundles are not admissible.

## Decision question

Does the hidden-mapping candidate produce an actual, measurable increase in
payment-graph ambiguity over the transparent baseline under the same fixed
workload and observer policy, while retaining the true assignment and complete
terminal coverage?

An owner-label swap alone is not an improvement. Legitimate colluder-known
edges stay fixed. The observer must retain a joint alternative in which the two
honest NF input labels exchange and each honest NF is linked to a created pair
different from truth. Eligible unknown outputs and NF-to-pair links must not be
unique. This is the minimum bounded payment-graph result; it is not
cryptographic proof or a general anonymity claim.

## Exact views

The four views are ordered and scored separately:

1. `public`: exact public candidate/chain bytes, NFs, commitments, proofs,
   amounts, fees, operation shape, rejected/orphaned candidates, reorg history
   and terminal grouping.
2. `dispatcher`: `public` plus cohort and role identities, connection/upload
   order, lengths, filenames, operation timing, receipts, routes and retries.
3. `corrupt-server-plus-wallet`: `public` plus server 1's complete selected
   shares, MAC state, randomness and authenticated transcript, and owner 1's
   Original, inputs/outputs, invoices and decrypted receipts.
4. `union`: the exact union of the preceding dispatcher and corrupt views. It
   must be constructed from those same admitted artifacts. Candidate counts in
   `union` may never exceed a weaker view.

The required categories are constants in `privacy_acceptance.py`. Every view
must carry source-derived per-category modeled/unmodeled/missing counts; one
generic `modeled_artifacts` count cannot cover many categories. A missing
category, artifact, terminal model, corrupt-server capture or retry history
makes the result `UNQUALIFIED`. Unknown opaque bytes are unmodeled, never
silently harmless.

The capture source inventories fixed closed roots into a salted private
manifest. It constructs dispatcher and corrupt side views from that inventory
and derives `union`; a caller cannot supply four unrelated lists. The public
capture receipt exposes category/count coverage and the private manifest seal,
not private paths, bodies or unsalted body hashes. The observer reopens the
same manifest and verifies an exact artifact/constraint union and candidate-set
subset lattice before it may emit a positive lattice attestation.

## Truth and sealing order

The observer receives no honest truth or honest Original. It enumerates
complete candidate assignments for all four views, including the consistent
two-round-plus-terminal candidate graph, and seals four salted capsules. A
durable public barrier binds the pre-truth comparison/run selections, capture
receipt, private manifest seal, observation receipt and every capsule before
any scorer mounts truth.

Each owner scorer mounts only that owner's truth for both rounds and emits a
private count/membership leaf, including full-workload truth-vector masks. The
aggregate role mounts the four original capsules and three private score leaves,
but no truth or Original. Public output contains counts, commitments and
booleans only. Any repeated observer, scorer or aggregate query for the admitted
trial refuses before private intake.

The only admissible public chain is capture receipt -> observation receipt ->
barrier -> three score receipts -> aggregate receipt -> bundle. The v2 bundle
derives classification and every hash from the frozen selection and fixed
actual trial paths. The CLI accepts no caller-provided classification or
coverage declaration.

## Fixed pass criteria

The transparent baseline and hidden-mapping candidate use the same comparison
selection, method, workload, observer source, capture source, coverage policy
and bundle producer. They use distinct fresh trial IDs, diagnostic/run
selections, capture identities, manifests, receipts and all eight capsules.
The baseline must retain truth and detect a payment link in **both** rounds and
in the complete workload graph. Otherwise the attack control is invalid.

The candidate passes only if all four views have zero missing/unmodeled
artifacts in every required category, a complete cross-round/terminal model,
source-derived exact-union/subset attestations and
`PASS_BOUNDED_DIRECT_CHECK`. The gate derives every view's status from its
fields; a supplied PASS label is not authority. In every view and round:

- truth, the honest 0/2 input swap, and one common graph alternative remain;
- that graph alternative keeps all colluder-known edges fixed and assigns each
  honest NF a created pair different from its true pair;
- there are at least 2 input-owner assignments, 3 output-creator assignments,
  3 output-pair partitions, 6 joint assignments and 6 NF-to-pair relations;
- at least two of the three input NFs retain at least six possible created
  output pairs (the colluder may know its own pair);
- no direct forbidden export or correct/wrong unique eligible prediction exists;
- no public ambiguity count may regress relative to the corresponding actual
  baseline view/round; and
- in `union`, output-pair partitions and NF-to-pair relations both strictly
  increase over the actual transparent baseline in each round.

For each complete two-round-plus-terminal view, the true workload vector and a
single terminal-consistent alternate graph satisfying the per-round honest
NF-input swap and different-pair predicates must remain. At least two full
workload graphs must remain, and no correct or wrong unique full-vector
prediction may exist. Full-workload candidate counts obey the same view lattice,
must not regress against baseline, and must strictly increase in `union`.

The threshold is deliberately stronger than merely exchanging owner labels:
the observer must lose the input-to-created-pair graph as well. There is no
posterior-probability claim and no averaging across failed rounds or views.

## Stop rules

- Wrong unique prediction, exclusion of truth, direct owner/pair/Delta export,
  loss of the honest input swap, loss of the alternate graph, or fewer than six
  possible created pairs for either honest NF: `FAIL_PRIVACY_GATE`.
- Missing/unmodeled view, incomplete terminal model or unavailable capture:
  `UNQUALIFIED`; do not fund or continue to Testnet.
- Baseline without a detected link in both rounds:
  `INVALID_BASELINE_CONTROL`; repair the experiment, not the threshold.
- Operational failure consumes that trial identity. Retry only with a fresh
  unfunded identity and unchanged method/source/workload/criteria.
- Do not omit amount, timing, ordering, contact, cohort, retry, rejected-candidate
  or corrupt-server evidence after observing an unfavorable result.

`PASS_BOUNDED_ACTUAL_PRIVACY_IMPROVEMENT` covers only the private-batch terminal
graph. It cannot authorize Step 3, payout broadcast, or the complete native
test-KAS rehearsal. A distinct exit-linkability receipt covering the
nine-exit/service-loss path is mandatory before Step 3. Independent
cryptographic review and the full deposit-to-independent-exit lifecycle remain
separate requirements.

METHOD03's owner-origin exit route can supply terminal-view evidence, but it
cannot substitute for the private financial batch or its server view. A
source-only or coverage-only METHOD03 result cannot pass this gate.

## Frozen execution readiness

The append-only producer contract is frozen, but it is deliberately
source-only. `privacy_capture_producer.py` emits only
`kpb-capture-producer-source-only/v1` with role hooks, inherited-FD selection,
launcher selection, launch authorization and actual-receipt emission all
false. The bundle bridge requires a distinct future
`kpb-capture-producer-receipt/v1` from selected role hooks and a selected
launcher. It rejects the source-only receipt and also rejects a synthetic
receipt that merely repeats digest-shaped source/build/launch values.

The transitive closure pins the producer, its C++ hook interface and
implementation, every observer/scorer/acceptance/launcher dependency, the
Python and bubblewrap binaries, and the root-guard helper. The Linux kernel,
dynamic loader and system libraries remain an explicit host trust boundary,
not reproducibly pinned evidence.

Therefore the current executable outcome is `UNQUALIFIED`: the scoring method
is frozen and testable, but no actual baseline/candidate bundle or privacy PASS
can be produced until genuine capture role hooks and their one-shot launcher
exist. This is a stop rule, not permission to substitute fixtures.
