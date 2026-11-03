# Native-KAS privacy research journal

This is the living record of our independent experiments: what we believe,
what would falsify it, what we observed, and what changes next. Update it when
evidence or a decision changes. Keep earlier results and their limits intact;
link detailed specifications, measurements and exact transaction evidence.

North star: private native-KAS payments, correct backing, and exits that users
can complete without privileged cooperation. No new token. Work within current
Kaspa L1; consensus changes are a last resort. Testnet only, no real funds.

The [shared-pool branch plan](SHARED-POOL-PLAN.md) maps these results to the
repository phases and defines completion, stop and redesign criteria. Recovery
and practical privacy are the next decision gates. A completed hypothesis below
does not by itself close a roadmap phase.

## Current position

Current L1 can execute the bounded direct-pool payment and withdrawal layouts
we tested. Four wallets can receive, re-spend and withdraw their own claims,
paying miner fees from those claims. This is evidence for continued direct-L1
research, not a production architecture decision or proof of general liveness.

Partial withdrawal with private change and equal first payouts preserved more
amount ambiguity in our synthetic workload. It did not improve unique-source
identification or deposit-origin ambiguity for the four selected withdrawals.
Cryptographic confidentiality, chain inference and network privacy remain
separate questions.

Version 3 now prevents below-floor claims in the proof relation. A funded
rehearsal also recovered from one competing reserve spend: the losing wallet
found the accepted successor, rebuilt its proof and confirmed its payout after
the winner stopped. A fresh measured repetition also passed. Missing public
history, fee changes, setup compromise, reorgs, contention starvation, scalability
and independent cryptographic review remain open. Cold parameter loading is a
measured usability bottleneck.

The reusable-authorization follow-up now lets Bob exit after Alice's unrelated
payment with the exact same private proof. A complete TN10 rehearsal and fresh
measured trial both passed, with Bob's prover stopped and a public-only rebuild
process taking about 21 ms. Keep this separation for further research: it removes
reproving for the tested update, at a higher native fee. Capacity, continuing
contention, initial proving/parameter loading, anchor-choice privacy and actual
anonymity remain unresolved. [Measured evidence](../poc/shared-pool/ANCHORED.md).

The compact-state follow-up now carries that exact-proof result through 100
intervening TN10 payments. All 204 native transactions and the final drain
passed. Keep compact public settlement for further research: it removes the
old array limit at the tested scale, while history retention, initial proving,
fees and privacy remain open. [Measured evidence](../poc/shared-pool/COMPACT.md).

## Hypotheses and decisions

| ID | Falsifiable claim | Evidence/status | Decision |
| --- | --- | --- | --- |
| H1 | A private native-KAS payment and authorized exits can pay their own fees on existing L1 without a sponsor or privileged withdrawal key. | Supported for one funded two-wallet sequence; four native transactions accepted. | Continue direct-L1 experiments; no need demonstrated for a vProgs runtime in this bounded case. |
| H2 | Private withdrawal change increases feasible consumed-note candidates relative to whole-note withdrawal in the paired four-wallet workload. | Supported for all four selected exits initially and three after complete drain; input amounts remained non-unique for 4/4 partial exits versus exact for 4/4 full exits. | Retain partial change for further study. Equal 0.25 tKAS payout policy was bundled with the change mechanism. |
| H3 | Enforcing a protocol-level note minimum can prevent the tiny-liability obstruction at the tested fee rate without privileged rescue. | Supported by creation-path boundary tests, 870 native mass/policy combinations and an exact-minimum claim's funded exit. | Retain a 0.26713-tKAS note floor and 0.1-tKAS payout floor in this fresh experimental version; arbitrary future fee rates remain unresolved. |
| H4 | After two wallets race on the same reserve, the losing wallet can discover accepted state, rebuild its proof and exit using its own keys and public data. | Funded rehearsal and fresh measured trial passed. Both losers generated a new proof after discovering the accepted successor and received payouts after the winner stopped. | Keep permissionless self-proving recovery. Address cold startup and sustained-contention fairness before claiming usability or general liveness. |
| H5 | Bob's private withdrawal authorization can survive Alice's unrelated payment, with public-only transaction rebuilding and no further proof. | Supported offline and in complete TN10 rehearsal/measured trials. The exact proof/auth bytes survived a change from 3 to 5 commitments; Bob's stopped prover was not needed. Full local rebuilding took 20.650/20.783 ms with no additional proof. | Retain authorization/current-settlement separation. The larger covenant raises exit fees; investigate scale, contention and anchor-choice privacy separately. |
| H6 | Compact native state can preserve Bob's exact proof through 100 payments, with no second proof or privileged settlement service. | Full offline gate, complete short TN10 rehearsal and fresh 100-payment trial passed; all 204 measured native transactions confirmed and every claim drained. | Retain fixed-depth public settlement for further research. Native size/mass stayed constant at payments 1, 10 and 100; history retention, fee cost and old-anchor privacy remain unresolved. |
| H7 | Three wallets can recover incoming payments from pre-payment backups and public data, then create their first exit proofs without the original services. | Offline passed; funded recovery in progress after a pre-broadcast RPC interruption. | Keep the initial note opening for the depositor; require independently retained public data. No complete live result yet. |

Candidate counts are marginal logical possibilities, not probabilities, people
or joint-history counts. Synthetic results must never become claims of
real-world anonymity. Passing tests is not proof of cryptographic correctness.

## Experiment record

### 2026-10-19 — Stage 1 independent recovery (H7), started

The owner authorized backup definition, offline implementation/execution and,
only if it passes, TN10 rehearsal and measured trial. All three wallets must
exit independently. [ADR-0020](adr/0020-independent-wallet-recovery.md) and
[RFC-0008](rfc/0008-independent-wallet-recovery.md) define the unchanged compact
relation, minimum backup/public-data inputs, three-wallet workload and rejection
controls. Unlike H6, these restored wallets create their first exit proofs only
after recovery.

All three offline restorations passed with one note/payout each, 26 recovery
controls, 113 inherited native rejections and complete integer reconciliation.
Keys alone cannot discover the initial deposit: Alice must retain that note's
opening. Bob and Carol's backups predate their received notes and contain none.

The first funded rehearsal confirmed funding and both payments, then stopped
before Bob's exit submission. His proof completed, but synchronous cold proving
blocked WebSocket processing and the RPC connection dropped. The reserve was
observed unspent; no submission intent existed. Close RPC during local proof
work, reconnect and recheck the current reserve before sending. A fresh offline
restoration of all three saved-fixture backups passed with the revised client.
Fresh ordinary cleanup of the interrupted pool precedes another complete
rehearsal and measured trial. No complete live H7 success is claimed yet.
See [recovery report](../poc/shared-pool/RECOVERY.md) and
[review](../poc/shared-pool/RECOVERY-REVIEW.md).

### 2026-10-19 — Branch plan established

The owner requested an explicit plan after the incremental H1–H6 experiments.
[SHARED-POOL-PLAN.md](SHARED-POOL-PLAN.md) now records the evidence baseline at
`203198b`, maps our work to repository phases 2–7, and sets five remaining stages:
independent recovery, practical privacy, failure/fee limits, a usable payment
cycle and independent review. Each has completion and stop/redesign conditions.

Recovery and privacy must inform whether this candidate warrants expansion.
Earlier variant results are not treated as features of the compact version, and
the full multi-user shutdown/recovery gate remains open. Future thresholds are
planning choices, not measured outcomes or retroactive criteria for H1–H6.
This is a documentation change; no protocol change, new experiment or funding.

### 2026-10-19 — Compact state (H6), completed bounded test

Hypothesis: 100 unrelated payments can advance the pool while Bob retains the
same private exit proof. Fixed-depth native Merkle checks authenticate current
spentness and public state updates, without an operator signature or second
proof. [ADR-0019](adr/0019-compact-public-settlement.md) records the design;
[RFC-0007](rfc/0007-compact-state.md) records the gates and unresolved questions.

- Offline: 204 native transactions, 203 genuine private proofs, Bob's identical
  authorization/proof after 100 payments and complete drain passed. All 204 SDK
  round trips and a separate public-only sandbox passed. Independent Python
  reconstruction matched the public trees, amounts, lineage and successor
  scripts. Five Rust test groups and 117 hostile native rejections passed.
- TN10: the complete two-payment rehearsal passed all eight transactions and
  terminal payout. In the fresh measured trial, all 100 intervening payments
  and Bob's original-proof payout are confirmed. Both original provers stopped
  before his public-only process discovered and verified the updates. The
  remaining 101 claims then exited. All 204 accepted transaction bodies/full
  hashes matched, and exact payouts/fees reconciled with zero reserve left.
- Work: Bob's local public rebuild took 352.426 ms, including process startup
  and native validation. Fetching accepted chain history separately took
  11,356.203 ms. The original proof took 9,759 ms and was not regenerated.
- Cost: the same 21,688,400-sompi fee and 16,514 estimated bytes at
  payments 1, 10 and 100; Bob's exit fee was 21,729,600 sompi and his payout was
  378,270,400 sompi. Trial fees totaled 4,407,152,500 sompi (44.071525 tKAS),
  including ordinary funding. Rehearsal cost 1.521885 tKAS; reusing prior ordinary
  coins cost 0.032952 tKAS. Total: 45.626362 tKAS. First submission to observed
  terminal payout took 42 minutes 2 seconds, including live proving and cleanup.
- Tradeoff: state shrank from 1,539 to 105 bytes, but the complete transaction
  grew and the continuing exit fee rose about 2.75%. Public history and wallet
  reconstruction work still grow. Native checks have fixed-depth bounds.
- Privacy: Bob's authorization remains anchored at three historical commitments
  even when current state contains 203. Those entries are not three people or
  necessarily three plausible notes. This is no anonymity measurement.
- Limits: depth-16 finite capacity, experimental setup, retained pre-payment
  bootstrap metadata, public history and a correct full-node view. No later
  deposits, partial withdrawals, arbitrary-reorg recovery or contention-fairness
  result in this variant. A separate capacity fixture passed a terminal exit
  at 65,535 commitments; its full preceding history was not executed.
- Evidence: [layout and measurements](../poc/shared-pool/COMPACT.md),
  [sanitized artifacts](../poc/shared-pool/evidence/2026-10-19-compact/README.md),
  [adversarial second pass](../poc/shared-pool/COMPACT-REVIEW.md). Earlier variants
  and evidence remain intact. Keys, note plaintexts and proving material remain
  outside Git. No push or upstream posting.

### 2026-10-19 — Reusable authorization (H5), completed bounded test

The owner authorized an offline test and, only if it passes, fresh TN10 execution.
The prior 10.845-second recovery reproved a whole state transition after one
competitor. The next question is whether we can remove that dependency rather
than merely repeat the race. [ADR-0018](adr/0018-reusable-private-authorization.md)
and [RFC-0006](rfc/0006-reusable-private-authorization.md) define the new relation,
invariant split, controls and stop conditions. No consensus change is assumed.

- Observation: offline native validation and 80 hostile controls passed. A funded
  rehearsal and fresh measured trial each confirmed six transactions and drained
  every private claim/reserve. Bob's 3.788513-tKAS payout used exactly the proof
  prepared before Alice's payment, after his prover process stopped.
- Cost: Bob's full exit cost 0.211487 tKAS. Rehearsal cost 1.058660 tKAS and trial
  cost 1.061836 tKAS; total 2.120496 tKAS. The difference is ordinary funding's
  storage mass from a smaller change output. The 21-ms local rebuild includes
  process startup and native validation, but excludes RPC and confirmation.
- What changed: private ownership/value authorization need not be coupled to the
  current reserve outpoint/nullifier state. Current native covenant settlement
  still enforces spentness, backing, complete state retention and immutable rules.
  No second proof/operator authority was introduced. Authorization initially took
  5.358/5.405 seconds for Bob; this work was not repeated for the target exit.
- Privacy consequence: a public commitment-prefix count can narrow candidate
  notes. The rule authenticates any current prefix, not a registry of historical
  block-boundary roots; wallets here use the full accepted count when proving.
  This experiment measures liveness/cost, not anonymity.
- Limits: fixed small state, one unrelated update, experimental setup, fixed fee
  assumptions, retained data/parameters and a correct full-node view. The shared
  reserve is still serialized. The continuing exit fee rose about 26.5% relative
  to v3, and cold parameter loading remained about one minute. The roughly 21-ms
  result is not proof of fair admission under continuous contention.
- Evidence: [report and exact receipts](../poc/shared-pool/ANCHORED.md),
  [adversarial self-review](../poc/shared-pool/ANCHORED-REVIEW.md). All wallet keys,
  private notes and proving material remain outside Git. No upstream post/push.

### Earlier foundation: reproduction and recovery

We reproduced upstream's four outer proofs on an RTX 3070 8GB and posted the
results on P11/#11. That evidence remains on `upstream-reproduction`.
The separate `p10-recovery-research` work recovered a fresh synthetic instance;
reproduction of the archived instance depends on unpublished public parameters.
P10 was not posted. These results motivate explicit artifact-availability
assumptions; they do not dictate which architecture our own experiments choose.
See the [recovery report](../research/p10-recovery/REPORT.md).

### 2026-10-19 — Self-funded private payment and exits (H1)

- Question: can native claims pay the actual L1 fee while preserving backing
  and allowing the recipient to withdraw without the sender's secret?
- Observation: funding, one private payment and both exits succeeded on TN10.
  Total fees were 0.492620 tKAS; no experimental reserve remained.
- What changed: the basic current-L1 mechanics are demonstrated for this
  layout. Sponsorship and an operator withdrawal signature are unnecessary for
  this case.
- Limits: single-party setup, small fixed state, retained public artifacts,
  unaudited implementation, two synthetic participants and sequential execution.
  This is not an anonymity measurement.
- Evidence: [report](../poc/self-funded/README.md),
  [RFC-0003](rfc/0003-direct-self-funded-trial.md),
  [ADR-0015](adr/0015-direct-self-funded-tn10-trial.md).

### 2026-10-19 — Four-wallet full/partial comparison (H2)

- Question: what can a chain observer reconstruct, and does private withdrawal
  change preserve ambiguity after everyone exits?
- Observation: 19 full-arm and 23 partial-arm transactions were accepted;
  every wallet drained and both reserves were spent. Fees were 2.849380 and
  3.517918 tKAS respectively. Public ledger accounting reconciled exactly.
- Inference: after drain, the selected full exits each had five possible source
  transactions; partial exits had five, six, seven and eight. All had four
  possible deposit ancestors. Full input values were exact in 4/4 cases;
  partial input values remained non-unique in 4/4 cases under the model.
- What changed: retain private change, but do not claim that more change
  outputs create more independent participants. The initial singleton spend
  remains linked, public deposits/payouts remain visible, and the four wallets
  share publicly visible funding.
- Limits: one fixed paired workload, no background users or network/RPC-client
  observation, precomputed proofs, no competing exits, wallet-only dust policy.
  The supplementary amount test was added after the first graph result; its
  timing and solver refinements are recorded in the methodology artifacts.
- Evidence: [report](../poc/shared-pool/README.md),
  [comparison](../poc/shared-pool/evidence/2026-10-19-tn10/comparison.json),
  [RFC-0004](rfc/0004-four-wallet-shared-pool.md),
  [ADR-0016](adr/0016-four-wallet-shared-pool-trial.md),
  [adversarial review](../poc/shared-pool/ADVERSARIAL-REVIEW.md).

### 2026-10-19 — Checkpoint and authorized next experiment (H3/H4)

The owner authorized a local commit of code, documents and sanitized evidence
on `shared-pool-four-wallet`, followed by the tiny-note fix and simultaneous
exit test. No push or upstream posting is authorized by this checkpoint.
Wallet secrets, note randomness and proving parameters remain outside Git.
The original worktrees and earlier transaction evidence are preserved.

Next result must record: the exact floor and fee assumptions; creation-path and
native boundary rejections; competing submissions against the same outpoint;
which transaction was accepted; how the losing wallet found and verified the
successor; proof regeneration; both actual native payouts; remaining reserve,
cost and elapsed time. A precomputed alternate winner/loser schedule alone is
insufficient evidence of independent recovery.

Checkpoint completed as `62c8550` on `shared-pool-four-wallet`; 439 files were
committed after scanning known secrets and secret-shaped JSON fields. The only
binary evidence is the earlier public verification key. Nothing was pushed.

H3/H4 design now recorded in
[ADR-0017](adr/0017-note-floor-and-independent-exit-retry.md) and
[RFC-0005](rfc/0005-note-floor-and-exit-contention.md): enforce immutable floors
in a fresh version-3 proof relation and make each wallet discover accepted
successors itself through public RPC. The earlier version-2 evidence remains
unchanged. Results and the interrupted rehearsal are recorded in the
[follow-up report](../poc/shared-pool/CONTENTION.md).

### 2026-10-19 — Protocol floor and autonomous exit recovery (H3/H4)

- Local evidence: eight native tests, five chain tests and a real sandbox/FIFO
  test passed. The proof rejects values one sompi below the applicable floor
  while accepting equal/above cases. Mass-only fixtures do not verify proofs.
- Operational failure: the first funded rehearsal stopped after its payment
  because the Node executable was outside the sandbox mount. A separate cleanup
  launch then exposed the host's restriction on nested user namespaces. Neither
  failed launch submitted an exit. Explicit Node mounting and sibling sandboxes
  fixed both causes without changing host policy or weakening wallet isolation.
- Recovery: a new cleanup identity drained that interrupted pool using the same
  autonomous wallets. It does not qualify as a successful full rehearsal.
  Its original accepted fees plus cleanup totalled 0.508184 tKAS.
- Fresh rehearsal: five transactions confirmed, one initial conflict rejected,
  both payouts received, no reserve left. Total fees: 0.508184 tKAS. Submissions
  shared one recorded millisecond; this is not exact network simultaneity.
  The loser regenerated its proof in 10.799 seconds and confirmed its payout
  16.883 seconds after its first submission. The winner had already stopped.
- Usability implication: cold parameter loading took about 142 seconds per
  wallet. Correct recovery alone does not make the current prototype convenient.
  Future fee changes and repeated competing spends can still prevent exits.
- Measured repetition: a fresh pool and fresh keys passed with submissions 5 ms
  apart. The loser reproved in 10.845 seconds and confirmed its payout 15.027
  seconds after its first submission. Both claims drained; fees were 0.508184
  tKAS. The recipient's exact-minimum note paid 0.1 tKAS after its own fee.
  The recipient won both races; the opposite live winner order was not tested.
- Total cost including the interrupted pool's cleanup: 1.524552 tKAS across
  15 accepted transactions. All three experimental reserves were drained.
- Decision: retain the protocol floor and public-data recovery path for further
  experiments. Keep the prover warm for practical use; study contention fairness
  and fee changes before scaling or claiming general exit liveness. Incorporate
  the new public floor in future inference models; do not apply it to v2 results.
- Evidence: [report](../poc/shared-pool/CONTENTION.md),
  [review](../poc/shared-pool/CONTENTION-REVIEW.md),
  [rehearsal](../poc/shared-pool/evidence/2026-10-19-contention/rehearsal/result.json),
  [measured trial](../poc/shared-pool/evidence/2026-10-19-contention/trial/result.json),
  [interruption and cleanup](../poc/shared-pool/evidence/2026-10-19-contention/interrupted-run/summary.json).

## How to extend this journal

For each bounded experiment, append its hypothesis, falsifier, assumptions,
observed result, interpretation, decision, remaining uncertainty and evidence
links. Update the status table without erasing contrary results. Put resolved
design decisions in an ADR and open choices in an RFC. Keep accepted-chain
evidence, local validation, source analysis and recommendations distinct.
