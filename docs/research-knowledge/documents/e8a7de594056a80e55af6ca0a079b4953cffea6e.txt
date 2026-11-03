# Native-KAS privacy research journal

This is the living record of our independent experiments: what we believe,
what would falsify it, what we observed, and what changes next. Update it when
evidence or a decision changes. Keep earlier results and their limits intact;
link detailed specifications, measurements and exact transaction evidence.

North star: private native-KAS payments, correct backing, and exits that users
can complete without privileged cooperation. No new token. Work within current
Kaspa L1; consensus changes are a last resort. Testnet only, no real funds.

The [shielded-KAS branch plan](SHARED-POOL-PLAN.md) defines the current ten-milestone
programme. Branch: `shielded-kas-research`, formerly `shared-pool-four-wallet`.
Historical experiment names, identities and results below are unchanged. A completed
hypothesis does not by itself close a programme milestone.

## Current position

The owner approved a broader research programme on 2026-10-20 (Australia/Sydney):
retain the direct-L1 candidate and work toward an independently usable testnet
payment system. Focus the normal privacy hypothesis on persistent shielded balances;
measure entry, cashout and emergency-exit disclosures separately. Permissionless
exit remains a requirement even when its use reduces privacy.

Milestone 1 is complete as a requirements decision. The owner adopted
[RFC-0012's targets](rfc/0012-useful-privacy-requirements.md), recorded in
[ADR-0027](adr/0027-shielded-payment-targets.md), and authorized their commit/push
followed by starting milestone 2. The targets are prospective; no current
implementation has passed this new qualification.

Milestone 2 is complete for the bounded offline integration gate in
[RFC-0013](rfc/0013-coherent-v6-lifecycle.md). The
[public replay component](../poc/shared-pool/PUBLIC-REPLAY.md) at `fa1dcf1` removes
the participant roster while preserving native funding checks. The subsequent
[own-key wallet trace](../poc/shared-pool/WALLET-LIFECYCLE.md) passes new admission,
offline receipt, original-backup recovery, payment/change, second recovery and
fresh terminal exit. Six positive proofs reconcile 32 = 29.6 payouts + 2.4 pool
fees; a separate seventh proof checks unusable delivery.
Synthetic ancestry, externally supplied offline heads and same-host isolation
remain explicit. Live acceptance, general recovery and the adopted targets
are not qualified by this result.
Integration, cryptographic review and privacy evaluation remain separate work.
The owner has moved the first current-candidate privacy gate ahead of dedicated
milestone 3 work. Evaluation continues against the unchanged milestone 1 targets.
Milestone 7 becomes broader validation. The public-surface audit and
[first calibration slice](../poc/shared-pool/EARLY-PRIVACY.md) are complete:
later withdrawals narrow one payment amount's upper bound, without forcing either
ordinary payment amount in the tested models. The
[32-role/eight-adversary first stage](../poc/shared-pool/POPULATION-PRIVACY.md)
has started: 26 controls passed and four paired request sets generated. The
full-history solvers have produced no predictions; interrupted searches and a
confirmed Z3 out-of-memory kill are preserved. A narrower local search completed
all eight histories with no forced undisclosed facts. A separate cashout-guessing
batch also completed all eight:
99/99 primary immediate-cashout amounts were recovered exactly; the strongest
of three simple attacks guessed 5/99 persistent amounts within 10%, none exactly.
All predictions were sealed before scoring and every history passed both original
full-model truth checks. These bounded results are not a privacy pass. The M2
recovery trace itself establishes no privacy result.
The subsequent [native address-reuse diagnostic](../poc/shared-pool/ADDRESS-REUSE.md)
completed seven genuine offline proofs and found a conditional internal-payment
disclosure. The owner authorized a fresh-v2 funding-key separation follow-up
under [ADR-0030](adr/0030-separate-funding-and-exit-keys.md), preserving exact
legacy backup behavior. The [offline retest](../poc/shared-pool/ADDRESS-KEY-SEPARATION.md)
passes ten genuine proofs, original-backup recovery and native payout spending.
Both fresh-v2 cases remove this script-equality inference; the legacy control
retains it. The subsequent
[stronger practical screen](../poc/shared-pool/POPULATION-PRIVACY-STRONG.md)
completed sixteen fresh histories: the strongest tested variant guessed 3.72%
of primary senders, 5.68% of recipients and 4.34% of amounts within 10%, only
slightly above its prior. No raw cap exceedance or certified breach was found
in the declared primary comparisons.
All histories, full-model truth checks and independent recounts completed.
This is a bounded synthetic result with wide uncertainty and limited attacks;
the 32-role gate remains open.
The subsequent [native usage screen](../poc/shared-pool/NATIVE-USAGE-PRIVACY.md)
has completed and raised finite-case privacy warnings. At the next public
withdrawal, C+D guesses 12/36 honest-to-honest amounts within 10%, against prior
7/36. This exceeds the absolute and prior-improvement caps; the prior alone
does not exceed the observed absolute cap. Investigate withdrawal-related
inference before dedicated milestone 3 work. The completed native accounting
and full drainage do not qualify privacy.
The subsequent [working-balance comparison](../poc/shared-pool/WORKING-BALANCE-PRIVACY.md)
is complete and fails its frozen directional gate. Partial payouts improve the
overlapping independent-demand case, but sparse pooled final amount guessing
is unchanged at 11/37 and receipt-correlated cashouts become more guessable.
All eight arithmetic histories conserve value and drain. Retain partial payout
and change as mechanics; do not adopt this wallet policy or begin its conditional
native continuation. The next question is whether sparse split/tail hits follow
actual change lineage or common-price coincidences, alongside the practical
cash-demand correlation assumption.
The [primary-source review](../research/shielded-kas-privacy-requirements-2026-10-20.md)
and earlier capability map remain the starting evidence. No new funded trial,
paid service, recruitment or upstream publication is initiated by this step.

## 2026-10-21 — Working-balance withdrawals: mixed benefit, frozen gate failed

The owner authorized committing/pushing the investigation, then comparing
whole-note withdrawals with partial payouts and private change under frozen
attacks and criteria through a completed result. The investigation was pushed
as `feef0e02150aca9f74081c89e75ffd7a2a31fb69` on `shielded-kas-research`.
[RFC-0016](rfc/0016-working-balance-withdrawals.md) and
[ADR-0031](adr/0031-arithmetic-working-balance-screen.md) scope the new comparison
as an arithmetic rejection screen before native integration. Existing wallet,
proof relation, setup, key derivation and exit invariants stay unchanged.

The [specification](../poc/shared-pool/WORKING-BALANCE-PRIVACY-SPEC.md), model,
13 attacks, scorer and controls were frozen before fresh sampling. The
[prefreeze review](../poc/shared-pool/WORKING-BALANCE-PRIVACY-REVIEW.md) and a
complete public-seed rehearsal passed. A rehearsal sandbox argument-limit
failure was fixed by staging the same exact file allowlist read-only; original
predictions were preserved and stricter scoring agreed exactly. Development
accuracies were not used to select attacks or thresholds.

Fresh attempt `working-balance-privacy-20261021-01` froze at 05:53:27 UTC and
sampled at 05:53:48, after 68 isolated public unittest cases passed. Four fresh
economic histories each ran under both policies: overlapping/sparse activity
crossed with independent/half-receipt-correlated cash requests. Each history has
32 roles, eight colluders, 64 private payments, 32 cash requests, two urgent
exits and final drainage. Cash requests earmark native liquidity, not merchant
spending; whole-note overshoot remains owned and reusable. There is no cover
traffic, extra subsidy or compulsory exit delay.

All 1,506 observer jobs sealed before truth scoring, which completed at
06:05:05 UTC. Every obligation and all eight independent arithmetic replays
pass, including ownership, unique consumption, bridge ancestry, fee accounting
and zero final reserve. This establishes arithmetic consistency, not native
proof validity, signing, real latency or backup recovery. A separate public
[aggregate audit](../poc/shared-pool/artifacts/working-balance-result-audit-20261021.json)
finds no discrepancies across 48 groups, 7,800 metric rows, 16 decisions and
eight accounting summaries. Its six public control groups pass; it does not
independently recompute accuracy against hidden per-payment truth.

**Result:** overlapping independent-demand amount guessing falls 13/40→8/40
for both observers at next payout and final drainage, matching prior 8/40.
Sparse C+D improves only 10/37→9/37 (2.70 points), below the required five.
Sparse pooled final stays 11/37 in both arms: the candidate's `split_tail`
reaches 5.41 points above prior 9/37. Some identity non-regression gates fail
too, but arm-specific creation priors already differ; do not label every such
count difference as a new causal withdrawal disclosure.

In receipt-correlated stress cases, partial payout amount scores worsen to
21/42 and 22/36, with 19 and 21 exact hits from the half-cash inverse attack.
Their earlier-prefix guesses remain available after drainage. Stress amount
scores were reported separately under the frozen contract. Exact matches may
include common-price coincidences; the 45-tKAS prior optimizes within-10%
accuracy and is not an exact-match information baseline.

Partial payouts eliminate ordinary-request overshoot and avoid 11/13 re-entries
in the independent cases; 16 and 17 retained partial-change notes are consumed
by later PAYs. Modeled total fees are 68.811→68.800 and 71.213→69.600 tKAS
there, but rise 64→68.4 and 63.201→69.201 in the correlated cases. The low-value
ordinary-fee gap and the prior/absolute-privacy target conflict remain. No
capital-normalized fee ratio qualifies the adopted lifecycle target.

**Decision:** preserve the failed frozen gate and stop its conditional native
continuation. Partial payout/private change remains useful mechanics, not an
adopted privacy fix. The next exploratory diagnosis should classify sparse
split/tail support against actual change lineage and price coincidences, then
inform a separately frozen candidate if warranted. Do not retune this result.
The [full report](../poc/shared-pool/WORKING-BALANCE-PRIVACY.md) and
[public evidence package](../poc/shared-pool/evidence/2026-10-21-working-balance/README.md)
retain the mixed findings. No real funds, broadcasts, new token or milestone
qualification follows; new comparison work remains local at this checkpoint.

## 2026-10-21 — Withdrawal amount investigation

The completed native result, public evidence, independent arithmetic recount,
RFC status and branch plan were committed and pushed at
`2c036c0fe01b11ee68306c90ca8cfd56d7e0235f`. The owner then directed investigating
why withdrawals improve amount guesses and what might reduce the leakage.

The [source investigation](../research/shielded-kas-withdrawal-privacy-2026-10-21.md)
finds a concrete wallet-policy mechanism: whole-note EXIT publishes the selected
notes' sum minus a public fee. The frozen attacker adds the fee and optionally
subtracts a known co-input, then ranks plausible payment/change explanations.
Modeled times affect recency ranking; they are not real network measurements.
The post-run trace reproduces 864 sealed guesses exactly. At the next public
withdrawal, C+D's twelve within-10% hits are six exact true-receipt whole exits,
five approximate matches to other receipts and one prior fallback. Compared
with prior seven hits there are eight gains and three losses. Pooled's ten hits
are the same six exact receipt matches and four prior fallbacks. Native-graph
and residual amounts coincide for all 36 targets at that horizon; no selected
graph ownership tier explains the improvement. Actual receipt relationships
are scorer-side diagnostic facts, not newly supplied observer inputs.
The [aggregate diagnosis](../poc/shared-pool/artifacts/native-usage-withdrawal-diagnosis-20261021.json)
passes twelve public controls and source review. Its first final-drainage phase
label was corrected with the initial artifact retained; all non-phase aggregate
counts stayed identical. No original privacy result or frozen input was changed.

The existing v6 relation already supports partial native payouts with private
change; the current own-key wallet command does not expose that operation.
Retain optional balance-based cashouts as the candidate to compare, with later
private spending and full final drainage. A fresh address does not hide value,
and partial payout followed by a linkable tail reconstructs the original amount.
H17/H18 evidence remains unchanged; the failed short-delay policy is not adopted.

The proposed comparison must match external cash needs, account for baseline
over-withdrawal and candidate underfulfillment, include tail/re-entry fees, and
allow stronger observers to ignore extra disclosures and use the public-only
strategy. A directional privacy improvement would not fix the known fee gap or
the 21.10% expected price-prior accuracy against a 20% absolute target. No target,
wallet behavior, proof relation, exit invariant or parameter identity is changed
by this investigation; no fresh experiment or funded trial is started.

## 2026-10-21 — Native usage privacy: completed with warnings

Generation completed at 04:05:40 UTC, the prediction batch was sealed at
04:12:30 UTC and scoring completed at 04:13:25 UTC (15:13 Australia/Sydney).
The frozen attempt completed 159 proof-bearing operations, including 64
ordinary payments and 59 withdrawals, with all claims drained. Native replay,
whole-experiment integer accounting, original-backup preservation and both
concrete-witness solver checks passed. All 83 prefixes, ten observer profiles
and 1,920 target/profile/horizon combinations completed.

A separate post-run arithmetic recount agrees with every aggregate score and
warning: zero discrepancies across 228 comparison groups, including 2,400
metric counters and 1,440 ranked counters. It checks the completed prediction
seals before its sole fixed hidden-truth read and imports no frozen scoring
logic. Twenty public controls passed. The closed-allowlist public exporter
passes 31 controls, preserves exact bytes/hashes (with reversible prediction
compression), and excludes seeds, backups, full truth and honest wallet records.

Primary results concern 36 honest-to-honest payments. C+D residual/native-graph
amount guesses at the next public withdrawal hit 12/36 within 10% (33.33%),
versus prior 7/36 (19.44%): +13.89 percentage points. Exact hits are 6/36.
Final C+D attack accuracy is 10/36 (27.78%); pooled next-withdrawal/final
accuracy is also 10/36. The observed prior alone remains below 20%, unlike its
21.10% expectation under the published mixture. Preserve that distinction.

The score records 95 amount comparison warnings and one P1 final split sender
warning (2/36 versus prior 0/36, +5.56 pp). These repeated comparisons are not
independent discoveries or certified population breaches. No primary joint
sender–recipient guess is correct. Four public native bridge edges produce
one correct same-owner guess, one cross-user false positive and two abstentions
per profile; value flow is not ownership proof.

**Decision:** preserve the finite-case warning and the frozen criteria. Document,
commit and push the evidence, then investigate the withdrawal inference and
candidate mitigations. No protocol change, new privacy qualification, funded
trial or milestone 3 authorization follows. Later analysis of this seen history
must be labeled exploratory. The [report](../poc/shared-pool/NATIVE-USAGE-PRIVACY.md)
links the public evidence and its exact identity/serialization receipts.

### Prospective design retained

The owner authorized committing/pushing the completed stronger screen, then
starting a new test with more realistic usage and actual transaction data.
Checkpoint `9ae5b3efeb1698cf45d35e064c95f91c1ac5a54e` is pushed to
`origin/shielded-kas-research`. The preceding results and private evidence remain
unchanged.

[RFC-0015](rfc/0015-native-usage-privacy-screen.md) and the
[prospective specification](../poc/shared-pool/NATIVE-USAGE-PRIVACY-SPEC.md)
define one fresh 32-wallet/eight-colluder native history: 64 payments, uneven
activity, repeat counterparties, common/irregular invoice values, receipt spending,
intermediate withdrawals and four genuine self/cross-user re-entry controls.
The initial ownership directory is explicit side information. Native value flow
is not silently promoted to common ownership. Each observer gets only the
transactions, parents and participant records available at its declared prefix.

Use current v2 wallet/proof semantics and existing parameters. New experiment
helpers vary funding amounts and sign ordinary payout-to-funding transfers while
preserving all checks. Freeze source, binaries, workload, attacks and criteria
before hidden seed sampling or fresh wallet creation. Seal all predictions before
scoring. The planned outcome is a finite native-case measurement, not population
qualification; no funds, broadcasts or observed network timing are involved.

Frozen at 2026-10-21 01:21:18 UTC, before seed sampling at 01:21:42 UTC:
`f841e1d66a1f3e5fdd564aefe035701e3a32c41ffe0f7d4ca498d94509e74ac5`.
All 109 isolated development control groups passed (4 runner, 13 generator,
36 adapter, 30 observer, 26 scorer). Separate native-context negative controls,
published native replay and a full-size public-fixture solver check passed.
At that pre-run checkpoint generation had started and no privacy result was
asserted. The fixed
honest amount prior already predicts about 21.10% within 10% under the published
usage mixture, exceeding the 20% absolute target in expectation. Preserve this
pre-run warning and measure transaction-derived advantage separately.

## 2026-10-21 — Stronger practical privacy screen

The owner authorized freezing attacks and criteria, then running fresh
32-user/eight-adversary histories through a result. Candidate `52c2092` preserves
the preceding key-separation implementation and evidence. The new
[specification](../poc/shared-pool/POPULATION-PRIVACY-STRONG-SPEC.md) and
[source review](../research/shielded-kas-strong-privacy-screen-2026-10-21.md)
were frozen before sampling hidden seeds. No previous attempt was overwritten.

**Question:** can known deposits/notes, nonadaptive amount tags, chronology and
later cashout splits reveal internal persistent-balance payments? Three fixed
heuristics and a policy-aware prior predict sender, recipient and amount, with
selective relationship rankings. They make guesses, not disclosure certificates.
Freeze 16 independent four-round histories, eight overlap/eight sparse, the
pooled final view, unchanged RFC caps, and simultaneous bounds for 99 comparisons.
The prospective specification explicitly excludes a qualification pass at this
sample size and scope.

**Execution:** all 62 control groups passed before hidden seed generation.
All 16 predictions were sealed before any scoring. All 2,048 ordinary payments
were predicted; 968 meet the primary honest-to-honest/post-admission predicate.
Every history drained with exact accounting and passed actual-truth checks in
both original full encodings. There was no solver failure, missing request,
seed replacement, history retry or post-score attack change.

**Result:** `bounded-screen-complete-no-certified-breach`, with no raw cap
exceedance in the declared primary comparisons either. Split balance was
strongest on the pooled primary metrics:
36/968 senders, 55/968 recipients and 42/968 amounts within 10%, against prior
counts of 31, 52 and 37. It guessed both parties correctly on 3/968 and the exact
amount on 1/968. Those hits are not uniqueness proofs. Selective relationship
precision stayed low. A separate author-team checker reproduced all sixteen
scores and all 99 intervals; it is not an external audit.

**Interpretation:** retain the candidate for further testing, with no new wallet
policy or milestone-3 clearance. The sixteen-history rate-bound radius is about
50.88 percentage points, so the absence of a certified breach is weak evidence
by itself; the low raw rates describe only these attacks and this artificial
workload. Native bytes/network observations, other views/horizons, adaptive
attacks and independent users remain untested. More histories alone cannot fix
these omissions. Keep earlier cashout, legacy-key and H16/H18 failures intact.

**Retained outcome:** [report and evidence](../poc/shared-pool/POPULATION-PRIVACY-STRONG.md).
Private seeds/truth stay outside Git. Frozen sources and original evidence remain
unchanged. No native proofs, funds, broadcasts, setup or protocol changes were
made. Next scope the missing observations and qualification power prospectively;
do not reinterpret this completed screen as anonymity or cryptographic security.

## 2026-10-21 — Funding-key separation and backup compatibility

The owner authorized committing/pushing the completed address-reuse result,
then separating funding/exit derivation and rerunning the test. Checkpoint
`b62cfd1910d77f9962882b1088d6cc718e7df1b2` is pushed to
`origin/shielded-kas-research`. Earlier experiment sources/evidence are preserved.

**Decision:** [ADR-0030](adr/0030-separate-funding-and-exit-keys.md) assigns a
funding-specific HMAC label to fresh v2 backups and preserves the exit derivation
byte-for-byte. Explicit legacy v1 backups keep both old paths and their known
reuse risk. Unknown/mixed profiles reject. No automatic migration, new secret,
proof relation, setup, privileged role or changed invariant is introduced.

**Prospective checks:** fixed derivation vectors and profile/ownership controls;
fresh v2 matched-index/different-index histories; a fresh legacy backup generated
by the frozen old CLI and recovered by the new wallet; unchanged original-backup
restoration and native payout spending; unchanged privacy observer and retained
positive control. Freeze the new experiment before wallet creation and seal
predictions before truth scoring. No funds or broadcasts are authorized here.

**Observed:** 35 focused implementation tests and all ten genuine native proofs
passed. Both fresh-v2 cases use different funding/exit scripts, including equal
numeric indices. The genuine v1 backup made by the old CLI derives exactly the
same funding information under both binaries and retains its old script reuse.
All three fresh recovery processes discover the expected notes from original
backups, generate valid exits and sign valid native payout spends. Each history
reconciles 32 = 30.4 payouts + 1.6 pool fees with zero reserve. Eight invalid
requests reject, including the intended wrong-purpose ownership errors; 45
process guards and all 76 before/after source/binary pins pass. No funds,
broadcasts, setup changes or new chain-acceptance evidence are involved.

**Privacy result:** all three predictions were sealed before any private scoring.
Actual truth passes both original encodings. Sender, recipient and amount remain
ambiguous in all four observer profiles for each v2 case. Only the legacy final
linked profile forces all three, and the historical public positive control
still works. This is removal of the tested conditional inference, not a privacy
level, anonymity rate, external cryptographic audit or 32-role gate pass.
An adversarial author-team review independently checked 180 saved satisfying
assignments and 24 fresh solver queries for all six forced facts, including the
historical positive control. It also checked source identity, all intended
rejection causes, process isolation and seal-before-score order, with no blocker.

**Next boundary:** preserve explicit v1 compatibility and its recorded weakness;
do not relabel old backups as a privacy migration. Continue testing stronger
practical attacks and persistent shielded balances before dedicated milestone 3
work. Arbitrary native UTXO/index discovery and general recovery remain open.
[Report, exact identities and evidence](../poc/shared-pool/ADDRESS-KEY-SEPARATION.md).

## 2026-10-21 — Native funding/exit address reuse

The owner authorized committing/pushing the completed population checkpoint,
then testing native script reuse offline. Checkpoint `dbf4dac` was pushed to
`origin/shielded-kas-research`; the new experiment is a local continuation.
The [prospective specification](../poc/shared-pool/ADDRESS-REUSE-SPEC.md) and
executable/dependency bytes were frozen before fresh wallet generation.

**Observed:** seven genuine proofs completed two matched economic histories:
20-tKAS founding, 12 admission, 19.2 internal payment and terminal 30.4 payout.
Each reconciles 32 = 30.4 payout + 1.6 pool fees. Funding index 3 repeats B's
mandated exit script; index 0 avoids the equality. Both histories pass native
validation and independent replay. There were no funds or broadcasts; ancestry
and expected heads are synthetic. Four invalid wallet requests were rejected.

**Privacy result:** both isolated predictions were sealed before either private
scorer ran. CP-SAT and Z3 force sender A, recipient B and exactly 19.2 tKAS only
for the matching final history when the script-derived owner link is included.
The same transcript without that link, the different-index control, and all
creation-horizon profiles leave those fields ambiguous. Actual truth satisfies
both encodings in both arms. Seven control groups passed; a second author-team
review independently checked 90 saved hypothetical assignments and the public
scripts, anchors, native replay identities and observation/scoring order.

**Limits:** this is a two-funded-wallet diagnostic, not the 32-role workload.
The full three-field deduction assumes known distinct funding-owner pseudonyms,
self-bootstrap with zero change, self-admission and own-key/common-owner exits.
Generic wallet PAY does not enforce self-bootstrap. Without that assumption,
A could bootstrap to B and B could self-pay; sender uniqueness no longer follows.
The report separately gives an analytic recipient deduction from positive last
PAY output, immediate full drainage, valid backing/conservation and the exit
ownership binding; that is not a newly tested relaxed-bootstrap solver model.
No ambiguity score establishes real-world anonymity or cryptographic security.

**Next:** review separate funding and exit key derivation with explicit backup
version/recovery behavior. Keep the failed current behavior and controls as
regressions. Do not silently change old backup interpretation or mistake removal
of this link for a fix to amount/timing inference. No protocol/key change or new
funded test is part of this result. [Report and evidence](../poc/shared-pool/ADDRESS-REUSE.md).

## Evidence position through H18

H18's [scheduled-payout comparison](../poc/shared-pool/SCHEDULED-PAYOUT.md)
is complete: the frozen privacy gate fails, while fees and delay pass.
Across 24 new paired ledgers, the strongest fixed attack has the same success
with full and scheduled partial exits: 22/84 and 23/84 chain-only guesses,
93/252 and 95/252 separate-participant guesses, for overlapping and sparse
activity respectively. These are synthetic attack outcomes, not privacy levels.
All 48 sparse common payouts have one correctly matched, time-compatible tail
under the declared normal-policy/clock assumptions. Some alternatives widen
with overlap, but the required reduction in guessing success is absent.

The policy adds 1.6 modeled tKAS per ledger (21.05%) and 16 synthetic minutes
at p95. All 252 observations, 504 original-graph checks, nine controls repeated
under the solver replay setting, and a separate immediate-change exit control
complete. One memory-exhausted observation is recovered with one solver worker;
no rule, workload or completed prediction is changed. Reject this particular
short-delay policy as a demonstrated privacy mitigation. The conditional
native/TN10 step is not triggered; zero funds or new proofs are used. Stage 2
remains open. Keep private change and independent exits; decide how to handle
isolated complete cashouts before another wallet or live implementation.

H17's [common-size partial payout test](../poc/shared-pool/COMMON-PAYOUT.md)
passes its frozen privacy screen and genuine offline exit checks. Separate
participant views force 4/28 original cashout sources after complete drainage,
down from 7/28. No pair regresses and original payment links remain 4/24;
chain-only cashout links stay 0/28 and payment links 2/24. All four wallets exit
independently, with seven saved final proofs unchanged.

Size and criteria were committed in `71d2aca`: one 200,000,000-sompi payout per
wallet, all tails and fees included. The four extra operations cost 160,000,000
sompi; total pool fees rise from 7.6 to 9.2 test KAS. The fixed schedule adds
40 synthetic minutes against the unchanged 30-minute target, so the combined
gate fails and Stage 2 remains open. Keep optional common cashouts as a research
candidate; assess practical scheduling separately before wallet expansion.
Twenty complete observations, 40 original-witness checks and the genuine
calibration pass. This establishes no real-world anonymity or new live result.

H16's [participant-disclosure study](../poc/shared-pool/PARTICIPANT-PRIVACY.md)
fails its strict screen: one participant's records expose two additional
early fresh-policy payment sources. Across separate participant disclosures,
4/24 fresh payments and 7/28 fresh full exits have a forced source, versus
6/24 payments and 28/28 exits with saved proofs. These are distinct synthetic
targets linked by at least one eligible participant, not one pooled observer
or an anonymity percentage. Fresh retains more payment alternatives in all
sixteen matched case/participant pairs. Keep fresh normal proofs and private
fallbacks; prioritize withdrawal-amount policy before wallet expansion.
Strong privacy remains open. All 64 observations and 30 controls complete,
with truth retained and 1,216 original amount/input-graph prefix checks passing.
No new proofs or funds were used.

The two new fresh payment links were already visible at startup: excluding the
participant's own deposit leaves only the bootstrap source. Later fresh exits
do not create additional unique payment links in these fixtures, but participant
records expose some partial and full withdrawals. H17 tests the resulting
common-payout question through complete drainage and all fees. Its measured
cashout improvement leaves those earlier payment links unchanged.

H14's [genuine calibration](../poc/shared-pool/TWO-INPUT-RECONSTRUCTION.md)
remains unchanged: all four wallets paid, seven saved proofs preserved, both
branches drained. H15/H16 inherit these mechanics; they do not rerun or extend them.

H13 now passes its **bounded offline and TN10 payment/exit trace**. The documentation was
committed first as `c50855a`; the new immutable v6 circuit/covenant supports
two-input payment, private change and partial withdrawal change that can be
spent again. All four wallets receive payouts through six unchanged saved
proofs, with correct native backing and zero remaining reserve. Genuine proofs
and native validation first used synthetic UTXOs. The live continuation adds
actual funding and isolated clients that discover accepted history and submit
their exits without the stopped prover or controller state. They share one host
and one correct RPC, with four known depositors. General recovery and real-world
anonymity do not follow. The [offline](../poc/shared-pool/TWO-INPUT.md) and
[TN10](../poc/shared-pool/TWO-INPUT-TN10.md) reports record cost, controls and gaps;
[RFC-0011](rfc/0011-two-input-private-payments.md) remains Open. Keep this relation
as a research candidate and preserve older variants. H14–H16 below add
merging/padding, known-client and participant observers. Independent review, broader
qualification, cold-start cost and strong privacy remain open.

H12's equal-net funding comparison passes its frozen offline screen. With all
four deposits before payments, every withdrawal retains four funding candidates
through complete drain, versus 91.875% / 84.115% uniquely identified under varied
funding and 24.063% / 22.656% under equal gross funding. Genuine proofs match the
model and all saved/fresh offline drains pass. A complete TN10 rehearsal and
fresh measured trial passed: all four wallets paid and zero reserve remains.
Keep fresh proofs, private fallbacks and equal net credits as a candidate wallet
policy. This bounded symmetry does not establish real-world privacy or protect
early exits. [H12 report](../poc/shared-pool/NORMALIZED-DEPOSITS.md).

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

Stage 1 recovery now passed offline and in complete TN10 rehearsal/measured
trials. Three wallets restored from pre-payment backups on a separate host,
discovered their notes and created their first exit proofs after the original
services stopped. Keep the initial depositor's note opening as well as the three
keys and pool pin. Public history/parameters must remain independently available.
Useful privacy remains a decision gate. [Evidence](../poc/shared-pool/RECOVERY.md).

Stage 2's initial audit now identifies the source transaction of Bob's H6 exit
from public fields alone, despite 100 intervening payments. Keep reusable proofs
as independent exit fallbacks; frozen-proof waiting cannot fix this source link.
A genuine matched offline fresh-proof comparison now increases source candidates
from 1 to 3/5 after two/four payments, while both proofs remain independently
usable until one spends. The singleton remains linked. Keep a fresh normal-path
candidate and private fallback; the traffic-policy thresholds remain untested.
[Audit](../poc/shared-pool/PRIVACY.md), [comparison](../poc/shared-pool/FRESH-PROOF.md).

[H10](rfc/0010-compact-independent-deposits.md) now implements independently
funded deposits in a fresh immutable v5 pool, reusing the exact private relation
and parameters. The offline gate passed all eight saved exits in four drain
orders, plus backing/spentness/delivery controls. Complete TN10 rehearsal and a
fresh measured trial also passed: all eight saved proofs settled, all four
wallets received their payouts, and both pools drained.
This supplies admission mechanics for the population study, not a privacy
result. [Report](../poc/shared-pool/DEPOSITS.md).

## Hypotheses and decisions

| ID | Falsifiable claim | Evidence/status | Decision |
| --- | --- | --- | --- |
| H1 | A private native-KAS payment and authorized exits can pay their own fees on existing L1 without a sponsor or privileged withdrawal key. | Supported for one funded two-wallet sequence; four native transactions accepted. | Continue direct-L1 experiments; no need demonstrated for a vProgs runtime in this bounded case. |
| H2 | Private withdrawal change increases feasible consumed-note candidates relative to whole-note withdrawal in the paired four-wallet workload. | Supported for all four selected exits initially and three after complete drain; input amounts remained non-unique for 4/4 partial exits versus exact for 4/4 full exits. | Retain partial change for further study. Equal 0.25 tKAS payout policy was bundled with the change mechanism. |
| H3 | Enforcing a protocol-level note minimum can prevent the tiny-liability obstruction at the tested fee rate without privileged rescue. | Supported by creation-path boundary tests, 870 native mass/policy combinations and an exact-minimum claim's funded exit. | Retain a 0.26713-tKAS note floor and 0.1-tKAS payout floor in this fresh experimental version; arbitrary future fee rates remain unresolved. |
| H4 | After two wallets race on the same reserve, the losing wallet can discover accepted state, rebuild its proof and exit using its own keys and public data. | Funded rehearsal and fresh measured trial passed. Both losers generated a new proof after discovering the accepted successor and received payouts after the winner stopped. | Keep permissionless self-proving recovery. Address cold startup and sustained-contention fairness before claiming usability or general liveness. |
| H5 | Bob's private withdrawal authorization can survive Alice's unrelated payment, with public-only transaction rebuilding and no further proof. | Supported offline and in complete TN10 rehearsal/measured trials. The exact proof/auth bytes survived a change from 3 to 5 commitments; Bob's stopped prover was not needed. Full local rebuilding took 20.650/20.783 ms with no additional proof. | Retain authorization/current-settlement separation. The larger covenant raises exit fees; investigate scale, contention and anchor-choice privacy separately. |
| H6 | Compact native state can preserve Bob's exact proof through 100 payments, with no second proof or privileged settlement service. | Full offline gate, complete short TN10 rehearsal and fresh 100-payment trial passed; all 204 measured native transactions confirmed and every claim drained. | Retain fixed-depth public settlement for further research. Native size/mass stayed constant at payments 1, 10 and 100; history retention, fee cost and old-anchor privacy remain unresolved. |
| H7 | Three wallets can recover incoming payments from pre-payment backups and public data, then create their first exit proofs without the original services. | Offline, complete TN10 rehearsal and fresh measured trial passed. All three payouts confirmed and every claim drained; an interrupted first attempt was also recovered through ordinary exits. | Retain this recovery path and declared backup/public-data requirements. Cold loading, data retention and useful privacy remain open; proceed to Stage 2's privacy audit. |
| H8 | Public anchor and single-spend constraints uniquely identify the source transaction of the first H6 full exit even after later payments. | Confirmed in retained two-payment and 100-payment traces by an isolated chain-only observer. Coverage 1/4 and 1/102; source certificate leaves two note positions. Small joint-value and fresh-anchor controls also executed. | Stage 2 audit complete with redesign: retain exit fallback, reject frozen-proof delay for this case, test fresh authorization next. Privacy policy thresholds and real-world anonymity remain unestablished. |
| H9 | A genuinely fresh proof for the same note/payout removes the old source singleton when later activity exists, while the old proof remains a private independent fallback and only one can spend. | Supported offline in two/four-payment fixtures: 1 → 3/5 source candidates through full drain; singleton stays 1. Both winner orders reject the other proof, six no-prover rebuilds pass and all claims drain. | Retain fresh authorization as a candidate normal path and private fallback for exit. No added native fee; about 9.5 seconds extra warm proof work. Population privacy, common-anchor policy and real-world anonymity remain open. |
| H10 | Three later signed native deposits can each add two backed claims without invalidating saved exit proofs; all four wallets independently drain their eight notes. | Offline plus complete TN10 rehearsal/fresh trial passed. All four wallets paid using eight unchanged saved proofs; both reserves drained. | Retain this admission candidate for the population privacy study; Stage 2 remains open. Preserve v4 evidence; use a new immutable pool with the exact existing private relation/VK. |
| H11 | Fresh latest-root proofs reduce full-coverage source inference by at least 25% in both frozen low-activity regimes, within the fee/delay screen. | Passed: 35.6% / 61.5% reduction through complete drain; 64 primary ledgers plus 17 controls. Two genuine native calibrations match; four no-prover drains pass, with zero extra native fee. | Retain fresh proofs/private fallbacks. The bounded study is complete; funding origins remain mostly exposed. Test equal net credits separately before a larger relation change. |
| H12 | Equal net credits reduce deposit-origin inference through full drain while preserving independently payable saved/fresh exits. | Passed in 64 paired ledgers; 0/704 equal-net withdrawals uniquely assigned to a deposit. Genuine calibrations, saved/fresh adapter drains, complete TN10 rehearsal and measured trial passed; all four wallets independently paid. | Retain the bounded candidate funding policy on the existing relation; interleaving, mixed amounts and external knowledge remain open. |
| H13 | Two private inputs can fund varied payments/change and partial withdrawals while every positive note retains an independent exit, including an unrelated unchanged saved fallback after later activity. | Supported for the bounded offline/TN10 trace: 13 pool operations, four wallets paid, six unchanged saved proofs, private change re-spent, backing reconciled to zero. Live clients independently reconstruct accepted history on one host/RPC. Constructed capacity-boundary exit passes; general recovery and broader qualification remain open. | Retain v6 as a research candidate. Selected fee 0.4 tKAS, warm proof about 20–22 seconds; review cost and merging/padding inference before further runs. No privacy outcome is claimed. |
| H14 | Fresh exits retain multiple payment-source combinations through full drainage in at least half of six payments per case, and increase alternatives relative to saved exits in at least one case, without losing independent exits. | Frozen at `1bf14d0`; modest screen passed in four paired offline ledgers. Fresh ambiguity is 5/6 or 6/6, with more source alternatives in two cases. Unique payment links remain 2/24 in both arms; full-exit recency guesses fall from 28/28 to 8/28. One genuine 26-proof calibration drains both arms with all four wallets paid and seven saved proofs unchanged. | Retain fresh normal authorizations and private fallbacks. Strong privacy is not established; evaluate public wallet-policy knowledge before wallet expansion. |
| H15 | Fresh exits retain at least three ambiguous payment-source sets per six-payment case and more alternatives than saved exits in at least one pair when the observer knows the prototype construction defaults. | Frozen at `7bf197f`; modest screen passed in all four pairs on unchanged H14 inputs. Fresh has 5/6 or 6/6 ambiguous payments and more alternatives in every pair. Unique payment sources remain 2/24 for both; unique full-exit sources are 20/28 saved and 0/28 fresh, with only 9–10 fresh candidates. | Retain fresh normal authorizations/private fallbacks. Strong privacy is open; next consider an observer with one participant's own activity, excluding that participant's relationships from scoring. |
| H16 | One complete participant record creates no new unique uninvolved fresh-payment sources; at least half remain ambiguous in every case/participant pair; fresh retains more alternatives in at least one pair. | Frozen at `5c44c55`; first clause fails on two startup payments, other clauses pass in all sixteen pairs. Separate participant views force sources for 4/24 fresh payments and 7/28 fresh exits, versus 6/24 and 28/28 saved. All 64 observations, 30 controls and 1,216 original-witness prefix checks pass. | Keep fresh normal proofs/private fallbacks and the compact research candidate. Strong privacy remains open. Prioritize common-size partial payouts/private remainder as an untested wallet-policy question, preserving full-drain accounting and immediate independent exits. |
| H17 | One frozen 2-tKAS partial payout per wallet reduces the seven linked original cashout claims to at most five through full drain, without pair regression or new original-payment links, while preserving independent exits. | Privacy clauses pass: 7/28 → 4/28 distinct claims, or 7/84 → 4/84 separate-participant observations; original payment links unchanged. All twenty observations, forty original-witness checks and genuine fresh/saved drainage pass. Fees +21.05% pass; forty added synthetic minutes fail the thirty-minute delay target. | Retain optional common cashouts as a research candidate, with fresh normal proofs/private fallbacks. Do not adopt this fixed schedule or close Stage 2. Scope practical scheduling separately; no general anonymity or live result follows. |
| H18 | Independently scheduled 2-tKAS partials and 5–15-minute tails reduce full-coverage source guessing by at least 25% in both activity regimes and observer profiles, within unchanged fee/delay limits. | Frozen at `b3fe70e`; privacy fails in all four comparisons: zero reduction. Fees +21.05% and p95 delay +16 synthetic minutes pass. All 252 observations and 504 exact original-graph checks complete; no new unique payment-source links. | Reject this short-delay policy as a demonstrated privacy mitigation. Stop before conditional native/TN10; preserve independent exits and earlier results. Stage 2 remains open. No retuning or general impossibility claim follows. |

Candidate counts are marginal logical possibilities, not probabilities, people
or joint-history counts. Synthetic results must never become claims of
real-world anonymity. Passing tests is not proof of cryptographic correctness.

## Experiment record

### 2026-10-21 (Australia/Sydney; 2026-10-20 UTC) — Privacy tests: computational limits and bounded results

- **Observation:** the original Boolean CP-SAT search returned no initial answer
  before interruption. Compact input indices and explicit per-note monetary-flow
  equations also returned no initial answer after approximately eight hours each.
  An independent original-model Z3 probe exited 137; the kernel log confirms an
  out-of-memory kill. None produced a held-out prediction or privacy finding.
- **Preservation:** all methods used the same generated first persistent history
  and pooled view. No seeds, amounts, eligibility rules, thresholds or integer
  domains changed. Frozen sources, passing controls, isolation manifests and
  interruption/termination evidence are retained in the
  [public evidence](../poc/shared-pool/evidence/2026-10-20-population-privacy/README.md).
  The first checkpoint and private generated histories remain intact.
- **Checks:** method 02 compared 15 complete tiny prefix sets (36 projected
  solutions); method 03 compared 13 sets (33 projected solutions), including
  checks in both old and new encodings. These controls support implementation
  equivalence on the tested cases, not privacy or general solver tractability.
- **Decision:** stop the stalled searches and try an explicitly weaker
  [local disclosure relaxation](../poc/shared-pool/POPULATION-PRIVACY-METHOD-04.md).
  Keep exact constraints for bootstrap, disclosed authors, each target and its
  first three later cashouts. A forced fact can still be decisive after dual
  solver checks and sealed-prediction/full-truth validation. Alternatives in
  this slice are inconclusive. This is an analysis change, not a protocol change.
- **Boundary:** computation failure is not evidence of privacy. The early gate
  remains open and milestone 3 remains blocked by it. No funds, new proofs,
  broadcasts or publication were used in this continuation.
- **Completed local batch:** method 04's frozen isolated controls passed
  (26 original plus 12 new). All eight histories completed 64 targets each,
  with no forced disclosure among 99 primary payments per arm and no undisclosed
  forced facts in other strata. Each prediction was sealed before both original
  full models checked actual truth. This deliberately weaker attack also fails
  to force prompt-cashout amounts that the simple matching attack recovers
  exactly; logical alternatives here cannot support a privacy claim.
- **Completed practical measurement:** method 05 froze three public cashout
  guesses and limited constant/public-hash baselines. All eight prediction files
  were sealed before any score. Its 26 original plus seven new controls passed;
  all eight concrete histories satisfy both original full models and accounting.
  Primary denominators are 28, 23, 24 and 24 per arm, totaling 99 paired payments.
  Prompt cashout exposes all 99 amounts exactly. Persistent within-10% counts are
  baseline 3, total-cashout 4, half-cashout 0 and known-note residual 5; exact
  recovery is zero for every persistent variant. Recipient residual guesses
  score 4/99 versus the limited role baseline's 6/99; sender is baseline-only.
  A separate author-team review checked every score counter against 512 scored
  rows and checked prediction seals/isolation. Seeds and full truth remain private.
- **Interpretation/next:** prompt-cashout exposure is reproduced. These fixed
  attacks perform poorly on persistent histories; four independent request sets,
  weak baselines and missing stronger attacks cannot establish anonymity or a
  privacy-gate pass. Continue practical native-linkage/behavioral attack testing
  without requiring whole-history reconstruction first. Preserve the exact
  measurements and all incomplete attempts; do not move milestone 3 past the gate.

### 2026-10-20 — Start the 32-role/eight-adversary privacy test

- **Checkpoint:** the owner authorized committing/pushing calibration, then
  starting this test. Commit `aa6ed4947f7c25db128cd5d89b7c021d6b8fe690`
  is verified on remote `shielded-kas-research`.
- **Question:** can current-wallet ownership rules, eight colluding participants'
  records and later withdrawals force a private internal-payment fact?
  [RFC-0014](rfc/0014-owner-aware-privacy-evaluation.md) separates a decisive
  conditional counterexample from statistical/privacy qualification.
- **Design:** four independent hidden request sets, each paired across persistent
  balances and prompt receipt cashout, with 32 roles, eight active roles, mixed
  amounts, interleaved admission, sparse/overlap regimes and full drainage.
  Primary targets are uninvolved honest-to-honest payments after all admissions.
  [Specification](../poc/shared-pool/POPULATION-PRIVACY-SPEC.md), code and dependency
  bytes were frozen before seed generation; seeds and truth stay outside Git.
- **Checks:** 13 model and 13 workload controls passed in isolation. The model
  controls include 545 exact propositions checked by independent tiny exhaustive
  enumeration. A second author-team review found no pre-run blocker. Passing
  controls does not establish cryptographic security or complete attack coverage.
- **Progress:** eight histories generated with 64 ordinary payments each and no
  skipped requests, seed retries or unpaid modeled claims. The first observer is
  running on persistent request set 1 with pooled records and final public history.
  No held-out prediction or separately scored disclosure has completed.
- **Boundary/next:** this first stage can reject a claim but cannot pass the
  adopted privacy rates. Missing cases, views and horizons remain open. Review
  the first result against pinned generated truth; preserve any failure and its
  exact assumptions. Native script/address reuse, complete byte-level coverage,
  realistic priors, infrastructure exposure and independent users remain separate.
  No funds, new proofs, broadcasts or protocol changes.
  [Report and public checkpoint](../poc/shared-pool/POPULATION-PRIVACY.md).

### 2026-10-20 — Early privacy test: first calibration completed

- **Authorization/checkpoint:** the owner directed committing/pushing the work
  order, then starting the early privacy test. The plan is pushed as `6dff59d`.
- **Scope:** [frozen first-slice specification](../poc/shared-pool/EARLY-PRIVACY-SPEC.md),
  SHA-256 `1b21810517d21d1221364e4c63f258710022100c8942dcc795c200266142e96e`.
  Decode actual M2 public native bytes; cross-check exact amount extrema under
  relation-only and current-wallet-shape constraints. Published three-wallet
  evidence calibrates the method; it is not held-out 32-role qualification.
- **Source audit:** H15/H16's one-input DRAIN policy is not the current wallet's
  one-or-two-input rule. The earlier decoder's distinct-commitment and artificial
  timing assumptions must not silently carry forward. Preserve old results under
  their original scope and reject false unique deductions in new controls.
- **Result:** method-04 completes 48 position/horizon amount bounds, cross-checked
  with CP-SAT and integer Z3. All 20 controls pass, including 454 tiny exhaustive
  feasible-value comparisons. With current-wallet shape, payment position 5 has
  extrema 0.6–30.8 tKAS throughout; position 7 narrows from 0.6–30.4 to 0.6–20.4
  after a later cashout. Only public ADMIT credit 11.6 and padding zero are forced.
  Extrema are not continuous sets, probabilities or guessing-accuracy scores.
- **Attempts:** preserve three interrupted solver-search attempts. The completed
  attempt adds runtime diagnostics and uses eight CP-SAT workers; inputs,
  constraints, integer domains, metrics and specification are unchanged.
  [Report and retained evidence](../poc/shared-pool/EARLY-PRIVACY.md).
- **Boundary/next:** calibration completes; the 32-role/eight-adversary held-out
  gate stays open. Freeze its workload, ownership/disclosure model, attacks,
  baselines and statistics next. A source-derived funding/exit address-reuse path
  remains untested. No new proofs, funds, broadcasts or privacy pass. The
  [source review](../research/shielded-kas-privacy-surface-sources-2026-10-20.md)
  retains the public-byte, participant and infrastructure boundaries.

### 2026-10-20 — Privacy testing moved before milestone 3

- **Direction:** the owner challenged waiting until milestone 7 to test the
  design's privacy premise. The old plan mentioned parallel privacy work but
  prioritized cryptographic review and wallet/recovery expansion in its next step.
- **Change:** the [plan](SHARED-POOL-PLAN.md#early-privacy-gate--before-milestone-3)
  now puts a privacy gate immediately after M2 and before dedicated milestone 3
  work. Routine safety review remains continuous. Milestone 7 expands/repeats
  privacy validation with broader clients, infrastructure and users.
- **Evidence:** [review](../research/shielded-kas-early-privacy-gate-2026-10-20.md)
  uses the candidate at `bf4505c`, the accepted RFC-0012 targets, current public
  wallet/native interfaces and existing H16/H18 failures. M2 demonstrates
  mechanics on synthetic ancestry, not anonymity. Old source-transaction
  inference results do not qualify owner identity or private amount protection.
- **Next test:** public-surface/direct-link audit first; then a frozen held-out
  persistent-balance versus prompt-cashout comparison with 32 roles, eight
  active/colluding roles and C/C+P/C+P+A observers through full drainage. Score
  both endpoints, relationships and private values. Keep truth separate from
  observers and treat missing cases or invalid controls as incomplete.
- **Decision rule:** a reproducible supported-claim counterexample can stop the
  candidate early. A pass requires the complete frozen privacy gates and controls;
  a small screen with no discovered attack is insufficient. Known fee/latency
  failures remain separate failures. No privacy result, implementation change,
  new proof, funded experiment or publication follows from this planning update.

### 2026-10-20 (Australia/Sydney) — New participant and backup recovery

- **Authorization/checkpoint:** the owner directed committing/pushing the replay
  slice, then continuing milestone 2 with new admission and backup recovery.
  Replay is now committed/pushed as `fa1dcf1`.
- **Decision:** [ADR-0029](adr/0029-own-key-admission-and-recovery.md) specifies a
  local wallet wrapper and six-proof lifecycle on unchanged v6 parameters;
  [RFC-0013](rfc/0013-coherent-v6-lifecycle.md) records the bounded integration gate.
  No funded trial is initiated.
- **Source basis:** [new review](../research/shielded-kas-admission-recovery-2026-10-20.md)
  refreshes current sources and identifies reuse of existing keys, encryption,
  proving and settlement. ADMIT receipts and positioned nullifiers make the
  older H7 scanner unsuitable without adaptation. Retained exact v6 parameters
  were available; full-byte hashes and embedded VK checks passed before use.
- **Prospective test:** initialize B after founder bootstrap; seal B's backup
  before admission and incoming payment. Restore with only that backup and
  public data, spend both recovered notes into a payment and private change,
  then restore again and freshly withdraw the change through drainage.
  Required pool accounting is 32 = 29.6 payout + 2.4 fees + zero remaining tKAS.
- **Falsifiers:** privileged note/key export, changed descriptor/setup, missing
  ADMIT receipts, incorrect positions/spentness, unauthorized or unbacked value,
  unsafe credit of malformed delivery, or failure to complete native-validated
  terminal exit. Negative controls and isolated recovery access accompany the
  positive trace.
- **Observed:** the full trace passed on unchanged descriptor, backup and
  parameters: six positive proofs, nine integration controls and 29 isolated
  process checks. Fourteen wallet tests and fifteen replay tests pass. B also
  signed a locally valid ordinary spend of its terminal payout using its restored
  native key and a known local derivation index. Automatic native coin discovery
  is not implemented.
- **Adversarial review:** fixed a malformed-receipt scan denial of service and a
  private input-position leak through the public payout derivation index.
  A separate seventh genuine proof delivered an unusable opening; B credited
  nothing new and still prepared/circuit-checked its valid prior claim. This was
  no eighth proof or completed exit. Author-side review is not an independent audit.
- **Evidence:** [report and public exports](../poc/shared-pool/WALLET-LIFECYCLE.md)
  preserve both full lineages, funding contexts, VK and exact source/binary hashes.
  All 17 candidate hashes stayed unchanged. Both exported histories replay exactly;
  private-field and fresh-secret export checks pass. Backups and local views stay
  outside Git. Earlier evidence and protocol instances are unchanged.
- **Costs:** six pool fees total 2.4 tKAS; founding/ordinary funding fees add
  0.030416 separately. The terminal ordinary-spend control costs 0.002038 and
  the separate malicious fork costs 0.4. Preparation takes 38.132–39.315 seconds,
  proving 20.495–21.486 seconds and parameter loading 202.939–205.838 seconds.
  These component observations expose target gaps; they are not p95 qualification.
- **Outcome:** milestone 2's bounded offline integration gate passes. All funding
  ancestry is synthetic, expected heads come from the driver, and isolation is
  on one host. No new testnet acceptance, useful privacy, independent cryptographic
  assurance, general recovery or milestone 1 performance pass follows.

### 2026-10-20 (Australia/Sydney) — Milestone 2 lifecycle integration started

- **Starting point:** milestone 1 adoption was committed/pushed at `a869d16`,
  followed by fee-basis wording clarification at `cbeaa6f`.
  [RFC-0013](rfc/0013-coherent-v6-lifecycle.md) maps the current lifecycle and all
  sixteen invariants; [ADR-0028](adr/0028-public-funding-replay.md) records the
  bounded first implementation scope.
- **Source/reuse result:** [current upstream and local review](../research/shielded-kas-lifecycle-integration-2026-10-20.md)
  identifies reusable own-key, backup and public-history contracts, but no general
  v6 wallet to import. The old H7 and upstream RISC Zero relations do not share
  v6 proof/backup identities.
- **First slice:** public replay without a participant roster, resolving actual
  founding/admission inputs from canonical parent bodies. Reuse retained genuine
  proofs and require exact state/native reconstruction and rejection controls.
  A new depositor still needs its own proof/signature; no live admission follows
  from replaying an existing trace.
- **Trust boundary:** actual parent bytes are stronger input context than
  self-declared authorization amounts, but accepted-chain/current-head evidence
  remains external. Strict ordinary-parent formats and available retained history
  bound this first slice. Missing older parents cannot be fabricated.
- **Result:** the additive component replays both retained histories exactly:
  fourteen native founding/pool transactions each, original public state and
  proof/auth bytes, 56 tKAS entering the reserve = 50.8 payout + 5.2 pool fees +
  zero remaining. Founding fees are accounted separately. Fifteen focused tests
  and both CLI modes pass; malformed funding, reused inputs, damaged native
  authorization and broken/terminal history reject. These are offline checks
  of retained evidence and isolated controls, not new chain acceptance.
- **Review:** a second adversarial pass found no implementation blocker and
  requested additional direct funding-output boundary controls, now included.
  This does not establish cryptographic correctness or useful privacy.
- **Status:** this first local slice is complete;
  [report, commands and limits](../poc/shared-pool/PUBLIC-REPLAY.md). Full milestone
  2 remains open: connect local keys/backups, new admission, scanning, spending
  and independent recovery/exit without a participant list or secret export.
  No new funded experiment, proof setup or change to previous pool instances
  was performed.

### 2026-10-20 (Australia/Sydney) — Milestone 1 targets adopted and closed

- **Decision:** the owner adopted the recommended numerical targets and directed
  closing milestone 1, committing/pushing the documentation, then starting
  milestone 2. [RFC-0012](rfc/0012-useful-privacy-requirements.md) is Accepted;
  [ADR-0027](adr/0027-shielded-payment-targets.md) records the rationale.
- **Target profile:** repeated payments from shielded balances, 10–1,000 tKAS;
  complete fee accounting; ordinary CPU-only laptop operation; explicit proof,
  payment, cold-start, exit and fresh-recovery times. Privacy gates cover
  uninvolved identities, private amounts and targeted subsets in a 32-role/eight-
  adversary workload through full drainage. The RFC holds the exact numbers,
  definitions and uncertainty requirements.
- **Safety and availability:** invariants remain unchanged. Reference, 2× and 5×
  fee scenarios must preserve user-controlled exits, including small change and
  service loss. Performance targets do not abort trials or remove liabilities.
  Acceptance latency is not consensus finality; network anonymity needs separate
  evidence.
- **Known gaps:** H13's proving/startup/memory and small-payment fees miss the
  adopted targets. Pinned default Groth16 verification cost alone exceeds the
  10-KAS endpoint's 1% budget. This motivates research into amortization or other
  designs, without selecting a new architecture or claiming current-L1 impossibility.
- **Completion boundary:** specification, source/reuse review and capability map
  complete milestone 1. No implementation, security, privacy or performance pass
  is implied. H1-H18 retain their original frozen criteria and evidence.
- **Next work:** start milestone 2 with current-version interfaces and enforcement
  obligations, including removal of the live adapter's fixture participant list
  while retaining actual native funding verification. The previously published
  draft checkpoint is `8bb7561`.

### 2026-10-20 (Australia/Sydney) — Privacy requirements draft (milestone 1)

- **Work completed:** source/evidence review and an open
  [requirements RFC](rfc/0012-useful-privacy-requirements.md), after the roadmap
  was committed/pushed through `76ac3f5`. The draft names internal payments,
  public ingress/egress and urgent recovery separately; defines chain,
  participant, active, infrastructure and endpoint observers; and maps eight
  requirements to falsifiers and current evidence gaps.
- **Source basis:** the [dated review](../research/shielded-kas-privacy-requirements-2026-10-20.md)
  pins current Kaspa and mature-protocol material. Requirements are adapted;
  no primitive, runtime or inherited security assurance is selected. Source
  inspection is not network deployment verification.
- **Main findings:** v6's payment/change and saved-exit evidence does not establish
  current-version pre-payment-backup recovery, arbitrary participant admission or
  general settlement retries. Ciphertext binding is not proof of correct delivery.
  Old anchors, witness queries and service observations require explicit privacy
  treatment. Merged inputs have structural deposit ancestry, but do not uniquely
  assign each source's sompi to later outputs.
- **Evaluation proposed:** compare persistent shielded activity with prompt cashout
  using held-out user-level relationship, amount and funding targets through full
  drainage. Include participant/collusion and active-user controls, costs and
  delay. This specifies the question; no new simulator or trial was run.
- **Still open:** the intended activity/participant envelope, acceptable absolute
  disclosure, target device/cost/latency and fault envelope. Until those are fixed,
  there is no scored usefulness pass. Milestone 1 is started, not declared complete.
- **Boundary:** documentation and read-only source analysis only. No new proof,
  transaction, funded trial, protocol change or independent cryptographic audit.
  H1-H18 and their original criteria/evidence remain unchanged.

### 2026-10-20 (Australia/Sydney) — Broader shielded-KAS roadmap

- **Decision:** adopt the ten-milestone [branch plan](SHARED-POOL-PLAN.md), retaining
  direct covenant settlement as the research candidate. The destination is a
  coherent testnet wallet used by separate owners, with private payments, correct
  native backing and recovery/exits after original services disappear.
- **Reason:** the independent source/evidence assessment supports the native
  mechanics but does not establish useful privacy or general exit liveness.
  Current v6 saved exits do not inherit the older version's backup-recovery result.
  Source-transaction candidate counts do not establish owner or amount privacy.
  H18's short-delay cashout policy remains rejected.
- **Order:** privacy requirements; coherent protocol; early cryptographic/setup
  review; usable wallet; recovery/data availability; fault-tolerant exits; complete
  privacy evaluation; measured architecture choice; independently owned testnet
  trial; reproducible research release. Integration, review and attacks overlap.
- **First deliverable:** an open privacy RFC and current-source/capability map.
  Persistent shielded spending is a testable use-case hypothesis; prompt cashout
  has to earn a separate claim. New requirements must name observable information,
  participant/collusion assumptions, metrics, costs and failure conditions.
- **Continuity:** the branch is now `shielded-kas-research`. H1-H18 and their
  frozen criteria/evidence remain unchanged. The previous five-stage plan is
  retained at [the pre-roadmap checkpoint](https://github.com/elldeeone/kaspa-privacy-initiative/blob/c3afb1b94f023057bfe99d780271f6de52c43da4/docs/SHARED-POOL-PLAN.md).
  No old failed screen becomes a pass, and no invariant or deployed pool changes.
- **Authority and boundary:** the owner requested plan/journal updates, commit and
  push, then starting milestone 1. This records research direction; no new proof,
  native transaction, funded experiment or independent cryptographic assurance is
  claimed. Later testnet trials and publication follow their separately scoped
  authorization rather than being inferred from this roadmap.

### 2026-10-20 UTC — Independently scheduled common payouts (H18), completed

- The owner authorized the frozen local policy, offline comparison and
  conditional native/TN10 validation. Q stays at 200,000,000 sompi, with
  a 5–15 minute local remainder timer and immediate saved-exit override.
- `b3fe70e` commits the policy, observer, 24 new paired ledgers, two controls,
  decision thresholds and private master-seed hash before implementation.
- Nine controls pass: tiny exhaustive amount/ownership/source enumeration,
  the complete timing-score objective, queue boundaries, two-input preservation,
  full accounting, wrong amounts, immediate exits, parsing and missing-matrix
  rejection. No new cryptographic or native implementation is introduced.
- The observer receives public fields and at most one participant's records,
  with the same metadata isolation as H16. All predictions must finish before
  hidden-truth scoring. A failed gate stops before TN10.
- `de2eeb5` implements the blinded comparison. All 252 predictions complete
  before scoring, including one originally incomplete observation recovered
  with a separately hashed one-worker wrapper. The initial process was killed
  by the kernel at approximately 23 GB anonymous RSS; the identical captured
  query solves in 0.16 seconds with one worker. The complete missing observation
  takes 14.37 seconds. All completed predictions and failed attempts are retained;
  controls pass under both search settings. No timeout becomes ambiguity.
- Result: all four required attack-family improvements are zero. Correct
  guesses remain 22/84 and 23/84 chain-only, and 93/252 and 95/252 across
  separate participant views. The paired intervals do not establish improvement.
  Unique participant cashout observations stay 24/252 in both arms/regimes;
  no original payment acquires a new unique source.
- Post-score explanation: all 48 sparse common payouts have exactly one
  time-compatible remainder, agreeing with truth. Their original-source
  alternatives match the full baseline in all 336 eligible claim/view pairs.
  Overlap permits more tail pairings and some wider source sets, but does not
  reduce the winning attack. Even the inherited untimed model retains the same
  unique-claim totals; this is not a pure timestamp-effect claim or a replication
  of H17's four-case benefit on the new workloads.
- Accounting: 19 versus 23 pool operations, 7.6 versus 9.2 modeled tKAS fees;
  all wallets receive payouts and all reserves drain. Added completion delay
  is 16 synthetic minutes at p95 in both regimes, at most 18/17 minutes.
  These pass the operational screens; ordinary allocation/genesis are not
  modeled. Actual test KAS spent is zero.
- All 504 original amount/input-graph checks and 2,304 narrowing checks pass.
  A separate post-partial escape control accepts immediate change exit under
  the original relation while the normal-timer observer rejects that history.
  The optional wait is not a protocol lock; these are observer/arithmetic
  controls, not new genuine proofs or a live independent-exit result.
- Decision: do not proceed to the conditional native/TN10 step. Reject this
  particular short-delay policy as a demonstrated mitigation, preserve v6
  payment/change/exit mechanics, and keep Stage 2 open. No seed, denomination,
  budget or delay is retuned. [Result and evidence](../poc/shared-pool/SCHEDULED-PAYOUT.md).
- [Author's second pass](../poc/shared-pool/SCHEDULED-PAYOUT-REVIEW.md) and
  [source refresh](../research/scheduled-payout-sources-2026-10-20.md).

### 2026-10-20 UTC — Common-size partial payouts (H17)

- Owner authorized this bounded offline test, independent exits, and code,
  results and journal on `shared-pool-four-wallet`.
- `71d2aca` freezes Q=200,000,000 sompi, the four original workloads,
  original-claim provenance metrics, both horizons and rejection criteria.
- Result: the frozen privacy clauses pass. Distinct original claims linked by
  at least one separate eligible participant fall from 7/28 to 4/28, and the
  overlapping observation count falls from 7/84 to 4/84. No pair regresses,
  no claim becomes newly unique and no original payment acquires a new unique
  source. Chain-only stays 0/28 cashouts and 2/24 payments; participant payment
  links stay 4/24 distinct, or 6/48 overlapping observations.
- The three removed links belong to split claims; all four remaining links
  belong to unsplit claims. Equal-payout legs have no singleton at either
  horizon, including after every tail exits. Original-source candidates after
  drain are 9–10 chain-only and 6–9 for those equal-payout legs with one
  participant's records. These are creating transactions, not people or odds.
- Validation: all 20 logical observations finish before truth scoring, with
  540 full prediction rows, 40 original integer amount/input-graph checks and
  136 candidate-set narrowing checks. Ten base controls and additional solver
  oracle/two-input controls pass. Five complete same-input solver comparisons
  agree on all 27 rows each.
- Exact SMT searches were slow. Retain nineteen completed plain/bounded
  results; the last case completes in 60.578 seconds with direct integer
  CP-SAT and the same relation. Its positive graphs are checked against the
  original integer model. Publicly implied suffix domains and one-input
  balances, and batched queries, change only search. No unknown result is
  counted as privacy. All earlier attempts remain available.
- Genuine mechanics passed: 34 proofs; four optional pre-partial saved full
  exits and seven fresh/seven saved final exits in isolated workers. Both
  winner orders and final replay/alternative rejection pass. Both branches
  pay every wallet, consume 920,000,000 sompi in fees, pay 4,680,000,000 sompi
  and leave zero from 5,600,000,000 funded. All 23 public transaction bodies per
  branch independently revalidate and exactly match the model.
- Cost: 23 versus 19 pool operations, fees 9.2 versus 7.6 test KAS, exactly
  one extra 0.4 fee per wallet. Calibration needs 34 versus 26 proofs. The
  +21.05% fee passes its screen; +40 synthetic minutes fails the unchanged
  30-minute delay target. No actual test KAS is spent, and synthetic starting
  funding UTXOs omit allocation/genesis transactions from this offline trace.
- A collector metadata write failed after complete scoring because the
  resource file already existed. A separate scope receipt fixes it. Repeating
  collection/validation on the same predictions leaves the complete summary
  unchanged; no observations were rerun for that fix.
- Decision: keep optional common cashouts as a bounded research candidate,
  together with fresh normal proofs/private fallbacks. Do not adopt this fixed
  schedule or close Stage 2. A separately scoped scheduling comparison can
  address the delay; startup inference and general privacy remain open.
- No consensus/circuit/covenant/parameter change, TN10 broadcast, funds, push
  or upstream posting. See [scope](../poc/shared-pool/COMMON-PAYOUT-SPEC.md),
  [report](../poc/shared-pool/COMMON-PAYOUT.md) and
  [sanitized results](../poc/shared-pool/evidence/2026-10-20-common-partial-reconstruction/summary.json).

### 2026-10-20 UTC — One participant's records (H16)

- Freeze: `5c44c55`, before implementation or observation. Reused all four H14
  economic cases, eight public traces and original plans/truth byte-for-byte.
  Four separate participant views × two exit arms × two profiles = 64
  observations. Disclosures are never pooled.
- Knowledge: only own positive receipts and authored transactions, exact values
  and input choices, local equality of addresses used by that sender, and
  complete own spentness. Receipt alone supplies no sender identity or sibling
  plaintext; sending a note does not reveal its later nullifier. Future records
  are excluded at each prefix. No keys, global wallet IDs, four-owner bound,
  other views, private truth or network/RPC access enters the observer.
- Result: the frozen no-new-link claim fails. In both schedule-1 amount rows,
  participant 2 excludes its own early admission, reducing the first payment's
  source sets from three to the bootstrap alone. This is visible at appearance.
  At least half of eligible fresh payments remain ambiguous in every pair,
  and fresh retains more alternatives in all sixteen pairs: 835 versus 390
  summed marginal sets across overlapping observations.
- Distinct targets linked by at least one separate eligible participant:
  fresh/saved payments **4/24 versus 6/24**, partials **3/8 versus 4/8**, full
  exits **7/28 versus 28/28**. The actual rotated observation counts are 6/48
  versus 8/48, 3/24 versus 4/24, and 7/84 versus 72/84. These are neither
  independent samples nor anonymity percentages. All 48 payment input-note
  sets remain ambiguous, even where the creating transaction is unique.
- Diagnosis: records alone force six distinct fresh full exits and two partials;
  added ownership rules force one further exit and partial. Fresh payments
  narrow later on 20/48 observations but none becomes newly unique. Saved
  payments narrow on 38/48, with two new later singleton links. Checkpoint
  timing does not identify an individual withdrawal as the sole cause.
- Validation: 28 initial controls plus two second-pass partial-change controls;
  independent integer oracle, CP-SAT/SMT/hybrid comparisons, truth retained at
  all scored horizons, three candidate-set nesting checks of 3,168 sets each,
  and 1,216 fixed original amount/input-graph prefix checks. The native code,
  setup, old proofs and H14/H15 evidence remain unchanged.
- Correction: inherited `/proc` and supervisor arguments exposed host case/arm
  labels, though observer code did not read them. Stopped the first attempt
  after 30 completed predictions without scoring. The complete repeat uses
  no `/proc`, namespace PID 1, dropped capabilities and denied nested user
  namespaces. All 64 access probes pass; all 30 earlier completed predictions
  agree exactly. Private inputs and observer equations did not change.
- Cost: zero funds, new proofs, extra native fee or wallet delay. The corrected
  run took 67m30.30s with ten workers; the interrupted attempt used 22m57.87s.
  These are analysis costs, not wallet proving times or privacy guarantees.
- Decision: retain fresh normal authorizations/private fallbacks; Stage 2 stays
  open. The startup failure needs honest explanation, not a claim that elapsed
  time creates privacy. Next investigate withdrawal amounts using existing
  partial-withdrawal support: one frozen common payout size, private remainder,
  original-payment linkage metrics and complete drainage, including all added
  fees. Reject gains that disappear at final remainders or merely count extra
  self-change notes. No follow-up implementation, TN10 trial or publication
  is part of this continuation.
- Evidence: [report](../poc/shared-pool/PARTICIPANT-PRIVACY.md),
  [frozen scope](../poc/shared-pool/PARTICIPANT-PRIVACY-SPEC.md),
  [sanitized results](../poc/shared-pool/evidence/2026-10-20-participant-reconstruction/summary.json),
  [second-pass review](../poc/shared-pool/PARTICIPANT-PRIVACY-REVIEW.md).

### 2026-10-20 UTC — Known wallet behavior (H15)

- Hypothesis/freeze: committed the rules and input/source hashes as `7bf197f`
  before observation. Reused all eight H14 public transcripts and original
  hidden truth byte-for-byte. No new amounts, schedules, identifiers or proofs.
- Observer: first profile knows deposit/partial padding and one-note full exits;
  primary profile additionally knows receipt-time fallback anchors. Current
  roots still allow older notes; fresh/saved labels and private input choices
  are never supplied. No automatic coin-selection policy exists to infer.
- Outcome: all four pairs pass the frozen modest screen. Fresh leaves five or
  six ambiguous payment sources per six-payment case and more alternatives in
  every pair. Both policies retain the same 2/24 uniquely linked payment sources.
  Fresh source-set totals fall from H14's 746 to 722; saved falls from 676 to
  548 with shape rules and 375 with the receipt-anchor rule. These are marginal
  alternatives, not joint histories, people or probabilities.
- Withdrawals: unique full-exit sources are 20/28 saved versus 0/28 fresh; fixed
  recency guesses are correct in 28/28 versus 8/28. Fresh has 9–10 candidate
  source transactions per exit, compared with H14's 77–78 source combinations.
  Shape alone leaves saved uniqueness at 4/28; receipt-anchor knowledge accounts
  for the increase to 20/28. Exact spent-note positions are unique for 8/28 saved
  exits and 0/28 fresh exits. Partial-withdrawal sources remain non-unique.
- Drainage: source alternatives narrow for four fresh-policy payments and twenty
  saved-policy payments. No additional payment becomes unique. Both encodings
  and the exact hybrid engine agree with independent exhaustive tiny ledgers.
  Sixteen controls, sixteen observations and all 1,072 joint horizons pass;
  every true set survives and wallet/shape/protocol candidate sets nest.
- Cost/safety: one complete full run, 9 minutes 17.01 seconds with four workers;
  zero funds and zero new proofs. Native code, parameters and H14 calibration
  are unchanged. Private truth/provenance and unused capabilities stay outside
  Git. This is a conditional known-client attack, not a consensus statement or
  a cryptographic/real-world privacy result. RPC/network observation is absent.
- Decision: retain fresh normal authorizations/private fallbacks. Stage 2 stays
  open. The next proposed narrow question is whether a participant's own
  activity lets an observer reconstruct relationships between the other users.
  That follow-up is unrun and would exclude already-known participant targets.
- Evidence: [report](../poc/shared-pool/WALLET-POLICY-PRIVACY.md),
  [frozen scope](../poc/shared-pool/WALLET-POLICY-PRIVACY-SPEC.md),
  [sanitized results](../poc/shared-pool/evidence/2026-10-20-wallet-policy-reconstruction/summary.json),
  [adversarial review](../poc/shared-pool/WALLET-POLICY-PRIVACY-REVIEW.md).

### 2026-10-20 UTC — Blinded two-input reconstruction (H14)

- Hypothesis and falsifier: committed the four economic workloads, attacks,
  controls and decision in `1bf14d0` before generation/scoring. Fresh exits must
  leave at least three of six payments with multiple source sets in every case,
  and strictly increase alternatives in at least one paired case. This is a
  necessary screen, not a strong-privacy threshold.
- Observation: all eight observers complete. Fresh and saved policies each
  leave 2/24 private-payment source sets uniquely identifiable; those are the
  early payments before another deposit. Fresh exits increase source alternatives
  in two of four cases. Saved exits retroactively narrow ten payments, without
  producing additional unique links. The fixed recency rule guesses full-exit
  sources correctly in 28/28 saved cases and 8/28 fresh cases; only 4/28 and 0/28
  respectively are logically forced. Correct guesses and unique inference are
  separate metrics. No real-world anonymity percentage follows.
- Mechanical calibration: unchanged v6 circuit/covenant/VK; 26 genuine proofs
  and synthetic native UTXOs. Both nineteen-operation branches pay all four
  wallets and drain. Seven receipt-time saved proofs remain byte-identical.
  Exit adapters have public state/bundles only; current spentness rejects the
  alternate authorization and replay in both winner orders. Rechecking all
  transported bodies verifies both branches; invalid proof/backing/lineage
  mutations fail. Other cases are models, not native proof executions.
- Controls and methods: two integer encodings and the final exact graph search
  match independent tiny enumeration. Every true input/source set survives;
  all 536 required joint observation points are scored. Filesystem/network
  isolation excludes the manifest, generator and truth. Seven incomplete
  observer batches are retained; economic/public inputs are byte-identical.
  Solver ordering, integer presolve and conservation-derived bounds changed
  computation only. Nine earlier completed predictions match 603 required
  observation points exactly. Unknown/unfinished search never counts as privacy.
- Cost: zero actual tKAS; each branch models 7.6 tKAS in fees at 0.4 per pool
  operation. Seven additional fresh proofs take 150.232 seconds; cold loading
  takes 203.054 seconds. All warm proofs take 21.020–21.988 seconds. Peak native
  proof-process memory is about 6.49 GiB. Traffic times are synthetic.
- Interpretation/decision: keep fresh normal authorizations and private exit
  fallbacks. The clearest benefit is exit linkability; forced payment links did
  not improve. Remaining source sets are marginal possibilities, not identities
  or uniform probabilities. Known one-note withdrawal/deposit-padding behavior,
  common funding and outside knowledge remain stronger attacks. Evaluate those
  before broad wallet work. Stage 2 and the later review/usability gates stay open.
- Evidence: [report](../poc/shared-pool/TWO-INPUT-RECONSTRUCTION.md),
  [frozen scope](../poc/shared-pool/TWO-INPUT-PRIVACY-SPEC.md),
  [sanitized results](../poc/shared-pool/evidence/2026-10-20-two-input-reconstruction/summary.json),
  [adversarial review](../poc/shared-pool/TWO-INPUT-RECONSTRUCTION-REVIEW.md).

### 2026-10-20 UTC — TN10 continuation of H13

- Observation: the complete funded rehearsal and fresh measured trial passed.
  Each paid all four clients through six unchanged saved exits, including the
  terminal payout. All 15 accepted transaction bodies/full hashes per run match;
  both reserves are zero. Alice kept 11.89 private change; Bob withdrew 2.11,
  then privately re-spent his 4.8 change. Exits discovered accepted history
  themselves with the original prover stopped, receiving no controller state.
- Cost: 0.4 tKAS per pool operation; 5.215345/5.216205 tKAS per full run,
  including allocation/genesis. Eighteen ordinary coin-consolidation transactions
  cost 0.049428 tKAS, bringing total test fees to 10.480978 tKAS. Warm proofs took
  20.036–21.430 seconds; preparation took about 8.5 minutes per run and peaked
  at 6.44 GiB RSS. Native saved-exit replay/build was 40–60 ms in the rehearsal,
  excluding RPC time. The circuit, covenant and VK are unchanged from `bf64f3d`.
- Qualification correction: descriptor reserialization initially masked all
  negative fixtures behind a hash mismatch. Those results are invalid evidence.
  Exact-byte copying and expected-cause assertions corrected the six controls;
  the gate passed before pool funding. Ten ordinary consolidation transactions
  had already completed. No proof or covenant check was weakened.
- Evidence: [report](../poc/shared-pool/TWO-INPUT-TN10.md),
  [measured receipt](../poc/shared-pool/evidence/2026-10-20-two-input-tn10/trial/result.json),
  [accepted bodies](../poc/shared-pool/evidence/2026-10-20-two-input-tn10/trial/chain-confirmed.json)
  and [public-only export replay](../poc/shared-pool/evidence/2026-10-20-two-input-tn10/public-replay-check.json).
  Both exported traces replay without private files or network. Only accepted
  bodies, public verification material and allowlisted checks are committed.
- Decision: retain this bounded payment relation for review. This closes the
  requested TN10 mechanics test, not Stage 2, general recovery or strong
  privacy. Review merging/padding inference and cost before another study;
  no further experiment or upstream publication follows automatically.

- Test contract: repeat the same 13 pool operations after offline adapter
  qualification, with a complete rehearsal before a fresh measured identity.
  Preserve exact proof/authorization bytes and backing; each client gets only
  its own saved capabilities and descriptor/VK, not the controller's current
  state. Ordinary allocation/genesis are counted separately. Never repeat a
  submission within a used identity.
- Boundary: four generated test wallets on one host, using the owner's correct TN10
  RPC view and a pinned four-depositor source set. This is not generic recovery,
  multi-node verification, unknown-depositor support or a privacy measurement.
  Shared test funding is one public cluster. Ordinary payouts may be recycled;
  this creates no privileged reserve withdrawal path.
- Falsifier: any accepted value mismatch, modified private proof, unavailable
  saved exit within the declared model, or reliance on the original prover's
  keys/current state blocks success. Record full accepted transaction bodies and
  full hashes, script/fee measurements and isolated process exits. Keep private
  wallet files, PK and unpublished alternative capabilities outside Git.

### 2026-10-19 UTC — Two-input offline mechanics (H13)

- Hypothesis/falsifier: the new relation can merge two receipts, retain private
  payment/withdrawal change and preserve unrelated saved exits. Reject it if
  change is unspendable, backing fails, a second authorization spends the same
  note, or an exit needs a privileged/private prover secret after proof saving.
- Authorization: commit docs, build/run offline and keep code/journal on
  `shared-pool-four-wallet`. Spec checkpoint `c50855a`; no TN10, push or upstream
  publication. Native SDK remains `01b532e8b553523216471682649693af92f0fd16`.
- Observed: 13 native-validated synthetic transactions, payment of 7.31 with
  11.89 private change, 2.11 partial payout leaving 4.8 private change, then a
  re-spend of that change. Six unchanged proof/auth exits run in isolated
  workers without keys, PK or external network. All four wallets paid;
  `56 = 50.8 payouts + 5.2 fees + 0 reserve` in synthetic tKAS.
- Controls: 279 native reserve-script mutations rejected, supplementary actual
  funding/signature controls, 15 constraint fixtures and five unit tests passed.
  Normal/fallback alternatives cannot both spend in the two tested winner
  orders. A constructed maximum-CM/near-maximum-NF state accepts a saved terminal
  proof without appending CMs; it is not a replayed full-capacity history.
- Cost: selected exact fee 0.4 tKAS per operation; 330,497–331,628 mining mass,
  30-million declared reserve script units, about 14.85–15.03 million used.
  Minimum note 0.6, payout floor 0.1; 36 mass-only exit sweeps support the bounded
  envelope. Circuit 4,372,824 constraints; PK 962,197,520 bytes. Warm proofs
  20.131–22.286 seconds, cold load 214.688 seconds, main fixture 534.974 seconds.
  Concurrent constraint checks make these workload timings, not clean benchmarks.
- Correction: the supplementary omitted-funding fixture initially failed the
  harness balance check before native execution; its output was adjusted to
  preserve balance and reach covenant rejection. Protocol checks were unchanged.
- Interpretation/decision: the application can support these payment semantics
  with current pinned L1 primitives. Keep the candidate, but do not convert
  encrypted change into an anonymity claim. The previous single-parent observer
  is unsuitable after merging. Review/qualify the outstanding cases before any
  funded run; general privacy and all-fee-market exit liveness remain open.
- Limits: single-party setup, supplied synthetic chain context, retained public
  data and exact fees. The parent knows fixture secrets; worker isolation proves
  absence of a private exit dependency, not live discovery or full recovery.
  No funds moved and no live claims remain. Sanitized artifacts omit raw proofs,
  saved fallbacks, note openings, private keys and parameters.
- Evidence: [measured report and author review](../poc/shared-pool/TWO-INPUT.md),
  [summary](../poc/shared-pool/evidence/2026-10-19-two-input-offline/summary.json),
  [RFC-0011](rfc/0011-two-input-private-payments.md),
  [ADR-0024](adr/0024-two-input-private-payment-scope.md).

### 2026-10-20 (Australia/Sydney) — Two-input design specification (H13, untested)

- User scope: write the spec, preserve independent exits and review chain
  inference; no code or tests. Inspected shared-pool baseline `228e5d0`.
- [RFC-0011](rfc/0011-two-input-private-payments.md) gives amount equations,
  real/padded input and output rules, a 377-byte candidate authorization,
  5,228-byte proposed public payload, native transaction shapes, and proof/public
  rebuilding separation. These are proposed layouts, not measured execution.
- A no-append `DRAIN` path and larger NF tree address exit capacity. Counts
  including padding cannot establish outstanding value or terminal eligibility.
  Keep exact fees; arbitrary fee increases still require fresh owner authorization
  or waiting, and public-data loss can still block recovery.
- [ADR-0024](adr/0024-two-input-private-payment-scope.md) records why this relation
  question takes priority over more unchanged-relation policy runs. Olaf's
  inspected integrated circuit also has one input and whole-note exits; changing
  its outer runtime alone would not add merging/private withdrawal change.
- The [privacy review](../poc/shared-pool/TWO-INPUT-PRIVACY-REVIEW.md) distinguishes
  hidden change from public ingress/egress and joint inference. The previous
  one-parent/deposit-label model cannot score merged notes without redesign.
  No new anonymity percentage, cryptographic assurance or execution result.
- Open gates: independent padding/NF/capacity review, exact economic constants,
  measured native/proving costs, future mechanical qualification and a separately
  frozen varied/interleaved privacy study. Existing evidence remains intact;
  implementation and experiments remain on hold.

### 2026-10-20 (Australia/Sydney) — Equal net funding policy (H12)

- Scope frozen at `a522e59` before generation: varied, equal gross and equal net
  funding with equal total backing, topology, schedules and exit order. Target
  funding deposits separately from H11's note-creating transactions.
- All 64 primary paired ledgers retained, 704 targets per policy. Equal net
  credits leave four feasible deposits for every target at withdrawal and after
  drainage. Strongest fixed deposit guesses are 25.313% / 26.563%; unique deposit
  fractions fall from 91.875% / 84.115% to zero, meeting the original screen.
- Equal gross controls retain 24.063% / 22.656% unique deposits. Removing the
  112,000-sompi bootstrap/admission credit difference removes that fingerprint
  in this workload. Early/singleton exits stay linked; shared funding stays one
  funding cluster. There is no claim of equally likely people or anonymity.
- 58 genuine proofs in two unchanged-relation calibrations match the model;
  four alternative saved/fresh drains pass. The new exit adapter also pays ten
  claims in each arm without wallet/PK inputs, plus nine rejection controls.
- Review found three controls initially failing at descriptor serialization
  rather than history checks. Exact-byte copying corrected them; the offline
  gate was rerun and the still-unfunded rehearsal replaced with a fresh identity.
  No pool transaction was broadcast by the stopped identity. A separate ordinary
  funding-key lookup fix preserves exact key/script ownership checks.
- Complete TN10 rehearsal and measured trial passed: 18 confirmed transactions,
  ten unchanged-proof exits and all four wallets paid in each. Both pools closed.
  Independent chain-only decoding reproduces exact model candidate sets, with
  shared funding ancestry explicitly visible. Provers stopped before broadcast.
- An earlier funded rehearsal also paid every claim, then failed in final hash
  recording. Read-only reconciliation verified every accepted body/full hash;
  no transaction was rebroadcast. The corrected complete path passed on a fresh
  rehearsal identity before the measured run. Keep that failure in the evidence.
- Measured cost 3.569999 tKAS, including ordinary funding. Pool fees 3.510392;
  normalization adds no pool fee. All actual work, including the first funded
  rehearsal and 75 ordinary recycling transactions, cost **10.824305 tKAS** across
  129 transactions. Offline tests spent no native funds. No mainnet funds used.
- The study does not change the covenant, proof relation, setup or invariants.
  Retain the policy within its workload; interleaving and mixed amounts need a
  separate test before broader privacy claims or wallet expansion.
- [Specification](../poc/shared-pool/NORMALIZED-DEPOSITS-SPEC.md),
  [result](../poc/shared-pool/NORMALIZED-DEPOSITS.md),
  [adversarial review](../poc/shared-pool/NORMALIZED-DEPOSITS-REVIEW.md),
  [policy decision](adr/0023-equal-net-deposit-policy.md).

### 2026-10-20 (Australia/Sydney) — Independent-deposit privacy policy (H11)

- Frozen specification committed as `294dfc6` before generation/scoring. Both
  primary regimes retain all 32 ledgers; 17 controls and every final withdrawal
  are reported separately. Total 81 ledgers/882 withdrawals, 704 primary.
- Fresh full-drain source guessing: 64.4% / 38.5%, versus 100% with saved proofs.
  Relative reductions 35.6% / 61.5%; paired 95% intervals [32.2%, 39.1%] /
  [58.3%, 64.6%]. The original 25% target passed; no threshold was revised.
- Remaining leakage: 94.4% / 88.5% of funding deposits are uniquely inferable
  after full drainage. At-withdrawal source guesses were lower, 33.4% / 20.8%.
  Shared funding ancestry gives one public cluster, not an owner attribution.
- Genuine calibration: 58 proofs, four complete native-validated alternate drains,
  76 main transaction occurrences and 44 paid claims. Both old/fresh arms settle
  with no wallet/PK; candidates match the model and only anchor fields differ.
  Current-state builder rejects the losing same-nullifier bundle in both orders;
  H10 retains the hostile native duplicate-witness evidence.
- Cost: no extra native mass/fee/transaction for refreshing. Hypothetical total
  native fees per calibrated arm are 3.512441 / 4.388993 tKAS; actual chain spend
  is zero. Cold load 100.541 seconds; fresh proofs 9.579–26.977 seconds amid CPU
  contention. Conservative cold-plus-proof p95 component estimate 122.057
  seconds, excluding history/RPC/confirmation. A 20-minute no-traffic wait adds
  no measured privacy benefit.
- Method correction: generic Z3/CP-SAT solving was slow. An exact single-ancestor
  flow reduction matched 45 completed CP-SAT fresh traces, both horizons, and
  the tiny exhaustive oracle. All 81 ledgers/native plans stayed byte-identical;
  every final case was rerun. No timeout became ambiguity or an excluded sample.
- Checks: 25 Python and 12 existing Rust tests passed; isolated public-only
  observers, separate scorer, actual native byte projection and export secret/
  unused-fallback guards. This is self-reviewed offline evidence, not a security
  audit, real-world anonymity study or a live network/RPC privacy result.
- Decision: keep fresh proofs with private saved fallbacks. The next proposed
  test is equal **net** credited deposits: equal gross contributions leave a
  112,000-sompi bootstrap/admission difference. This proposed fix was not tested
  or implemented. No protocol expansion, TN10 broadcast, push or upstream post.
- Evidence: [report](../poc/shared-pool/PRIVACY-STUDY.md),
  [self-review](../poc/shared-pool/PRIVACY-STUDY-REVIEW.md),
  [frozen scope](../poc/shared-pool/PRIVACY-STUDY-SPEC.md),
  [aggregate results](../poc/shared-pool/evidence/2026-10-20-privacy-study/summary.json).

### 2026-10-20 (Australia/Sydney) — Independent compact deposits (H10)

- Hypothesis: three independently signed deposits add backed claims without
  invalidating earlier v5 exit authorizations. All four wallets drain using the
  exact proofs saved immediately after joining, with every prover stopped.
- Implementation: new immutable v5 covenant, existing v4 private relation and
  exact parameters. Distinct admission adds two commitments/history and leaves
  NF state unchanged. Normal spend checks and previous variants stay intact.
- Offline: 12 library tests; four drain orders, 32 unchanged-proof settlements,
  all four terminal roles and zero reserve/liabilities. The final suite rejected
  35 native mutations (32 in the reserve script itself). Genuine deposited-note
  transfer, same-claim old/fresh winner orders, repeated proof with fresh backing,
  minimum-note exits and independent Python accounting passed.
- Boundary: constructed maximum-capacity state accepts a saved exit while
  refusing another admission. This is not an accepted 32,000-deposit history.
  A correct current-chain view remains necessary: valid stale public history
  can replay, and populated UTXO contexts alone do not prove unspentness.
- Cost: pool fees 263,384,000 sompi (2.63384 tKAS), leaving 37.36616 tKAS from
  four 10-tKAS contributions. Ordinary genesis/allocation fees are additional.
  Minimum deposit 142,005,200 sompi; fixed exit 21,934,400 per note. Floor gate
  passes, with future fee repricing still unresolved.
- Funding preparation: 82 confirmed ordinary consolidations cost 0.225172 tKAS.
  The first offline plan found that a reused exit's payout-key index can precede
  settlement by several updates. Exact-script matching now searches earlier
  indices. The failed plan never broadcast; no pool reserve was used.
- TN10: complete rehearsal and a fresh measured trial each confirmed 14 exact
  transaction bodies/full hashes, paid all eight notes from unchanged saved
  proofs and drained the pool. Every prover stopped before any exit. Each exit
  client had only its own bundles and public data, using its own RPC connection.
  Alice's count-three proofs survived three later deposits and all other exits.
- Measured run: 2.656933 tKAS including allocation/genesis; rehearsal 2.648059.
  Both runs plus ordinary coin consolidation cost 5.530164 tKAS over 110 accepted
  transactions. Measured local rebuilds took 25.848–46.605 ms; cold loading
  100.716–100.865 seconds and each proof 9.324–9.721 seconds. Independent Python
  reconstruction and byte comparisons agree with both live results.
- Boundary: same-host isolated clients, correct node view and retained public
  data. The coins share a public allocator ancestor; four signing keys do not
  mean four unrelated users. No live race, pruning/reorg or anonymity result.
- Decision: retain the smallest admission extension for the Stage 2 population
  study. No privacy threshold has passed; setup, fixed-fee, data-availability and
  correct-node assumptions remain. Stop mechanical expansion and assess policy.
- Evidence: [report](../poc/shared-pool/DEPOSITS.md),
  [review](../poc/shared-pool/DEPOSITS-REVIEW.md),
  [offline receipts](../poc/shared-pool/evidence/2026-10-20-deposits/offline/result.json),
  [live costs/results](../poc/shared-pool/evidence/2026-10-20-deposits/summary.json).
  Raw secrets/unused authorizations stay outside Git. No push or upstream post.


### 2026-10-19 — Independent compact deposits (H10), scope only

The owner requested the minimal current-L1 extension on this branch, preserving
existing exit proofs across later deposits and requiring four independent exits.
This step records research/design only: no implementation, build, experiment,
TN10 connection, funding, broadcast, push or upstream posting.

[RFC-0010](rfc/0010-compact-independent-deposits.md) and
[ADR-0022](adr/0022-compact-two-note-deposits.md) select a distinct two-input native
admission branch: reserve plus the depositor's ordinary SIGHASH_ALL input. Reuse
the unchanged two-output proof relation with its virtual input value bound to
actual new funding. Add exactly deposit-minus-fee backing and two claims; append
the resulting root to history; do not admit the virtual input/root/nullifier or
change current spentness. Preserve verified bootstrap and independent public
descriptor/lineage checks. The [source review](../research/compact-deposits-source-review-2026-10-19.md)
records current Kaspa support, mature-protocol analogues and signature exclusions.

This requires a new immutable application version, not an upgrade of an existing
v4 reserve. Saved proofs created in that new pool before later deposits must
remain byte-identical; v4 claims cannot cross into the new domain. The hypothesis
fails if any old claim loses backing, requires a replacement private proof or
operator help, or cannot drain under the declared fee/data assumptions.

The main proposed fixture has four 10-tKAS contributions, one bootstrap, three
later admissions and eight saved exits: 13 native transactions, excluding input
preparation. Stop each prover after preparing its wallet's exits, then drain
newest wallet first and Alice last. Other offline orders exercise each wallet's
terminal role; native negative controls and a genuine deposited-note transfer
regression are required. No such fixture has been run.

Tradeoff: the unchanged circuit requires two notes of at least 60,000,000 sompi,
so the minimum deposit is 120,000,000 sompi plus fee and each depositor has two
full exits. New covenant size/mass/fees must be measured before proofs are frozen;
the worst configured exit fee plus payout floor must fit the circuit's note
floor. Existing v4 measurements are references, not new estimates. Actual spend
for this scope is zero.

Decision: retain this bounded prerequisite for a separately authorized offline
implementation. It enables actual independent-funding workloads; it does not
establish anonymity or close Stage 2. Old anchors, public deposit totals/ancestry,
full-exit amounts, setup, history and fixed-fee limits remain explicit. Keep the
population thresholds and chain-only/RPC separation unchanged.

### 2026-10-19 — Fresh proof and private fallback (H9), bounded offline result

The owner authorized building and running the matched comparison offline, keeping
the old proof private, verifying only one authorization can spend, and retaining
code/journal on this branch. The [specification](../poc/shared-pool/FRESH-PROOF-SPEC.md)
was hashed before proving. No circuit, covenant, setup or L1 change; no new token,
funding, TN10 transaction or upstream post. Existing experiment evidence remains.

Generated 24 genuine proofs across three designed ledgers. The same target note,
recipient script, payout and fee are compared at old count three versus fresh
count 3/7/11. The observer sees each exclusive transaction history separately,
without truth, keys, workload seeds, the other history or pending authorizations.
After complete drainage, target source candidates are 1 → 1, 1 → 3 and 1 → 5.
All-exit unique-source coverage is 2/2 → 2/2, 1/4 → 0/4 and 1/6 → 0/6. Recency
top-1 success is 2/2 → 2/2, 3/4 → 2/4 and 3/6 → 2/6. Both observation horizons
agree. No population inference follows from these deliberately chosen ledgers;
the target was the earliest received note, and every pool has one deposit ancestor.

Both winner orders reject the other genuine proof against the winner's current
successor. All 34 native hostile controls reject; separate UTXO lookup rejects
old-outpoint replay. The singleton duplicate also has a terminal-shape conflict,
so the larger fixtures provide the cleaner spentness controls. Six independent
public rebuilds with no wallet/PK/network preserve exact proof/auth bytes. Every
claim drains in both histories, and 48 serialized transaction instances pass
native Full/policy checks using explicit synthetic UTXOs. Twelve observer and
six export/scoring tests pass. This is offline validation, not chain acceptance.

Fresh target proofs take 9.514–9.589 seconds, plus 100.414 seconds if parameters
must be deserialized cold. Old fallback rebuilds take 8.345–8.614 ms locally.
Same native transaction count, mass and fee: target exit 0.217296 tKAS; added
native fee zero. Modeled complete-history fees are 0.653525/1.521885/2.390245 tKAS;
actual chain expenditure is zero. Prover peak memory was not measured: the first
external timer only captured wrapper resources, now explicitly labeled. Future
launcher timing is inside the sandbox. Proof generation completed in one run.

Both pending bundles, every old history and all private material stay outside
Git. Only fresh histories and aggregate old-side results are exported, scanned
against 33 secret values, three unused old proofs and two distinct old statements.
Six actual-material injection controls pass. The singleton shares authorization
bytes across proofs; its unused old proof still remains private.

Decision: retain the fresh-proof mechanism and private fallback under
[ADR-0021](adr/0021-separate-exit-fallback-and-privacy-policy.md). Stage 2's
population thresholds remain untested; full-exit amount leakage, useful independent
activity, setup/data availability and cold proof work remain open. No live run
or Stage 3–4 expansion follows automatically. [Result, costs and reproduction](../poc/shared-pool/FRESH-PROOF.md),
[adversarial self-review](../poc/shared-pool/FRESH-PROOF-REVIEW.md).

### 2026-10-19 — Stage 2 initial privacy audit (H8), redesign gate reached

The owner authorized pushing the branch and executing Stage 2. Pushed the existing
checkpoint `af9bae8` to the owner's fork after scanning 3,274 new-history blobs
against 216 locally available secret values and credential patterns; no findings.
No upstream issue comment or PR was created.

Recorded the [audit specification](../poc/shared-pool/PRIVACY-AUDIT-SPEC.md) before
executing the new observer, while explicitly acknowledging H6/H7 are already
known exploratory traces. Refreshed upstream/P13 and established-protocol sources
in the [source review](../research/compact-privacy-source-review-2026-10-19.md).
This audit changes no proof relation, covenant, setup or L1 rule.

Projected only accepted transaction bodies and block-header fields. The observer
ran with no home/secret/truth mounts and no network. It found one source transaction
for each selected first H6 exit, at withdrawal and after complete drain, with two
possible note positions. All-exit source prediction coverage is 1/4 and 1/102;
other exits are abstentions, not demonstrated private payments. H7's three exits
each retain two source transactions under the small joint integer model. All
109 full exits expose consumed value as payout plus fee. Every trace has one
initial deposit, so deposit ancestry does not measure independent-user privacy.

A fresh-anchor abstract sensitivity changes the small H6 target from one source
to three, including full drainage. No modified proof/transaction was generated;
the old proof would fail with changed authorization. Twelve control tests passed,
including 340 brute-force matching systems/1,252 target queries. New native
transactions and fees were both zero. [Report and evidence](../poc/shared-pool/PRIVACY.md).

The documented old-anchor stop condition applies: no traffic simulator or new
funded privacy trial. The 25% inference/25% fee/30-minute delay thresholds remain
untested. Independent later deposits and partial exits are not compact features.
Keep reusable authorization for exit liveness; investigate fresh proof creation
against recent anchors as the normal path. Keep unused fallback authorization
private: its nullifier would link it to a fresh one if both were published.
[ADR-0021](adr/0021-separate-exit-fallback-and-privacy-policy.md) records the decision;
[RFC-0009](rfc/0009-compact-anchor-privacy.md) scopes the open follow-on. Stage 3–4
expansion remains behind useful privacy. No real-user anonymity or independent
cryptographic-review claim.

### 2026-10-19 — Stage 1 independent recovery (H7), completed bounded test

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
Fresh ordinary cleanup drained the interrupted pool. A separate complete
rehearsal and fresh measured trial then passed with the same finalized runtime.
All three recovered clients ran away from the original host, with one private
backup each, a retained public copy and a separate public TN10 RPC. The original
prover and HTTP data source stopped before each set of restores. The public
mirror omitted the original manifest/receiver list; backups supplied no future
note openings or prepared exit proofs.

Bob, Carol and Alice received 3.782704, 1.782704 and 3.348936 tKAS respectively.
Every pool drained completely. The measured trial cost 1.110008 tKAS including
funding; all Stage 1 live work cost 3.299148 tKAS across 23 accepted transactions,
including interruption cleanup and five ordinary funding-reuse transactions.
The final funding fee increased because its small change output raised storage
mass. The two private payments and three exits still cost 1.085656 tKAS per pool.

Measured cold recovery took 136–151 seconds per wallet: roughly 105 seconds
loading parameters and 12 seconds proving, plus public-data/confirmation work.
Each restored wallet read about 479 MB of public files. Preserve the evidence
boundary: one initial deposit, three synthetic claimants, retained public data,
correct node views and single-party setup. This is recovery evidence, not an
anonymity result or independent cryptographic review. Stage 2 is the next gate.
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
