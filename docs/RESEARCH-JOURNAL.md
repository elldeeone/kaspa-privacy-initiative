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

Milestone 1 has started: [RFC-0012](rfc/0012-useful-privacy-requirements.md) drafts
the privacy promise, observer knowledge, user-level metrics, operating requirements
and falsifiers, with a source/capability map of the current v6 candidate. The
[primary-source refresh](../research/shielded-kas-privacy-requirements-2026-10-20.md)
records what established designs contribute and what is not inherited.
Use-case thresholds remain open. Integration, independent cryptographic review and
privacy attacks then proceed together. Later milestones cover a usable wallet,
current-version recovery, settlement under faults, measured architecture selection,
independently owned testnet activity and a reproducible research release.

The branch and its 16 previously local commits were pushed at `c3afb1b`. The owner
then authorized updating and pushing this plan/journal and beginning milestone 1.
This scope includes local requirements/source work; it does not initiate a funded
trial, paid service, recruitment or new protocol implementation. The roadmap is a
work programme, not evidence of its outcomes.

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
