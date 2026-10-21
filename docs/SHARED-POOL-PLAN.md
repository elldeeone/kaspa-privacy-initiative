# Shielded native KAS research plan

Updated: 2026-10-21 (Australia/Sydney). Branch: `shielded-kas-research`.
Evidence baseline: `c3afb1b94f023057bfe99d780271f6de52c43da4`.

## Destination and current decision

Build an independently usable testnet payment system: separate people hold their
own keys, receive private payments, spend them again, recover on another machine,
and withdraw native test KAS after the original services disappear. The result
must state its privacy, cost, availability and trust limits.

Retain the direct-L1 pool as the current research candidate. Focus the privacy
hypothesis on payments between persistent shielded balances; deposits, ordinary
cashouts and emergency exits have separately measured disclosure. An independent
exit remains available even when exercising it sacrifices privacy. No token,
privileged withdrawal path, real funds or mainnet deployment is part of this plan.

The owner adopted milestone 1's targets, authorized their documentation
commit/push, and directed starting milestone 2. Local integration work remains
research/testnet only. The later roadmap does not authorize funded trials, paid
infrastructure, participant recruitment or upstream publication. Existing branches,
secrets, protocol instances and evidence stay intact.

**Current position:** milestone 2's bounded offline integration gate is complete:
new own-key admission, recovered receipts, payment/change and fresh terminal exit
share one current-version interface. Qualification against the accepted
[RFC-0012 requirements](rfc/0012-useful-privacy-requirements.md) remains open. The first
integrated delivery spans milestones 2, 4 and 7, with early review in milestone 3.
Requirements acceptance does not mean that any implementation meets them.

**Next action:** use the [withdrawal investigation](../research/shielded-kas-withdrawal-privacy-2026-10-21.md)
to design a prospective comparison of whole-note cashouts against requested
native payouts with private change and continued shielded spending. The existing
v6 relation supports partial payouts; the current wallet interface only exposes
whole-note EXIT. Preserve immediate independent full exit, count all tails and
fees, and do not adopt a wallet policy before the comparison. H18's short-delay
policy remains rejected. The broader early privacy gate and a
sufficiently powered qualification study remain open. Milestone 7 remains
broader validation. Routine safety review and fixes continue throughout.

The owner authorized the next bounded test under
[RFC-0015](rfc/0015-native-usage-privacy-screen.md): one fresh 32-wallet history
with genuine offline native transactions, uneven activity, repeat contacts,
intermediate cashouts and transparent self/cross-user re-entry controls. Freeze
all attacks and criteria before generation, then evaluate public/participant
prefixes through a completed result. This has completed: public-plus-directory
amount guesses improve from prior 7/36 to 12/36 within 10% after the next public
withdrawal, exceeding both frozen caps. All 64 payments and 59 withdrawals
completed, with 159 genuine proofs and exact native accounting. One history
cannot supply statistical qualification or chain/network evidence. Preserve the
warning; do not advance the privacy claim or retune the retained test. Its
known-price prior has expected accuracy above the absolute 20% cap, so a future
test must separately assess transaction-derived advantage and this requirements
tension without changing either the old workload or adopted targets.

## Evidence carried forward

| Existing work | Supported result | Boundary for the new programme |
| --- | --- | --- |
| [H5/H6 reusable authorization and compact settlement](../poc/shared-pool/COMPACT.md) | An unchanged private authorization settled after 100 intervening payments; the tested pool drained on TN10. | Finite capacity, retained history and serial activity; not general contention or anonymity. |
| [H7 independent recovery](../poc/shared-pool/RECOVERY.md) | Three older-version wallets restored from pre-payment backups on a separate host and generated their own exit proofs. | Retained exact parameters/history and correct nodes; this is not recovery of the newer v6 relation. |
| [H10/H12 deposits and funding policy](../poc/shared-pool/NORMALIZED-DEPOSITS.md) | Independent admission mechanics and bounded equal-net-credit inference results. | All-deposits-first symmetry and shared live funding ancestry do not establish independent anonymity participants. |
| [H13 two-input payments](../poc/shared-pool/TWO-INPUT-TN10.md) | v6 private payment/change, partial withdrawal and four wallets paid through six unchanged saved exits on TN10. | One host/RPC, four known funding sources and precomputed capabilities; general current-version wallet recovery remains open. |
| [H14-H16 reconstruction and disclosures](../poc/shared-pool/PARTICIPANT-PRIVACY.md) | Fresh proofs retain more alternatives than saved anchors; participant records expose additional links. | Source-transaction alternatives are not owner anonymity or a private-amount guarantee. H16's strict screen failed. |
| [H17 common payouts](../poc/shared-pool/COMMON-PAYOUT.md) | The bounded privacy screen improved; genuine offline exits drained both arms. | The schedule failed its delay target; no general or live privacy result. |
| [H18 independently scheduled payouts](../poc/shared-pool/SCHEDULED-PAYOUT.md) | Strongest tested attack success was unchanged in all four comparisons. | Reject the tested short-delay policy. Its conditional native/TN10 continuation remains stopped. |

Keep fresh normal authorizations, private fallback capabilities, native integer
accounting, private change and blinded evidence collection as candidate mechanisms.
Single-party setup, unaudited composition, data availability and fee adequacy remain
assumptions. Passing implementation tests is not cryptographic security; synthetic
privacy results are not real-world anonymity.

## Milestone 1 — Define the privacy promise

**Status:** complete as a requirements decision on 2026-10-20.
[RFC-0012](rfc/0012-useful-privacy-requirements.md) is accepted and is the
source of truth for the adopted payment-size, privacy, fee, hardware, latency,
recovery and fee-stress targets. [ADR-0027](adr/0027-shielded-payment-targets.md)
records the owner-directed decision.

The [primary-source review](../research/shielded-kas-privacy-requirements-2026-10-20.md),
observer definitions, falsifiers and current capability map are complete for this
milestone. The profile protects ordinary internal payment relationships/amounts,
measures later disclosure and preserves immediate independent exit. Experiments
must freeze concrete workloads and statistical procedures before evaluation.

**Completion boundary:** requirements are adopted; privacy, cryptographic security,
independent wallet recovery and performance are not established. Current v6 has
known cost/resource gaps against the profile. Keep the targets fixed while testing;
record any future change explicitly without reclassifying old failures.

## Milestone 2 — Consolidate one protocol candidate

**Status:** complete for the bounded offline integration gate on 2026-10-20.
[RFC-0013](rfc/0013-coherent-v6-lifecycle.md) maps the lifecycle
and all sixteen invariants. [ADR-0028](adr/0028-public-funding-replay.md) scopes an
additive offline public replay component with actual funding-parent bodies and
no participant roster. The [reuse review](../research/shielded-kas-lifecycle-integration-2026-10-20.md)
records current upstream/H7/v6 boundaries.

The [first component's checks](../poc/shared-pool/PUBLIC-REPLAY.md) pass: both
retained histories replay exactly, 15 focused tests pass, and both CLI modes
reach the original terminal state/accounting. No new participant, proof or funded
trial was created; the accepted-chain view remains an external assumption.

Replay was committed/pushed at `fa1dcf1`. The owner then authorized the next
local slice: [own-key admission and backup recovery](adr/0029-own-key-admission-and-recovery.md).
Its [complete trace passes](../poc/shared-pool/WALLET-LIFECYCLE.md): a wallet created
after bootstrap admits with its own key, receives while offline, restores both
notes from its original backup, spends into payment/change, restores again and
freshly exits through terminal drainage. The descriptor and backup stay unchanged.
Six positive proofs reconcile 32 = 29.6 native payouts + 2.4 pool fees + zero
reserve. A separate seventh proof tests malformed delivery without blocking a
valid prior claim. Nine integration controls and 29 wallet/replay tests pass.

**Completion boundary:** synthetic funding ancestry, externally supplied offline
heads and same-host process isolation. No new testnet acceptance, independent
public-data survival, general recovery, useful privacy, cryptographic assurance
or milestone 1 performance qualification is established. The restored-key native
payout-spend check uses a known derivation index; automatic native coin discovery
is later wallet work.

Use one circuit, covenant, parameter identity, wallet format and public-data format
for deposit, private transfer/change, withdrawal and recovery. Map all security
invariants to proof, covenant, wallet or availability obligations. Establish the
backing argument from valid genesis through terminal drainage, retaining liabilities
until their actual payout. Preserve native integer-sompi semantics throughout.

Replace fixture-only participant/funding discovery with validation of actual native
funding. Retain evidence from each earlier version under its original identity.

**Gate:** a previously unknown participant can join and complete the supported
lifecycle with its own keys, without descriptor edits or privileged state exports.
Every accepted liability is backed and every enforcement assumption is visible.

## Early privacy gate — Before milestone 3

**Status:** the public-byte audit and
[specified amount-inference calibration](../poc/shared-pool/EARLY-PRIVACY-SPEC.md)
are complete; the 32-role held-out gate remains open. The
[first-slice report](../poc/shared-pool/EARLY-PRIVACY.md) records 48 cross-checked
amount bounds. Later cashout narrows one payment's upper bound from 30.4 to
20.4 tKAS; neither ordinary payment is uniquely determined by the tested models.
This is calibration, not owner anonymity or an amount-guessing result.
The [32-role/eight-adversary test](../poc/shared-pool/POPULATION-PRIVACY.md)
has now started under [RFC-0014](rfc/0014-owner-aware-privacy-evaluation.md).
Its first stage seeks forced disclosures with an explicit ownership model;
26 controls passed and four matched request sets generated. Full-history
reconstruction has not produced a prediction; two equivalent formulations were
stopped after approximately eight hours each and Z3 exhausted memory. Preserve
these incomplete attempts. A reviewed local relaxation completed all 512
ordinary targets across eight histories: no forced disclosure among 99 primary
payments per arm, with generated truth separately checked in both original full
models. This weaker result cannot establish privacy; no
qualification pass is available. A separate fixed cashout-guessing batch completed
all eight histories: prompt receipt cashout exposed 99/99 primary amounts exactly;
the strongest of three simple attacks guessed 5/99 persistent amounts within 10%
and none exactly (constant baseline 3/99). Four request sets and these limited
attacks do not qualify privacy. This failure-seeking stage does not replace the
powered rate study.
The subsequent [native address-reuse test](../poc/shared-pool/ADDRESS-REUSE.md)
demonstrates an allowed funding/exit script collision with seven genuine offline
proofs. In its two-funded-wallet diagnostic, the link resolves the internal
sender, recipient and exact amount under known funding associations and a
declared self-bootstrap schedule; the same-history ablation and different-index
control remain ambiguous. This is a concrete wallet privacy problem, not a
32-role rate verdict. [ADR-0030](adr/0030-separate-funding-and-exit-keys.md) now
adopts funding/exit separation for fresh v2 backups, while preserving exact v1
recovery and its known risk. The
[ten-proof offline retest](../poc/shared-pool/ADDRESS-KEY-SEPARATION.md) passes
original-backup recovery and native payout spending in both versions. Both fresh
v2 cases avoid the equality and its conditional disclosure; the legacy case
still leaks. Keep this regression. The subsequent
[stronger practical screen](../poc/shared-pool/POPULATION-PRIVACY-STRONG.md) is
complete: 16 fresh independent histories, 32 roles/eight active colluding roles
each, four payment rounds and 968 primary eligible payments. The strongest
tested attack guessed 36/968 senders, 55/968 recipients and 42/968 amounts within
10%, versus prior counts of 31, 52 and 37. All histories drained, both full-model
truth checks passed, and separate recounting reproduced all scores and 99
intervals. There are no raw cap exceedances or certified breaches in the declared
primary comparisons. This is a completed bounded synthetic screen, not a privacy
pass: sixteen histories give
wide uncertainty, and only the pooled final view and limited attacks were tested.
The 32-role gate remains open; no protocol or wallet change follows from this
result.
The subsequent [native usage screen](../poc/shared-pool/NATIVE-USAGE-PRIVACY.md)
completed all 83 prefixes and ten profiles. It finds transaction-derived amount
advantage in a varied-usage history: C+D next-withdrawal 12/36 versus prior 7/36,
and pooled next-withdrawal/final 10/36. A separate P1 final sender comparison
also exceeds the five-point prior-improvement cap (2/36 versus 0/36). No primary
joint relationship guess succeeds, which is not a proof of privacy. These
finite-case warnings now take priority over expanding this candidate.
The owner challenged the work order
after the milestone 2 commit `bf4505c`: test whether the integrated candidate can
meet the intended privacy promise before investing further in that candidate.
Keep milestone numbers stable; this brings privacy evaluation forward from 7.
The [evidence and scope review](../research/shielded-kas-early-privacy-gate-2026-10-20.md)
separates current findings from untested claims.

1. Audit the complete current public surface: native transaction bytes, funding
   ancestry, amounts, ciphertexts, anchors, nullifiers, output order, timing and
   exported wallet metadata. Include what counterparties know. Check for direct
   identifiers and deterministic amount/relationship deductions before building
   a larger model. Existing M2 transcripts are calibration data, not a privacy
   sample; their published experiment narrative must not become observer input.
   Classify shared receive data and auxiliary proof timings by actual exposure;
   local-only diagnostics are not automatically public-chain observations.
2. Freeze a blinded evaluation of repeated spending from persistent shielded
   balances, with prompt cashout as a matched comparison. Use RFC-0012's 32 user
   roles, eight active/colluding roles and C, C+P and C+P+A views. Include
   interleaved admissions, varied amounts, sparse activity, private change,
   pooled disclosures, amount tagging and exits. Freeze distributions, adversary
   powers, eligible targets, baselines, sample size, attack selection and
   statistical procedure before generating/scoring held-out data.
   Thirty-two roles need not supply 32 plausible honest alternatives at every
   payment. If the public prior itself breaches a cap, report that workload's
   information limit; do not exclude those targets after scoring.
3. Score sender and recipient identity separately, relationship targeting and
   private amounts at payment, later cashouts and complete drainage. Reuse
   existing observers only where their inputs and semantics match current v6;
   source-transaction alternatives are not user identities or amount privacy.
   Calibrate any modeled transcript against actual current transaction bytes.
   Label modeled histories separately from genuine proof/native validation.
   Separate observer predictions from the scorer's private truth.

The adopted RFC-0012 gates remain unchanged: identity accuracy at most 10%;
amount guessing within ±10% at most 20%; both with at most five percentage
points advantage over the frozen baseline; relationship precision at most 50%
at 5%, 10% and 25% coverage; zero logically forced unauthorized disclosures.
Use its confidence-bound, multiple-comparison and independent-session rules.
Singleton/all-other-users-adversarial controls must detect known disclosure;
they cannot be treated as a qualifying 32-role population.

**Failure:** a reproducible disclosure defeats a supported claim, the held-out
privacy gates fail, or private witness material crosses the declared boundary.
Stop expansion of that candidate and choose a concrete redesign, an explicitly
reviewed claim change, or abandonment. Preserve the failure; do not tune the
evaluated seeds or silently lower targets.

**Pass:** all frozen privacy gates and controls pass on the complete eligible
held-out workload. This justifies proceeding to deeper candidate review under
the stated cryptographic/setup assumptions; it is not proof of privacy or security.
**Incomplete:** missing cases, unresolved solver results, invalid controls,
unfrozen details or insufficient statistical power. Finding no attack in a small
screen cannot pass this gate.

Report cost/latency/exit results separately. Known fee and prover gaps remain
failures against milestone 1; a privacy pass cannot qualify the overall system.
Immediate user-controlled exits stay available. Network/infrastructure privacy,
independently operated users and broader deployment workloads remain milestone 7
obligations. No new funded test or protocol change is authorized by this work order.

## Milestone 3 — Review cryptography and setup trust

**Status:** author review and negative controls exist; independent assurance open.
Dedicated milestone work follows the early privacy gate. Safety triage and
review needed to interpret that gate continue immediately.

Review the actual private relation and native covenant together: bootstrap backing,
range/conservation, real/padded slots, nullifiers, historical anchors, recipient
spendability, replay and terminal release. Compare established constructions and
record adaptations; their security does not transfer automatically to this protocol.

Evaluate a reviewed multiparty setup process and a feasible transparent-proof route
against the current single-party assumption, including proving and recovery costs.
Continue routine review alongside specification and integration, before wallet
polish; do not start a setup/proof-system engineering programme before checking
the current candidate's privacy premise.

**Gate:** unresolved credible inflation, double-spend or unauthorized-exit findings
block expansion. Experimental setup can support conditional research only; tests,
parameter hashes and source review cannot establish honest setup or erased trapdoors.
Architecture changes require the relevant RFC, ADR and synchronized threat model.

## Milestone 4 — Deliver a usable wallet lifecycle

**Status:** current-version offline own-key lifecycle passes; general client incomplete.

Support independently generated keys, offline receiving, authenticated scanning,
repeated private payments, private change, deposits and partial/full withdrawals.
Validate recipient ownership and spendability before showing a claim as available.
Keep private proving local initially and name every service's information access.

Provide clear balances, documented backup/restore, fee handling and interrupted
operation recovery without editing proofs, Merkle paths or transaction JSON.

**Gate:** separate users complete the same current-version workflow with ordinary
wallet inputs. No fixture key bundle, researcher intervention or secret supplied to
an untrusted prover is necessary. Measure cold and warm operation separately.

## Milestone 5 — Make recovery and data availability ordinary

**Status:** older-version separate-host recovery and current-version bounded
offline backup recovery pass. Current-version independent-host/public-data
survival and live recovery remain open.

Restore a newly received payment using a backup that predates it, on another machine,
without precomputed exits or sender/coordinator note exports. Authenticate the pool,
parameters, current accepted state and all material needed to reconstruct witnesses.

Distribute verifiable public parameters, history and ciphertexts using independently
retained copies. Start with ordinary files/archives; introduce authenticated snapshots
only when justified. Test publisher loss, a pruned node, corrupt/missing data, lost
local caches and replacement data providers.

**Gate:** every supported claimant recovers and exits using its own documented
backup and surviving independent public sources. Missing all indispensable data is
a recovery failure even if the client safely halts. Public parameters are not wallet
secrets; being once included on L1 does not establish permanent availability.

## Milestone 6 — Finish independent settlement and exits

**Status:** saved-proof settlement works in bounded traces; broader liveness open.

Handle stale reserve inputs, both race winner orders, ambiguous submissions, dropped
RPC connections and competing exits. Reconcile accepted outcomes before retrying;
rebuild current public settlement while preserving valid private authorization.
Test progress during finite competing-payment schedules, then measure sustained
competition. Record each claimant's progress, retries, costs and any intervention.

Cover baseline and increased fees, minimum claims, commitment/nullifier capacity and
controlled reorg/rollback. An exact-fee proof cannot be silently repriced; fresh
user-controlled proving may be needed. Separate consensus validity, relay acceptance
and actual inclusion. Keep simulated faults distinct from TN10 observations.

**Gate:** all supported claims remain backed and exit within the declared operating
envelope without privileged scheduling, subsidy or rescue. Replay cannot pay twice.
Repeated starvation at modest activity challenges the architecture. An uneconomic
claim fails the supported exit target; do not shrink the envelope after results.

## Milestone 7 — Broaden and independently validate payment privacy

**Status:** blinded arithmetic observers exist; broader independent evaluation open.
The first current-candidate privacy gate is before milestone 3. This milestone
repeats and expands that evaluation as real clients, recovery and settlement
behavior become available; an early pass is not carried forward automatically.

Build independent attacks using full public transaction bytes and documented wallet
behaviour. Cover varied/interleaved payment graphs, persistent balances, known
counterparties, collusion, attacker-controlled wallets, amount tagging, retries,
old-proof exposure and eventual withdrawals. Measure RPC requests, scanning and
broadcast exposure as distinct observer profiles.

Keep attack development separate from held-out evaluation. Continue observing after
individual cashouts and through final drainage. Report absolute performance against
public-prior baselines, precision/coverage and uncertainty, not just improvements
over revealing saved anchors. Never turn solver failures into privacy or extra
wallets owned by one actor into independent honest participants.

**Gate:** the specified use case survives its frozen requirements under the declared
observations, with failure regions reported. A negative finding selects a narrower
claim, a concrete redesign or stopping that approach. More seeds or timer changes
alone are not a new milestone. Synthetic success remains a research screen.

## Milestone 8 — Select architecture from measured limits

**Status:** direct pool retained provisionally; production architecture unselected.

Measure proof/startup/recovery time, memory, transaction mass, per-user payment and
cashout costs, capacity and settlement/exit progress. Compare alternatives under the
same backing, privacy, recoverability and exit requirements.

| Candidate | Evidence that would justify it |
| --- | --- |
| Direct shared pool | Meets the chosen workload and gives users reliable progress. |
| Batching | Per-payment proof/fee overhead or reserve contention is the limiting factor; batchers remain replaceable and exits independent. |
| Based-app execution | L1-ordered submissions and verifiable processing of activity are demonstrated requirements; adopting the current vProgs runtime is a separate decision. |
| Shards | Required parallelism outweighs measured privacy fragmentation, with correct cross-shard backing and exits. |
| Consensus change | A specific necessary requirement cannot be met with current capabilities after credible alternatives are evaluated. |

**Gate:** record the choice and reconsideration conditions in an ADR. A faster
exclusive operator cannot satisfy permissionless exits. Resource measurements must
fit the use case selected before evaluation, not a retrospectively relaxed target.

## Milestone 9 — Run an independently owned testnet trial

**Status:** future work after safety, recovery and privacy qualification.

Separate people generate and retain their own keys on their own devices, obtain
public data independently, and choose payment requests across multiple sessions.
Include offline receiving, continued shielded spending, independent cashouts, sparse
periods and consented adversarial participants. Remove the preferred services and
exercise backup recovery while other users remain active.

Keep undisclosed ground truth separate; attackers receive only the participant
records and infrastructure observations declared for their profile. Measure actual
accepted native transactions, wallet/network exposure, usability, costs, failures
and interventions.
An implementing team's extra wallets do not establish an honest population.

**Gate:** the same version maintains backing, pays all supported claims and meets
its declared privacy/operating targets under those observed conditions. Coordinator
rescue is recorded as workflow failure. Complete an authorized rehearsal through
terminal payout before a measured TN10 trial; use fresh identities for retries.

## Milestone 10 — Deliver a reproducible testnet research release

**Status:** future work, with publication within the owner's authorized scope.

Package the client, protocol specification, public recovery artifacts, independent
verification tools and reproducible evidence. Include measured limits, privacy
claims that survived, failed cases, setup assumptions and unresolved findings.

**Gate:** another team can reproduce the lifecycle and challenge its conclusions
without our private experiment directories. Record a continue, redesign or stop
decision. This is a research/testnet release; mainnet remains a separate decision.

## Dependencies and immediate work

Milestone 1 defines the evaluation contract. Integration (2) is followed by the
early privacy gate before dedicated cryptographic/setup work (3). Routine safety
review accompanies every step; privacy attacks continue throughout and broaden
in milestone 7. Wallet work (4) supplies the current
version used by recovery (5) and settlement fault testing (6). Measurements feed
architecture selection (8). The independent-user trial (9) follows qualification;
the reproducible release (10) includes the resulting evidence and limitations.

Milestone 1 and the bounded offline milestone 2 gate are closed. The initial
public-surface/amount calibration is complete. The frozen 32-role/eight-adversary
ownership/disclosure test has bounded pooled final-history results. Preserve the
immediate-cashout exposure and incomplete whole-history attempts. Funding/exit
key separation removes one conditional native link for fresh v2 backups while
retaining legacy recovery and its weakness. The fresh sixteen-history stronger
attack screen is complete with low observed rates and no certified breach.
Complete the remaining declared views/horizons, challenge the synthetic workload
and observer surface, and freeze an adequately powered qualification study;
neither more samples alone nor low heuristic rates qualify the candidate. A
supported failure still requires action under the frozen rules.
Resolve the early gate's pass/fail/incomplete result before expanding into
milestones 3–6. Keep the known
fee/cold-load gaps visible. Existing failed H16/H18 screens remain warnings;
neither those old workloads nor the M2 mechanics trace qualifies the new privacy
requirements.

## Earlier stages and frozen evidence

This roadmap replaces the work order of the
[previous five-stage branch plan](https://github.com/elldeeone/kaspa-privacy-initiative/blob/c3afb1b94f023057bfe99d780271f6de52c43da4/docs/SHARED-POOL-PLAN.md).
The branch was renamed from `shared-pool-four-wallet`; historical references retain
that original name. H1-H18, their frozen criteria, failed outcomes and raw/exported
evidence are unchanged. Earlier "Stage 1 complete" means the bounded older-version
recovery workload, not milestone 1 or current-version general recovery here.

| Earlier stage | Continuing obligation |
| --- | --- |
| 1 Independent recovery | Milestones 2, 5 and 6, qualified on the current version. |
| 2 Practical privacy | Milestone 1, the early privacy gate before 3, and broader milestone 7; H18 stays failed and its TN10 condition stays unmet. |
| 3 Failure and fee limits | Milestones 5, 6 and 8. |
| 4 Usable payment cycle | Milestones 2, 4 and 9. |
| 5 Independent review | Milestones 3 and 10, with review starting early. |

Each experiment retains its own frozen criteria. Where used, the historical 25%
relative privacy improvement, 25% additional whole-ledger fees and 30-minute delay
screens remain attached to their original experiments.
They are not automatically the new user-level privacy or operating requirements.
Any future numerical target is specified before evaluation; replacing a research
question does not turn an earlier failure into a pass.

## Recording progress and preserving the constraints

For each milestone, update this plan and the [journal](RESEARCH-JOURNAL.md) with
its question, exact candidate identity, evidence level, result, remaining gap and
decision. Preserve observations that contradict the candidate. Keep facts,
interpretations and untested proposals separate; milestone numbering is not a
claim of completion.

Before architecture changes, refresh primary/mature-protocol sources, update the
RFC/ADR, [architecture](ARCHITECTURE.md), [threat model](../THREAT-MODEL.md) and
[open questions](../QUESTIONS.md). Preserve all [invariants](../SECURITY-INVARIANTS.md).
This roadmap changes research direction and work order, not protocol rules.

Inflation, double spending, unauthorized payout or unverifiable accepted state
stops the affected path. Resolve the cause before further funding. Operational
harness limits alone are not protocol failures: preserve the failed run and repair
the harness. Never weaken a safety check, invent an unpaid claim away, expose
wallet secrets or conflate synthetic, local-native, TN10 and independent-review
results. Every native amount remains integer sompi.
