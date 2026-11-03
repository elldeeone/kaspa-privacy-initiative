# Shielded native KAS research plan

Updated: 2026-10-20 (Australia/Sydney). Branch: `shielded-kas-research`.
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

The owner approved this ten-milestone roadmap, its documentation commit/push, and
starting milestone 1. Milestone 1 defines requirements and evaluation; it does not
implement a new cryptographic subsystem. The later milestones describe the
programme, not authorization for funded trials, paid infrastructure, participant
recruitment or upstream publication. Existing branches, secrets and evidence stay
intact. Routine source research and local milestone-1 documentation can proceed.

**Current work:** define the privacy promise, adversaries, observations,
measurements and operating requirements. The first integrated delivery target
combines that specification with one current-version wallet lifecycle and an
independent attack suite. It spans milestones 1, 2, 4 and 7; it is not already
complete because individual older experiments passed.

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

**Status:** first authorized work package; specification and source review next.

Specify the intended user activity, protected relationships and amounts, explicit
public information, adversaries and required honest participation. Separate
payments from an existing shielded balance, entering/leaving the pool, and recovery.
Compare persistent balances with prompt cashout rather than assuming either is private.

Define owner/payment attribution, funding relationship inference, amount disclosure,
attack precision/coverage, uncertainty and observation horizons. Evaluate actual
payers and recipients rather than treating note counts as people. Set usable
payment sizes, hardware, fees and delay targets before scoring; distinguish chosen
research thresholds from established privacy guarantees and measured baselines.

**Deliverable and gate:** an open privacy RFC, current-source/reuse review and
requirement-to-evidence map. Every proposed claim names its adversary, observations,
assumptions, failure condition and evidence still needed. Unresolved numeric targets
remain explicit; they cannot silently become a passing gate. This completes a
requirements milestone, not a privacy validation.

## Milestone 2 — Consolidate one protocol candidate

**Status:** bounded v6 mechanisms exist; integrated lifecycle incomplete.

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

## Milestone 3 — Review cryptography and setup trust

**Status:** author review and negative controls exist; independent assurance open.

Review the actual private relation and native covenant together: bootstrap backing,
range/conservation, real/padded slots, nullifiers, historical anchors, recipient
spendability, replay and terminal release. Compare established constructions and
record adaptations; their security does not transfer automatically to this protocol.

Evaluate a reviewed multiparty setup process and a feasible transparent-proof route
against the current single-party assumption, including proving and recovery costs.
Start review alongside specification and integration, before wallet polish.

**Gate:** unresolved credible inflation, double-spend or unauthorized-exit findings
block expansion. Experimental setup can support conditional research only; tests,
parameter hashes and source review cannot establish honest setup or erased trapdoors.
Architecture changes require the relevant RFC, ADR and synchronized threat model.

## Milestone 4 — Deliver a usable wallet lifecycle

**Status:** experiment clients exist; general client incomplete.

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

**Status:** older-version bounded recovery passed; current-version work remains.

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

## Milestone 7 — Attack complete payment privacy

**Status:** blinded arithmetic observers exist; broader independent evaluation open.

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

Milestone 1 defines the evaluation contract. Integration (2), cryptographic review
(3) and privacy work (7) then proceed together. Wallet work (4) supplies the current
version used by recovery (5) and settlement fault testing (6). Measurements feed
architecture selection (8). The independent-user trial (9) follows qualification;
the reproducible release (10) includes the resulting evidence and limitations.

Begin with the privacy RFC and source/capability map. Use the resulting gaps to
scope the first coherent wallet increment and independent attack suite. The
persistent-balance versus prompt-cashout comparison is an early diagnostic inside
this programme, not the whole programme or a reason to delay all useful integration.

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
| 2 Practical privacy | Milestones 1 and 7; H18 stays failed and its TN10 condition stays unmet. |
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
