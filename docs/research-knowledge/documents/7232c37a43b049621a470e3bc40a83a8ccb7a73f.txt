# Shared-pool branch plan

Updated: 2026-10-20 (Australia/Sydney). Branch: `shared-pool-four-wallet`.
Evidence baseline: `203198b3a604dd2388533a8c69484efe032e0cf8`.

**Current position:** H13's authorized bounded offline and TN10 implementation passed:
two private inputs, spendable private change, partial withdrawal and four wallets
paid through six unchanged saved proofs. Thirteen pool operations drain the
reserve to zero; TN10 adds ordinary allocation and genesis. The
[live report](../poc/shared-pool/TWO-INPUT-TN10.md) records
costs, controls and limitations. [RFC-0011](rfc/0011-two-input-private-payments.md)
remains Open; this supplies candidate payment mechanics, not practical privacy
or general recovery. Live clients reconstruct accepted history without the
original prover/controller state, within a four-depositor, one-host/RPC fixture.
The original spec is committed as `c50855a`. No new privacy run or publication
is part of this bounded continuation.

**Earlier completed evidence:** H11's bounded fresh-proof screen is complete. H12's
equal-net funding comparison also passes its frozen offline screen: all four
funding deposits remain feasible for every target through drain in the declared
all-deposits-first workload. Genuine calibration, isolated exit adapters and
complete TN10 rehearsal/measured trials pass, with all four wallets paid.
Keep fresh proofs/private fallbacks and equal
net credit as candidate wallet policies. Strong or general privacy is not
established. [H12 result](../poc/shared-pool/NORMALIZED-DEPOSITS.md).

**Earlier milestones:** bounded payment/exit mechanics and Stage 1 three-wallet
recovery passed on TN10. Stage 2's initial public-field audit is complete and
activated its old-anchor redesign condition: the first H6 withdrawal identifies
one source transaction despite 100 later payments. H9's bounded offline
fresh-proof comparison now passed: the target retains 3/5 possible sources in
two/four-payment fixtures, while a private old fallback remains independently
usable and only one proof can spend. Useful privacy remains unestablished;
see [the comparison](../poc/shared-pool/FRESH-PROOF.md).

The independent-deposit prerequisite is specified in
[RFC-0010](rfc/0010-compact-independent-deposits.md): a new immutable pool version,
the existing private circuit, two notes per funded admission, and four wallets
draining with proofs saved before later deposits. H10's implementation passed
the offline gate and complete TN10 rehearsal/fresh trial: all four wallets paid
using eight unchanged saved proofs and zero reserve. Stage 2's privacy thresholds
remain unchanged. [Measured report](../poc/shared-pool/DEPOSITS.md).

**Finish line:** a reproducible testnet wallet can receive, send and withdraw
native test KAS, maintain correct backing, recover without privileged help, and
state measured privacy and operating limits. This plan does not promise mainnet.

## Scope and order

This is our independent execution plan within the [repository roadmap](ROADMAP.md),
not a replacement for its requirements or an upstream-approved protocol. Decisions
follow evidence; they do not depend on a maintainer reply. Work within current
Kaspa L1, with no new token, real funds or privileged withdrawal path. A consensus
change would require a separate research decision, not an implementation shortcut.

| Branch stage | Roadmap phases | Status | Decision it must support |
| --- | --- | --- | --- |
| Baseline: payment and settlement | 2–3 | Bounded results recorded | Keep the direct-L1 candidate for further tests; broader recovery remains open. |
| 1. Independent recovery | 3–4 | [Bounded H7 completed](../poc/shared-pool/RECOVERY.md): offline, complete TN10 rehearsal and fresh trial | Can users recover without the experiment's private files or services? |
| 2. Practical privacy | 5 | Bounded H11/H12 complete; H13 mechanics pass offline and TN10, broader qualification open | Review the v6 relation/limits and use a correct merging/padding observer before varied-payment privacy claims. |
| 3. Failure and fee limits | 4 | Partial H3–H6 evidence | Under what conditions can every valid claim still exit? |
| 4. Usable payment cycle | 6 | Not complete | Can a testnet user operate the resulting design without manual proof handling? |
| 5. Independent review | 7 | Not complete | Does independent scrutiny justify broader testnet use or require redesign? |

Stage 1 is complete for its declared three-claimant workload. Stage 2's
[anchor-policy study](rfc/0009-compact-anchor-privacy.md) now supports continuing
the candidate, with a substantial funding-origin limitation. This is a measured
screening result, not completion of general privacy or stages 3–4. A discovered safety flaw
takes priority at any stage. Stage 5 review can start earlier; its completion is
not implied by an implementing agent's self-review.

Creation of this plan authorizes no new experiment, funding, service deployment
or upstream publication. Existing artifacts and variants stay intact. The next
implementation needs a concrete experiment specification within the user's
authorized scope; no standing requirement to seek a maintainer's permission.

## Evidence we can carry forward

These tests were developed incrementally. This plan does not retroactively
preregister them or combine different protocol variants into one working system.

| Journal entry | Supported result | Boundary carried forward |
| --- | --- | --- |
| [H1](../poc/self-funded/README.md) | Payment and independent authorized payouts paid native fees from claims. | One bounded sequence; experimental setup and retained artifacts. |
| [H2](../poc/shared-pool/README.md) | Four wallets exited; partial change with equal first payouts preserved more amount ambiguity. | One synthetic workload; no improvement in unique-source identification. Partial exits are absent from the compact variant. |
| [H3/H4](../poc/shared-pool/CONTENTION.md) | A note floor and one competing-exit recovery worked in version 3. | Tested fee assumptions; loser generated a new proof. Not compact-state contention evidence. |
| [H5](../poc/shared-pool/ANCHORED.md) | An existing private authorization survived one unrelated payment. | Small array state, existing authorization, public bootstrap/history available. |
| [H6](../poc/shared-pool/COMPACT.md) | Exact proof reused after 100 payments; 204 native transactions confirmed and all claims drained. | Serial workload, finite depth, retained metadata/history; no recovery-from-backup or anonymity result. |

The compact baseline has no later deposits or partial withdrawals. Its proof
binds an exact fee and historical anchor; fee repricing needs new authorization,
and public rebasing does not enlarge that anchor's candidate set. Single-party
setup, history availability and a correct node view remain assumptions.

For cost comparisons, H6 measured 21,688,400 sompi per transfer and 21,729,600
sompi for Bob's exit at 100 sompi/mass. His original proof took 9,759 ms, public
rebuilding 352.426 ms, and RPC discovery another 11,356.203 ms. These are measured
TN10/workload results, not current fee quotations or wallet performance promises.

## 1. Independent recovery

**Observed completion, 2026-10-19:** all three wallets restored from pre-payment
backups on a separate host and exited through a separate public RPC after the
original prover/data source stopped. Offline controls, a complete rehearsal and
a fresh measured trial passed; the interrupted first attempt was also drained
through ordinary independent exits. Keep three private keys plus the descriptor
pin, and the initial depositor's note opening. Retained public parameters/history
and a correct node view remain requirements. This is one initial deposit with
three synthetic claimants, not general pruning/reorg recovery or a privacy result.
Exact payouts, costs, limits and evidence are in [RECOVERY.md](../poc/shared-pool/RECOVERY.md).

**Hypothesis / decision:** a recipient can be offline during payment, then recover
and exit using a declared backup and authenticated public data. Determine the
minimum backup and availability requirements before building more wallet features.

**Smallest test:** three wallets, with Bob offline for his incoming payment.
Stop all original wallet/prover processes and experiment state services. Restore
each wallet separately, discover its claims and complete all native payouts.
Bob's backup must predate the incoming payment and contain no plaintext or witness
for that payment. A newly received note needs its first private proof; this is a
different test from H6's reuse of an already-created proof.

**Complete and supported when:**

- The input inventory names every private backup field and public dependency:
  pool identity/descriptor, accepted history, ciphertexts, verification and
  proving parameters, and independently obtained chain state. Authenticate the
  descriptor and parameters against the intended pool; do not publish the
  experiment manifest's receiver list as a wallet bootstrap shortcut.
- All three wallets recover and receive the exact expected payout, with complete
  backing/fee reconciliation. No sender secret, coordinator export of new notes,
  precomputed exit authorization or privileged signature is supplied.
- Offline isolation passes, followed by a complete TN10 rehearsal and fresh
  measured trial. The live recovery uses infrastructure independent of the
  original experiment services; same-node replay alone does not close the
  [roadmap recovery gate](ROADMAP.md#early-exit-and-recovery-gate).
- One public-history source can disappear and another independently accessible
  source suffices. Corrupt, substituted, missing and stale data are rejected or
  detected before acceptance. Losing all required history causes a reported safe
  halt, not invented witnesses; this negative control is not recovery success.
- Record the backup recipe, public-data inventory, per-wallet payouts, fetched
  bytes, proof/startup/recovery times, fees and actual shutdown/isolation evidence.

**Stop/redesign:** any wallet needs unpublished operator data; a required public
artifact has no independent recovery path; invalid history is accepted; or a
claim remains unpaid within the declared available-data model. If keys alone
are insufficient, record that failed hypothesis and specify/test the additional
backup requirement explicitly. Static public mirrors may suffice; do not build
an operator network without evidence that it is needed.

## 2. Practical privacy

**Current mechanics gate, H13:** [RFC-0011](rfc/0011-two-input-private-payments.md)
specifies two-input/two-output normal payments, partial withdrawal change and a
no-append full-exit fallback. [ADR-0024](adr/0024-two-input-private-payment-scope.md)
records the documentation-first decision and subsequent owner authorization.
The bounded offline and TN10 implementation passes with private change, partial
withdrawal, six unchanged saved-proof exits and all four wallets paid. Live
clients discover accepted state through RPC without operator state; the capacity
test still uses a constructed boundary state. This does not complete Stage 2,
broader mechanical qualification or general wallet recovery.

Before broader qualification, resolve review objections concerning dummy NF injection,
value conservation, terminal accounting, capacity and proof preservation. Stop
or redesign if a valid funded claim can be stranded within the declared fee/data
model, if a privileged party is needed, or if current L1 cannot express the
checks. The [report](../poc/shared-pool/TWO-INPUT.md) establishes bounded costs
and saved-proof exits and names remaining tests. A later privacy study needs frozen economic workloads and a model
that permits merges and padding; do not reuse the old unique-deposit target or
thresholds as if they already evaluated this relation. General privacy stays open.

**Observed audit outcome, 2026-10-19:** the public-only observer found a unique
source transaction for the first H6 exit in both retained compact runs. Two
possible note positions share that source; this does not identify a person.
Coverage is 1/4 and 1/102 exits, with abstention elsewhere; H7 leaves two source
transactions for each of its three exits. A small joint-value sensitivity admits
three sources instead of one with a newer anchor, but no replacement proof was
generated. [H8 report](../poc/shared-pool/PRIVACY.md) and
[ADR-0021](adr/0021-separate-exit-fallback-and-privacy-policy.md) retain reusable
exits and reject frozen-proof waiting as this case's privacy remedy. Stop before
the conditional traffic simulator/funded trial. The 25%/25%/30-minute policy
thresholds below are untested; the candidate has not passed practical privacy.

**Bounded follow-on, H9:** genuinely fresh proofs now expand the target's source
candidates from 1 to 3/5 after two/four payments, including full drainage. With
no activity the source stays unique. Both old/fresh winner orders reject the
second spend; six isolated rebuilds need no wallet/PK/network. The old fallback
and alternate histories remain private. Added native fee is zero; fresh proof
work is 9.514–9.589 seconds, with 100.414 seconds for cold parameter loading.
The [frozen specification](../poc/shared-pool/FRESH-PROOF-SPEC.md) and
[report](../poc/shared-pool/FRESH-PROOF.md) explicitly limit this to three designed
offline fixtures. This selects a mechanism for further policy work, without
passing or revising the population thresholds or authorizing TN10/wallet expansion.

**Completed workload prerequisite, H10:** [RFC-0010](rfc/0010-compact-independent-deposits.md)
and [ADR-0022](adr/0022-compact-two-note-deposits.md) scope independently signed
native deposits into a fresh immutable compact pool. Each deposit adds two notes
and accepted history without changing existing spentness; prior proofs within
that new pool must remain usable. The main fixture has four separately funded
wallets, 13 native transactions and eight prepared exits, with all provers stopped
before drainage. Require exact backing, byte-identical old proofs, each wallet's
terminal role and no operator help. Existing v4 proofs are preserved as evidence,
not migrated. Offline fees/composition and all four terminal roles passed;
complete TN10 rehearsal and a fresh trial paid all eight claims using their
original proofs. The measured 14-transaction run including ordinary allocation
cost 2.656933 tKAS. This prerequisite supplies
real admission mechanics for the later study; it cannot pass the privacy gate.

**Hypothesis / decision:** an established wallet policy can materially reduce
chain-only relationship inference at tolerable delay/cost. Determine whether to
retain the layout, change it, or narrow the intended use case.

**Completed bounded study, H11:** [the result](../poc/shared-pool/PRIVACY-STUDY.md)
retains all 64 primary ledgers plus 17 controls, with 882 withdrawals through
complete drain. Relative inference reductions are 35.6% / 61.5%, with paired
95% intervals [32.2%, 39.1%] / [58.3%, 64.6%]. Added native fee is zero; the
measured cold-load-plus-proof component estimate is about 122 seconds at p95,
excluding RPC/confirmation. Two genuine native calibrations match the model;
both proof arms drain without PK/wallet inputs. The 20-minute wait produces no
gain without further activity. The predeclared screen passed; high residual
funding-origin inference is a separate limitation, not a changed pass criterion.
**Follow-on H12:** the separately frozen
[equal-net comparison](../poc/shared-pool/NORMALIZED-DEPOSITS-SPEC.md) is now
executed offline. It preserves total funding and topology across net/gross/varied
policies. Its four-way deposit ambiguity survives complete drain, with the
singleton and early-exit controls retaining their linkage. Native calibration
passes; complete TN10 rehearsal and measured trial both paid all four wallets
using unchanged exit proofs, with no remaining reserve. General interleaved-user
privacy and mixed-denomination behavior remain open.

**Study definition:** [H11's frozen specification](../poc/shared-pool/PRIVACY-STUDY-SPEC.md)
compares saved versus fresh proofs with independently funded admissions. A
bounded waiting control assumes no invented background traffic. Two low-activity
regimes, all eventual withdrawals, separate truth/observer processes and native
calibration precede the keep/redesign decision. Equal payouts with private change
remain a separate proposed relation; they are not silently imported into v5.

**Complete when:**

- Preregister workloads, seeds, exact observer fields, attacks and decision
  thresholds before evaluation. Include singleton activity as a negative control,
  two low-activity regimes, and independent deposit funding plus a shared-funding
  control. Do not infer user counts from note counts. Public amounts/timing,
  addresses/scripts, reserve ancestry, nullifiers, anchor age/count and all other
  serialized fields belong to the chain observer. Private wallet-owner labels,
  note ownership and the hidden payment graph belong only to the scoring process;
  attack code must not read them. RPC/IP information is a separate arm.
- Baselines cover timing/order, amount compatibility and jointly consistent
  payment histories. The primary target is the transaction that created a
  withdrawal's consumed note, on a preregistered matched set of withdrawals;
  report deposit-ancestor inference separately. Report correct source inference,
  precision versus coverage, remaining candidates, abstentions, extra delay,
  native fees and transaction count. Hold observation horizons and coverage
  comparable, include eventual withdrawals, and report uncertainty across
  independently generated ledgers.
- As a proposed research decision threshold, require at least a 25% relative
  reduction in correct top-1 source inference at full coverage in both declared
  low-activity regimes, with paired 95% intervals excluding no improvement.
  Additional total native fees must be at most 25%, and p95 added withdrawal
  delay at most 30 minutes. These are branch screening targets, not anonymity or
  user-acceptance guarantees; any revision must precede evaluation and be logged.
  A relative gain alone is insufficient to claim useful privacy: report absolute
  attack success and its comparison with an observer using only public priors.
- The report distinguishes measured current behavior from modeled modifications,
  lists each policy's assumptions/protocol changes, and records keep/redesign/stop.
  No synthetic score becomes a claim about real-world anonymity. Network/RPC
  privacy remains open unless separately tested.

**Stop/redesign:** no policy meets the declared tradeoff; improvement relies on
hidden observer data, excluded failed cases, unbounded delay, assumed background
users or a trusted mixer; old anchors defeat the target; or the outcome merely
repeats a known limitation without selecting between designs. A null result
completes the study but does not pass the candidate. Do not fund a live privacy
trial when offline results cannot inform a new design decision.

## 3. Failure and fee limits

**Hypothesis / decision:** compact settlement supports independent retries and
exits within a stated fee, contention, history and capacity envelope. Specify
that envelope instead of claiming unconditional liveness.

**Complete and supported when:**

- Two compact wallets race, with each winner order tested. The loser discovers
  accepted state and exits with identical authorization/proof after the winner
  stops. Also test exit attempts during a declared finite competing-payment
  schedule, recording every user's retries, proof work and payout; a serial
  post-activity exit does not satisfy this case or prove sustained fairness.
- Offline fee cases cover the measured baseline and 2x/4x rates, including the
  minimum accepted note. Any necessary repricing preserves authorization,
  backing and payout constraints. Record when new private proof work is needed;
  do not silently change an exact-fee authorization. Validate viable cases on
  TN10 under actual relay policy; do not manipulate the public network's fees.
- Controlled rollback/replay cases invalidate orphaned anchors and reconstruct
  accepted spentness without double payment. Capacity exhaustion preserves all
  existing exits and rejects unsupported new activity. Keep simulated reorgs
  and synthetic capacity fixtures distinct from live observations.
- A bounded failure matrix records safety, recovery outcome, required data,
  latency/cost and the decision for every case. All supported claims can drain.

**Stop/redesign:** an in-envelope claim becomes uneconomic/unspendable, repeated
competition prevents demonstrated progress, rollback loses liabilities, or any
case needs privileged rescue. Never weaken spentness or state validation. A
safe halt preserves safety but does not pass liveness. Out-of-envelope failures
must narrow the documented support claim; the envelope cannot be shrunk after
results merely to mark the stage passed.

## 4. Usable payment cycle

**Hypothesis / decision:** the retained design supports a repeatable user workflow
on explicitly supported hardware, with comprehensible backup and fee behavior.

**Complete and supported when:**

- One coherent version supports later deposits, offline receiving, private send,
  partial withdrawal/change and full exit. Repeat the cycle with three users and
  independently drain all claims. Earlier variants' features do not count as
  features of the compact version.
- A clean testnet user can follow the documented wallet commands without editing
  proofs, Merkle paths or transaction JSON. Deterministically reject unspendable
  received notes before showing them as usable balance. Exercise backup/restore
  and the supported failure cases through the same wallet path.
- Before optimization, state the intended payment sizes, supported hardware and
  numerical fee/time/memory budgets in the experiment specification. Completion
  requires measured compliance, including cold startup/parameter download,
  warm proofs, scanning, RPC discovery and payout separately. Current timings
  are baselines, not an adopted usability target.
- Selected privacy policies and their limits are reflected in the workflow;
  RPC and broadcast exposure is documented separately. No service receives
  private witnesses merely to make proving look faster.

**Stop/redesign:** costs miss the declared use case, added features break recovery
or privacy, or routine use requires hidden manual/operator help. Preserve a small
working command-line client; defer UI polish until the full cycle passes.

## 5. Independent review and branch conclusion

**Complete when:** reviewers independent of the implementation assess the actual
proof/covenant relation, setup assumptions, value accounting, spentness, native
payout binding, history/backup requirements and privacy claims. Findings have
reproducible evidence and explicit dispositions; no unresolved critical issue is
carried into a broader testnet pilot. Produce a reproducible testnet specification
and a clear continue/redesign/stop conclusion. Experimental single-party setup
does not become an acceptable production setup by passing functional tests.

**Stop/defer:** independent review is unavailable, critical issues remain, or the
needed trust/performance assumptions conflict with the north star. Mainnet is a
separate decision outside this branch plan, even if every testnet stage passes.

## How this plan stays current

For each new experiment, record in the [journal](RESEARCH-JOURNAL.md): stage and
hypothesis; exact version and inputs; predicted outcomes and decision thresholds;
result/evidence; costs and assumptions; and the next decision. Update the status
table above at the same time. A study can be complete with a negative result;
mark the candidate `redesign` or `stopped`, not `passed`.

A new experiment must close a listed criterion or change a stated design
decision. Otherwise, do not run it. Add or reorder stages only with a journal
entry explaining the new evidence and which decision changes. Do not extend a
completed test merely to collect larger numbers.

Before changing cryptographic/state/exit architecture, refresh the relevant
primary-source and mature-protocol comparisons, update the RFC and record the
decision in an ADR. Keep [invariants](../SECURITY-INVARIANTS.md), architecture,
threat model and open questions synchronized. This plan changes work order and
acceptance criteria; it changes no protocol rule or invariant.

Inflation, double spends, unauthorized payout or acceptance of unverifiable
state stop the affected trial immediately. Preserve evidence and resolve the
cause before funding that path again. Operational harness limits alone are not
protocol failures: record them and fix the harness. Measured resource costs can
still fail a declared usability target. Use fresh trial identities for retries,
complete rehearsals through terminal payouts, and keep all amounts in integer
sompi. Never weaken a check or erase a failed run.

**Current result:** independent deposits passed H10, the fresh-proof population
screen passed H11, and equal net credits passed H12's bounded offline comparison.
Code, journal and sanitized evidence stay on this branch. Conditional TN10
validation also passed with all four wallets independently paid. Preserve
the remaining Stage 3–5 gates and the privacy limits: four compatible deposit
labels are not a general anonymity guarantee or permission to expand wallet
features without addressing the documented assumptions.
