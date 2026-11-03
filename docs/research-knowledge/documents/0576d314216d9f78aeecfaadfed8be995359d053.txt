# Shared-pool branch plan

Updated: 2026-10-19. Branch: `shared-pool-four-wallet`.
Evidence baseline: `203198b3a604dd2388533a8c69484efe032e0cf8`.

**Current position:** the bounded payment/exit mechanics work on TN10. Independent
wallet recovery and useful privacy remain unestablished. The next gates are
recovery and privacy; a larger transaction count alone is not the next milestone.

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
| 1. Independent recovery | 3–4 | Offline passed; [H7 live recovery](../poc/shared-pool/RECOVERY.md) in progress | Can users recover without the experiment's private files or services? |
| 2. Practical privacy | 5 | Preliminary H2 only; next | Does the candidate hide useful relationships under explicit low-activity assumptions? |
| 3. Failure and fee limits | 4 | Partial H3–H6 evidence | Under what conditions can every valid claim still exit? |
| 4. Usable payment cycle | 6 | Not complete | Can a testnet user operate the resulting design without manual proof handling? |
| 5. Independent review | 7 | Not complete | Does independent scrutiny justify broader testnet use or require redesign? |

Execute stage 1 first. Stage 2's offline analysis can proceed independently and
must finish before substantial wallet expansion. Stages 1 and 2 must justify
continuing this candidate before stages 3–4 expand it. A discovered safety flaw
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

**Hypothesis / decision:** an established wallet policy can materially reduce
chain-only relationship inference at tolerable delay/cost. Determine whether to
retain the layout, change it, or narrow the intended use case.

**Smallest study:** first audit the compact public transaction fields and old
anchor leakage. If that already makes the chosen target deterministically
identifiable, document the counterexample before building a simulator. Otherwise
compare identical hidden payment ledgers under baseline and at most two policies:
bounded randomized withdrawal delay, and equal public payouts with private
change. The latter is proposed for compact state, not implemented behavior.

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

**Immediate next artifact:** a stage-1 recovery input inventory and bounded test
specification, plus the stage-2 observer/attack specification. No experiment was
run to create this plan.
