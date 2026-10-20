# RFC-0012: Useful privacy requirements for native KAS payments

**Status:** Accepted — requirements profile approved by the owner; milestone 1
complete. No implementation qualification or validated privacy claim is implied.

**Decision:** [ADR-0027](../adr/0027-shielded-payment-targets.md).

**Date:** 2026-10-20

**Scope:** [Shielded-KAS roadmap, milestone 1](../SHARED-POOL-PLAN.md).
Implementation/evidence baseline: `c3afb1b94f023057bfe99d780271f6de52c43da4`.

## Context

The intended product is an optional domain for native test KAS in which a person
can receive a payment, spend it again, recover from a backup and exit without an
operator's permission. The present candidate has bounded native payment/exit
evidence. It does not yet establish useful financial privacy or an independently
operated current-version wallet.

This RFC defines what a useful result must mean before further implementation is
judged. Requirements apply regardless of proof system, input count, pool layout or
execution runtime. They do not turn the current v6 choices into permanent rules.
The [source review](../../research/shielded-kas-privacy-requirements-2026-10-20.md)
records established designs to study and the limits of that reuse.

## Goals, constraints and adopted use case

All [security invariants](../../SECURITY-INVARIANTS.md) remain unchanged.
Correct native backing, conservation, authorization, single spending, recipient
spendability and independent recovery are requirements, not privacy tradeoffs.
No new token, privileged withdrawal path, real funds or mainnet deployment.

The adopted primary use case is repeated payments from an existing shielded
balance, with recipients able to keep and spend received value. The hypothesis is
that this offers more useful privacy than repeatedly entering and immediately
leaving. The use case is selected; its privacy advantage remains an untested hypothesis.

Evaluate three activities separately:

| Activity | Intended protection | Explicit boundary |
| --- | --- | --- |
| Internal payment and later private spending | Uninvolved parties should not reliably infer payer/recipient relationships, private amounts or remaining balances beyond the declared leakage budget. | Intended counterparties know their own transaction details. Small or adversarial populations may offer little anonymity. |
| Deposit and ordinary cashout | Limit linking native ingress/egress to internal payments or unrelated users. | Native amounts, scripts, funding ancestry and reserve movements are public; their consequences remain attack inputs. |
| Urgent exit or recovery | Preserve ownership, backing and user-controlled access after service loss. Measure resulting disclosure. | An older saved proof, rapid cashout or recovery traffic may reveal more than ordinary use. |

A privacy timer, minimum participant count or another user's cooperation must
never become an exit condition. A user may knowingly choose an immediate,
potentially revealing exit. Ordinary chain inclusion, adequate fees, authentic
state and sufficient recovery data remain explicit availability assumptions;
there is no promise of progress under arbitrary network censorship.

Alternatives remain open: an immediate-cashout payment service needs its own
successful privacy/economic qualification; transparent native payments provide a
useful baseline but do not meet this goal. Batching or a based-app runtime may
address a measured bottleneck later. Neither supplies privacy automatically.

## What privacy means here

Distinguish a **person controlling keys**, a **wallet**, a **note**, a **payment**,
and a **native transaction**. Several wallets or deposit outputs may belong to one
person. Combining notes also destroys the old assumption that each payment has
one funding ancestor.

For each evaluated target, record its ground-truth sender, recipient and amount
privately, and define which of those facts the observer legitimately already knows.
A funding target must distinguish structural ancestry from allocation of value.
The actual consumption/creation graph defines a transitive set of deposit
ancestors: take the union across consumed inputs. It does not assign particular
sompi from those deposits to later outputs. After merging two deposits and
splitting the result, there may be no unique economic allocation. Score the
structural set (or membership in it), or a specified proposition over feasible
value allocations. Do not label a chosen allocation as economic ground truth
or infer funding ownership merely from ancestry.

Cryptographic confidentiality, logically feasible alternatives, measured attack
accuracy and real-world anonymity are different properties. None substitutes for
the others. Candidate count is not a probability distribution or a people count.

## Observer profiles and available information

Profiles can be combined; they are not a single ordered threat ladder. Every
experiment specifies the exact combination, time horizon and withheld ground truth.

| Profile | Information/actions available | Main question |
| --- | --- | --- |
| C: public chain | Full accepted transaction bytes/history, amounts, scripts, ancestry, roots, nullifiers, ciphertexts, fees, sizes and declared public timing observations; wallet algorithms/policies. | What relationships, funding sets and private values follow from public activity? |
| P: participant disclosure | C plus the complete declared records of named participants. Evaluate separate records and explicit pooled collusion separately. | What additional information about uninvolved parties follows from counterparties' knowledge? |
| A: active participant | C/P plus attacker-chosen deposits, payments, distinctive amounts, timing and attacker-controlled wallets. | Can an adversary isolate or tag honest activity, or remove its own wallets from the apparent anonymity set? |
| I: infrastructure | Declared RPC, archive/scanning, broadcaster or network observations, optionally combined with C/P/A. | Do requests, IPs, timing or retries identify users or selected notes? |
| E: endpoint exposure | Precisely defined stolen viewing/spending material or local records, and the time of compromise. | Which past/future information and spending authority become exposed? |

An attacker is not given hidden ground truth merely to improve a score. Conversely,
records explicitly included in P/A/I must not be withheld to make privacy look
better. For owner-level metrics, collapse alternatives known to share control into
one owner; remove only candidates known to be attacker-controlled at the target
and observation horizon. Honest co-owned notes remain candidates, and receiving
funds from an attacker does not make the recipient attacker-controlled. A public
wallet cannot generally verify that several plausible on-chain candidates
represent independently controlled honest people.

Endpoint secrecy against an attacker who already possesses that endpoint's
records is outside the corresponding claim. Forward secrecy, view-only balances,
sender anonymity from the recipient and network anonymity each need separate
design/evidence; none is inherited from a zero-knowledge proof.

## Leakage and trust register

| Class | Requirement |
| --- | --- |
| Private wallet boundary | Do not send spending secrets, undisclosed note openings, private proof witnesses or selected note indices/membership paths to RPCs, archives, executors, logs or hosted provers. Local proving is the initial candidate policy. Outsourcing changes the trust profile. |
| Intended disclosure | Recipient information needed to accept a payment; deliberate user disclosures; public native ingress/egress. Explicitly measure what these reveal about other transactions. |
| Metadata to measure | Operation type, input/output shape, padding, change order, anchor age, fees, timing, sizes, retries, nullifier reuse across competing authorizations, scan ranges and network linkage. No default exemption. |
| Cryptographic assumptions | Commitment hiding/binding, encryption confidentiality and recipient privacy, nullifier properties, proof soundness/zero knowledge, implementation correctness and setup integrity require analysis/review. |
| Availability assumptions | Enumerate user-held backup material, public parameters, history/ciphertexts, accepted chain view and software. Missing all copies of essential data is a recovery failure, even if the client safely rejects. |

The [earlier private-wallet RFC](0002-shielded-payment.md) supplies the witness
boundary and receipt/recovery obligations. Only requirements are reused here;
its older transition pipeline is not substituted for v6.

An honest setup is currently a conditional research assumption. A reserve balance
cap alone does not prevent forged claims from stealing backing owed to existing
holders. Parameter hashes identify an instance; they cannot prove trapdoor erasure.

## Requirements, falsifiers and evidence still needed

All privacy rows apply to the named observer profiles above and the disclosed
population/workload assumptions. The adopted numerical targets are specified below.
Safety violations are failures regardless of a privacy score.

| ID | Required property | Falsifier / decisive observation | Evidence still required |
| --- | --- | --- | --- |
| R1 | Native liabilities remain backed; consumption, fees and payouts obey the unchanged invariants. | Any accepted unsupported liability, duplicate spend or unauthorized reserve release. | Integrated current-version argument/review and boundary/adversarial tests; a passing trace is insufficient. |
| R2 | A recipient accepts only authenticated, owned, unspent, protocol-spendable value. | A wallet credits a malformed, substituted, already-spent or otherwise unusable receipt it cannot detect before acceptance. | Current-version scanning/acceptance and negative delivery cases; ciphertext presence or decryption alone is insufficient. |
| R3 | Internal payment relationships have useful privacy against C and the specified P/A combinations. | A repeatable attack exceeds the frozen absolute leakage budget for uninvolved targets, including after subsequent activity. | Independent held-out evaluation with user/control labels and realistic side information. |
| R4 | Private amount/balance and funding-set claims survive the same C/P/A observations. | Exact recovery or commercially revealing narrowing exceeds the frozen budget, even where several transaction ancestors remain possible. | Feasible value ranges, funding-set evaluation and calibrated guessing where justified; no existing owner/amount result is carried forward. |
| R5 | Ordinary wallet operation does not export private witnesses; I-profile claims include actual service observations. | Selected-note requests, metadata or private data leave the declared boundary or make the claimed protection fail. | Instrument local proving, scanning, RPC/broadcast and recovery; chain-only evidence cannot close this row. |
| R6 | Any claimed privacy lasts for its declared observation horizon. | Later withdrawals, fallback exposure or full drainage invalidate a durable-privacy claim. | Scores at payment, later cashouts and terminal drainage, retaining all prior observations. |
| R7 | Each supported claimant recovers and exits without privileged cooperation. | Loss of one preferred service, a routine race, or stated fee change requires an operator signature, another party's private-state export, privileged rescue or abandoned liability. | Current-version pre-payment-backup recovery plus bounded fault/fee/inclusion evidence; assumptions and starvation limits explicit. |
| R8 | Supported payments and exits meet a chosen operating envelope. | All-in user costs, latency, hardware or recoverable minimums fail predeclared targets. | Per-user cost frontier, cold/warm measurements and fee sensitivity; whole-ledger cost averages alone are insufficient. |

No weakening of R1/R2/R7 is permitted to improve R3/R4. Safe halting protects
safety, but does not count as successful recovery or timely exit.

## Measurement contract

Before an evaluative run, freeze a manifest containing the protocol/version and
public parameter identity; workload and participant control; observer inputs;
targets and exclusions; attack development/evaluation split; timing source and
observation horizon; costs/hardware; thresholds; and treatment of missing results.

Report:

1. **Relationships and ownership:** absolute full-coverage guessing accuracy plus
   precision at stated coverage for selective attacks. Exclude facts already known
   to that observer; report exclusions/counts. Compare with a public-prior baseline
   frozen before the tested disclosures. Uniform guessing needs a justified prior.
2. **Values and funding:** exact feasible amount/balance ranges and funding sets
   under stated constraints; calibrated probabilistic predictions when available.
   Report exact and narrow disclosure separately. Multiple feasible assignments
   are logical alternatives, not equal posterior probabilities.
3. **Uncertainty and failures:** group uncertainty by independently sampled
   ledger/session, not correlated notes. Declare attack selection before held-out
   evaluation. Missing traces, timeouts and unknown solver results are incomplete
   evidence, never additional anonymity.
4. **Economics:** admission, transfer, merge/change management, retries and final
   cashout costs per user. Report fee/payment and fee/payout ratios, supported
   amount range, minimum recoverable claim, cold/warm time and peak memory.
   Separate proving, sync, submission and acceptance latency.

All native amounts use integer sompi; percentages are reporting calculations.
Report each observer/activity/horizon separately. There is no aggregate
"privacy percentage." A relative improvement over an especially revealing policy
cannot establish an acceptable absolute outcome.

### Adopted qualification targets

The owner adopted this profile on 2026-10-20. These are prospective research
acceptance criteria for a useful system, not measurements, cryptographic security
parameters or permission to use real funds. Failing a target does not reopen an
old result or change a target retrospectively.

| Area | Adopted target | Measurement boundary |
| --- | --- | --- |
| Payment amount | 10–1,000 tKAS; test 1 and 10,000 tKAS as boundary cases. | Normal range is 1,000,000,000–100,000,000,000 integer sompi. Boundary cases are 100,000,000 and 1,000,000,000,000 sompi. Native units do not imply stable purchasing power. |
| Ordinary payment fees | At most 1% of the payment amount. | Include necessary merges/change management and the user's attributable batch/service costs. Count all actual costs; an undisclosed subsidy cannot satisfy the target. |
| Complete lifecycle fees | At most 2% of the private payment amount for deposit → payment → complete cashout. | Include ordinary funding, admission, payer change, recipient claims, retries and all final tails. Report each user's burden; do not divide by a larger overfunded deposit or hide costly recipients in an average. |
| Reference device | CPU-only laptop, four physical cores, 16 GB RAM, SSD; aggregate wallet peak memory at most 4 GiB. | Include required wallet/prover subprocesses, account for shared memory consistently, and record the actual CPU/model/thread count. No GPU. A separately operated optional node is outside wallet memory, not outside the chain-view trust model. |
| Warm proof | p95 at most 10 seconds. | From locally available selected notes and accepted public state through local witness construction and verified proof. Include any additional synchronization in end-to-end payment latency. |
| Ordinary payment | p95 at most 60 seconds. | From user authorization to the recipient independently recognizing accepted, spendable value; include preparation, proving, submission, acceptance observation and scanning. RPC acknowledgement alone is insufficient. |
| Cold startup | p95 at most 60 seconds. | Launch to ready to prove, with required public files already downloaded. Disclose OS/cache state. Initial downloads are measured in fresh recovery, not hidden as installation work. |
| Independent exit | p95 at most 120 seconds. | Open, synchronized wallet to observation of its owned payout. Include fresh local proving where necessary; no operator permission or mandatory privacy delay. |
| Fresh recovery | At most 15 minutes for the declared 10,000-operation history at 20 Mbit/s usable download throughput. | New machine on the reference hardware, backup predating a received payment, no private controller exports or precomputed exit required. Include public parameter/history download, reconstruction, discovery, proving and payout observation. Record latency/bytes and network conditions. |

Fees above qualify the reference-rate workload. Recompute actual transaction
costs at reference, 2× and 5× rates and require user-controlled exits at all three,
including valid small change claims and loss of a preferred service. Freeze
100, 200 and 500 sompi per normalized mining-mass unit as those research cases.
The numerical reference comes from the pinned default relay rate, whose minimum
fee uses `relay_mass = max(compute_mass, ceil(transient_mass / 2))`. Research
costing uses `mining_mass = max(relay_mass, storage_mass)` and can exceed that
relay minimum. These are fixed research assumptions, not market quotations or
guarantees of inclusion.
The 1%/2% ordinary-cost targets are not silently extended to arbitrary congestion.
Every accepted liability remains accounted for even when a fee scenario fails.
A missing repricing path or economically stranded supported claim is a failure,
not permission to erase it or redefine the supported minimum after the run.
Count the economic principal once in lifecycle ratios; recycled principal and
self-transfers cannot enlarge the denominator to dilute costs.

Latency targets describe a declared healthy-network acceptance policy, not
irreversible consensus finality. Name that policy and follow subsequent rollback
observations. Fault/contended traces report all claimants and the worst case as
well as percentiles. The healthy p95 must not excuse a permanently stranded user.
Performance targets score completed work; they are not short operational timeouts
that abort a funded trial or prevent its final payout.
Keep slow and failed operations in the assessment; a success-only percentile
cannot establish compliance.

### Adopted privacy targets

The primary research workload has 32 user roles, including eight active or
colluding adversarial roles. Simulated roles are a model; they do not establish
independent human ownership. Smaller populations, singleton cases and sparse
periods remain useful controls and failure-region evidence. A small pilot cannot
inherit the 32-role qualification.
Freeze the adversary's transaction/value share and scheduling powers as well as
its number of roles; eight roles need not mean one quarter of the traffic.

Apply every gate below separately to C, C+P and C+P+A, through payment, subsequent
individual cashouts and eventual complete drainage. Specify individual disclosures
and pooled collusion. Score sender and recipient separately as well as their
relationship: joint-pair accuracy cannot hide exposure of one endpoint.

| Protected target | Adopted gate |
| --- | --- |
| Uninvolved sender or recipient identity | Strongest evaluated full-coverage attack accuracy at most 10%, **and** improvement at most five percentage points over the strongest frozen prior baseline. Both limits apply. |
| Undisclosed private amount | Guess within ±10% of the true amount with success at most 20%, **and** improvement at most five percentage points over its frozen prior baseline. In integer arithmetic the tolerance is `10 * abs(guess - amount) <= amount`. |
| Concentrated relationship targeting | Attack precision at most 50% at each of 5%, 10% and 25% selected coverage, measured over the full predeclared eligible set. Selection, ranking and tie rules are frozen before held-out evaluation. |
| Forced disclosure | Zero independently reproducible, logically forced unauthorized identity/relationship or exact private-value disclosures on supported targets. |

Freeze eligibility and baseline inputs before evaluation. Give observers stable
candidate identities, declared public funding-to-owner associations, published
workload distributions and permitted participant records; keep only actual hidden
assignments/seeds and undisclosed records private. A weak uniform baseline or secret
harness labels cannot establish privacy. Exclude only legitimately already-known
facts under the frozen rules, not cases made easy by the tested transcript. If
public priors themselves violate an absolute cap, record that workload's information
limit; do not remove the affected cases after seeing them.

Use one-sided 95% upper confidence bounds for the rate/advantage gates, with an
analysis plan accounting for multiple comparisons and independent ledger/session
sampling. Report raw outcomes, denominators and uncertainty. Insufficient cases,
invalid controls or unresolved solver queries mean incomplete evidence. A zero
observed forced-link count is not proof that such a link cannot exist.

Private historical balances and structural ancestry remain reported diagnostics;
any stronger quantitative claim needs its own predeclared target. Keep a historical
balance's time fixed when later data arrive: the intentionally public final zero
balance is not a secret. A unique structural ancestor set containing every deposit
is not automatically an identity disclosure. No economic allocation of merged
sompi is invented. The adopted amount gate applies to undisclosed payment amounts,
not public deposit/payout values or values legitimately known to a counterparty.

These gates do not establish network anonymity. The private witness boundary
remains mandatory, while I/E profiles need their own measured qualification before
any corresponding privacy claim. Emergency exits remain available when their use
reduces privacy; an exposed fallback's effect on ordinary historical targets must
still be included in their observation horizon.

### Remaining experiment details and present feasibility

Milestone 1 closes the requirements decision. Each experiment must still freeze
its workload rates, amount/timing distributions, balance residence, acceptance
policy, contention schedule, exact reference CPU, sample size, attack selection
and statistical procedure before scoring. These instantiate the adopted targets;
they cannot lower them or quietly restrict the use case to successful cases.

Current v6 is not qualified against these targets. H13 measured roughly 20–22 s
warm proving, 201–204 s cold parameter loading and 6.44 GiB peak prover memory;
its chosen 0.4-tKAS fee is 4% of a 10-tKAS payment before other lifecycle costs.
See the [named TN10 workload](../../poc/shared-pool/TWO-INPUT-TN10.md).

At the pinned upstream default relay rate, Groth16 verification's 140,000 compute
grams alone correspond to approximately 0.14 KAS before other transaction costs.
A 10-KAS payment's 1% ceiling is 0.1 KAS, so individually verified payments cannot
meet that endpoint merely by reducing wallet overhead. Fewer on-chain verifications
per payment, or another justified design, must be investigated. This is a scoped
cost inference, not an impossibility claim for current Kaspa L1 or adoption of
batching/vProgs. Sources: [verification cost](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/tags.rs),
[relay rate](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/mining/src/mempool/config.rs).

## Current candidate: capability and evidence map

This is a source/evidence inventory, not a new execution or cryptographic review.
Links point to existing code/reports at the baseline named above.

| Area | Candidate capability / demonstrated evidence | Gap against this RFC |
| --- | --- | --- |
| Keys and receipts | [`Wallet`, `Receive`, `Note`, `Wallet::decrypt`](../../poc/shared-pool/src/protocol.rs) provide separate spending/viewing/native secrets, encrypted note delivery and commitment/ownership checks. | R2/R5: no general v6 receipt/scanning interface. Viewing secret alone is not a complete watch-only wallet; nullifiers use spending authority. Receive-key reuse may be linkable to counterparties. |
| Spending and conservation | [v6 circuit](../../poc/shared-pool/src/two_input/circuit.rs) and [native covenant](../../poc/shared-pool/src/two_input/covenant.rs) enforce the experimental relation and settlement conditions. | R1: conditional on relation/composition/setup correctness; independent review remains open. |
| Public transcript | [`Authorization`/`Bundle`](../../poc/shared-pool/src/two_input/mod.rs) expose anchor/count, nullifiers, commitments, mode, fee, payout/script, deposit/funding and ciphertext binding. Current public settlement also carries state/witness data. | R3–R6: attacks must consume full native/public data, not only a selected JSON summary. Ciphertext hashing does not prove correct encryption of the committed output. |
| Payment lifecycle | [H13](../../poc/shared-pool/TWO-INPUT-TN10.md): v6 payment/change and partial exits; four wallets paid through six unchanged saved authorizations. | R2/R7: scripted one-host/RPC workload, known funding sources, precomputed capabilities; not independently operated current-version wallets. |
| Admission and participant independence | [Live discovery](../../poc/shared-pool/src/two_input/live.rs) validates the fixture's known funding inputs. | R1/R3/R7: arbitrary new participants must join without researcher descriptor edits; four keys controlled by the harness are not four independent people. |
| Recovery | [H7](../../poc/shared-pool/RECOVERY.md): older compact wallets restore from pre-payment backups on a separate host. | R7: v6 live exit consumes saved bundles; discovery/proving from a v6 backup created before receipt of the payment is untested. No cross-version backup compatibility is implied. |
| Public data | Exact proving parameters, authenticated history/ciphertexts and a correct chain view support witness reconstruction. | R5/R7: durable independent distribution, pruning/rollback and malicious-source handling remain open. Public parameters are not secrets; unused fallback authorizations remain private. |
| Fees and resources | [v6 TN10 report](../../poc/shared-pool/TWO-INPUT-TN10.md) records 20.036–21.430 s warm proofs and 201.797/204.154 s cold parameter loads. Candidate note/payout floors are 60,000,000/10,000,000 sompi; chosen fee 40,000,000. | R7/R8: measured workload only. An exact-fee authorization cannot be repriced without another proof; this spend layout does not admit an extra sponsor input. |
| Contention | [Live client](../../poc/shared-pool/two-input-client.mjs) checks the current reserve before one submission. | R7/R8: changed reserve aborts; general retry, ambiguous submission, fee changes and reorg recovery remain open. |
| Privacy evidence | [H16](../../poc/shared-pool/PARTICIPANT-PRIVACY.md) adds separate participant disclosures; [H18](../../poc/shared-pool/SCHEDULED-PAYOUT.md) rejects a short-delay cashout policy. | R3–R6: source-transaction inference is not owner/amount anonymity; collusion, active/network observers and independently chosen activity need evaluation. |

## Smallest decisive next evaluation

**Work order updated after milestone 2:** this is now the immediate privacy gate
before dedicated milestone 3 cryptographic/setup work or further wallet expansion.
The [branch plan](../SHARED-POOL-PLAN.md#early-privacy-gate--before-milestone-3)
records the gate. Milestone 7 broadens and independently validates privacy later;
it is not the first test. Routine safety review continues throughout. This changes
scheduling, not the adopted targets or the cryptographic assumptions.

The next *specified* evaluation is a blinded comparison of persistent shielded
spending and prompt cashout under the same declared user requests and total
resources. It is not run by this RFC and does not replace wallet integration.
First audit the current public transcript and define structural funding targets and
observer exclusions; do not build a new simulator before those are correct.

The [initial public-byte/amount calibration](../../poc/shared-pool/EARLY-PRIVACY.md)
is now complete on the published three-wallet M2 history. Later cashout narrows
one ordinary payment's amount bounds, but the tested models force neither
ordinary payment amount. This does not score guessing accuracy, ownership or
pooled/active disclosure; the held-out evaluation and all adopted gates remain
open. Its 48 cross-checked bounds are method calibration, not qualifying samples.
The [32-role owner-aware first stage](../../poc/shared-pool/POPULATION-PRIVACY.md)
has started under [RFC-0014](0014-owner-aware-privacy-evaluation.md), with a frozen
failure-seeking workload and isolated pooled-record observer. The whole-history
solver remains incomplete, but a bounded guessing batch completed all eight
histories: immediate cashout exposes 99/99 primary amounts exactly; the best of
three fixed simple attacks guesses 5/99 persistent amounts within 10% and none
exactly. A weaker local exact-disclosure search has separate bounded results.
Four request sets, limited priors and incomplete attack coverage cannot qualify
the rate thresholds below; all adopted gates and statistical qualification remain
open. The separate [native script-reuse diagnostic](../../poc/shared-pool/ADDRESS-REUSE.md)
confirms conditional internal-payment disclosure in a sparse two-funded-wallet
history. Its known startup/ownership assumptions and small population do not
instantiate this RFC's 32-role qualification; they motivate review of the wallet
key scheme without changing any requirement or threshold.

Use interleaved admissions, mixed amounts and sparse periods, with held-out
payment graphs. Give observers C and declared P records, including known common
funding; a separate active-attacker arm removes controlled wallets from cover.
Score internal relationships, amounts and funding through final drainage.
Include total user costs and delay; persistent balances are not free privacy.

Required known-answer controls include constructed singleton and
all-other-users-adversarial cases where the declared observer inputs determine the
chosen target. The evaluation must detect that absence of ambiguity. Authorized
exits must remain available. Separately test distinctive amount tagging, immediate
full cashout, old fallback publication and pooled disclosure; those attacks are
not required to succeed. Their outcomes are measured rather than prescribed.

- **Failure:** forbidden private data is required outside the wallet; a reproducible
  public/disclosure attack defeats the frozen primary claim; or costs/exit behaviour
  fail the chosen envelope. Keep the negative result and select a concrete
  redesign, narrower claim or stop decision.
- **Success:** all eligible held-out cases complete and all predeclared privacy,
  cost and exit screens pass, including the declared controls. This supports only
  continuation of that bounded candidate; it is not real-world anonymity.
- **Incomplete:** the envelope/ground truth is unresolved, cases are missing,
  controls are invalid, or an observer is given the wrong data. No pass verdict.

The requirements envelope above is adopted. The next evaluation must freeze its
concrete workload and measurement manifest. Early adversarial screening may find a
decisive failure before a full run; it must not claim success from incomplete cases.
Report an early **privacy** verdict separately from the combined privacy/cost/exit
verdict above. The known v6 fee and resource gaps remain failures; they cannot be
waived by a privacy pass. An absence of attacks in the three-wallet integration
trace is not a pass against the 32-role requirements.

## Outcome and remaining decisions

The owner adopted the target profile and authorized closing milestone 1 on
2026-10-20. [ADR-0027](../adr/0027-shielded-payment-targets.md) records the decision.
The requirements, observer definitions, falsifiers, capability map and source
review are complete for this milestone. No proof, native transaction, independent
cryptographic audit or achieved privacy/performance qualification follows from it.

Milestone 2 now consolidates one current-version lifecycle and maps its enforcement
and availability obligations. Cryptographic/setup review, useful privacy, general
recovery, arbitrary participant admission and contention remain open in their
respective milestones. A mechanism change needs an ADR and synchronized threat
and architecture documentation; adopting these requirements selects no new proof
system, runtime or consensus change.
