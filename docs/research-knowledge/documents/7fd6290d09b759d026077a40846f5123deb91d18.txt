# RFC-0012: Useful privacy requirements for native KAS payments

**Status:** Open — milestone 1 working draft; not a validated privacy claim.

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

## Goals, constraints and proposed use case

All [security invariants](../../SECURITY-INVARIANTS.md) remain unchanged.
Correct native backing, conservation, authorization, single spending, recipient
spendability and independent recovery are requirements, not privacy tradeoffs.
No new token, privileged withdrawal path, real funds or mainnet deployment.

The proposed primary use case is repeated payments from an existing shielded
balance, with recipients able to keep and spend received value. The hypothesis is
that this offers more useful privacy than repeatedly entering and immediately
leaving. That is an untested use-case choice, not an anonymity guarantee.

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
population/workload assumptions. Numeric adoption thresholds are still open below.
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

### Open qualification envelope

These fields must be chosen for a concrete use case before any usefulness verdict.
They are not silently set by v6 constants or the earlier 25% relative screens.

| Unresolved choice | Required decision |
| --- | --- |
| Activity and participants | Supported payment sizes/frequency, balance residence, interleaved admissions, quiet periods, independent control and adversarial share. |
| Acceptable leakage | Absolute relationship/funding inference limits, amount/balance disclosure tolerance, required coverage and observation horizons for each claimed profile. |
| Usability | Target device(s), memory/storage, cold start, sync/recovery time, payment/exit latency and fee-to-value limits. |
| Fault envelope | Competing activity, fee changes, data-source losses, reorg assumptions and required exit progress. |

A requirements draft can be reviewed with these open. Milestone 1 cannot authorize
a scored privacy claim or a broader pilot while the applicable envelope is unset.
No universal number of users or fixed privacy percentage is proposed as a security
threshold. Chosen empirical limits would remain research acceptance criteria.

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

The next *specified* evaluation is a blinded comparison of persistent shielded
spending and prompt cashout under the same declared user requests and total
resources. It is not run by this RFC and does not replace wallet integration.
First audit the current public transcript and define structural funding targets and
observer exclusions; do not build a new simulator before those are correct.

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

The first unresolved decision is the qualification envelope, not another timer
or denomination. Early adversarial screening may find a decisive failure before
all utility thresholds are chosen; it must not claim a success while they are open.

## Outcome and remaining decisions

Milestone 1 has started with this reviewable requirements draft, capability map
and primary-source refresh. It has not demonstrated privacy or closed the operating
envelope. No new proof, native transaction or cryptographic implementation is
part of this work.

Resolve the use-case envelope and review the attack/ground-truth definitions next.
Keep cryptographic setup, general current-version recovery, recipient acceptance
and contention gaps visible when scoping milestones 2–7. A resolved architecture
change needs an ADR and synchronized architecture/threat documentation; this RFC
selects no new protocol mechanism.
