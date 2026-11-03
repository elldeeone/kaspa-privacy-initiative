# Whole-note withdrawals versus a working private balance

Status: prospective specification; not frozen until the execution manifest is
written. Research only. This is a fresh **arithmetic falsification screen**, not
new native transactions, proofs, recovery testing or real-world anonymity.
Earlier native-usage and H17/H18 evidence remains unchanged.

## Question and scope

Does paying requested external liquidity and retaining reusable private change
reduce the amount information exposed by whole-selected-note withdrawals?
Both arms must meet the same economic obligations with the same initial funds.
Cash requests cumulatively earmark native liquidity held outside the pool;
they do not simulate payments to external merchants. Excess whole-note
withdrawals stay in that external wallet and satisfy subsequent increases
in requested liquidity before either arm withdraws again. Re-entry is allowed only when
needed to make a scheduled private payment, with public ancestry and fees.

The current v6 relation already supports partial payout plus private change.
This screen does not add that command to the own-key wallet or change the
relation, covenant, parameters, security invariants or exit authorization.
An arithmetic rejection stops the candidate before native implementation.
A positive screen requires genuine native construction and recovery validation
before any native-policy claim; it does not establish security or anonymity.

## Prospective matrix and workload

Four independently sampled economic histories, each replayed in both arms:

| Cell | Activity | External cash requests | Decision role |
| --- | --- | --- | --- |
| overlap-independent | 1–3 modeled minutes between payments | independent owner and size | primary |
| sparse-independent | 60/120/180 modeled minutes between payments | independent owner and size | primary |
| overlap-correlated | 1–3 modeled minutes between payments | recipient of preceding payment, half its amount | stress |
| sparse-correlated | 60/120/180 modeled minutes between payments | recipient of preceding payment, half its amount | stress |

These are four ledgers, not independent observations for every payment. No
confidence interval or population privacy estimate is inferred from them.
The stress rule is known to the attacker. Complete receipt cashout is a
separate handmade negative control: partial payout cannot conceal an amount
that the user deliberately withdraws in full.

Each history has 32 roles, with roles 0–7 colluding. Honest activity is a
private random permutation: four receive-only roles, eight one-send roles,
eight two-send roles and four six-send roles. Each adversary sends twice.
There are 64 ordinary private-payment obligations. First four sends are from
adversaries 0–3 to the four high-activity honest roles, ensuring early known
tagged receipts can be consumed in later private payments. Remaining sends
are shuffled, with a preferred nonself recipient selected with probability
70%, otherwise a uniformly selected nonself role.

Initial net private capitals are independently selected from 350/700/1400
tKAS. Honest amounts retain the prior native-usage distribution: 60% uniform
over 10/20/25/40/50 tKAS, 40% uniform over the 4,001 cent values from 10 through
50 tKAS inclusive. Adversary values are
`20 KAS + (role+1)*1000 sompi + authored ordinal`. All arithmetic uses integer
sompi. The public observer knows distributions, not the sampled assignments.

After each pair of private payments there is one external cash request (32
total). Independent requests use a separate random permutation of all 32 roles
(one request each), and uniformly choose 10/20/25 tKAS, separately from invoice
sampling. This bounded exposure avoids unbounded repeated cash demands on a
low-capital sender; it is an explicit workload limitation. Correlated requests
choose the preceding recipient and floor-half its invoice in integer sompi.
The request time is one modeled minute after that payment. Request indices
7 and 23 additionally demand an immediate complete exit of that role's
current private balance in both arms. Later scheduled payments may require
re-entry; this is counted. The external request amounts/times are matched,
not published as an extra attacker input. Requests create no artificial
private payment or cover traffic. Final drainage starts 60 modeled minutes
after the last request, in one sampled role order shared by the arms.

## Accounting and wallet policy

Every pool operation costs 40,000,000 sompi. Positive private notes must be
at least 60,000,000 sompi; public payout floor is 10,000,000. Native bridge
fee is modeled as 100,000 sompi per required re-entry; it is a synthetic
accounting parameter, not a current network fee quote. Initial admissions
cost the same pool fee, funded in addition to each declared net capital.
There is no new external subsidy after initialization.

For an ordinary private payment, select the largest owned live note plus the
oldest other live note when present. If this pair cannot cover the obligation
and fee with zero or floor-valid change, re-admit available external surplus
(after modeled bridge and admission fees) and retry. If necessary combine
that largest-plus-oldest pair through a private self-merge, charging a pool
fee, and retry. All merges,
re-entry, zero-change cases and failures are counted; merges are public
zero-payout SPENDs and may not be secretly labeled for observers.

For a cash request, earmark external surplus first; previously earmarked cash
remains available to its owner and cannot fund later private payments. If more is needed, select the
one- or two-note set with the smallest total covering the remaining demand
plus fee. Ties prefer fewer notes then lower note positions. Whole-note arm
drains that set completely; partial arm pays the shortage (raised to the public
payout floor if smaller, with that overshoot counted) and keeps
private change, except a sub-floor remainder is also paid publicly. Thus the
candidate cannot leave dust or silently underpay. Excess remains external.
If no pair covers the shortage, withdraw the greatest-total pair (ties choose
lower positions), or the only singleton, repeatedly until it is met;
the partial arm pays the lesser of shortage and available total minus fee.
An urgent exit drains all notes immediately, irrespective of privacy policy.
The final phase drains lowest-position pairs then a singleton for each role.
Every positive remainder, earmarked native cash and native surplus is included
in final accounting. Re-entry may deposit only surplus after prior cash
obligations; its public bridge consumes all that owner's external coins and
includes source payout/bridge outputs, input value, deposit, fee and native
change retaining the earmarked amount. There are no modeled external merchant
spends or missing merchant change edges.

No modeled timer, peer, operator or privileged key gates any exit. This is an
arithmetic availability condition, not a cryptographic recovery demonstration.
At every operation, inputs plus deposit equal private outputs plus payout plus
fee. Across the history, original injected value equals earmarked cash plus
external surplus plus private reserve plus pool and bridge fees. Earmarked
cash and external surplus are disjoint parts of the native balance; requested
liquidity is never counted twice as a separate transfer.
Final private reserve must be zero. No obligations may be dropped, resampled,
underpaid or silently reassigned to make either policy appear better.

## Public surface and observer separation

Public arithmetic events expose ordered ID, modeled minute, mode, deposit,
payout, fee, reserve, two commitment positions on ADMIT/SPEND and none on
DRAIN, and opaque commitment/nullifier labels. They do not expose consumed
note positions, live input count, positive-output count, owners or private
amounts. Initial funding directory associates the 32 initial admissions with
roles. Re-entry publishes edges to its actual previous native payout sources;
fresh destination scripts are not an owner directory. Opaque labels simulate
ideal hiding and are not cryptographic objects or measured byte metadata.
For partial payouts, output slot 0 holds private change and slot 1 is dummy;
for self-merges slot 0 holds the merged note and slot 1 is dummy. Public output
slots do not expose which notes are positive. All 32 initial credits use
mode-0 arithmetic admissions, without simulating the native genesis/bootstrap.

Every zero-payout SPEND is an observer target, including self-merges. Only
the original honest-to-honest economic payments enter the primary score;
the target mapping is opened after prediction seals. Positive-payout SPENDs
are withdrawals and must not become private-payment targets.
At each public prefix, compute only the observable targets whose public
creation/next-payout/final cutoff is that prefix. This selected-target list is
derived entirely from the public events, includes merges, and is hashed with
the observer inputs. Computing a row again at unused intermediate prefixes is
unnecessary; no private eligibility list is supplied. Public controls compare
selected rows with the same rows from full-prefix evaluation.

Profiles: C+D (public plus initial funding directory), and all eight colluders
pooled (their own authored input/output records and their own positive
receipts only). No honest wallet state, hidden cash requests, private role
assignment, source matching, seed or truth enters an observer. The pooled
family includes each C+D strategy unchanged, so using extra information badly
cannot be credited as privacy.

Horizons for each observable target are its creation, the next public positive
payout, and final drainage. There is no secret recipient-cashout cutoff.
Separate fixed strategies carry creation and next-payout guesses forward to
final; final reranking does not erase earlier disclosures.

## Frozen attacks and scoring

The executable observer and its tie-breaks are hashed before fresh sampling.
Use finite deterministic attacks, not an incomplete solver as a privacy score:

1. Exact distribution-aware amount prior and stable role guesses.
2. Next/recent payout plus public fee; known eligible co-input subtraction.
3. Payment/change split using known input values and later public payouts.
4. Bounded sums of up to three later payouts plus their fees, with separate
   nearest, most-supported and policy-timed partial/tail selections.
5. Receipt-correlated half-cash inverse (`2*payout`, with integer rounding),
   receipt recency and known colluder amount tags.
6. Deterministic family ranking, plus unchanged C+D and earlier-prefix
   carryforward strategies. Individual family members remain separately scored.

Subset reconstruction is a bounded heuristic, not exhaustive inference.
Known-note subtraction may use a note eligible at any included payout leg,
including a co-input received after an earlier partial payout. For the split
and split-tail strategies only, retain at most eight deterministic supports
per candidate value before pairing receipt/change explanations. Rank by known
owner first, summed elapsed minutes, span, event order, co-input position and
owner identifier, with the executable tie-breaks frozen. The raw subset/partial-tail strategies retain
all enumerated one-to-three-payout explanations. This prospective complexity
bound limits attack coverage; a missed reconstruction cannot count as proof
of privacy. Public development workloads are used to check completion before
sampling, never to select a favorable held-out result.
Unknown co-input/change ownership remains a hypothesis. No truth-selected
per-target best guess is permitted. For decision, take the largest aggregate
success count among the fixed strategies on the same targets, including prior
and carryforward. That family maximum is descriptive and not an independently
validated attacker-selection procedure. Report individual strategies too.

Score amount within ±10% using exact integer arithmetic, exact amount, sender,
recipient and joint sender/recipient, per cell/profile/horizon/arm. Every
eligible target has one guess per strategy; failures or omissions invalidate
the screen rather than count as private. Report paired gains and losses.
Retain unchanged absolute targets (amount 20%, sender/recipient 10%, advantage
over proper prior 5 percentage points). The legitimate prior already has
expected accuracy about 21.10%; this known target conflict is not repaired by
choosing new thresholds or amounts.

## Prospective decision and stop rules

Directional continuation requires, in **each primary activity cell and each
profile**, at both next-public-payout and final horizons:

- Partial arm's strongest fixed amount attack is at least five percentage
  points less successful than whole-note arm's strongest attack.
- Partial arm's strongest attack is no more than five percentage points above
  its matched amount prior.
- No sender, recipient or joint accuracy family maximum increases by more
  than five percentage points. Stress cells must also meet this non-regression
  condition, but are not required to improve amount privacy.

Failure of any condition rejects this candidate policy under the frozen screen.
Report stress amount outcomes separately, never pool them into primary gains.
All cash obligations, urgent exits, drainage and accounting must pass in both
arms; otherwise this is an invalid implementation/model result, not a privacy
result. Absolute privacy, 1% ordinary-payment and 2% complete-lifecycle fee
targets are reported separately and remain binding for eventual qualification.
Show fees, external overshoot, re-entry, merge counts and modeled delays;
simulated deadlines do not establish real proof, wallet or chain latency.

Controls and adversarial source review precede a manifest hashing this spec,
source modules and tests. A new private seed is created only after that freeze.
Generate all views, complete and seal every observer prediction, then open
truth once for scoring. Preserve errors/incomplete artifacts. No post-result
attack, threshold, workload or seed changes; a bug invalidates the attempt and
requires a separately identified prospective correction. Only a complete
directional pass can trigger a separately frozen genuine-native continuation.
