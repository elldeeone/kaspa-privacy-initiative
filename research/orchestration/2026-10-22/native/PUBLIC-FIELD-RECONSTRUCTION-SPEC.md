> Imported documentation snapshot. [Canonical status and ownership](../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Public-field reconstruction audit — standalone specification

Status: source/design only; not executed and not an amendment to the active price experiment.
Date: 2026-10-22, Australia/Sydney; source pins checked 2026-10-22 07:35 UTC.
Host: Forge, accessed through SSH alias `forge`.
Repository: `/home/luke/projects/kaspa-privacy-shared-pool`.
Reviewed HEAD: `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`.
Exclusive output directory: `/home/luke/projects/kpi-orchestration/2026-10-22/native-surface-review`.

## Result already established without running a check

**For a well-formed generated arithmetic transcript, deleting any one scalar public monetary field does not remove its exact value.** Every event `deposit`, `payout`, `fee` or `reserve`, and every bridge `input_value`, `deposit`, `fee`, `change` or individual source `value`, has an exact reconstruction from other retained public fields and/or published fixed constants. No price prior, ownership directory, participant receipt or hidden truth is required for this singleton-deletion statement.

The decisive evidence is direct:

- `working_balance_model.py:239-244` emits the reserve equation and monetary fields together; `working_balance_observer.py:107-118` checks both pool and bridge conservation.
- Pool fees are publicly fixed at 40,000,000 sompi and bridge fees at 100,000 sompi (`working_balance_model.py:13-18,101`; `working_balance_validate.py:9,140,208`).
- A bridge repeats its admission's deposit and publishes every source amount, their total, its fee and change (`working_balance_model.py:290-304`).
- Payout coins are stored with the public event ID and exact payout value; bridge change is carried forward with its public reference (`working_balance_model.py:266-267,294-300`).

Deleting an entire `payout` column, `deposit` column, `reserve` column or fee column separately also fails to remove that quantity: all payouts/deposits follow from adjacent reserves and the other terms; all reserves follow by cumulative conservation; fees remain constants. This claim concerns those named one-column deletions, not arbitrary simultaneous masks.

This is **representation redundancy**, not evidence that an honest private payment amount is uniquely identified. The current public event has no private payment-amount field to delete. On a zero-payout SPEND, reserve changes by the fee irrespective of how the private input is split between payment and change. A later DRAIN exposes the total value of its consumed note(s); linking that total or a guessed subset back to a particular earlier payment is a separate proposition.

All references below are under `poc/shared-pool/`. Only read-only sources and the named public development audit receipt were inspected. No active 512-history files, seeds, truth, predictions, correctness, profiling, experiment, build or install were used.

## Scope and meaning of “exact”

The later check audits a specified **masked interface**, using deterministic arithmetic and explicit public equivalences. It does not call the current heuristic, rank candidate payment flows, compare privacy accuracy, tune the frozen attack, or make an information-theoretic privacy claim.

A target is a typed quantity identified by an event/bridge/position and JSON pointer. These are different queries:

1. “What numeric value was omitted from `events[i].payout`?”
2. “What was the total private value consumed by that DRAIN?”
3. “Which earlier private payment, if any, had that value?”
4. “Which person owned or received it?”

An exact answer to 1 or 2 does not answer 3 or 4. An ownership directory is an explicit external identity association, not a monetary conservation equation.

An `exact_derived` answer requires a mechanically checkable derivation whose leaves are retained input values or declared invariant constants. A guess matching the reference number is not sufficient. An `ambiguous_under_rules` answer requires two distinct integer completions of the masked fields, identical on every retained input, both satisfying the declared equations and bounds, with different target values. Failure of a bounded derivation procedure without such a witness is only `unresolved_by_rules`.

These statuses are scoped to the declared public accounting rule set. They do not prove existence of alternative native note openings or compliance with an entire hidden sparse-demand schedule.

## Observation and rule boundary

Use a new standalone mask format. Do not remove keys from an input and pass it to the frozen observer: its exact-key schema intentionally rejects missing fields (`working_balance_observer.py:24-28,65-89`). Do not patch that validation.

The reconstructor may receive only:

- a typed masked public projection;
- an explicit prefix endpoint;
- the mask's JSON pointers and absence markers;
- the declared invariant/rule set below;
- optionally, the declared directory or permitted participant view in separately named cases.

The coordinator retains the original public fixture and reference values for later comparison. The reconstructor must not receive the complete fixture, a public fixture seed or generator, original unmasked input hashes, answer-bearing labels, cost summaries, old predictions or scoring artifacts. Hashes of the **masked** input are safe provenance for this calculation interface. An unmasked-input digest can serve as an equality oracle over a small candidate domain and must not be counted as information removed.

All fixture data is already public; this separation tests implementation provenance, not secrecy of the fixture. A solver reading the published fixture source instead of following retained-field dependencies has not passed the audit.

Keep auxiliary facts explicitly typed:

- `public_field`: a surviving value in the declared observation prefix.
- `model_invariant`: fixed fee, initial reserve zero, conservation, operation semantics and proven reference equality.
- `external_directory`: funding-group-to-role mapping.
- `participant_disclosure`: authored inputs/outputs or positive receipt, with its exact source pointer.
- `public_schedule_convention`: an explicitly admitted generator convention, never silently promoted to a chain fact.
- `price_prior`: a probability distribution or Bayes action; never an equality premise for an arbitrary event.
- `hypothesized_flow`: a guessed note linkage/support; excluded from exact reconstruction certificates.

## Field dependency map

Let `D_i,P_i,F_i,R_i` mean event deposit, payout, fee and post-event reserve, with `R_-1 = 0`.
Let bridge `b`, attached to admission `i`, expose source values `s_bj`, total `I_b`, deposit `D_b`, fee `f_b` and change `C_b`.

| Rule | Exact relation / derivation | Premises and limits | Source |
| --- | --- | --- | --- |
| E1 | `R_i = R_(i-1) + D_i - P_i - F_i` | Any one unknown is recoverable when the other four terms are known. For `i=0`, use the public initial-state rule. | model:169,239-240; observer:81,107-108 |
| E2 | `P_i = R_(i-1)+D_i-F_i-R_i`; `D_i = R_i-R_(i-1)+P_i+F_i`; `F_i = R_(i-1)+D_i-P_i-R_i` | Direct inversion, exact integers, no prices or owner labels. | E1 |
| E3 | `R_i = sum_(k=0..i)(D_k-P_k-F_k)` | Recovers all deleted reserve fields if the three flow columns remain. No future event may enter an earlier-prefix certificate. | E1 and model initial state |
| E4 | `F_i = 40000000`; `f_b = 100000` | Known model constants survive field deletion. A hypothetical unknown-fee case must be labeled a different information contract. | model:13-18,101; validator:9,140,208 |
| E5 | ADMIT: `P_i=0`; SPEND/DRAIN: `D_i=0` | Mode is retained. A zero-payout SPEND is not necessarily an economic payment: self-merges are also targets. | model:209-227; observer:95-106,165 |
| E6 | Empty destination implies `P_i=0`; a complete target roster containing mode-1 event `i` also implies `P_i=0` | Nonempty destination or exclusion from a complete zero-payout roster implies positivity, not an exact nonzero value. Record the roster's completeness/prefix. | model:243,266-267; trial:105-110; price runner:228-232,343-350 |
| B1 | `I_b = sum_j s_bj = D_b + f_b + C_b` | Total or any one source can be recovered from the remaining sum terms. Deposit/change/fee can each be isolated from the balance equation. | model:294-299; observer:114-118 |
| B2 | `D_b = D_i` | Duplicate representations of the same admission amount. Removing only one is a direct copy test. | model:296-304; observer:118 |
| B3 | Source `ref = event_id(k)` implies `s_bj = P_k`; source `ref = change_ref(c)` implies `s_bj=C_c` | Resolve only exact earlier unique public references. Do not infer an owner from the edge. Detect dangling, duplicate, cyclic or contradictory references. | model:266-267,294-300; validator:197-217 |
| B4 | `C_b=0` iff the model emits empty `change_ref` | Emptiness preserves a zero/nonzero bit; nonempty does not reveal the value alone. | model:298-300; validator:213-217 |
| N1 | ADMIT first note value `v_new0=D_i-F_i`; second note value `v_new1=0` | This is the declared current model/wallet output convention. Numeric credit does not require the owner's identity. | model:211-214; observer:169-172 |
| N2 | DRAIN input total `T_i=P_i+F_i` | Exact aggregate for that DRAIN. One/two real inputs are not identified by two public nullifier slots. It is not automatically the amount of an earlier payment. | model:224-227; observer:283-299 |
| P1 | `sum(v_inputs)+D_i=sum(v_outputs)+P_i+F_i` | May recover one omitted private value only when input membership and the other values are **disclosed/established**, not guessed. Receipt and authored-output duplicates must be joined by exact position. | model:231,245-248,382-391; validator:157-188 |
| S1 | Declared first-four public tags have a specified amount | The observer explicitly installs `20*SOMPI+(ordinal+1)*1000` for those targets. Label this public schedule knowledge, not a price guess or universal payment equation. | model:91,95; observer:184-189 |
| D1 | Directory `funding_group -> role` plus N1 associates that credit with a role | Supplies identity association; cannot change the numerical credit for a fixed event pointer. Querying “role X's credit” additionally depends on this lookup. | model:259-263,409; observer:169-175 |
| D2 | Initial generated admissions iterate `owner=0..31` in order | Public generator convention can also supply an initial association if admitted as adversary knowledge. Therefore directory removal alone must not be declared removal of every model-level owner clue. This audit records the dependency; it does not add a new active attack. | model:417-420 |

For a mode-1 zero-payout event, E1 reduces to `R_i=R_(i-1)-F_i`. Neither its private payment `A_i` nor its change appears. If disclosed inputs have total `T`, then `A_i+change=T-F_i`; without one component or an established later linkage, this identifies a sum, not the split.

For multiple masks, take the transitive closure of **all** retained equations and aliases. Deleting direct payout and reserve entries while leaving bridge source copies is not a closed deletion. A later retained checkpoint also gives an interval sum by E1; omitting intermediate reserves alone need not remove individual values if all but one interval flow remains known.

No assertion is made that these local rules discover every possible implication of the entire production generator. The exact-derivation certificate is sufficient evidence; the rule set's failure to derive is not a privacy result.

## Pinned public fixtures

The smallest later test can use the already published handwritten development fixtures in `working_balance_observer_tests.py`, without the full rehearsal or model generator:

- **O-base:** `Fixture`, lines 12-37. It constructs 32 admissions and four declared tagged control events using literal public labels.
- **O-partial:** lines 76-87. Two public payouts are emitted after a custom zero-payout SPEND.
- **O-split:** lines 119-124. Two DRAIN payouts are `40*S-F = 3,960,000,000` and `59*S+20,000,000 = 5,920,000,000` sompi. Their sum is `9,880,000,000`.
- **O-bridge:** lines 182-189. A DRAIN payout `3,960,000,000` is the sole bridge source; admission/bridge deposit is `2,040,000,000`, bridge fee `100,000`, and change `1,919,900,000` sompi.
- **M-source reference only:** `working_balance_model_tests.py:1-14,59-69,96-125,169-195` documents handmade public controls and repeated bridge-change references. Do not call its broad `controls()` or `plan/replay` for the minimal audit.

The observer fixtures are arithmetic surface controls, not independently accepted native transactions or full sparse-workload histories. Use their literal construction only; do not invoke `Fixture.observe()`, the heuristic controls, score helpers or seeds. Proposed negative controls below mask/perturb these same public arithmetic fixtures; they are not new sampled histories.

Exact SHA-256 identities:

```text
a1a8c3989d85f2309dcd726cd2d076c77c4ea77e407a7dfbd8c05f975dafbe00  working_balance_model.py
b492d5a2e63836751f51f5151c002c3ec6492c224b518846c45eca23f3ea7495  working_balance_observer.py
407c1abeebc913b8112754d70705eae41a36f86cf954aa946dfa565abef3eb14  working_balance_validate.py
d4c6a36f18909d46f6bdd8a0ab4efcc32c951460f4815ba4d4dd02b58caa9ab5  working_balance_model_tests.py
0f2ac35622e23dfafa960e8877b743118500c3530015eaa9b59b49c208d38147  working_balance_observer_tests.py
d8c73c52929743641c7180565f6e3af4abcfc8f55e53ce0902de8235eec0aa65  working_balance_trial.py
e1901ff96e13af0dc2bb2f556cf356c9df800a88d2a48d423caea61f084b97d7  price_leakage_trial.py
df33b6ebfb352fbe36bf0a83f171f68d0ba20871eb7847f08aaadf274a8b4fb8  evidence/2026-10-21-working-balance/public-development-rehearsal-audit.json
```

The last file records the older public development input `bytes(range(32))` and matching source identities. It is provenance only, not an audit input or a source of expected correctness. No bulk rehearsal archive was opened. Materialized fixture/mask byte hashes do not yet exist; the later coordinator must hash and seal them before the reconstruction process starts. Do not invent them in advance.

## Minimal later standalone check

One sequential stdlib-only process pair (coordinator/verifier and restricted reconstructor), three tiny public surfaces O-base/O-split/O-bridge, no probabilistic or combinatorial attack. Expected cost is seconds and at most a few small JSON objects; this estimate has not been benchmarked. No proof generation, GPU use, install, build or access to the active experiment is required.

1. Verify the above source/fixture hashes. Materialize only the named public fixtures using the literal builder code in an isolated scratch directory. Do not import or call heuristic functions. Seal complete public originals with the coordinator.
2. Enumerate every recognized scalar amount pointer in the public fixture. For each singleton mask, give the reconstructor only the masked view and declared rules, with no directory or participant records. Require an exact E/B-rule certificate for every case. Also check separate whole-column masks of event payouts, deposits, reserves and fees.
3. Exercise B2 and B3 specifically with the O-bridge: remove both deposit copies while retaining reserves; remove source value and input total while retaining the referenced earlier payout. Every successful path must name its exact dependencies.
4. Exercise the negative controls below. Verify certificates and counterexamples independently before comparing derived numbers with the coordinator's original public values. Report failures explicitly; do not repair masks opportunistically until they “pass.”
5. Repeat fixed-event numeric queries with absent, original and explicitly synthetic-permuted directories. The numeric result and public arithmetic certificate must be identical. Separate identity lookup results must declare directory or S/D-rule provenance. A synthetic-permuted directory case is an interface diagnostic, not a faithful generated-history claim.

Suggested control matrix:

| Control | Construction | Required result |
| --- | --- | --- |
| C1 singleton amount deletion | Every amount pointer in O-base/O-split/O-bridge, one at a time | `exact_derived`, identical to coordinator reference, with valid retained-field/constant certificate. |
| C2 whole event-column deletion | Separately hide every payout, every deposit, every reserve, or every fee | Exact recovery from E1-E4; no ownership knowledge. |
| C3 duplicate/alias retention | O-bridge masks described in step 3 | Exact recovery through reserve or reference aliases; flag that deletion failed to remove quantity. |
| C4 no-directory amount control | Same fixed-event masks, empty/original/permuted directory | Same numeric result. Any owner result must cite a declared identity source. Do not silently admit D2. |
| C5 zero-payout side information | Hide a zero payout but retain mode-1 membership in complete targets or empty destination | Exact zero via E6. This does not reveal the event's private payment amount. |
| C6 coupled unknowns | In O-split hide both DRAIN payout values and the intermediate reserve after the first; keep the reserve before the pair and after the second. No bridge/participant copies exist in this fixture. | `ambiguous_under_rules`: completion A = (3,960,000,000;5,920,000,000), completion B = (4,060,000,000;5,820,000,000); lower the hidden intermediate reserve by 100,000,000 in B. Both retain sum 9,880,000,000, fees, final reserve, positivity, mode and all other observed bytes. This witnesses ambiguity of each payout, while their sum remains exact. |
| C7 lucky prior / missing flow link | Supply an alleged exact answer consisting only of the 45-tKAS prior, or claim a DRAIN total equals an earlier payment using a guessed support | Certificate rejected even if its number happens to match a reference. E/N rules have no such binding. No accuracy score can substitute for proof. |
| C8 receipt/author duplication | Optional separately named participant case: hide one disclosed value but keep the exact-position duplicate or all other P1 terms | Mark as participant-derived. Never count this as public-only reconstruction. If no such source is present, no participant premise is allowed. |
| C9 contradictory source alias | Alter O-bridge source `value` by one sompi while retaining its source payout and original bridge totals | `invalid`, no best-effort amount or rounding repair. |
| C10 malformed / boundary / provenance | Boolean/float/negative/over-MAX amount, dangling/cyclic reference, out-of-prefix premise, hidden-target/original-digest dependency | `invalid` or a failed audit control; preserve artifact. Absent value must never become zero by default. |

C6 is an algebraic two-completion certificate for a public fixture. It does not certify two full private/native executions. For C8, the minimal mandatory check may report `not_in_minimal_fixture`; do not silently expand scope or collect participant records to fill it.

## Output contract

Write a standalone `reconstruction-audit.json` and `MANIFEST.json` under a **new** later audit directory, never into the frozen attempt or existing evidence export. No new executable is supplied by this specification.

Each audit record must include:

- `schema = kpi-public-field-reconstruction-v1`;
- `case_id`, fixture source hash, materialized masked-input hash, prefix endpoint, exact mask pointers, view profile and ruleset hash;
- target pointer/quantity kind (`public_payout`, `deposit`, `reserve`, `fee`, `bridge_source`, `drain_input_total`, etc.);
- one status: `exact_derived`, `ambiguous_under_rules`, `unresolved_by_rules` or `invalid`;
- for exact results, canonical decimal `value_sompi` plus a dependency DAG: rule ID, input pointers/constants, intermediate integer values, provenance tags and independently verified equations;
- for ambiguity, both assignments to **all affected masked variables**, their differing target values, retained-projection equality and constraint-check results;
- for unresolved/invalid cases, a specific reason and no amount asserted as reconstructed;
- identity fields, if any, in a separate association object with directory/schedule/participant provenance;
- independent certificate verification and reference-comparison results. Reference comparison must not be available during reconstruction.

`MANIFEST.json` lists source hashes, exact allowlisted fixture/mask files, hashes, coordinator/worker input boundaries, commands/tool versions, start/end times and output hashes. It must explicitly state: no active evaluation input; no seed/truth/prediction/score mounts; no network; no native proofs; frozen sources unchanged.

The top-level summary counts statuses and control passes/failures. It contains no privacy accuracy, p-value, per-ledger correctness, selected attack winner or revised qualification criterion. `unresolved_by_rules` is never summarized as hidden, private or secure.

## Fail / stop conditions

- Any source/fixture pin mismatch, unavailable named public fixture, ambiguous path, symlink escape or non-allowlisted input: stop and report; do not substitute an active ledger or freshly generated history.
- The worker can access an original fixture, seed, answer-bearing metadata, unmasked digest oracle, private truth or active prediction: invalidate the audit run.
- Any supposedly exact result lacks a verified derivation, depends on a guessed flow, or changes numerically when only a directory changes for a fixed event query: fail the control.
- Any two-completion witness changes a retained byte or violates a declared equation/bound: reject the ambiguity certificate; report unresolved until a valid witness exists.
- Any contradiction, integer/range error or malformed reference: reject; do not silently repair or use floats/tolerances.
- A result requires a new heuristic, broad private-flow search, hidden schedule, cryptographic generation or native rollout: stop that extension as outside this audit.
- Do not change active sources, masks, observers, criteria, sample size or interpretation based on this audit. The frozen price spec explicitly excludes field ablation within the active attempt (`PRICE-LEAKAGE-SPEC.md:150-159`).

The source result is already sufficient to reject “we removed the payout field, therefore payout information was removed.” The later standalone check verifies the reconstruction implementation and its refusal to confuse exact arithmetic, external associations and price guessing.
