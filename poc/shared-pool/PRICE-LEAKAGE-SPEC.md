# Price guessing versus transaction information: frozen test

Date: 2026-10-22. Development checkpoint: `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`.
This prospective contract is frozen with the sources and runtime before fresh
evaluation seeds or histories exist. It does not change a protocol, wallet
policy, the old rejected screen, or any absolute privacy requirement.

## Question and scope

Does the already selected `split_tail` heuristic predict private payment amounts
better than known-price guessing on fresh sparse independent-demand histories?
Separate its public-transcript advantage from the effect of added participant
records. Numerical success does not establish that a guessed construction is the
actual flow. This is a bounded arithmetic inference experiment, assuming ideal
hiding of opaque commitments and nullifiers, without genuine native bytes,
proofs, ciphertexts, keys, broadcasts, real funds or new cryptographic code.

Reuse the unchanged `working_balance_model.py`, observer and independent
accounting validator from the previous screen. Native generation would add
proving costs and a different withdrawal policy without answering this modeled
inference question. Existing native evidence is a source-map/development
reference only. Source rationale and statistical proof are in the
[research note](../../research/shielded-kas-price-baseline-test-2026-10-22.md).

## Fixed sampling, targets and observations

Generate exactly **512 independent ledgers**, each from a fresh 32-byte random
seed. Use only scenario `sparse-independent`, arm `partial`, final horizon.
For every seed call the unchanged `plan` and `replay`. Preserve its 32 roles,
eight colluders, 64 payment obligations, 32 cash requests, two immediate complete
exit requests, integer-sompi fees/floors, re-entry accounting and full drainage.
No favorable activity, request, amount or empty-stratum resampling is allowed.
The independent-demand generator is a model, not measured user behavior.

Each ledger supplies two isolated observer jobs: C+D (public arithmetic events
and initial funding-owner directory), and pooled (the same plus all eight
colluders' permitted authored operations and receipts). Honest input mappings,
amounts, owners, cash-request labels, activity class, seeds and truth are absent.
All observable zero-payout SPEND events, including colluder operations and
self-merges, are observer targets. Private primary eligibility is applied only
after the complete prediction barrier: original economic payment targets whose
sender and recipient both have role index at least eight. Do not disclose that
mask, remove difficult targets, or select eligibility using correctness.

There are **1,024 evaluation observer jobs**. Seal and verify every job, roster,
input digest, output, variant and rank before mounting any truth in a separate
scorer. The controller need not read truth to generate or observe. Observer
sandboxes receive no seed, home directory, process filesystem, external network
or other ledger. Public observation and participant disclosures remain exactly
the old contract; C+D includes the declared directory and model-level fields,
so its advantage is not automatically a native-byte or single-field effect.

Each ledger must independently pass conservation, ownership, requests, urgent
exit and complete-drain validation. Any missing prediction, malformed bundle,
empty eligible target set, seed collision or freeze mismatch invalidates the
attempt. Preserve failures and fix implementation errors explicitly; never
drop a ledger, weaken accounting, extend N, or interpret a failure as privacy.

## Frozen attacks and price baselines

Execute all thirteen unchanged base variants: `prior`, `residual`, `coinput`,
`split`, `subset_nearest`, `subset_supported`, `partial_tail`, `split_tail`,
`receipt_timing`, `cash_inverse`, `colluder_tags`, `bridge_ancestry`, `combined`.
Pooled also retains all thirteen `C_` public-only copies; validate equality with
the C+D prediction on every target. No fitting, revised tie-break, oracle
per-target/per-ledger winner or new attack is allowed. Full-family counts are
descriptive. **Only `split_tail` has inferential status**, selected from the old
development result before these fresh histories exist.

For within-ten-percent success use integer condition
`10*abs(guess-actual) <= actual`. The optimal marginal price-only action is
**45 tKAS**, with expected success `21103/100025` (about 21.10%). For exact
equality the separate optimal marginal action is **10 tKAS**, smallest of the
tied invoice modes, with expected success `3/25 + 2/(5*4001)` (about 12.01%).
These are mathematical priors for the unchanged honest-payment distribution,
not optimal conditional posteriors given every transcript fact. Assert the old
observer's prior is 45 tKAS on each eligible target; colluders do not directly
know these honest-to-honest payments. Do not claim unconditioned optimality after
conditioning on full participant information or other public selection.

Report exact amount, approximate amount, sender, recipient and relationship
counts separately. Correctness of exact 45-tKAS guesses is not the exact-price
baseline. The unchanged 20% absolute amount-privacy target is already exceeded
by this workload's marginal price prior: no result here qualifies privacy or
revives the rejected partial-withdrawal policy.

## Three paired estimands and nine tests

Within each ledger compute within-ten-percent accuracy on the same eligible
targets, then form three differences in [-1,1]:

1. C+D `split_tail` minus price45: public-transcript advantage.
2. Pooled `split_tail` minus price45: combined public/participant advantage.
3. Pooled `split_tail` minus C+D `split_tail`: effect of added colluder records
   on this heuristic. A fixed heuristic can worsen when given more information.

The combined difference equals the other two summed for each ledger. Weight
ledgers equally, irrespective of their target counts. Targets/supports inside
one ledger are dependent and are never counted as independent trials. Also
report pooled-target counts descriptively, clearly distinguished from these
equal-ledger means. These contrasts do not isolate an individual field or
establish a causal protocol effect.

Let `D_i` be a ledger difference. Freeze bets
`L={1/8,1/4,1/2,9/10}` and compute, after all predictions and scores are sealed:

```text
E_plus(theta) = (1/4) * sum_lambda product_i [1 + lambda*(D_i-theta)]
E_minus(.05)  = (1/4) * sum_lambda product_i [1 - lambda*(D_i-.05)]
```

For each contrast test exactly `E_plus(0)`, `E_plus(1/20)` and
`E_minus(1/20)`. Nulls are respectively mean advantage <=0, <=5 percentage
points, and >=5 percentage points. Reject a null only at **e-value >=180**.
Use exact rational products, mixture and comparison; decimal/log displays are
not threshold decisions. This is nine tests with familywise false-rejection
bound `9/180=.05`, using independent ledgers and fixed attacks. Nonnegative
factors have conditional expectation at most one under their null, so each
fixed product and its average is an e-value. The source note gives the proof
and mapping to the established bounded-mean betting construction.

For each contrast separately report:

- `E_plus(.05)>=180`: evidence of advantage exceeding five points.
- `E_plus(0)>=180` with the five-point question unresolved: positive advantage,
  material size unresolved.
- `E_plus(0)>=180` and `E_minus(.05)>=180`: positive advantage below five points.
- `E_minus(.05)>=180` alone: evidence below five points; zero is not established.
- Otherwise: unresolved under this frozen test.

Report all nine values, observed exact means and denominators. A non-rejection
does not establish absence; a below-five finding covers this attack and model
only. A descriptive family winner receives no inferential promotion. No
confidence interval, independence test, stronger-attack bound or universal
privacy conclusion is produced. N=512 was chosen before new data; analytic
power illustrations do not guarantee a resolved margin with unknown variance.

## Execution, stop and public evidence

Before fresh evaluation sampling, run meaningful public controls for optimal
priors, integer boundaries, exact e-values and null directions, clustering,
gains/losses, schema and disclosure validation, digest/replay rejection, closed
sandbox mounts, barrier enforcement and public export exclusions. Complete a
four-ledger **public-seed rehearsal through actual generation, all eight
observer jobs, scoring and export** using the same sources/spec/runtime. The
rehearsal's public seed formula is implementation-defined and recorded; it is
not an evaluation sample. Public controls/rehearsal may expose implementation
errors; document corrections and repeat rehearsal before freezing fresh data.

Create a new mode-0700 private attempt outside Git. Freeze code, this spec,
runtime, exact rosters and successful rehearsal receipt before sampling fresh
seeds. Generation is seed-only; observation is public-input-only; scoring gets
the closed allowlisted ledger tree only after the complete prediction barrier.
No seed enters scoring. Up to twelve concurrent observers are an operational setting,
not a statistical parameter. No operational timer/disk cap may truncate a
ledger or change the fixed sample. Retain failed attempts without overwriting
their identities. No intermediate scoring, attack inspection of correctness,
early stopping, seed replacement, parameter tuning or donor/field ablation is
permitted. Finish once all 512 ledgers are scored and checked, even if the
statistical answer is unresolved.

Keep seeds, truth, target masks, actual honest values/owners and truth-joined
correctness vectors outside Git. Export only explicitly allowlisted public
observations, permitted pooled records, sealed predictions, aggregate ledger
counts, global tests, validation/isolation/process receipts, source snapshots
and hashes. Compress bulk public artifacts without changing their bytes. An
independent recount should verify counts and exact inference. These controls
are author-operated evidence, not independent attestation.

No mechanism change follows automatically. A material public advantage directs
the next review toward surviving public amount/timing structure. A colluder-only
advantage directs it toward the participant knowledge model. A below-five or
unresolved result demands a stronger independently motivated test before a
confidentiality claim. In all cases retain direct-L1 mechanics and the old
privacy failure; do not assume either that vProgs is required or unnecessary.
