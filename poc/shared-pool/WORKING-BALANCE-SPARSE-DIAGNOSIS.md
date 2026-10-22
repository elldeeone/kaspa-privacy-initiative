# Sparse withdrawal attack: successful guesses versus actual paths

**Status: completed 2026-10-22. Keep the direct-L1 research platform; stop
general cashout-policy tuning and resolve the evaluation assumptions before
selecting another mitigation or changing transaction structure.**

The [original partial-payout policy](WORKING-BALANCE-PRIVACY.md) remains rejected.
This diagnosis explains its sparse result; it does not change the score, qualify
privacy, or authorize its stopped native continuation. No native transactions,
proofs, new histories or seeds were generated.

## Main finding

The partial arm's pooled final `split_tail` attack correctly guessed 11/37
amounts within ten percent, including two exact amounts. Among those 11:

| Selected explanations for the successful guess | Targets |
| --- | ---: |
| Only unrelated payout supports | 8 |
| Some actual receipt/change ancestry, without a closed value path | 3 |
| A complete actual receipt/change reconstruction | 0 |

Both exact matches belong to the unrelated-support group. Across all 37
targets and all 1,074 unique selected-key constructions, none has the actual
PAY input set, a closed receipt-side payout flow, or a closed sender-change
flow. The old book deduplicates these offers into 1,035 union-support records;
neither number counts independent observations or independently controlled users.

This rejects the interpretation that the retained 11/37 score itself demonstrates
eleven reconstructed receipt/tail chains. It **does not** show that transactions
supplied no predictive information, that other explanations are impossible, or
that a stronger attack would fail. Unrelated supports can still produce useful
guesses. All eleven successes remain successes under the unchanged metric.

## The unchanged totals conceal different targets

| Comparison: same fixed `split_tail` strategy | Before | After | Shared hits | Gained | Lost |
| --- | ---: | ---: | ---: | ---: | ---: |
| Partial pooled: prior → attack, within 10% | 9 | 11 | 5 | 6 | 4 |
| Pooled: whole → partial, within 10% | 11 | 11 | 3 | 8 | 8 |
| Pooled: whole → partial, exact amount | 9 | 2 | 2 | 0 | 7 |
| C+D: whole → partial, within 10% | 7 | 7 | 1 | 6 | 6 |

The pooled amount advantage is a net two successes, not two identified new
disclosures: six guesses improve and four deteriorate relative to the prior.
The equal 11→11 arm totals have only three shared successful targets. Partial
payouts reduce exact matches for this strategy, but still fail the original
directional continuation conditions.
The original prior optimizes within-ten-percent accuracy, not exact matching;
its zero exact hits are not an exact-match information baseline.

The C+D rows above concern fixed `split_tail`, whose seven successes are below
that observer's nine-success final family maximum. In the whole pooled arm,
`split`, `split_tail` and `combined` tie at eleven. In the partial pooled arm,
only `split_tail` reaches eleven among the original final family, including
public-only copies and earlier-prefix carryforwards. The
[aggregate evidence](evidence/2026-10-22-sparse-diagnosis/summary.json) retains
all original final maximizers and paired strategy comparisons. Base final
strategies are independently recounted; carryforward pairs are the unchanged
published aggregates with their arithmetic checked, not new detailed traces.

For partial pooled sender guesses, 5/37 succeed against 2/37 for the prior;
recipient and joint-pair successes are both zero. Arm-specific prior ties depend
on different opaque event IDs. These counts do not establish a causal identity
disclosure, and zero joint successes do not qualify relationship privacy.

## What the support classification means

The old observer combines a hypothetical known input total, a guessed receipt
value, and guessed sender change. Each side can use a whole payout or up to
three selected partial/full payouts, possibly subtracting a known additional
note. It ranks these hypotheses using disclosed endpoints, support count,
recency and fixed ties. Its saved book collapses the receipt/change partition.

The additive public tracer reconstructs the entire unchanged `split_tail` book
and retains every construction for the chosen key. It matches the old book,
guesses and ranks exactly before any truth is used. The private classifier then
checks actual input sets, closed payout flows, wrong branches and ancestry.

A closed flow must consume the actual root and any stated additional note,
account for every selected payout and fee, and leave no private frontier.
An intervening private payment/mix can create ancestry without such closure.
The graph separately follows native payout → re-entry sources → new notes;
missing a private-only path cannot silently mean an unrelated history.
For this partial arm the selected ancestry flags need no native re-entry path.

Among **all** 37 partial pooled targets, ten have some correctly sided ancestry,
six have only wrong-branch ancestry, and 21 have unrelated selected payouts.
Ancestry does not allocate particular sompi after mixing. Matching an actual
construction would still establish compatibility, not a uniquely forced fact.

## What this changes about the research direction

[ADR-0032](../../docs/adr/0032-sparse-diagnosis-and-privacy-evaluation.md) records
the decision:

1. **Retain direct-L1 native backing, payment/change, recovery and unilateral
   exit mechanics.** Persistent private spending remains an unqualified
   hypothesis. This result does not justify discarding the platform or selecting
   batching, vProgs or another runtime.
2. **Close general withdrawal-policy tuning as the next work item.** The
   partial policy and H18 schedule remain rejected. No new timer, denomination,
   favorable activity or cash-demand assumption is selected from these results.
3. **Next, specify an evaluation that separates public prior knowledge from
   transaction-derived signal.** Use the existing genuine-native usage history
   as development evidence, identify which public feature families an attack
   actually uses, and require explicit opposing predictions before another
   mechanism is selected. A feature-removal diagnostic must also remove redundant
   disclosure through reserve differences/fees; it is not a valid alternate
   transaction or a mitigation result. A subsequent held-out test needs frozen
   attacks, justified workloads, independent histories, all observations through
   full drainage, and the existing safety/exit constraints.

The next evaluation design must preserve both the absolute privacy target and
its prior-advantage limit. The current known-price prior has expected success
`21103/100025` (about 21.10%), above the unchanged 20% absolute cap even without
transactions. This workload remains unqualified. Neither unrelated matches nor
changing a denominator can remove that information limit. A changed requirement
would require an explicit new decision and would not reclassify old failures.

Cash needs also require support: the exact half-receipt stress rule and the
independent 10/20/25-tKAS requests are declared models, not measurements of user
behavior. The [primary-source review](../../research/shielded-kas-sparse-withdrawal-design-2026-10-22.md)
compares these limits with established designs and current Kaspa capabilities.

**Decision condition for a later redesign:** a reproducible protected linkage,
or robust additional predictive information on held-out workloads, must identify
the public information to change. A viable candidate must explain why changing
it helps while retaining backing, data availability, real costs and immediate
independent exits. A common-price hit alone selects no new architecture.

## Evidence and verification

The [contract](WORKING-BALANCE-SPARSE-DIAGNOSIS-SPEC.md), six new diagnostic/test
files and runtime were pinned before truth classification. Thirty-five public
controls passed, including actual sandbox execution. Adversarial source review
found an ordered-input comparison error in the new classifier; it was corrected
and covered by a control before freezing or opening truth.

Run the public controls from `poc/shared-pool`:

```bash
python3 -B -m unittest working_balance_sparse_classify_tests \
  working_balance_sparse_trace_tests working_balance_sparse_diagnosis_tests -v
```

- Baseline: `7d63e5b647d8519bf17d3ddfff97e4a3fb51e5ab`.
- Attempt: `working-balance-sparse-diagnosis-20261022-01`.
- Freeze: `a6eecde7a7d165b1cdbd83b60ceadfc771a7135c3ee44ed2ff5a0addb6e99642`.
- Original score remains `d2723f2a875d5d3df1e16348197e72a4c4b9e6ebc9623fbe8cca50c6e1a648f9`.
- All 1,506 original observation seals passed their unchanged public verifier.
- Four public-only sandboxes reproduced all 256 observable target rows and all
  3,328 base-strategy guesses/ranks; 1,664 pooled public-copy guesses also matched.
- The four-trace barrier sealed before either private truth file was staged.
  The classifier received no seed. Both original arithmetic replays, permitted
  disclosures, all 37-target scores and paired base-strategy counts agree.
- A separate reviewer independently traversed ancestry and simulated payout
  flows for all 37 primary partial-pooled targets and 1,074 constructions, without
  importing the diagnostic helpers. Its aggregate recount agrees.
- Aggregate SHA256:
  `17239e55cdc1715304231594fc706a61d2701cbb7f9b13bb5b65fee9d755e3de`.

[Public evidence](evidence/2026-10-22-sparse-diagnosis/README.md) includes all four
compressed public traces, aggregate results, source/input identities and review
receipts. Detailed truth joins remain outside Git. This is one paired synthetic
history under bounded attacks and author-operated same-host controls. It is not
independent attestation, cryptographic assurance, native acceptance or real-user
anonymity. No privacy gate or milestone is closed by this explanation.
