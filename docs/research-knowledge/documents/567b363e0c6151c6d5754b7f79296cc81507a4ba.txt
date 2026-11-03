# Price priors versus transaction information: completed result

**Result:** the preselected `split_tail` attack did not outperform price guessing
on fresh histories. Its mean approximate-amount accuracy was **13.53%** with
public observations plus the initial funding-owner directory, and **14.47%**
with eight colluders' records, against **20.88%** from the 45-tKAS price guess.
All three frozen comparisons support mean advantage below five percentage
points. None establishes a positive advantage under the frozen tests.

**Decision:** retain the direct-L1 research platform and the rejected-policy
result. Improve attack calibration and the native observation mapping before
using these amount guesses to justify another cashout policy or runtime change.
This result does not establish zero transaction information or qualify privacy.

## What ran

The [prospective contract](PRICE-LEAKAGE-SPEC.md) fixed the workload, attacks,
baselines, independent unit, nine tests and stop rule before fresh seeds.
Exactly **512 independent seeded ledgers** completed: sparse independent-demand
scenario, partial-withdrawal arm, final horizon. Each retains 32 roles, eight
colluders, 64 payments, 32 cash requests, two urgent exits and complete drainage.
This is the unchanged arithmetic model, with ideal hiding and synthetic clocks;
no native proof, wallet, chain acceptance, broadcast, GPU or real funds was used.

All **1,024 isolated observer jobs** sealed before truth entered scoring.
Observers covered 32,768 public zero-payout SPEND targets across the ledgers;
18,192 economic payments were honest-to-honest and eligible for the primary
score. Eligible counts ranged from 20 to 47 per ledger. No ledger was discarded,
resampled or added. All 32,768 payment obligations, 16,384 cash requests and
1,024 urgent requests reconciled; every ledger finished with zero private reserve.

Only `split_tail`, selected using the earlier development evidence, received
inference. All 13 original public strategies and 26 pooled strategies, including
the public-only copies, remain in the descriptive results. No attack or decision
criterion changed after sampling. The failed prior policy screen remains intact.

## Accuracy and paired changes

The inferential rates **average the 512 ledger accuracies equally**. Counts pool
targets and therefore have slightly different rates; targets within one ledger
are not independent samples.

| Approximate amount prediction | Correct / 18,192 | Pooled-target rate | Equal-ledger rate |
| --- | ---: | ---: | ---: |
| Price only: 45 tKAS | 3,810 | 20.94% | 20.88% |
| Public + directory `split_tail` | 2,461 | 13.53% | 13.53% |
| Added pooled records `split_tail` | 2,627 | 14.44% | 14.47% |

| Paired comparison | New hits | Lost hits | Equal-ledger difference |
| --- | ---: | ---: | ---: |
| Public + directory minus price | 1,990 | 3,339 | -7.34765 pp |
| Pooled minus price | 1,897 | 3,080 | -6.40577 pp |
| Pooled minus public + directory | 2,094 | 1,928 | +0.94188 pp |

The first two differences are negative observations, not a separately tested
negative-population claim. Gains and losses show substantial turnover: a worse
average does not mean every attack hit was the same price-prior hit. Nor do new
hits alone demonstrate transaction information; guesses at other common prices
can hit different targets without improving on the best marginal price action.
This experiment measures net prediction advantage, not each guess's causal path.

Exact equality has a different optimal price baseline, **10 tKAS**. Its result
was 2,207 exact hits (12.11% equal-ledger accuracy), versus 1,059 (5.80%) for
public `split_tail` and 940 (5.19%) for pooled `split_tail`. The old observer's
45-tKAS prior had only one exact hit; treating that as the exact baseline would
give a misleading comparison. Exact endpoints are descriptive here.

## All nine frozen tests

Each entry is the fixed four-bet mixture e-value; rejection requires **>=180**.
The code compares exact rational values. Rounded displays below do not decide
threshold crossings. The familywise false-rejection bound is 9/180 = .05 under
the declared independent-ledger model; these are not posterior probabilities,
p-values or confidence intervals.

| Contrast | Positive advantage | Above 5 pp | Below 5 pp |
| --- | ---: | ---: | ---: |
| Public + directory minus price | 0.00213714 | 0.0000830675 | **1.01346e22** |
| Pooled minus price | 0.00396893 | 0.000153912 | **2.44749e20** |
| Pooled minus public + directory | 5.71818 | 0.0190171 | **4.22526e6** |

Only the three below-five tests crossed. In particular, the observed +0.94-pp
effect of added colluder records did not establish a positive mean effect at
the frozen threshold. This measures the chosen heuristic: an optimal observer
can ignore extra records, and a heuristic's deterioration cannot imply that
available information decreased.

Descriptively, the price prior also led every fixed approximate-amount strategy
in both views. That observation does not extend the nine-test inference to the
whole family. For exact amounts, public `receipt_timing` reached 12.23% against
the 10-tKAS baseline's 12.11%; no inferential test of that small difference was
declared. Full strategy, identity and paired counts are retained in the evidence.

## Verification and evidence identity

The frozen control suite registered 101 tests: 100 passed and one nested-sandbox
check skipped inside the already restricted namespace. The real public rehearsal
separately exercised generation, eight observer jobs, scoring, verified export
and an independent aggregate recount with the same sources/spec/runtime.
The original model, observer and accounting validator are unchanged.

Two separate checks passed after completion:

1. The [aggregate recount](evidence/2026-10-22-price-leakage/independent-recount.json)
   independently recomputed all 195 strategy-metric summaries, paired arithmetic
   and all nine exact e-values from exported ledger counts.
2. The [target recount](evidence/2026-10-22-price-leakage/target-audit.json)
   independently derived economic targets from obligations and actual PAY
   outputs, then checked eligibility, both price baselines, all five selected
   attack metrics and paired counts against every frozen case. It verified the
   full 1,024-job barrier before reading truth in a separate seed-free sandbox.
   Its separately pinned code was prepared before accessing evaluation truth,
   passed seven public controls and the four-ledger public rehearsal, and changed
   no original result, attack or statistical criterion.

These are author-operated independent implementations and source reviews, not
external attestation, proof of independent sampling or cryptographic review.
The [public package](evidence/2026-10-22-price-leakage/README.md) retains all 8,225
allowlisted artifacts, sealed predictions, source snapshots and aggregate checks.
Seeds, raw truth, honest target masks and truth-joined rows remain outside Git.

| Identity | Value |
| --- | --- |
| Prior diagnosis commit, already pushed | `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02` |
| Attempt | `price-leakage-20261022-01` |
| Frozen UTC | `2026-10-22T07:08:43.912041+00:00` |
| Completion UTC | `2026-10-22T08:50:21.138316+00:00` |
| Freeze SHA-256 | `b21754e4e5991ec866cfcb121f5c2597f1baa6c395c1a5e442ef9d68733ad4f8` |
| Prediction-batch SHA-256 | `268dde87994d75db5c19aa58da17392df0c5638b4a166b760dd088906ea3c08b` |
| Original score SHA-256 | `80022f7b21018d9695863cafe31bdba8eb61e72bd22ad5016ec624bab7921556` |
| Public archive SHA-256 | `64671204f17bbcd7970dc66039928ca6df2e490cfda38662361edd86f9601f8f` |

Twelve CPU workers completed the run in about 102 minutes from freeze to final
receipt. Earlier public rehearsals were retained: one was stopped to raise
operational concurrency, and one found a fixture repository-path error inside
the sandbox. The fixture was corrected without weakening the production guard;
the successful third rehearsal preceded fresh evaluation sampling.

## Decision and limits

The specific sparse-case heuristic did not generalize into a useful predictor
beyond the price prior. The next privacy work should calibrate a stronger
declared attack against appropriate price knowledge, including confidence and
selective exposure, and verify which observations survive in genuine native
bytes. Existing public/native field dependencies can guide that design without
another general cashout-policy sweep. No architecture or runtime rewrite is
justified by this test alone; retain the direct-L1 mechanics and independent exits.

The unchanged common-price distribution has optimal marginal approximate
success about **21.10%**, already above the **20% absolute target**. This run
does not resolve that requirements tension, qualify the wallet, or revive the
rejected partial-withdrawal policy. Below-five evidence bounds this fixed
final-horizon heuristic under this generator; it does not bound stronger,
targeted, earlier-prefix or native-byte attacks, or prove zero leakage.

Native scripts/outpoints, real timing, ciphertext delivery, proof bytes, reorgs
and service/network observations are absent. The partial-payout relation exists,
but the current wallet's whole-selected-note Exit is a different action. The
initial owner directory is supplied externally, cash demand is unmeasured,
cohorts are well funded, and roles are not independently recruited people.
Those limits remain visible in the next experiment's design.
