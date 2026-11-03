# Frozen price-leakage result: interpretation

**Accepted as a final public result, with no material numeric or decision discrepancy found.** Snapshot reviewed at 2026-10-22T08:59:13.992029+00:00. Completion records 2026-10-22 08:50:21 UTC (19:50:21 AEDT), 512 ledgers, non-rehearsal; its score hash matches the public result. The target audit and aggregate independent recount report passing, and the archive-verification receipt is complete at 08:54:33 UTC. This review interprets those published receipts and the frozen protocol; it does not rerun them.

The frozen source base is `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`, frozen at 07:08:43 UTC, with 13 separately hashed source files. The protocol bytes reviewed match the freeze. These are final evaluation summaries, not the earlier development findings or a provisional export.

## What the headline measures

The primary success condition is **within 10%**, using `10*abs(guess-actual) <= actual`; it is not exact amount recovery. The fixed marginal price-only guess is 45 tKAS. All primary comparisons concern **18,192 eligible honest-to-honest economic payment targets**, among 32,768 observable targets, in the synthetic `sparse-independent / partial / final` setting. The independent inferential unit is the **whole ledger**, with each of 512 ledgers weighted equally. Payment targets within a ledger are not independent trials.

| Frozen predictor/view | Within 10%, equal-ledger mean | Correct / eligible targets | Within 10%, pooled-target rate |
|---|---:|---:|---:|
| Price-only, 45 tKAS | 20.88% | 3,810 / 18,192 | 20.94% |
| C+D `split_tail` | 13.53% | 2,461 / 18,192 | 13.53% |
| Pooled `split_tail` | 14.47% | 2,627 / 18,192 | 14.44% |

The headline uses the second column; pooled-target rates are descriptive. C+D includes public arithmetic events **and the initial funding-owner directory**. Pooled adds the eight colluders' permitted authored operations and receipts. These are modeled information views, not a native-byte or individual-field effect.

Exact amount recovery is separately descriptive: equal-ledger means are **5.80% C+D**, **5.19% pooled**, versus **12.11%** for the distinct optimal marginal exact-price guess of **10 tKAS**. The nine inferential tests do not concern exact recovery. See protocol lines 27–51 and 61–102.

## Frozen paired decisions

Each contrast uses the same eligible targets within each ledger. Only the preselected `split_tail` attack has inferential status. The 13 base variants and pooled public-only copies do not enlarge the inferential claim.

| Paired contrast | Observed mean difference | E: advantage > 0 | E: advantage > 5 pp | E: advantage < 5 pp |
|---|---:|---:|---:|---:|
| C+D minus price-only | −7.35 pp | 0.00214 | 0.0000831 | 1.013 × 10²² |
| Pooled minus price-only | −6.41 pp | 0.00397 | 0.000154 | 2.447 × 10²⁰ |
| Pooled minus C+D | +0.94 pp | 5.72 | 0.0190 | 4.225 × 10⁶ |

The table rounds already published values; it does not recount cases. Decisions use exact rational comparisons with **E ≥ 180**. All three below-five-point tests cross; none of the positive-advantage or above-five-point tests crosses. The frozen nine-test familywise false-rejection bound is 5%, conditional on its independent-ledger and fixed-attack assumptions (protocol lines 104–136).

Thus the justified inference is that **this fixed heuristic's mean advantage is below five percentage points in each of the three tested contrasts**. The observed +0.94 pp from adding colluder records is not a demonstrated positive population advantage under the frozen rule. Failure to reject a positive-advantage null does not establish zero advantage, and no confidence interval is produced.

## Decision boundary and evidence limits

**No payout-policy change is warranted by this result.** The price-only mean remains above the unchanged 20% absolute cap; its theoretical marginal success is about 21.10%, already above that cap before this evaluation. `qualification_pass` remains **false**. The earlier privacy failure and rejected partial-withdrawal policy are not reversed (protocol lines 70–85 and 170–175).

The negative observed differences do not show that transcripts carry no useful information: a fixed heuristic can perform worse with extra information, and a stronger observer could retain the price-only guess. This result does not bound untested attacks, targeted exposure, other workloads or horizons, real-user anonymity, native transaction acceptance, proof validity, or cryptographic privacy. Nor does it establish that collusion is harmless or isolate a causal effect of one field.

The public target audit reports independently deriving economic payment eligibility and checking the selected attack's five metrics, baselines, intersections and aggregate rates. The separate aggregate recount reports 512 ledger rows, 18,192 eligible targets and all nine exact tests passing its consistency checks. This resolves the previously noted aggregate-only target-verification gap **in the reported evidence**. Both remain author-operated evidence, not independent sampling or execution attestation; the archive-verification receipt explicitly says so. This reviewer read public summaries/protocol and checked their hashes, without opening case rows, archive payloads, private seeds, truth, or prediction payloads. No experiment, test, build, retuning, or recount was run.

## Source identity

Public export directory: `/home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/evidence/2026-10-22-price-leakage/`.

SHA-256 values directly checked for this review:

- `result.json`: `80022f7b21018d9695863cafe31bdba8eb61e72bd22ad5016ec624bab7921556`
- `completion.json`: `c2bb37f4debe8f285dabc4019a9ad52ded7b9acc0598b009520aa1cef1962b48`
- `archive-receipt.json`: `ae0b80763e611a1f46910f81da8cd5c38428c381b08c05738b1a1eb7286fec46`
- `archive-verification.json`: `a0e2e4346f51802cfabccfe84a1f894978e0d6c609e09900f19724676d71c7ec`
- `target-audit.json`: `c12ccf83c5d7362a44164fd0f19e919f76c9ea0cec27882b9f7afe8beca85520`
- `independent-recount.json`: `c02812ef03d45cb24b6fe2ce12edcc9d6b9e8f258c36e7bf4ba59b7d034508bb`
- `freeze.json`: `b21754e4e5991ec866cfcb121f5c2597f1baa6c395c1a5e442ef9d68733ad4f8`
- `poc/shared-pool/PRICE-LEAKAGE-SPEC.md`: `104bea66d0798c523de6c5d283861d4d4867632c0e30189f8179c1763bcfa885`

The public archive receipt and verification report bind archive SHA-256 `64671204f17bbcd7970dc66039928ca6df2e490cfda38662361edd86f9601f8f` (50,112,632 bytes). This review did not extract or independently reverify every archive member.
