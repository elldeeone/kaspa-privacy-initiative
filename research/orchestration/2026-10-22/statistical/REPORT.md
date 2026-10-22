> Imported documentation snapshot. [Canonical status and ownership](../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Independent statistical review: frozen price-baseline evaluation

Reviewed 2026-10-22. Source checkout: `/home/luke/projects/kaspa-privacy-shared-pool`, branch `shielded-kas-research`, HEAD `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`. The working sources include lead-owned uncommitted files; hashes below identify what was reviewed and are not an attestation of the private frozen copy.

## Decision

**The design supports its stated narrow sign/margin decision, provided the frozen pipeline completes validly. No blocking statistical defect was found in the reviewed source.** It tests the population mean of one fixed heuristic's paired, equally weighted whole-ledger accuracy differences on the declared synthetic distribution. It does not evaluate whether the system satisfies the adopted privacy requirements. Preserve the running evaluation, all nine tests, the original rejected-policy result, and any unresolved outcome.

This was source analysis on Forge only. No evaluation seeds, truth, predictions, scores or interim correctness were accessed; no test, scorer, model, observer or experiment was run. Nothing in an active checkout, system runtime or service was changed. This is not a fresh operational verification of the private run.

All line references below are relative to the source checkout. Bare filenames resolve under `poc/shared-pool/`; explicit `docs/`, `research/` and `evidence/` paths use their displayed location (`evidence/` is also under `poc/shared-pool/`).

## Why the narrow inference is defensible

- **Independent unit and pairing:** `PRICE-LEAKAGE-SPEC.md:27-32,87-102` fixes 512 independent whole ledgers and one scenario/arm/horizon. `price_leakage_trial.py:326-334,418-422` generates fresh per-ledger seeds and replays each independently. `price_leakage_score.py:128-135,153-183,287-321` uses identical eligible targets in each contrast, computes gains minus losses over the ledger denominator, and averages ledger differences equally. Pooled-target rates are separately labeled. There is no payment-level pseudoreplication. Independent seeds and the unchanged deterministic pipeline are assumptions supported by the design, not established by counting distinct output hashes.
- **Baselines match the loss function:** `working_balance_model.py:121-140` draws honest amounts from the declared 60% invoice / 40% cent-grid mixture; eligibility is honest sender and recipient. `working_balance_observer.py:49-62` optimizes the integer within-10% success intervals. The scorer uses 45 tKAS for approximate success and a separate 10 tKAS modal baseline for exact success (`price_leakage_score.py:14-18,74-78,158-164`). The marginal approximate optimum is 21103/100025, about 21.10%; it already exceeds the unchanged 20% absolute cap. This is not an optimal conditional observer given transcript/participant facts.
- **Selection and multiplicity:** `PRICE-LEAKAGE-SPEC.md:61-68` freezes `split_tail` before fresh sampling and relegates all other variants to description. Its development selection is visible in `WORKING-BALANCE-SPARSE-DIAGNOSIS.md:14-33,52-60`; independent new samples can validate that selected attack without pretending it was never selected. Only within-10% accuracy gets inference (`price_leakage_score.py:313-321`). There are three contrasts and three directional tests per contrast, not 39 inferential strategies.
- **Uncertainty calculation:** `price_leakage_score.py:194-228` correctly implements exact rational averages of four fixed wealth products. For D in [-1,1], the smallest factors for the three tests are .1, .055 and .145. Under each null, independence makes each product's expectation at most one; the fixed mixture retains that property. Markov plus a union bound gives at most 9/180 = .05 probability of any false rejection among these nine tests. Dependence between the three contrasts is harmless to this bound. This is a bound on false directional conclusions, not a posterior probability or a general confidence interval. The implementation's empirical means are exact arithmetic, not exact population means.
- **Eligibility and failures:** observers predict all observable zero-payout SPENDs before the hidden honest-to-honest mask is applied (`price_leakage_score.py:94-125,138-170`). The separate accounting validator reconstructs targets from economic obligations and checks their identity (`working_balance_validate.py:222-227,265-305`). Empty eligibility, missing predictions and malformed inputs fail rather than becoming zeros or dropped cases. The spec explicitly prohibits resampling, extending N or interpreting errors as privacy (`PRICE-LEAKAGE-SPEC.md:53-57,150-160`). The controller seals the full matrix before staging truth (`price_leakage_trial.py:235-285,385-399`).

## Material limits and required interpretation

| Finding | Severity / decision impact | Evidence and action |
| --- | --- | --- |
| The amount average can conceal exposure concentrated on particular targets; relationship ranks are validated but not scored for selective precision. | High if a result is promoted to privacy qualification; **not a defect in this explicitly narrower experiment**. | `price_leakage_score.py:117-124,165-179,294-321` retains full-coverage counts only. Adopted requirements demand precision at 5%, 10%, 25% coverage and a forced-disclosure gate ([docs/rfc/0012-useful-privacy-requirements.md:230-255](../../../../docs/rfc/0012-useful-privacy-requirements.md)). Do not claim these gates passed or that a below-five average protects each user. |
| Only the chosen final-horizon heuristic is bounded; strongest-family, earlier-horizon and retained-prefix attacks are not. | High if used to claim durable or strongest-attack privacy; no change to the present run is needed. | `PRICE-LEAKAGE-SPEC.md:27-28,61-68,131-136`. The earlier development report explicitly retained earlier-prefix copies (`WORKING-BALANCE-PRIVACY.md:15-18,27-30,52-56`). More information can worsen this fixed heuristic while an optimal observer can ignore it. A negative pooled-minus-public result cannot show that collusion reduces available information. |
| The independent public recount verifies aggregate arithmetic, not the target-level facts that make the arithmetic meaningful. | Medium evidence gap; it must not be described as independent validation of the entire experiment. | `evidence/2026-10-22-price-leakage/independent_recount.py:131-147,178-187,255-280,286-294` rederives differences/e-values from exported counts and explicitly disclaims eligibility, target correctness, independence and barrier verification. A systematic scorer error can survive internally consistent aggregates. The runner and accounting validator supply separate evidence; this review has not certified the live artifacts. |
| No measured-power guarantee exists at N=512, and the nine-test error budget does not cover future exploratory winners. | Reporting constraint, not a defect. | `research/shielded-kas-price-baseline-test-2026-10-22.md:109-124` correctly notes that fixed positive bets can lack power for small, high-variance excesses. Do not equate non-rejection with a small effect, extend N to get a preferred result, or apply this .05 familywise bound to later attacks/endpoints. |

## Strongest justified reading of each terminal outcome

Apply these separately to C+D minus price, pooled minus price, and pooled minus C+D. C+D includes the initial owner directory; pooled adds the declared participant records.

| Frozen result | Justified interpretation |
| --- | --- |
| Above-five test crosses 180 | Evidence that the **population mean** advantage of this fixed final heuristic exceeds five percentage points under this generator. The public contrast establishes bounded prediction benefit from the combined transcript/directory inputs; it does not identify an individual causal field. The pooled contrast includes legitimate participant information. |
| Positive test crosses, five-point question unresolved | Evidence of positive mean advantage; material size remains unresolved. |
| Positive and below-five tests cross | Evidence that this mean advantage is strictly between zero and five points, within the stated familywise error control. |
| Below-five test alone crosses | Evidence of mean advantage below five points for this contrast. Zero leakage, nonpositive advantage, conditional optimality and upper bounds on other attacks do not follow. |
| Neither relevant directional claim is supported | Unresolved. Report observed means, denominators and all nine e-values; do not turn absence of evidence into acceptance. |
| Missing/invalid ledger, prediction, accounting or provenance | Incomplete/invalid attempt, never a privacy pass. Preserve artifacts and document any correction separately. |

Every outcome leaves the 20% absolute amount target violated by this workload's prior, the original partial-policy rejection intact, and runtime/architecture selection undecided (`PRICE-LEAKAGE-SPEC.md:81-85,170-175`; `docs/adr/0033-price-baseline-evaluation.md:43-47`). A numerical hit is not proof of an actual flow reconstruction, and its failure to reconstruct a flow does not erase the hit.

## One smallest follow-up

After the complete terminal seal, commission a **separate, versioned target-level recount** of the already frozen 512 histories in a private, seed-free audit process. Independently derive the eligible event set and 45/10-tKAS baseline and `split_tail` approximate/exact counts from the sealed predictions and authorized truth; compare with each exported ledger count, then feed the existing aggregate recount. Do not regenerate histories, run new attacks, alter thresholds, add endpoints or overwrite the frozen verdict. Export only audit counts and digests. This closes the concrete semantic-verification gap above with no new experimentation; any discrepancy is a separately documented implementation finding.

## Reviewed source hashes

SHA-256 values are for the current read-only checkout, captured when this report was written. Portions of the model, validator and observer relevant to sampling, targets, priors and result production were inspected; this was not a comprehensive security audit.

Captured UTC: 2026-10-22T07:24:18.179973+00:00

```text
c605a5c07d1edbdee45ada102e0c21913e663a506219190818d846179bc6d6fb  AGENTS.md
44cf983d06c8895c61a492107f65487725331a1b2f93d1c89e7353fb5399733d  SECURITY-INVARIANTS.md
104bea66d0798c523de6c5d283861d4d4867632c0e30189f8179c1763bcfa885  poc/shared-pool/PRICE-LEAKAGE-SPEC.md
e1901ff96e13af0dc2bb2f556cf356c9df800a88d2a48d423caea61f084b97d7  poc/shared-pool/price_leakage_trial.py
cd41545f846e1324e98e057c505991ee66f3e18fb218b947f4ca45e01f8af475  poc/shared-pool/price_leakage_score.py
f8d332acabcc8b4812c75a1e19b78782306f1aa045347786a9c2faa40116aaa4  poc/shared-pool/evidence/2026-10-22-price-leakage/independent_recount.py
a1a8c3989d85f2309dcd726cd2d076c77c4ea77e407a7dfbd8c05f975dafbe00  poc/shared-pool/working_balance_model.py
b492d5a2e63836751f51f5151c002c3ec6492c224b518846c45eca23f3ea7495  poc/shared-pool/working_balance_observer.py
407c1abeebc913b8112754d70705eae41a36f86cf954aa946dfa565abef3eb14  poc/shared-pool/working_balance_validate.py
9f62faaca50dca456a2337cbe8ac9598e3b3c16d1a550748395485a08c93dc2c  poc/shared-pool/WORKING-BALANCE-PRIVACY.md
8a608e6ba7c6623f20d02f6fa58d7504403b855524c8af43526d39ba357ee5fa  poc/shared-pool/WORKING-BALANCE-SPARSE-DIAGNOSIS.md
ce96d64687c06b9f57bc36ff2d9aa222ba8e731705af6c8987c4973a49e27a19  docs/rfc/0012-useful-privacy-requirements.md
32d6cc25e90324e8410620f3c4c522da192371e25119d14dae107a9c534e8eb5  docs/rfc/0017-price-priors-and-transaction-leakage.md
44e693c6bd07ce08906c89e3ed2f325f58d09c29453de98991ca93892f9cb302  docs/adr/0033-price-baseline-evaluation.md
934b6302e03450a9a97f11a891d51d7a8d0e12e20eef7ffb6de067299db60b0b  research/shielded-kas-price-baseline-test-2026-10-22.md
1f66328cd706d046b49925caf1bc88cd588ed020922023b7b9e9a9bf3488f220  research/shielded-kas-privacy-requirements-2026-10-20.md
```
