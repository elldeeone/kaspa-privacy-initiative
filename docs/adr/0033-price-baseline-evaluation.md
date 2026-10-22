# ADR-0033: Evaluate transcript advantage against price guessing

**Status:** Accepted — bounded evaluation method, no protocol change.

**Date:** 2026-10-22 Australia/Sydney.

## Context

[ADR-0032](0032-sparse-diagnosis-and-privacy-evaluation.md) requires separating
priors from incremental information before another mitigation. Wrong guessed
flow supports do not settle whether public transactions improve amount guesses.
The owner authorized freezing and executing the next test to a result.

## Decision

Follow [RFC-0017](../rfc/0017-price-priors-and-transaction-leakage.md) and its
[prospective contract](../../poc/shared-pool/PRICE-LEAKAGE-SPEC.md). Reuse the
unchanged arithmetic workload, observer and accounting validator; generate 512
independent sparse partial-withdrawal ledgers. Select `split_tail` before
sampling and compare public, pooled and price-only approximate-amount success
using equal-ledger paired differences. Exact-price guessing has its own baseline.
Use nine fixed rational betting e-values with threshold 180, complete prediction
sealing before truth and a complete public-seed rehearsal before fresh sampling.

Native regeneration would not isolate the selected arithmetic question;
individual-field deletion and donor permutation introduce further design
assumptions. Keep them as possible separately frozen follow-ups. The small
study/power objection is addressed with a pre-data fixed budget and an explicit
unresolved outcome, never post-result extension or retuning.

## Consequences and reconsideration

The model assumes independent seeds, ideal hiding and declared observation
fields. Marginal price optimality is not full transcript-conditional optimality.
Pooled improvement includes legitimate participant information. No inflation,
authorization, spentness, proof, root, reserve-release or replay rule changes.
Dependency loss aborts the experiment without releasing value. Reorg/native
availability, stronger attacks, real distributions and cryptographic leakage
remain outside this test. No new privileged actor or trust in settlement is
introduced; the generator/scorer and operator remain experimental trust
assumptions checked by isolation, original accounting and independent recount.

The original absolute privacy target and failed policy remain unchanged. A
bounded result informs the next source/design review, not a new privacy claim,
cashout policy adoption, mainnet action or automatic runtime selection. Revisit
the method for a demonstrated implementation defect or a separately justified
observer/workload question, preserving this attempt and its frozen result.

## Outcome

The [completed result](../../poc/shared-pool/PRICE-LEAKAGE.md) has 512 valid
ledgers, all 1,024 predictions sealed before truth, and successful independent
aggregate and target-level recounts. The selected heuristic's observed public
and pooled approximate accuracies are 13.53% and 14.47%, below the price-only
20.88%. All three reverse-margin tests support advantage below five points;
none of the positive tests crossed. No new inference was added after results.

Retain the direct-L1 research platform and stop treating this heuristic's small
development-case wins as evidence requiring a public-structure rewrite. Improve
calibration and verify native observation coverage before another privacy test;
that is a future design decision, not an execution release. The broader
transaction-information question, selective exposure and privacy qualification
remain open. This outcome changes no protocol, adopted target or old failure.
