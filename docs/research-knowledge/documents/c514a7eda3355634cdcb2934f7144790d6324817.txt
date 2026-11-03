# ADR-0026: Test independently scheduled common payouts

Status: Completed. Frozen offline privacy gate failed; tested policy not
adopted. The condition for native calibration and TN10 was not met.
Date: 2026-10-20 UTC. Branch: `shared-pool-four-wallet`.

H17 reduced some cashout-source links after full drainage, but used a global
order and arbitrary ten-minute spacing. Its observer ignored elapsed-time
inference. Shortening timestamps alone cannot resolve practical scheduling.

Keep v6 unchanged. Screen one optional 2-tKAS partial followed by a locally
scheduled full remainder, with an immediate independent exit override. Compare
new paired workloads using timing-aware source guesses, all final remainders
and fees. The [frozen scope](../../poc/shared-pool/SCHEDULED-PAYOUT-SPEC.md)
defines the policy, sources of randomness, observer, thresholds and stop rule.

Reject a shared round/coordinator, additional cover traffic, a new denomination
search or protocol change for this question. Reuse existing private change and
saved exit mechanics. Timing assumptions constrain this experiment's wallet
model only; they do not become new consensus rules.

If the offline result fails, retain it and stop before TN10. Passing would
justify the already authorized bounded native/live qualification, not strong
privacy, mainnet readiness or a new cryptographic security claim.

## Observed decision

The [completed comparison](../../poc/shared-pool/SCHEDULED-PAYOUT.md) retains
24 new primary paired ledgers and two controls. Attack-family guessing success
is identical between full and scheduled partial exits in both regimes and
observer profiles, failing the required reduction. Fees and p95 delay pass.
No original payment gains a new unique source; all 504 exact truth checks pass.
The sole incomplete solver job is recovered with one worker and the same
constraints/objective, before scoring, without rerunning completed predictions.

Reject this particular 2-tKAS/5–15-minute schedule as a demonstrated privacy
mitigation; stop before funding, native calibration or TN10. Keep v6 private
change, fresh normal proofs and independent saved exits. Do not change the
frozen criteria or interpret the result as an impossibility theorem for all
current-L1 privacy. Stage 2 remains open; isolated complete cashouts require
a further explicit privacy/latency design decision.
