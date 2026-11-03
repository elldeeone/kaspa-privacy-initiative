# ADR-0026: Test independently scheduled common payouts

Status: Accepted for the owner-authorized frozen offline comparison; native
calibration and TN10 are conditional on its complete gate.
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
