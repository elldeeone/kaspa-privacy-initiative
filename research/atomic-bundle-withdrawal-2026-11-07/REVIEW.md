# Adversarial second pass

**Scope:** experimental board mode and the selected one-host offline result.
This is source/host review, not an independent cryptographic audit.

| Question | Check and remaining risk |
| --- | --- |
| Can the board mint value or release reserve KAS? | No board field is an economic kernel input. The existing proof-backed claims, three owner approvals and unchanged kernel verified 30 KAS payouts against 40 KAS supplied principal with 10 KAS liability/reserve left. The test did not construct a new accepted native settlement. |
| Can one claim spend twice? | Existing replay verifies distinct issue nullifiers and payout keys; whole-set intent validation binds exact sets. The test does not prove live contention or reorg spentness. |
| Can a false or partial bundle disclose one payout key? | Wallets reject absent/partial bundles and all three detect a bad blinded reply. The corrective check corrupts a *different* claimant's reply for each wallet and all three reject. The wallet also verifies the genuine eligibility proofs before its own unblinding/redemption. |
| Can the issuer still time releases? | A private `queued` reply has no signature. The local board is one atomic common object; the service-only observer got zero exact issue-to-payout links. The issuer can withhold the whole object, and an issuer-controlled RPC or network vantage can selectively delay its delivery. Those attacks remain untested. |
| Can the issuer tag or infer owners another way? | A common round/issuer/state/value is checked, and RSA blinded reply relations are checked. Known-owner/Sybil claims, distinctive public values, fee funding, labelled network origins and later participant disclosure can still collapse mappings. A single rank guess scored 1/3; no statistical anonymity claim follows. |
| What if accepted state advances or a reorg occurs? | Current proof/intent checks reject stale state at final settlement, but the local board has no accepted-chain checkpoint, confirmation buffer, canonical bundle selection or replay/rollback implementation. Native acceptance and independent data retention are next gates. |
| What if the issuer disappears? | The issuer can withhold all replies, reducing liveness. The old independent ordinary-exit requirement remains; this test did not replay that fallback after service disappearance. No issuer signature alone releases reserve value. |

No security invariant is relaxed. The test adds an explicit independent-reader
availability assumption and one ordinary payload transaction as a candidate
coordination mechanism. It does not establish production correctness or cost.
