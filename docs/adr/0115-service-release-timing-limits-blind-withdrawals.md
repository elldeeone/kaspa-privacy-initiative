# ADR-0115: Do not treat service-controlled blind registration as payout privacy

**Status:** Accepted research decision. **Date:** 7 November 2026.

The owner required a wallet round-agreement fix, a fresh active privacy test,
and cost work only if privacy survived, with no consensus changes. The
[executed local test](../../research/round-agreement-2026-11-07/RESULT.md)
shows that the wallet fix blocks per-client round tags before payout-key
redemption. A service can nevertheless hold three valid blind-signature replies
under one common round and release them one at a time, waiting for each payout
message. It recovered 3/3 exact claim-to-payout links; the genuine wallet
approvals and unchanged economic kernel accepted the complete payout set.

## Decision

1. Keep the wallet's genuine common-cohort check as a necessary local guard.
   It prevents the demonstrated round-ID leak and does not change fund authority.
2. Do not claim this service protocol hides payout ownership against an active
   service. Stop the conditional first-payment cost campaign for it.
3. Retain cached proof verification and optional batching as independently
   useful cost/liveness changes. Do not select a competing privacy architecture
   from this failed withdrawal experiment.
4. A future attempt must make signature/cohort availability independent of the
   service's per-client release timing and pass the same fixed active observer
   before cost work. Whether current-L1 public coordination can do this cheaply
   remains open; no chain rule change is proposed.

This is an offline host-kernel result, with one physical host for completed
wallet/service comparisons. No accepted native withdrawal, independent users,
full financial privacy or production security is established. The prohibited
second-host extension was stopped before a result and is excluded from evidence.
Current transparent amounts and known-owner disclosures remain adverse limits.
