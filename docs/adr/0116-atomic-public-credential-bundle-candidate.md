# ADR-0116: Retain atomic public credential bundles as a bounded candidate

**Status:** Accepted research decision, not a production architecture.
**Date:** 7 November 2026.

The owner asked for the smallest current-L1 way to remove a malicious blind
issuer's per-wallet reply timing control, using the actual private-payment
system and no consensus changes. The [frozen local test](../../research/atomic-bundle-withdrawal-2026-11-07/SELECTION.md)
uses a single complete bundle sized at 9,256 bytes in an atomic local
publication. Its [result](../../research/atomic-bundle-withdrawal-2026-11-07/RESULT.md)
blocks nine withheld/partial/broken-reply checks before payout-key disclosure.
The service-only observer has zero exact links and six compatible mappings;
the unchanged kernel accepts all three genuine payouts. Public replay verifies
the actual proofs, credentials and payment/withdrawal accounting. This is
same-host offline evidence, not chain acceptance or network privacy.

## Decision

1. Keep the new board checks **experimental and feature-gated**. All three
   genuine issue proofs and all three blinded RSA reply relations must validate
   under one state, issuer, amount and round before a wallet discloses a payout
   key. An issuer's private acknowledgement is never sufficient.
2. Treat an ordinary accepted transaction payload as the candidate common
   availability point. Wallets need independently authenticated accepted-chain
   reads, confirmation/reorg handling and recoverable bundle data. The issuer
   may withhold service, reducing liveness, but may not gain reserve-spending
   authority. Preserve the ordinary independent-exit requirement separately.
3. Do **not** claim that the candidate hides payout ownership globally or
   qualifies complete financial privacy. The prior per-client service path
   remains rejected under [ADR-0115](0115-service-release-timing-limits-blind-withdrawals.md).
   Known owners/Sybils, public amounts, network timing, fee funding and later
   disclosures still defeat or limit the benefit.
4. The next gate is actual Testnet payload acceptance and independent readers
   with the complete approved payout and restored-key spend. If that gate fails,
   stop this option and contribute the failure to upstream P13. If it passes,
   compare **complete** first-payment and service costs, including the new
   payload transaction, with the retained workload. The existing 47-useful-KAS
   native-fee quote is already 2.11% before a separate publication fee, so the
   unchanged workload cannot meet the retained 2% all-in target by adding this
   transaction alone. No full cost or production selection follows from this
   local result.

This decision adds no token, admin exit, cryptographic primitive, relaxed
proof/economic check, mainnet deployment or consensus rule. It introduces an
explicit independent-L1-reader and data-availability assumption for optional
privacy. The board test keeps the existing issuer, wallet proofs, whole-set
approvals and economic kernel; a real deployment would need exact chain-object
binding, accepted ordering and recovery semantics before any authority depends
on the bundle.
