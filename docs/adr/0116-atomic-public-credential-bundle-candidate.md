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
4. The selected Testnet gate and matched-cost check are recorded below. The
   47-useful-KAS workload was already above the retained 2% all-in target
   before the extra bundle transaction. No production selection follows from
   the local result.

This decision adds no token, admin exit, cryptographic primitive, relaxed
proof/economic check, mainnet deployment or consensus rule. It introduces an
explicit independent-L1-reader and data-availability assumption for optional
privacy. The board test keeps the existing issuer, wallet proofs, whole-set
approvals and economic kernel; a real deployment would need exact chain-object
binding, accepted ordering and recovery semantics before any authority depends
on the bundle.

## Testnet gate and retained decision, 7 November 2026

The [fresh TN10 result](../../research/atomic-bundle-withdrawal-2026-11-07/TESTNET-RESULT.md)
confirms one 9,204-byte ordinary accepted bundle, three separate wallet chain
readers using two public RPC operators, genuine approvals, a later private
payment, three native group payouts, zero final reserve/liability and five
restored-key payout spends. The service-only observer retained zero exact
ownership links and six compatible assignments; its one rank guess got 1/3.
The added paid native fee was 0.01894 KAS. All other fees in the same-shaped
complete TN10 path were unchanged. On the retained 47-useful-KAS comparison,
native fees project to about 2.15%, and the illustrative measured
proof-and-fee subtotal to about 8.25% before unpriced additions. The accepted
small-fixture fee is a same-shape proxy, not an actual 47-KAS bundle fee or a
normal-use percentage for the 1.2-KAS Testnet fixture.

**Keep the bundle optional and experimental.** It earns a real bounded
service-timing benefit on current L1, but does not meet the complete privacy
or roughly 3% complete-cost bar for the matched workload. This is a component
to contribute to the shared investigation, not grounds for a separate
production runtime. Per-wallet reads used one public operator each on one
physical host; header authentication, hostile-RPC behavior, live reorgs,
retention, independent users, known-owner attacks and complete service pricing
remain unqualified. No consensus, reserve authority or cryptographic relation
changed. The issuer can still withhold the whole bundle and reduce liveness.
