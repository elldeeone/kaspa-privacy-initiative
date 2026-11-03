# ADR-0025: Screen common partial payouts without changing the protocol

Status: Accepted for the owner-authorized offline comparison only.
Date: 2026-10-20 UTC. Branch: `shared-pool-four-wallet`.

H16 found fresh full-exit source links under a single participant's knowledge.
Test one 2-test-KAS partial payout per wallet using the existing v6 relation,
then drain every remainder. Freeze the amount and score original claims rather
than new change outputs. The exact experiment and rejection criteria are in
[the frozen scope](../../poc/shared-pool/COMMON-PAYOUT-SPEC.md).

Keep fresh normal proofs and private saved fallbacks. Optional cashout shaping
cannot be required for exit. Before a partial spends a note, its saved full
exit remains a valid competing choice; afterwards the owner retains a saved
exit for the replacement note. No new token, operator, circuit, setup,
covenant, consensus rule or fee sponsor is introduced. Exact fees, public-data
availability, setup trust and current-state authentication assumptions persist.

This accepts an experiment, not a production wallet policy. Reject repetition
with tuned sizes if complete drainage removes the benefit. The existing
30-minute branch delay target remains in force; the fixed schedule already
implies 40 added minutes. A positive privacy finding alone cannot close Stage 2.
