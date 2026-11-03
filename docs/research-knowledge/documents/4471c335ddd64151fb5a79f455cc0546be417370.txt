# Native KAS privacy research checkpoint

This checkpoint preserves the wallet-local experiments, depth-four native
trial tooling, finite public evidence, scorer corrections and architecture
proposal. It does not start further experiments or accept a new architecture.

## What was achieved

- [Wallet-local studies](wallet-local-payment-privacy-2026-11-01/RESULT.md)
  tested private re-spending, shared history, private change and full exits.
  Later corrections and negative results are retained alongside each study.
- [The completed native trial](full-drainage-executed-lifecycle-2026-11-01/run/tn10-attempt-06-public/README.md)
  used two deposits, three private transfers, five payouts and seven settlements.
  Successful attempt 06 ended with zero user principal, pending deposits,
  private liability, unpaid exits and permission rent. Its separate state rent
  is 100,000,000 sompi. Public endpoint corroboration is historical evidence.
- [The corrected assessment](full-drainage-executed-lifecycle-2026-11-01/CORRECTION.md)
  retains two gross histories in its limited known-owner model after everyone
  withdraws. B's 20,000,000-sompi payment to M is exposed. The original strong
  view selected the wrong history and cannot count as reconstruction.
- [Reserve-lineage analysis](full-drainage-executed-lifecycle-2026-11-01/NEXT-PRIVACY-RESULT.md)
  found that a synthetic common reserve obscures funding ancestry but leaves
  the two payment histories unchanged. That proposed mitigation was rejected
  as a direct-payment privacy fix; it was not implemented.

These are bounded research and Testnet results. They do not establish
cryptographic correctness, practical anonymity, independent custody, complete
service-loss recovery or production readiness. Ordinary native withdrawal
amounts and destinations remain visible.

## Open decision and retained work

[RFC 0004](../docs/rfc/0004-native-kas-private-payment-boundary.md) is an open
proposal comparing a minimal wallet-local shielded design with broader runtime
and consensus alternatives. Committing it does not accept its recommendation.
The owner goal remains private native KAS, no fixed MPC dependency, independent
full exits, no forced delays and no required user balance left behind.

MPC remains paused in the separate continuation checkout. Its rejected vendor
patch is retained there and excluded from this checkpoint. A stray historical
MPC width histogram in this checkout and the superseded invalid first attempt
inventory are retained locally under explicit Git exclusions. The corrected
attempt inventory is committed; the failed inventory is not authoritative.

The earlier halted attempts 02–05 still held a combined 550,000,000 sompi
(5.5 test KAS) in the retained read-only inventory. Successful attempt 06's
zero balance does not imply those separate trials were drained. Recovery was
not performed as part of this checkpoint.

Private wallets, keys, execution truth, proving parameters and raw runtime/RPC
evidence remain in local protected storage. No live transaction, rental,
mainnet action or MPC restart is part of tidying this work.

## Checkpoint verification

- All 48 targeted tests passed: nine default wallet tests, eight depth-four
  wallet accounting/circuit tests, eight default TN10 tests, three depth-four
  TN10 tests, one genuine-receipt payout-layout test, 18 scorer regression
  tests and one capture pagination suite. The capture harness was updated to
  supply the lane constant and check preservation of lane-active merge order.
- The depth-four native host compiled offline with receipt support. New Python
  and Node sources passed syntax checks; shell syntax and Markdown links passed.
- Eleven public manifests verified 710 entries. Both public observer outputs
  reproduced from the archive. Candidate files were compared against 58 local
  secret stores without finding matching secret bytes or encodings.
- Full `scripts/ci_fast.sh` is **not green**. Its remote-CUDA suite reported
  11 failures: nine historical package-restoration tests reject source hash
  drift after the new profile changes, and two process-watchdog tests did not
  observe the orphaned child terminate. Source/binary pins were not rewritten
  to imply the old binaries came from the changed sources. Remote proving and
  its watchdog/package work remain outside this checkpoint's qualified scope.

The full fast-check log and the reviewed staging allowlists are retained under
the ignored local checkpoint directory. Passing targeted tests does not remove
the recorded CI limitation or establish protocol security.
