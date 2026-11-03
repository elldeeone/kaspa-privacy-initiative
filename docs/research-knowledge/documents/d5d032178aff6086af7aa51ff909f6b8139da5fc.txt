# Full offline wallet validation, 2026-10-18

**Four genuine full-wallet receipts passed on the RTX3070**, including a spend
reconstructed from Alice's own backup and verified public history. Saved bytes
were reverified on CPU. All values below are synthetic integer sompi; there
were no native transactions, mainnet activity or real funds.

| Wallet operation | GPU proof time | Segments | Saved receipt |
| --- | --- | --- | --- |
| CREDIT: Alice 700 external + 300 internal | 20m10s | 691 | CPU verified |
| TRANSFER: Bob 600 + Alice internal change 400 | 41m30s | 1416 | CPU verified |
| Bob EXIT: 600, no append | 29m38s | 1012 | CPU verified |
| Alice restored EXIT: 400, no append | 30m31s | 1046 | CPU verified |

Each 223684-byte receipt is succinct, has the exact 229-byte reviewed journal,
no unresolved assumptions and development mode disabled. GPU process activity
was observed for every proof; sampled peak prover VRAM was 6096 MiB. Eleven
seal/image/journal/envelope mutations reject per receipt, 44 in total.

Actual generic wallet image:
`7461de1c1231e61823431d4800d70f1d8378cf7722b195e82321a028151b2ade`.
A clean target rebuild with the same pinned toolchain produced byte-identical
wrapped program bytes, SHA256
`3887533bb6855403ee137799b63b95b68e29e6e932c758bc721a6515a93226a0`.
The immutable host policy checks this image; the generic guest does not embed
its own identity. The original proving client and final reviewed restore/public
verifier have distinct recorded binary hashes. All receipts are checked by the
final canonical-envelope decoder as well as the original saved-byte verifier.

## Restore and current spentness

Eight network/filesystem-isolated restore runs passed with only the relevant
actor's own backup and public history/receipts mounted. Original witness files
and the other actor's backup were inaccessible. The runs cover Alice's initial
1000, Bob's received 600, duplicated credit/transfer histories, Alice's internal
400 change, Bob before/after exit and Alice after the restored spend.

The final four-operation history accepts all four receipts, retains eight
nullifiers and four appended leaves, and restores both wallets to zero
spendable balance. Private liabilities are zero; unpaid exits and synthetic
reserve both equal 1000. Replaying the transfer or either exit after restore
rejects without changing economics. Exit creates an unpaid claim; this harness
does not perform a native payout or drain native reserve.

The public-only verifier reproduces this state without any backup or witness.
Its externally trusted synthetic history digest is
`0b37a8e3758002235d2c2f9c39cdfaaa56338d3655d7d79b855278caa068009a`.
A mixed history containing a well-formed false receipt accepts three, rejects
one, advances the cursor to four, and retains private 400 / unpaid exits 600.
This is actual host verification and no-op classification, not a proved outer
validity/invalidity transition.

## Adversarial checks and review

- Shared host-executed relation: 111 negative cases and 12720 truncated/trailing
  witness frames rejected. The new parser matches nine frozen intents and
  rejects 15568 truncated/trailing public frames.
- Five selected invalid witnesses fail in the real VM: ownership, position,
  delivery, inflation and recovery signature. These are execution checks,
  not proofs of invalidity.
- Receipt-backed admission covers 14 rejected cases including all eight context
  fields, spent nullifiers on allowed old roots, orphaned roots, expiry and a
  second independently valid CREDIT signature mismatching the proved journal.
  Twelve capacity boundary checks, inclusive expiry and cursor overflow pass.
- Changed/truncated/foreign/missing history or backup inventory rejects;
  duplicate decoded keys and hex aliases reject. A caller-recomputed history
  pin selects a different synthetic branch and does not authenticate the
  original lineage.
- Canonical receipt bytes accept; one-byte, many-byte and concatenated-receipt
  trailing aliases reject, including when their hypothetical history is rehashed.
- Independent Python encoding/journal comparisons match all four cases;
  libsodium 1.0.18 independently verifies the CREDIT signature.

The [adversarial pass](WALLET-ADVERSARIAL.md) records the threat boundaries.
The [final separate-agent runtime review](reviews/offline-wallet-2026-10-18/final-runtime-review.md)
passes for this bounded offline experiment. It independently reverified all four
receipts and final/mixed histories using public inputs only. Historical reports
are retained under [the wallet review folder](reviews/offline-wallet-2026-10-18/).
Review blockers around history-before-scan, duplicate keys and canonical receipt
encoding were corrected and checked. One nonblocking typed-helper precondition
remains: directly constructing malformed ID widths can panic in
`Intent::journal`; every wire/guest/admission entry point shape-checks first.
Changing the frozen core would require a new image/proof revision.

## Evidence and limits

The [public manifest](evidence/2026-10-18-offline-wallet.json) identifies the
[four receipts, exact source and reports](evidence/2026-10-18-offline-wallet.tar.gz).
It retains proof costs, source/toolchain/program/verifier identities, isolated
restore outcomes, review snapshots and per-file hashes. Fresh keys, seeds and
private witness inputs are excluded. Prior sealed evidence remains unchanged.
Follow [the public verification command](WALLET.md#verify-retained-public-evidence-without-secrets)
to replay the retained history without secrets or GPU work.

This is an offline research prototype with locally trusted synthetic backing,
policy and history origin. Host state admission is not a proved outer classifier.
Native deposit recognition/bootstrap, canonical Kaspa history, credit/refund
and payout enforcement, paid markers/terminal reserve drain and independently
operated R16 remain open. Backups are plaintext local research files; secret
memory and traffic analysis are not hardened. Passing tests, genuine receipts
and shared-model/platform/host AI review are not external expert audit or proof
of cryptographic correctness, anonymity or production safety.
