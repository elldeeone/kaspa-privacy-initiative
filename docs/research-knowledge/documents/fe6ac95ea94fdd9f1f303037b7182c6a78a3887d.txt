# Real TRANSFER receipt and current-spentness runtime review

Date: 2026-10-18. Separate AI reviewer: `/root/crypto_composition_review`.

**PASS for the bounded two-receipt CREDIT → TRANSFER integration and repeated-transfer rejection.** I reverified both actual receipts and current synthetic state using public data only, independently reproduced both published history reports in filesystem/network isolation, and confirmed that replay of the real TRANSFER against its still-allowed old anchor rejects specifically because its nullifiers are already spent.

This is same-model/platform/host/backend CPU/runtime review, not external audit, independent proof-system assurance, a proved outer transition, native settlement or independently operated recovery. Bob's isolated secret-dependent restore is supplied author-run evidence, not a backup-dependent run by this reviewer. No witness/backup was read or copied and no GPU operation was used.

## Frozen public inputs

Fifteen public files were frozen under `transfer-runtime-inputs`, including the two retained receipts, TRANSFER public intent/auth/journal/case metadata, creator proof/CPU reports, both complete histories/public verification reports and both bounded isolated-Bob restore reports. Exact hashes/lengths are in `manifest.json`.

```text
Wallet image:
  7461de1c1231e61823431d4800d70f1d8378cf7722b195e82321a028151b2ade
TRANSFER receipt SHA256:
  85f1b62ffbbb3ad1f97df28fa1cb07a36a6418f55d9ef6e9d5be408e57995964
TRANSFER receipt bytes: 223684
TRANSFER journal SHA256:
  1e9dc3c5e4ce746395a81367007b22668d0158faf5c3c48fb6a629a2a1d0e420
Canonical CREDIT → TRANSFER history SHA256:
  09bf10cd181357d636ae26d1de9d62ad9ee8396773fdd5502dc60367a60b625d
Same history plus repeated TRANSFER SHA256:
  3f999fcc17a175e5c1f883864af99cafc3432bd2bf975d6dfb587f61a615e500
Reviewed canonical-profile host binary SHA256:
  a7bcf2acb7a8c31eeec1765417d5a7dc2948d6e36ec351926f83e9948a9258e5
```

The author's proof report records 2489.54322609 seconds, 1416 segments and 603,987,630 user cycles. Those are retained producer measurements, not reviewer GPU measurements. The separate CPU report identifies the same receipt/image/journal, successful saved-receipt verification, empty assumptions and 11 rejected proof mutations.

## Independent public-only runtime checks

The already frozen canonical-profile verifier binary was executed under `bwrap --unshare-all`, with read-only public history/receipts/binary/system libraries and an empty writable report directory. Network was unshared, stdin was `/dev/null`, and no backup or witness was mounted. For each history, the report output matched the supplied public report **exactly**. Reviewer outputs are under `transfer-public-runtime`.

| History | Accepted | Rejected | Cursor | Nullifiers | Leaves | Private / reserve |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CREDIT → TRANSFER | 2 | 0 | 2 | 4 | 4 | 1000 / 1000 |
| CREDIT → TRANSFER → repeated TRANSFER | 2 | 1 | 3 | 4 | 4 | 1000 / 1000 |

Both retain three allowed anchors, pending zero and no exit/fee liability. The rejected replay creates no extra output, nullifier or private entitlement; it remains represented in cursor/activity.

I also executed `transfer_runtime_probe.rs`, which compiles the frozen reviewed state/fixture modules and canonical receipt loader/verifier against existing local SDK libraries. It reads only the frozen public files and confirms:

1. The two real receipts are admitted by actual SDK verification and the reviewed state adapter.
2. The TRANSFER receipt uses the canonical saved-receipt encoding and matches the complete public 229-byte journal.
3. Its original membership anchor is **still allowed**, and differs from the new current root after TRANSFER.
4. Applying that same valid TRANSFER again returns exactly `already spent nullifier`.
5. The rejected replay preserves all economic bytes while advancing cursor two → three.

The resulting state commitments match both retained public histories:

```text
After first TRANSFER:
  3161ea8cf1b098b9217f890236d3a784849d69fffbc228378b21db6053a0b10c
After rejected repeated TRANSFER:
  c6bd748932409b6eb193c24368a9ea35da4106ac25b4ccb8e4195f0daa749ffa
```

This directly exercises the current-spentness distinction: a valid proof on an old accepted membership root does not reset consumption. The synthetic reserve remains unchanged. Probe results are retained in `transfer-runtime-results.json`.

## Supplied own-Bob restore evidence

The two author-run isolated restore reports use the same canonical verifier binary and identify the respective exact history/state commitments above. Each reports one external spendable note totaling 600 synthetic sompi, zero internal notes, no other actor backup or original proving-witness mount, and network isolation. The duplicate history has three records but only two unique receipt copies, confirming the W5 runner fix on this larger public history.

Those reports are consistent with the reviewed both-scope scanner, unique-key inventory, replay-before-scan boundary and prepared transfer. They support Bob's local own-backup receipt/scan recovery for this fixture. I inspected only the designated bounded public reports; I did not read either isolated work directory or any backup/key/witness.

## Findings and remaining limits

No new failure or source defect emerged from these checks. W5/W6 remain closed for the reviewed helper/canonical host profile; W3 remains the explicitly documented nonblocking typed-helper precondition. Core/guest source remains the earlier reviewed frozen relation; these tests do not replace cryptographic review or prove that every possible witness/receipt is handled correctly.

The real Bob EXIT receipt, three-receipt adversarial/restore exercise, Alice restored-spend proof, final four-receipt reconciliation and final isolated restore evidence remain pending. The result here is two-receipt offline integration and one actual stale-anchor replay control, not full P2/P3/P4/P5 completion.

Synthetic policy/deposit/history origin is still locally trusted. No native deposit authority, canonical Kaspa order, refund/payout, reserve drain, native R16, independent operator or external audit is established. All reviewer writes stayed in this task folder; no repository edits, wallets, funding/broadcasts, infrastructure changes, commits or pushes occurred.
