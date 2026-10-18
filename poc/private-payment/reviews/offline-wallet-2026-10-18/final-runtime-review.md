# Final four-receipt offline wallet runtime review

Date: 2026-10-18. Separate AI reviewer: `/root/crypto_composition_review`.

**PASS for the bounded offline wallet lifecycle and current synthetic host admission profile.** All four retained real wallet receipts verify, the public final and mixed histories reproduce exactly in isolation, and repeated TRANSFER plus both EXITs reject on current spent nullifiers. No new implementation blocker emerged. This supports completion of this offline experiment; it does not qualify a proved outer transition, native funding/withdrawal or production safety.

This is a separate-agent review sharing the model/platform/host and verification backend. It is **not** an independent human/external cryptographic audit, independent operator recovery, or proof-system soundness certification. Reviewer execution was CPU/public-only: no GPU job, backup, original witness, `input.bin`, isolated work tree, funds or network operation was used.

## Exact reviewed inputs

`final-runtime-inputs/manifest.json` freezes 117 public evidence/source files with SHA256 and lengths. Its SHA256 is:

```text
1d1a94ef176cceeee42a4681e974ac662b785fd3aa0e9dc5a2d540537d6b4295
```

`final-runtime-review-evidence.json` identifies reviewer scripts, compiled probe/link artifacts and independent runtime outputs. The frozen final code matches the modules used by the probe. Core codec/relation and guest hashes remain:

```text
wallet-core/src/codec.rs
  376a20eeed3c1e6fac4a4ac38adb5af787778c68550edbd7bb93536492089a0b
wallet-core/src/lib.rs
  09a984d88b52f7c4202e33a928613c74f4fc90bc2bfb419cc81842ebb5143cba
wallet-guest/src/main.rs
  c88cc7db59fb1b2307c5f7eebec22326dcaa2c181934371c73efc7ec10f31a2d
Wallet image
  7461de1c1231e61823431d4800d70f1d8378cf7722b195e82321a028151b2ade
Wrapped program SHA256
  3887533bb6855403ee137799b63b95b68e29e6e932c758bc721a6515a93226a0
Reviewed public-verifier/restore-host binary SHA256
  a7bcf2acb7a8c31eeec1765417d5a7dc2948d6e36ec351926f83e9948a9258e5
Pinned verifier-parameter digest
  ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013
```

The provenance explicitly distinguishes the original proving client (`0d1763565d19504c2b0308749bd428bbd22602ffa2185abae95f17c7a475a719`) from the later canonical-profile host. I checked retained source/provenance hashes; no byte-identical host-client claim is inferred. The earlier same-toolchain clean-target guest reproduction remains supporting evidence, not an independent compiler/toolchain audit.

## Four genuine receipts

Each is 223,684 bytes. Independently loaded canonical envelopes, actual SDK receipt verification, the exact image/parameters and complete 229-byte public journals all pass. Final history I/auth bytes exactly match the frozen public case files.

| Case | Receipt SHA256 | Producer seconds / segments |
| --- | --- | ---: |
| CREDIT | `2f43a8b38919d68a53500911e8eac36d09ea187b4cb08ddcece32328dab81442` | 1210.17 / 691 |
| TRANSFER | `85f1b62ffbbb3ad1f97df28fa1cb07a36a6418f55d9ef6e9d5be408e57995964` | 2489.54 / 1416 |
| Bob EXIT | `5401cbfc16334cebb0d85607d56a92c9402f804922767bd0e354953ebcc7cabc` | 1777.73 / 1012 |
| Restored Alice EXIT | `1e12d4b54d023d712360b958b505c46471f3843cdf17cd3454802b1eeec66c1b` | 1831.01 / 1046 |

Timings/segment counts and each producer CPU report's 11 rejected mutations are supplied measurements. My separate CPU reruns verify the receipts and admission behavior; I did not reproduce proving. Saved reports identify development mode disabled and no unresolved assumptions, consistent with the reviewed succinct-only verifier. Four-case Python intent roundtrips/journals and libsodium CREDIT-signature verification were also rerun from copied public tooling and reproduced the supplied report exactly.

## Independent isolated public replay

For both histories, I ran the frozen CLI under `bwrap --unshare-all`, mounting only read-only public history, receipt directory, binary/system libraries and an empty writable report directory. Stdin was `/dev/null`; neither backups nor witnesses were mounted. Output JSON matched each supplied public verification report exactly.

| History | Accepted / rejected | Cursor | Private / unpaid exits / reserve | Nullifiers / leaves |
| --- | ---: | ---: | ---: | ---: |
| Final CREDIT → TRANSFER → Bob EXIT → restored Alice EXIT | 4 / 0 | 4 | 0 / 1000 / 1000 | 8 / 4 |
| CREDIT → false proof → TRANSFER → Bob EXIT | 3 / 1 | 4 | 400 / 600 / 1000 | 6 / 4 |

Amounts are **synthetic integer sompi counters**, not funded KAS balances. Both have pending/fees zero and three allowed anchors. Final state has two unpaid exit claims. The `exit_only` operations add no output leaves.

```text
Final history SHA256
  0b37a8e3758002235d2c2f9c39cdfaaa56338d3655d7d79b855278caa068009a
Final state commitment
  b36347c3ccc5329242efcaada34090cc7a8564b0f92d69971151f09cb0d3ce21
Mixed history SHA256
  df4b77d9c4cbb6c45cac3d2405e4ae7c9a8a6133963008532bdc02a143c34979
Mixed state commitment
  96316d7e4760bb8682a37072bb19fdf2b6513b37ad076cb18b126d37082628d8
```

The independently compiled frozen-module probe additionally confirms:

1. TRANSFER, Bob EXIT and restored Alice EXIT each still reference an allowed anchor at final state. Reapplying any returns exactly `already spent nullifier`, preserves economic bytes and advances cursor by one.
2. The mixed false receipt actually fails cryptographic verification, creates no economic effect, and advances cursor. Subsequent genuine operations succeed; the manually replayed full state equals history replay.
3. Checked final reconciliation is private 0 + unpaid 1000 = reserve 1000, with no payout/reserve release.

Relevant frozen source: `wallet-host/src/state.rs:100` validates policy/root/expiry/current nullifiers, `:184` reconciles liabilities, `:196` applies atomically; `history.rs:39` replays the pinned complete history; `proof.rs:65` enforces canonical receipt bytes and `:74` verifies the complete expected journal/image. Independent outputs are `final-public-runtime/` and `final-runtime-results.json`.

## Restore and adversarial evidence

The supplied three-receipt exercise passed 14 negative admissions, seven history/backup rejection cases and 12 capacity boundary checks. Source/report agree on all eight immutable-policy mutations, an orphaned anchor, duplicate CREDIT/spend/exit, actual receipt expiry, inclusive expiry/checked cursor overflow, and a second valid Ed25519 signature on the same intent rejected by the receipt's complete journal binding. Capacity checks exercise the arithmetic interface; no full 2^32-leaf tree was materialized.

The same-length ciphertext alteration rejects under the original externally trusted pin. Deliberately replacing that pin trusts another synthetic branch: only CREDIT is accepted, Alice retains 1000 and Bob receives zero. This is correct available-invalid no-op behavior, **not authentication of canonical Kaspa history**. Missing/stale history, unavailable receipts and duplicate decoded backup keys/hex aliases remain errors before scanning.

`recovery.rs:313` constructs the fourth witness using Alice's internal change returned by replay/scan, plus a new dummy, without reading the original proving witness. The actual fourth receipt now accepts. Four final author-run isolation reports identify the canonical host, own-backup-only mounts, no other actor backup/original witnesses, and network isolation: Bob recovers 600 before his exit and zero after; Alice recovers internal 400 after Bob's exit and zero after her restored exit. Their history/state identities match the public replay. These are inspected **author-run secret-dependent evidence**; I did not read backups or independently repeat those private restore runs. The joint final driver also reports both actors zero and three rejected replays.

## Finding disposition and limits

W1 replay-before-scan trust boundary, W2 duplicate-key inventory, W4 replacement-pin regression, W5 unique receipt-copy handling and W6 canonical receipt envelope remain closed for this reviewed offline profile. Earlier counterexamples and prior-version reports stay preserved as historical evidence. W3 remains the documented nonblocking typed `Intent::journal` shape precondition; decoded untrusted guest/host paths validate shape first. No new finding was observed in this final runtime pass.

C1–C4 have the previously reviewed offline design corrections and tested relation/host effects. The full proved outer must still implement immutable policy, actual image/runtime binding and state transitions; host comparisons do not establish that proof. Synthetic credit authority, history origin/order/pin freshness and reserve are locally trusted. Native registration/bootstrap, full R13 total transition, canonical Kaspa/reorg history, native deposits/refunds/payouts/paid markers, independently operated R16 and external audit remain open. Missing/unparseable data can halt this host harness. Incoming recovery does not establish outgoing audit-history recovery or anonymity/timing protection.

The frozen WALLET.md opening still describes the proof/restore runs as pending; the author has subsequently updated that status without changing core/guest/host code. This snapshot deliberately retains the exact reviewed bytes.

All reviewer writes stayed under this review task. No repository mutation, wallet creation, funding/broadcast, infrastructure change, commit or push occurred.
