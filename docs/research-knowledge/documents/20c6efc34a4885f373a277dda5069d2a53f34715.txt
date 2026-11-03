# Duplicate-history runner closure and receipt encoding finding

Date: 2026-10-18. Separate AI reviewer: `/root/crypto_composition_review`.

**W5 is closed for the reviewed helper revision. W6 is a reproduced P3 canonical-profile/evidence-integrity issue, with a focused host-only fix agreed but not yet reviewed here. No theft, inflation or double-credit bypass was demonstrated.**

This remains same-model/platform/host/backend research review. No private inputs/backups, GPU, native transactions, external audit or independent-operator claim is involved.

## Frozen review identities

`duplicate-receipt-inputs/manifest.json` pins the revised helper, unchanged receipt loader/verifier source and three supplied public reports.

```text
c60488e3bc328e643ae97463d894e985ac10094ea3773379a3212d4a32aa2494  check_isolated_restore.py
d45d7db3b3a1f7dc573ac3fa57c0ede7a7143692e2233ca16367e3935fac7794  wallet-host/src/history.rs
757fcbef121e796f84e2eeba111919762a05688a4eb49b0285fb9b63d71e8c71  wallet-host/src/proof.rs
05a9b2b40f96f56c4ba84b6a95a230499e7a7fdf6255daccf65da9ee45eb9a2e  credit-duplicate-history.json
7fd6a5a4852fa6c3b45ff45766e5723c619673a0a8b4d35c9ff495291466fe3b  credit-duplicate-public-verification.json
c93ee3f58cf188f0e1270f4b1468f89fe379ce1ff6954e36c69df0b73c5db409  isolated-credit-duplicate-alice/report.json
```

Source paths are under `poc/private-payment/`. Full source and bounded report copies remain in the review folder; no backup or witness was copied.

## W5 closure

The helper now keeps a name-to-digest table, copies each unique proof name once, requires repeated names to declare the identical receipt digest, and checks copied bytes against that digest. It reports `historyRecords` separately from unique `receiptCopies`. The original unconditional directory-creation failure for legitimate repeated names is removed without weakening receipt identity checks.

The author-run own-backup restore report records two history entries, one receipt copy, two recovered notes totaling 1000 synthetic sompi and one internal note. It identifies the same state commitment as the public verification report:

```text
5405d0e896ec399e940e1f8a20dab849bfb0162cf9f71020ffa68405b487ecc2
```

I independently reran `verify-history` against this duplicate history in a namespace with only the public verifier/history/receipt/system libraries mounted, network unshared and no backups/witnesses. The output exactly matched: one accepted CREDIT, one rejected duplicate, cursor two, private/reserve 1000, two leaves/nullifiers and no exit/fee liability. Output is retained in `duplicate-public-runtime/verification.json`.

Thus the repeated operation remains represented in activity/order while creating no second entitlement. The secret-dependent isolated restore is supplied author-run evidence, not a second backup-dependent run by this reviewer.

## W6: top-level bincode accepts trailing receipt aliases

**Location:** `history.rs`:27–37 and saved-receipt verify mode in `proof.rs`; upstream `bincode-1.3.3/src/lib.rs`:177–185.

The top-level `bincode::deserialize` function explicitly configures `allow_trailing_bytes`. Both host file-loading paths call it directly. The actual selected receipt writer is deterministic for the tested original object, but its decoder accepts the same serialized receipt followed by unrelated bytes.

**Concrete public-receipt experiment:** `receipt_codec_probe.rs` reads only the frozen genuine CREDIT receipt, public intent and public auth. It appends (a) one zero byte, (b) 32 bytes of 0xff and (c) an entire second copy of the receipt. For all three:

1. Loading against the original pinned receipt digest fails, as required.
2. Loading against the deliberately recomputed alias digest succeeds through the current real `history::load_receipt`.
3. Actual CPU receipt verification and first-credit admission still pass.
4. Re-serialization removes the appended bytes and exactly reproduces the original 223,684-byte receipt.
5. Logical state/activity commitment equals the original typed receipt's commitment, because state uses canonical re-serialization.

Results are in `receipt-codec-results.json`; the appended public artifacts are under `receipt-codec-probe`. Hashes:

```text
2f43a8b38919d68a53500911e8eac36d09ea187b4cb08ddcece32328dab81442  original
82ba83ab193f8b2f67d7f3655c5efe81a767eab0f215389d5719374b5905c219  original + 1 byte
7c7eb119b2ac918b0e241bfc42a0de89d21a92dfbc7e7d50b7008d7089340d5d  original + 32 bytes
59ebab3111cd8668a0333fef93a5218b844c31cbadb69205060fa676cfb754aa  original + another receipt
```

This demonstrates trailing-data encoding aliases, not an exhaustive search over every possible alternate SDK/bincode representation. It does not forge a receipt, ignore the originally pinned raw hash, create new value, reset current spentness or provide a valid proof for a changed public intent. To admit the alias in this experiment, the test deliberately supplied its new expected raw digest. An adversary unable to replace the external history/receipt pin cannot silently substitute it for the frozen original.

## Recommended exact resolution

The bounded offline profile should require one canonical saved-receipt encoding. Add a shared host `decode_receipt(raw)` that deserializes with the existing selected bincode configuration, requires `bincode::serialize(&receipt)? == raw`, and returns the typed receipt. Route **both** history loading and saved-receipt verification through it. Current canonical receipts should pass byte-for-byte; appended aliases should fail before ordinary receipt verification/admission. This leaves the core/guest and program image unchanged.

Using `DefaultOptions::new().reject_trailing_bytes()` without also selecting the existing fixed-int configuration would change decoding semantics; avoid that accidental format switch. Roundtrip equality directly pins the current writer's canonical byte language and also rejects any normalization aliases encountered by its decoder.

Required focused regression: original real receipt accepted; each retained alias rejected by both loader paths; original-pin hash checks still enforced; ordinary public CREDIT replay/duplicate controls remain unchanged. Record canonical-format failure as a host-profile rejection/unavailable-envelope result consistent with the harness's declared language. This does not implement total malformed-proof R13 classification.

The author has agreed to this shared host-only decoder and will provide the fixed source for focused review. W6 is therefore **open pending reviewed code and regression evidence** in this report. The running transfer proof and existing immutable guest are unaffected.

No repository edits, GPU work, private-input/backup access, wallet creation, funding, broadcasts, infrastructure changes, commits or pushes were performed by the reviewer.
