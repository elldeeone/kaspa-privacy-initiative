# Public verification CLI and isolated first-credit restore

Date: 2026-10-18. Separate AI reviewer: `/root/crypto_composition_review`.

**PASS for the new public verification path and the supplied first-credit restore evidence.** I independently ran the actual `verify-history` CLI in a filesystem/network namespace containing public history, the saved public receipt, the verifier binary and system libraries only. Its output exactly matched the author's public verification report. The reported Alice-only isolated restore recovered two notes totaling 1000 synthetic sompi, including one internal note, at the identical state commitment.

The reviewer did **not** read, copy or rerun any private backup/witness. The Alice restore itself is author-run evidence inspected through its bounded public reports and reviewed runner/source, not a second secret-dependent restore performed by this reviewer. Both executions use the same host/backend; neither is an independent operator, external audit or native R16 result. Transfer/exit/final restored-spend evidence is still pending.

## Frozen inputs

The three changed/helper sources and five owner-designated public reports were frozen under `isolated-credit-inputs`; their complete hashes and lengths are in `manifest.json`.

| Source | SHA-256 |
| --- | --- |
| `wallet-host/src/recovery.rs` | `c152d2cd3e5654cb1cd21d6fe37e620f5d33b89b23f2658b9c92e10442cf5a4b` |
| `wallet-host/src/main.rs` | `3deae2603108387e36124a061f22645e7f9889daf92b493264b9a542ee185be5` |
| `check_isolated_restore.py` | `b0545ed9c9c3bf3d8ffb6d6c957883a19903c1a568ea867fdb026766f3e26847` |

Paths are under `poc/private-payment/`. Relative to the previously reviewed recovery source, the only new helper reads public history, calls the existing replay function, and saves public state/count metadata. The match arm passes exactly history path, externally trusted pin, public proof directory and output path. It adds no alternative admission or key path.

Relevant runtime identities:

```text
Host binary SHA256:  73ed6c28a072332f6e53c11e63bc57c9bfec7b900923e5a39776d14e4d557aaa
History SHA256:      8e44dc3351f4f08faf187584bd8d55bd764ace8ac0047a18606c7ee84d5305c3
Receipt SHA256:      2f43a8b38919d68a53500911e8eac36d09ea187b4cb08ddcece32328dab81442
Program SHA256:      3887533bb6855403ee137799b63b95b68e29e6e932c758bc721a6515a93226a0
Wallet image:        7461de1c1231e61823431d4800d70f1d8378cf7722b195e82321a028151b2ade
State commitment:    99ed8c64e927001edf08296c04323bafaa03d391ede9efae12cb907cc51511ad
```

The actual verifier binary's hash matched the author's isolated-run report. I compared `/tmp/kpi-offline-wallet-cyuo2yo8/reproduced-program.bin` directly with the already frozen original wrapped program; the bytes and SHA-256 were identical. The author's `reproduction.json` reports a clean-target build with the same pinned toolchain/image. I verified equality of the two resulting artifacts, not a third independent compiler/toolchain rebuild.

## Public-only verification rerun

Reviewer output is retained at `public-cli-runtime/verification.json` and `public-cli-runtime/reviewer-report.json`.

The reviewer invoked the copied actual binary with `bwrap --unshare-all`, a fresh `/proc` and `/dev`, read-only system libraries, read-only public history and proof directory, and an empty writable report directory. Neither backups nor original witness/program-input files were mounted; stdin was `/dev/null` and the environment contained only PATH. No prover/GPU operation was invoked.

The CLI independently verified the saved receipt and replayed the synthetic CREDIT. Exact output matched the author's `credit-public-verification.json`:

- One admitted operation, zero rejected operations, cursor one.
- Two nullifiers, two leaves and two allowed anchors.
- Pending zero, private liabilities 1000, reserve 1000, no exit/fee liability.
- Correct actual wallet image and the state commitment above.
- Public-input-only verification and zero native transactions.

Thus the evidence archive can verify this actual receipt/current synthetic state without a private input file or backup. It still relies on the externally trusted history pin and locally trusted synthetic genesis; it is not canonical Kaspa history authentication or a proved outer transition.

## Isolated restore runner review

The runner first checks the externally supplied history pin. It creates a private 0700 work/report tree, copies the selected owner backup as a 0400 file, and mounts only that work tree and system libraries into the restore namespace. Other actor backups and original proving witnesses are not among those mounts. The environment is reduced to PATH, and `--unshare-all` includes network isolation. The source checks process success and expected restored balance before writing its bounded report.

The supplied first-credit Alice reports identify the same binary/history/state commitment as the reviewer-run public verification. They record two spendable notes/1000 synthetic sompi and one internal note. This is consistent with the two credited output slots and reviewed both-scope scanner. No native withdrawal/reserve release is asserted.

The selected-backup role is a controlled lab-input assumption: the wrapper's `ownBackupOnly` field describes its intended caller-supplied backup and mount list; it does not cryptographically prove that an arbitrary supplied backup contains only one actor's keys. The previously reviewed fixture source generates the distinct Alice/Bob backups correctly. No independent operator/host or hardened secret-storage assurance follows.

## W5 — nonblocking duplicate-record-name edge in runner

**Location:** frozen `check_isolated_restore.py`:28–32.

The runner creates the proof directory with `exist_ok=False` for every record. A complete history containing the same receipt name twice therefore aborts before replay, even if both records reference the same exact receipt hash. The reviewed history adapter intentionally supports replayed/duplicate operations by verifying and rejecting their economic effects, so the runner accepts a narrower operational set than the restore command.

This does not affect the unique-name first-credit case, produce false balances, or weaken proof verification. It is a P3 operational helper issue for later duplicate/replay histories. Minimal correction: copy each unique proof name once, require repeated names to declare the same receipt hash, and distinguish record count from unique receipt-copy count in reporting. Alternatively explicitly limit the runner to unique-name fixtures; do not advertise that as general complete-history restore. The author has been notified; this report reviews the frozen pre-fix bytes above.

## Remaining limits

This adds concrete early runtime evidence for public receipt verification and a filesystem/network-isolated own-backup scan. It does not complete the three/four-receipt lifecycle, the restored-spend proof or all pending replay/recovery controls. Same-host namespace isolation is not independent operation or protection from a compromised host/kernel.

Core/guest relation source is unchanged. External cryptographic audit, full ordinary proved outer verification, native deposit authority/bootstrap/ordering, refunds/payouts, terminal native drain and native R16 remain open. No funds, wallet creation, broadcasts, repository edits, GPU control, infrastructure changes, commits or pushes were performed by this reviewer.
