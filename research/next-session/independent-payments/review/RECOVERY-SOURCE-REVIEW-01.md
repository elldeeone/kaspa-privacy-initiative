# Recovery source and execution-boundary review

Source ACK for the root-authorized public preparation/cold build scopes.
Actual build/retrieval results and publication review remain separate gates.
No main backup, private witness, real funding or live-state authority was read
or granted by this review.

## Cold software

The reviewed launcher `run_clean_build.py`, SHA256
`3954b44bf8fa385d7eef1fbf08bd5886be13fb869022f93f1cda2c7d3e63d405`,
mounts only an owned tree reconstructed from authenticated inventory entries.
The source bundle itself is absent from compilation. Cargo invocation is fixed,
network unshared, Cargo home/target initially empty and original source/cache/
target paths absent. Installed compiler/toolchain and system OS remain trusted.
Exact selected ELF comparison determines interchangeability; mismatch cannot
select or authorize replacement software.

Two boundaries were identified before build:

1. Verifying only listed bundle files does not authenticate unlisted Cargo
   configuration/build scripts/imports. Fixed restore copies only rehashed
   inventory entries into a fresh tree; the launcher uses only that tree.
2. The new two-pass restore reused a one-shot forbidden-input iterator. After
   the real verify pass, a same-length public source could be replaced by a
   declared forbidden hardlink; its bytes were read before digest rejection.
   [Pre-fix result02](COLD-RESTORE-ITERATOR-02.json) records one **public sentinel**
   read against source `467e8050...`. Different-length calibration01 correctly
   rejected at length first and is not counted as a reproduction.

The fix materializes the iterator once before both passes. Independent
[post-fix source](cold_restore_swap.py) and
[result03](COLD-RESTORE-ITERATOR-03.json) bind current source
`1cb6e539e703bd382f18be0a8771111cdf71652514a25625afa5245b47153a64`:
the same generator/hardlink swap rejects `public-private-inode-alias` with zero
sentinel reads. No actual private data was used in either control.

The reconciliation module is a strict join contract with selected-adapter/
validating-node premises, not a live KPX4 adapter. Its actual synthetic canary
must retain backing/currentness/spend authorization false. Fixture flags,
nonces, hashes and empty address queries cannot prove live consensus. Missing,
pruned, stale, changed-head or reorg evidence must halt; a future broadcaster
must recheck the exact head immediately before submission.

## Public transport preparation

Reviewed `poc/recovery-distribution` sources:

| File | SHA256 |
| --- | --- |
| `prepare.py` | `c928ad6545a77fbfb829994e7d52ab2c7ae443987104ed54d1547b697aac4427` |
| `public_fetch.py` | `37f1a3aa6a7b0c9e4f5363ffb15f2deebde087295c49b60d1cd9b2b9f6eb32ae` |
| `trusted_util.py` | `78633b9e62a57796d609b600139cea77f4e1866ec362aa5bdd2588516baad9a6` |
| `retrieve.py` | `e7b3f56b404fa73a6a27a4add7102c604ad2c814b69143406c6a02f007a6abcb` |

The preparation path validates the external selection and four small objects
before PK packing/copying. Whole PK and chunk identities remain externally
anchored; vendored ba6/c713 transport code is fixed. Tuple-once forbidden inputs,
metadata-before-open, owned-byte verification, exact lengths, finite inventories
and DO_NOT_FUND notice remain present. Raw main history/owner data is not part
of its fixed source input set.

Fetch enforces system TLS and selected host/scheme on each redirect, bounded
exact streaming/SHA and no-clobber atomic publication using parent FDs.
Redirect queries never enter receipts and failures use fixed categories.
Downloaded sources cannot choose software or financial authority. Negative
controls and the exact public material scan remain required before upload.
Several URLs under one administrator are one control domain; genuine separate
operator failure/retention and live currentness remain unresolved until actual
evidence establishes them.
