# Current W wallet and launcher: independent source review

**Final source ACK: no blocking issue found in the owner/filesystem/READY/FD/export scope.** The trusted installed launcher closes the pre-import alias boundary that the owner module alone cannot establish. This review did not execute controls, a launcher, a prover or native validation, or read actual inventories, backups, PKs, private inputs or runtime plans.

## Bound source identity

Source freeze03: `f4f9b187e838be5a5d99a2f40bec7639451a34e3988b8b9766349fa6b1486b7f`, at `settlement-wallet/SOURCE-FREEZE-03.json`. Independent checksum verification passed all nine current files and their nine archived source copies.

| Source under `poc/shared-settlement-wallet/` | SHA256 |
| --- | --- |
| `run_owner.py` | `7db1ec4d0cdbebc9533510ac4cd80f0ef141a6a9504149b2a34e947ea721140e` |
| `owner.py` | `2c811d7d013421bea92f5d2586fa357372f587f4c0b0905418fc39f0c2dc35bd` |
| `paths.py` | `425b1b07d2840ab9d04711d157244f99b7ae7cbb90bfc38c704a0ebc205bc222` |
| `reuse.py` | `3131877bc3d9bd9b9139a06c3003ed41b2de5a718eb609feb471ccf82c70bd49` |
| `runtime.py` | `8781b01653b13627e62b89199933d2647215ef42e1f538b0502f011cdba3ea61` |
| `selected.py` | `bf12a517aa4da0e5e74bad48c2d10c472dc6cbc1d41ce3165cae17f4d4770fd1` |
| `no_append.py` | `d7cd8b6c7ba54079ddc8dfbc7fe371fcc0a50cdfd422a8985c070da4beba36e9` |
| `recovery.py` | `b9fbeaf62ae0195b97e143fe64e5739ae3a77205286902d7de59b13600175278` |
| `test_wallet.py` | `3743c07834e4ed017b85b119738f889e626b6c59920dd8e026886de3167146ee` |

## Metadata and restored-source isolation

`run_owner.py` imports only standard-library modules. Its launcher implementation is trusted installed code; a downloaded inventory does not authenticate itself. The caller must independently select its SHA.

Before public content reads, the launcher checks the single original backup's regular-file/mode metadata and compares its device/inode against the inventory, public inputs and optional PK. It authenticates inventory bytes only after checking that inventory is not the backup. `verified_entries` then checks **every** listed member's path, type, device/inode and size before the first listed member is read or hashed. The complete iterator is materialized once. Each source is checked again before snapshotting and its bytes/hash authenticated before use.

Literal `..` components and symlink components reject. Outside-Git checks probe the existing backup's parent directory and the fresh controller's closest existing directory with clean-environment Git checks. The internal owner guard repeats metadata checks, including all seven new execution modules and reused dependencies. Since owner imports its installed modules before that internal guard, the outer launcher remains part of the required boundary.

`mapping()` defines exactly 24 public runtime/source/SDK mounts. Namespace execution uses those restored snapshots, four explicit public inputs, one readonly backup, one output directory, and a readonly PK only for preparation. It mounts no whole repository, backup parent, controller, test module, fixture generator or other owner input. Ordinary pinned executable files are used; no special executable FD or old-module global mutation is introduced. The namespace clears its environment, unshares networking and uses explicit resource limits.

## Private ordering and output boundary

The preparation path validates complete public replay first, starts the selected4ef prover with an empty inherited witness pipe, matches the whole selected role/domain/manifest/VK/build READY record, and only then reads its original backup. Selection binds the new d55 domain, d6f manifest, 6c PK and 074c VK. Candidate preparation and exact stable quote precede the sole private-witness serialization. READY, material or quote failure reaches cleanup without a witness write. Constructor failure closes both descriptors; normal failure cleanup closes the pipe and terminates/waits for an outstanding worker.

Recognition-only recovery deliberately needs no PK or worker. It still requires complete public replay before backup recognition and claims neither witness/spend authority nor currentness. This exception is explicit in source and design.

Recovery counts all recognized historical and actionable claims, retaining accepted duplicate-index claims rather than using normal-credit accounting to hide them. Exported summaries contain counts and public transaction/proof/authorization/quote data; they do not serialize seed, receipts, spend/NF keys, Candidate witnesses, owner maps or private-input fingerprints. Private controller/quote alternatives are outside the publication boundary.

Historical direct-action budgets accept a canonical u16 and rely on fresh native Full validation, rather than rejecting a valid foreign transition because of the wallet's optimizer preference. New own preparation uses1500; the aggregate selection remains1600. This source review does not establish an actual fee quote or native success.

Cleanup records manager state while leaving a missing kernel process observation explicitly unknown. The source does not turn that absence into zero processes. Trusted-host/source-inode immutability and independently installed selection remain premises. Genuine proof/native lifecycle, chain backing/currentness, availability and cryptographic correctness require their separate evidence.
