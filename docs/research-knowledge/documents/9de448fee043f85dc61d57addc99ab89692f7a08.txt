# Cold software recovery and accepted-state reconciliation

Base: `5aaf99532d8714e510d421102df719f60f54d073`. ADR0057 and I-6/I-9/I-10/I-11 remain authoritative. No existing package, relation, key or source pin changes.

## Decisive experiments

1. Copy the exact reviewed selected compact prover sources and Cargo.lock into a public distribution bundle, with every locked crates.io source vendored. Inventory every file, selected output ELF, compiler/Cargo/toolchain and trusted system dependencies. The bundle root is independently authenticated; a downloaded manifest cannot select its own authority or executable.
2. Build offline from a fresh writable source copy, empty CARGO_HOME and empty target in an unshared network/filesystem namespace. Original repository, registry cache, old target, operator data, backups and PKs are absent. Only the authenticated bundle, a selected existing Rust toolchain and system OS are mounted. This is a cold artifact build from vendored dependencies, not a newly downloaded compiler or an independently operated machine.
3. Compare the rebuilt ELF with the already selected 1662fcd9 release. Exact bytes are required to call it an interchangeable selected executable. A mismatch remains a recorded result, never automatic new software authority. The original selected executable can separately be restored from authenticated public release bytes without executing untrusted downloads.
4. In a separate minimal namespace use only PUBLIC_SYNTHETIC_DO_NOT_FUND canary material to exercise receipt recognition and public proof verification. No main backup, private workload witness, PK/proving operation or funding is authorized here. Recognition, public verification and supplied-context native checks do not demonstrate accepted backing/current spend readiness.

## Package API

`inventory(root, typed_paths, external_release_selection)` emits strict relative-path `{kind,path,bytes,sha256}` entries and a canonical root. No commands/import paths/callbacks are read from a mirror. `verify_bundle(root, expected_inventory_sha256, backup_metadata_only=...)` verifies exact owned public files before use, rejects traversal/symlink/duplicate/hardlink aliases, and returns only fixed categories on error. A trusted fixed launcher selects which verified files may be built/executed. Downloaded executable hashes must match externally installed authority.

Cargo dependencies are copied from the current local registry by Cargo vendor, with upstream Cargo.lock registry checksums retained and checked. The result claims no network acquisition. Exact sources, versions, checksums, license files and compiler build identity are retained. OS loader/libc/linker/compiler trust remains explicit; inventory is not proof against a malicious compiler or host writer.

## Accepted-state seam

Existing compact history is explicitly SYNTHETIC_NATIVE_VALID_CONTEXTS_NOT_ACCEPTED. There is no selected KPX4 accepted-chain network adapter. The existing live adapter gates KPX3 and cannot be relabelled. Therefore the actual canary will always return `accepted_chain_backing_verified=false`, `currentness_verified=false`, and `spend_authorized=false`.

New reconciliation code checks a strict public selected-node observation separately from immutable retained bytes. It requires the same independently pinned network/genesis/D/founding identity and locally replayed ordered transaction IDs/head state; a nonce from the current acquisition session; a complete finite accepted frontier and accepting-block contexts; the exact archived prefix followed by every discovered relevant successor; explicit removals/reorg events; no pruning/missing/gaps; exact current head input UTXO amount/SPK/DAA/coinbase/covenant and every historical reserve spentness query; and a post-query accepted suffix/removal sweep watching all relevant currently live points. A changed head or rollback invalidates prior witness/proof preparation. Unavailable evidence is INCOMPLETE, never zero balance. A terminal result requires validated terminal semantics and all reserve inputs absent, not an empty address query.

The pure reconciliation control receives data from a selected installed network adapter, never from capsule metadata, and states the selected-validating-node trust premise. Synthetic positive controls are explicitly labelled controlled contract fixtures; they do not activate the old owner CLI, confer accepted backing or authorize a real spend. The module has no proof, signing, broadcast or spend API. Immediately before an actual future submission the broadcaster must requery the exact UTXO and reconcile any removals/successors again. Hashes, timestamps, nonces and self-asserted fresh flags cannot independently prove consensus/finality or exclude a lying selected node.

## Controls and privacy

Test wrong root/source/crate/ELF, missing bytes, path traversal, duplicates, symlinks and declared backup hardlinks before content reads. Currentness controls cover intact stale archive, stale nonce, missing suffix, reordered prefix, reorg/removal, changed/spent head, current-query mismatch, incomplete/pruned frontier, postquery spend and terminal reserve mismatch. Public canary data is disjoint from all main notes/NFs. No actual private input or its hash/path/role map enters reports. Tests are bounded implementation evidence, not security or production qualification.
