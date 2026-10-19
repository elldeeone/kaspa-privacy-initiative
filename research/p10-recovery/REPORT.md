# P10: independent wallet recovery, 2026-10-19

**The published instance is not reproducibly recoverable from the public artifacts located in this investigation. Its exact public Groth16 proving parameters are missing from the checked distribution channels.** Public state reconstruction and existing-proof verification work. A separate fresh synthetic instance restored successfully with only Bob's backup and staged public data, producing a newly verified exit proof.

## Source and scope

Inspected upstream main [`cde2b88de3a16af401a2046bd90a124aa105418a`](https://github.com/olafweller/kaspa-privacy-initiative/tree/cde2b88de3a16af401a2046bd90a124aa105418a). P10 is open with no comments. PR51 remains open at `2525d804bbd34e8b0f4e6c38153d060f30af617c`; its `private-native`, `private-note-chain` and `private-note-wallet` paths are identical to main. [Source/status evidence](evidence/source-pins.json).

Read AGENTS, CONTRIBUTING, SECURITY-INVARIANTS, reviewer guidance, shielded-KAS priorities, RFC-0001/0002 and ADR-0014. The relevant target is I-10 and P10's clean rebuild/exit requirement, not the older finite A1 recovery trial. No upstream implementation was changed. Work is on `p10-recovery-research`; `offline-wallet` and `upstream-reproduction` retain their original heads.

## Required inventory

| Item | Expected holder / current availability |
| --- | --- |
| Owner/nullifier secret and incoming decryption secret | **Private user backup:** 32 + 32 bytes in the current raw 64-byte format, stored owner-only. Neither belongs in a public bundle. This is not a general seed/derivation backup format. |
| Native payout key | **Private user material:** retain the key/derivation controlling the chosen native recipient. The exit command needs its public x-only key; its default is a publicly known test destination. This key is separate from the 64-byte shielded backup. |
| Groth16 proving parameters | **Public artifact, missing distribution:** 156,439,536 bytes, SHA256 `812b3bda0ec5f9b0c17fc1d530e49fc21defc9dcc5ea9c70a133ca62fec31e99`. Required to create a fresh proof; a verification key or an existing proof cannot substitute. Setup randomness/toxic waste is not recovery material. |
| Verifier, protocol identity and encodings | **Public:** pinned VK `d3c179aae5c2c6c013b1de1da5ad4412e4b2c8bae7288c0b9d85e0c986b5a3ec`, domain/version, circuit, source and Cargo locks are retained in Git. |
| Commitments and ciphertexts | **Public:** ordered leaves and complete encrypted delivery records are present in the published synthetic inputs/state. The owner decrypts note contents locally and checks ownership and commitment. No Alice secret is needed. |
| Membership witnesses and spentness | Paths are reconstructed locally from the ordered leaves; nullifiers, permitted anchors and current ledger state must be available. They cannot be reconstructed from a root alone. The fixture has four leaves and a single 400M-sompi Bob note. |
| Economic/native state and history | Public reserve/deposit/exit/permission data and canonical transition preimages are retained for this **synthetic** lifecycle. `bob-public` reconstructs its pre-exit state without an operator database. General accepted-L1 history, pruning/archives and reorg recovery are not supplied by this result. |
| Software and trusted inputs | Public source builds locally. Independently pin the software, parameter-file hash, VK/domain and accepted current state/lineage. `bob-exit` checks accounting and the supplied state; it does not independently authenticate a canonical L1 checkpoint. |

Primary source: [backup/discovery](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/poc/private-note-wallet/src/wallet.rs#L38-L108), [parameter deserialization/VK check](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/poc/private-note-wallet/src/wallet.rs#L203-L229), [latest `bob-exit`](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/poc/private-native/host/src/main.rs#L421-L480), [public replay command](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/poc/private-native/host/src/main.rs#L525-L530), [required retention/reorg limits](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/docs/rfc/0002-shielded-payment.md#L195-L221).

## Observed results

1. **Published public state works:** in a clean namespace, unchanged `bob-public` reproduced `credit-transfer.state.bin` byte-for-byte, SHA256 `9f90a7662c11a50c02367a2b99a86a8bc0c052e902f383d95b63d87c88276f69`. The archived Bob exit also passed a separate public-only verifier process, with the existing upstream replay and mutation controls.
2. **Fresh published-instance proving is blocked:** `bob-exit` fails reading the absent parameter file before backup decoding/discovery. Supplying `vk.bin` instead fails the expected full-file hash check. These precondition probes use a fresh placeholder backup, **not the original Bob backup**; they do not claim to restore that user.
3. **Public availability:** no location for the exact parameters was found in tracked files, six checked public archives, releases, all three current Actions artifacts or inspected added GHCR workload layers. The docs explicitly say the parameters remain local. The full base-image filesystem was not downloaded; its build source was inspected. [Channel evidence and exact queries](ARTIFACT-AVAILABILITY.md).
4. **Fresh synthetic control works:** unchanged `private-note-chain-host generate` created a new setup; `restore` then received only Bob's backup plus parameters, public pre-exit state and `exit.json` (the older command's public statement template). Isolated restore took **39.18s**, generated different proof bytes for the same statement/nullifier, and checked admission against the supplied current state. A second unchanged wallet CLI verified the new exit using **only public operations and VK**, without a backup or proving parameters. [Runtime result](evidence/runtime-result.json), [restore report](evidence/synthetic-restore-report.json), [public verification](evidence/synthetic-public/separate-verification.json).
5. **That is a different instance:** synthetic VK `635e6757a1f83b010a7403435817e898ea5a77f42e9b5873f7a43192985ddaf2`; parameter SHA256 `32023e7121dad8e41d5c90c483b0861edd3aec2a5eef559c757e0cf9b6cf7d1c`. The unchanged latest `bob-exit` rejects these parameters. No pin was weakened. The generic older restore checks its independently supplied VK but only records the full parameter hash; the latest CLI additionally pins that hash. [Older restore source](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/poc/private-note-chain/host/src/main.rs#L432-L484).

Bubblewrap unshared mount, PID, network and other namespaces. Recovery had no source checkout or generation-directory mount; only its four allowlisted inputs, built software and system runtime were accessible. Its PID namespace contained two processes and only loopback networking. This is local OS isolation, not a second physical machine. [Mount/input inventory](evidence/recovery-mount-inventory.json), [namespace audit](evidence/synthetic-recovery-namespace-audit.stdout.log), [all commands/exit statuses](evidence/isolated-runs.json).

## Reproduce

Requires Linux user namespaces, `bwrap`, Rust 1.95.0 and ordinary native Rust build prerequisites. Upstream documents Rust 1.91.0; this investigation used 1.95.0 with unchanged lockfiles. Builds may fetch dependencies; runtime namespaces have no external network. Start from the repository root:

```bash
p10_task=$(mktemp -d /tmp/kpi-p10-XXXXXX)
mkdir "$p10_task/source"
git archive cde2b88de3a16af401a2046bd90a124aa105418a | tar -x -C "$p10_task/source"
export CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR="$p10_task/target"
cargo +1.95.0 build --locked --release \
  --manifest-path "$p10_task/source/poc/private-native/Cargo.toml" --bin kpi-private-native-host
cargo +1.95.0 build --locked --release \
  --manifest-path "$p10_task/source/poc/private-note-chain/Cargo.toml" --bin kpi-private-note-chain-host
cargo +1.95.0 build --locked --release \
  --manifest-path "$p10_task/source/poc/private-note-wallet/Cargo.toml" --features tn10-rehearsal
python3 research/p10-recovery/run_isolated.py "$p10_task/source" \
  "$p10_task/target/release" "$p10_task/run" "$p10_task/evidence"
```

This deliberately creates a **new synthetic identity**, not the missing published setup. No pre-existing ignored operator files are read. The harness exports only public proofs/reports; private synthetic backups remain in its temporary private work directory.

To reverify the retained synthetic exit without generating parameters or accessing backups, use the wallet binary built above and a disposable public-data copy:

```bash
mkdir "$p10_task/check"
cp research/p10-recovery/evidence/synthetic-public/* "$p10_task/check/"
RAYON_NUM_THREADS=4 "$p10_task/target/release/kpi-private-note-wallet" verify \
  "$p10_task/check" 635e6757a1f83b010a7403435817e898ea5a77f42e9b5873f7a43192985ddaf2
```

## Smallest gap and limits

**Publish the existing parameter bytes at a durable public URL, with size, SHA256 and VK binding in a small recovery manifest.** Then repeat the latest `bob-exit` in isolation using a legitimate owner's backup and the public bundle. Publishing secrets, inventing a replacement setup, changing verifier pins or building new recovery infrastructure is unnecessary for this first gap. [Unposted P10 draft](P10-COMMENT.md).

The synthetic public bundle was staged locally, not proven independently distributed. Its snapshot/lineage is trusted as a synthetic fixture. Neither run establishes canonical L1 acceptance, permission issuance, native payout, multi-user shutdown exits, pruning or reorg recovery, an audit or production safety. An archived proof verifying is not evidence of fresh proving capability. The isolation/allowlist review found no mount exposing original operator files or another user's backup; cryptography and protocol code remain unchanged. No real funds, broadcast, paid service, commit, push, merge or upstream posting occurred.
