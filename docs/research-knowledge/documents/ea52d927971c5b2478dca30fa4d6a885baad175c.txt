# Current recovery composition: build qualification

Status: **build succeeded; owned service and descendants exited; no proof or protocol test authorized or executed**. This record concerns the unchanged source package accepted by the two static reviewers. A build result is not evidence that recovery, rebasing or drainage has passed.

## Identity and authorization

- Base source commit: `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`.
- Prepared source manifest: `a78c3dda3fab1d0240c987a34484b3e129ea4b3faf9e2cc18a50287462addbd5` (65 source files and three lane artifacts).
- Worktree: `/home/luke/projects/kpi-orchestration/2026-10-22/exit-recovery-review/implementation-v1/worktree`.
- Runtime lane: `/home/luke/projects/kpi-orchestration/2026-10-22/exit-recovery-review/implementation-v1`.
- Explicit parent authorization: recovery **build phase only**, 2 CPU, 12 GiB, two-hour wall budget. The concurrently allocated GPU lane has separate limits of 2 CPU, 4 GiB host memory and at most 3 GiB device memory. Neither lane may raise its limits.
- Build-only `release.json` SHA-256: `481efacfbd4756075b171289af157d6b0f4734654b24c324d9d587e44689ecea`. The frozen schema's legacy `run_authorized: true` is accompanied by `authorized_phase: build`, `proof_phase_authorized: false` and explicit build-only scope. It does not release the proof phase.

The parent accepted the frozen evaluation's terminal evidence: 1,024 seal and observer process records, public completion at 19:50:21 AEDT, successful recount and target audit, and archive-binding verification. The old service was unloaded and its cgroup absent. Its then-displayed default `ExecMainStatus=0` was not used as retained exit evidence. No correctness, seed, truth or prediction payload was read for resource qualification.

## Actual service qualification

The tiny runtime-only qualifier reused the frozen launcher's `check_preconditions`, `cgroup_gate`, `stop_owned` and `audit_owned` functions. It performed no Cargo/project/proof/GPU computation. The qualifier created a sleeping child in a separate process session, then stopped only its own UUID service and checked the child's disappearance plus final cgroup membership.

Qualification identity: `d596287971d3407a9a16a6fb3b16be0f` under the runtime lane's `qualification/` directory. Qualifier source SHA-256: `b5ddcc9972db1481632aa804f0d8ef78f0dbfefa2854421e4887aa5149e64078`. Result SHA-256: `d0b326a7d90a3eace783a21399df7a1048fbfe3d98e9bd6b0f9a1e48a1ce9233`.

Observed cgroup controls matched the frozen build envelope:

| Control | Actual value |
| --- | --- |
| `cpu.max` | `200000 100000` |
| `memory.max` | `12884901888` |
| `memory.swap.max` | `0` |
| `pids.max` | `256` |
| `RuntimeMaxUSec` | `2h` |
| `TimeoutStopUSec` | `30s` |
| `KillMode` / `SendSIGKILL` | `control-group` / `yes` |

Owned cleanup passed, including the separate-session child; no survivor or unknown-state outcome remained. This qualifies observed configuration and the exercised explicit-stop path. It does not establish a measured CPU/memory maximum under stress, an OOM result, the SIGKILL-after-grace branch, or a two-hour timer expiry. No frozen source, manifest, dependency or protocol file changed.

## Build invocation and capacity

At 20:01:32 AEDT immediately before the build: 14 logical CPUs, one-second CPU activity 0.21%, 21.17 GiB `MemAvailable`, zero recent memory PSI and approximately 279.89 GiB disk free. The check conservatively reserved the other lane's entire 4-GiB allowance in addition to this build's 12 GiB, with at least 2 GiB left over. Rust 1.95.0 was already installed.

Build service: `kpi-exit-recovery-v1-build-ef230f2607ae49ce97396208451f0dd1.service`. Output directory: runtime lane `launches/ef230f2607ae49ce97396208451f0dd1/`. It entered its own actual cgroup gate and matched the same build limits before Cargo. The frozen command is:

```sh
cargo +1.95.0 build --release --locked --offline --jobs 2 \
  --manifest-path poc/shared-pool/Cargo.toml \
  --bin kpi-two-input-wallet \
  --bin kpi-two-input-lifecycle \
  --bin kpi-two-input-recovery-race
```

The worktree and `CARGO_TARGET_DIR` are exclusive to this lane. No dependency fetch, installation, broad test, setup generation or proving command is part of this invocation. Raw command/output and launch/release/cgroup receipts remain in the private runtime directory.

## Terminal result and executable identities

The first build attempt succeeded without source edits, a dependency fetch, installation or retry. Cargo reported 7m 59s; systemd reported 8m 0.007s service runtime, exit status 0/SUCCESS, 15m 51.048s CPU and a rounded 3G cgroup memory peak with zero service swap. The highest captured exact pre-terminal `MemoryPeak` was 3,232,129,024 bytes (about 3.01 GiB); this is service/cgroup memory, not a prover RSS measurement.

The launcher's terminal receipt recorded return code 0 and a complete owned-unit cleanup audit. A fresh independent metadata check found the cgroup absent and no surviving PIDs. All 65 frozen source hashes plus three artifact hashes still matched; the detached HEAD remained the base commit and tracked core/dependency files were unchanged.

Compiler: Rust 1.95.0, commit `59807616e1fa2540724bfbac14d7976d7e4a3860`, host `x86_64-unknown-linux-gnu`, LLVM 22.1.2. Executables reside in the lane's exclusive `build-target/release/`:

| Executable | Bytes | SHA-256 |
| --- | ---: | --- |
| `kpi-two-input-wallet` | 16,072,176 | `1ee3835b1b0ed3e4c4ca0ce4f5ee1cd6f85b79d19b2cef10a7402ece42e298a3` |
| `kpi-two-input-lifecycle` | 15,396,112 | `67d54d203f5e101deae92c388e0e961132a5896e871215d5e43444343d2382bd` |
| `kpi-two-input-recovery-race` | 15,972,072 | `f174d433b8e6c383d8930dabe19a2370835a2d7c494595d40d881f4efdd9f762` |

The terminal build receipt SHA-256 is `00b354dc80bcc69335c21a3e2ea6e18f27b3329c96b6d3cdaf8f75502c91f9c8`. The runtime index (`runtime-index.json`, SHA-256 `5571a54c7c7809133d730e38ce3667c91b08dab3fa525032b44071fdc86a7b53`) binds the launch, actual cgroup, exit, stdout/stderr and post-build capacity receipts in the same launch directory. Cargo stderr SHA-256 is `146f643525ce17fc0442597db98fca8fb76cdece200b786a1f0980f118c35433`. These records establish the observed build's source/command/executable chain; no executable was run as a recovery/proof test.

The parent offered a runtime-only increase to CPUQuota 400% after this build was already terminal. No property change, restart or recompile was performed. The effective build quota remained 200% throughout; the recorded before value is `cpu.max=200000 100000`, and there is no post-change value because no change occurred. The memory/no-swap/two-hour controls and frozen bytes stayed unchanged.

## Final capacity and proof hold

Metadata-only snapshot at **2026-10-22T20:11:31.796948+11:00**: 14 logical CPUs, 0.21% busy over one second; load 0.50/1.55/3.93; 21.23 GiB MemAvailable, 1.04 GiB host swap used, 272.82 GiB disk free. Recent memory PSI averages were zero. RTX 3070 was at 0%, 1/8,192 MiB and no compute processes. No active project compute service was listed at that instant; the parent's new native (up to 4 CPU/512 MiB) and relation (up to 6 CPU/3 GiB) reservations still must be counted when scheduling. Snapshot SHA-256: `d48ce9d7739f3c53a73256ff17efa2a2f3053a6519b1f12b5943587b56ff3865`.

The unchanged reviewed proof configuration can use **one prover process, four Rayon threads and CPUQuota 400%**, with 12 GiB maximum memory, no swap and the two-hour wall budget. The bwrap environment fixes `RAYON_NUM_THREADS=4`, so changing an outer environment variable cannot enlarge that configuration. It has no CPU-affinity selection. Existing same-v6 evidence suggested roughly 6.4 GiB peak for planning, but this lane has generated zero proofs and has no new proving-memory measurement. The 12-GiB hard allocation still needs a separate fresh parent decision against other reservations. Any future GPU quiet timing window takes precedence over proof execution.

No parameters, backups, generation, proof, native runtime test or private evaluation payload were accessed during this build qualification. The four-proof experiment remains held; successful compilation does not close the recovery composition evidence gap. Staging and commit of this canonical document belong to the evidence-lineage owner; this lane made no commit or push.
