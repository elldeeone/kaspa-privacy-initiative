# GPU v4 runtime qualification — 2026-10-22

Runtime attestation, Linux containment, CUDA context/kernel execution and C+D prediction equivalence passed. The overall experiment is **BLOCKED_OR_FAILED**, because the pooled GPU worker stopped at its ownership guard. This document is a qualification receipt, not a successful acceleration or adoption claim. See [RUNTIME-RESULT.md](RUNTIME-RESULT.md) for the failed speed criterion and incomplete pooled GPU case.

## Immutable identities

All paths below are on Forge. UTC is used throughout (AEDT = UTC + 11 hours).

- Frozen source: `/home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/revisions/v4`.
- Source manifest SHA-256: `2515abffcb08c0ff2e942e5551c21b017b74c7a862e1e0e693ed35db2daa8e61`.
- Reviewed source patch: `6f6e7976c748ecd166196b43868fe19fb9decf2082b89b37290a0ef4588bf645`.
- Attempt: `/home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/executions/20261022T092500Z`.
- Full screen within the attempt: `package/runs/20261022T093037.341789Z`.
- Runtime lock: `438bae3f3ff1c490b34b919290f13bebcaa0a11cad606ca93f7ad0c9c4fbf194`.
- Requirements lock: `52c90385c6914d4ec96396df5e62fb0dffb265d60c24c87d74b9562c55958011`.
- Raw receipt manifest: `receipt-manifest.json`, SHA-256 `16f97707a1c1de272b80581a02a547e9106803fe5ab98df7376703e53bdac955`.
- Derived receipt index: `runtime-evidence.json`, SHA-256 `93c3bdbbd54aaadcaa9ed5879d41aec53ec10d21b1347984b7e6c1c170e72969`.

The receipt manifest covers 1,062 files / 10,851,961 bytes: attempt receipts and helpers, qualification evidence, load samples, setup logs, run snapshots/outputs/kernel caches, and source/environment lock receipts. Installed environment and download-cache bytes are excluded from that manifest; their runtime content is attested by the runtime lock. Post-run SHA checks found zero mismatches in all 28 v4 source files, the 28-file executed copy, and all 27 v3 source files. Frozen v3 and its failed attempt were not changed.

## Release, units and enforced bounds

The attempt began at 09:26:48 UTC with an absolute 09:56:48 deadline. The screen terminated at 09:53:47, before that deadline. No deadline, numerical criterion, worker cap or source change was made during execution.

| Phase / unit suffix | Invocation ID | Observed UTC interval |
| --- | --- | --- |
| `qualify-20261022T092500Z` | `90713eb568bc499fa3283e375b7f84dc` | 09:26:48–09:26:56 |
| `setup-20261022T092500Z` | `4272d2244b944c13a42aa9ad958c236f` | 09:27:22–09:27:50 |
| `controls-20261022T092500Z` | `78582cb0138847dbace26c479516ea1c` | 09:29:04–09:29:28 |
| `screen-20261022T092500Z` | `6494794f83ef462db9135b25fd0b670f` | 09:30:37–09:53:47 |

Each unit has prefix `kpi-gpu-v4-` and suffix `.service`. Journals and load receipts retain phase metadata. The setup phase used its own 2-CPU / 4-GiB / no-swap unit, with no benchmark worker concurrent. It took 27.567 seconds, charged 4 GiB peak including file cache, and had no OOM or swap-out growth. Resolve, venv, install and attestation helpers all exited successfully and completed owned cleanup.

The worker cgroup was `/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/kpi-gpu-benchmark-v4`: `cpu.max=200000 100000`, `memory.max=4294967296`, `memory.swap.max=0`, `memory.oom.group=1`, `pids.max=64`. Actual worker and wrapper process metadata confirmed CPU affinity 0–1. The separate controller/monitor unit had a 128-MiB hard memory limit, no swap, 64 tasks and 0.25 CPU; aggregate lane reservation was 4.125 GiB. Systemd's CPUAffinity property was empty because the launch used taskset; the live process masks provide the observed affinity evidence.

Workers retained the reviewed 300-second envelope including cleanup. GPU allocations retained the 2-GiB CuPy allocator limit and the 3-GiB sampled whole-device stop. The whole-device guard is not a hard VRAM partition and samples can miss peaks.

## Qualification evidence

1. A disposable tighter probe (128 MiB, 8 PIDs, 0.5 CPU, no swap) demonstrated actual CPU throttling, memory enforcement and PID refusal. Its intentional memory case produced one group OOM event; its PID case reached EAGAIN. This was expected probe behavior, not a benchmark-worker OOM.
2. Owned cleanup handled an exited wrapper and surviving TERM-ignoring child/grandchild; final cgroup population was zero and the probe was removed. The subsequent namespaced worker timeout/descendant probe also cleaned up successfully.
3. The isolated environment installed the exact 12-distribution wheel lock. Python was 3.14.4, NumPy 2.3.5, CuPy CUDA12x 14.2.0 and CUDA toolkit 12.9.2.0. Exact remaining distributions and actual tool/device/library identities are in the lock and `runtime-review.json`. Attestation covered 3,618 venv and 1,359 stdlib file records.
4. The reviewed two-link distro policy was checked against actual bytes, links, metadata and package ownership. Its policy SHA was `909e556a0bd314f3b2a18b9cb05e1acd8e6761295df622729c318f3b05d927eb`. The attester, controller and workers used `-I -S -B`; no host Python, hook, driver, Bubblewrap or global environment was changed.
5. Both the prerequisite qualification run and full screen re-attested actual runtime content against the lock. Namespaced workers had only loopback networking, no host home and no truth mount. Only pinned historical public development inputs were used.
6. Reference, array and GPU retained controls each passed all 28 checks. GPU controls actually initialized a context (0.224626 s), compiled the kernel (0.157215 s) and recorded 2.791168 ms of kernel execution. The device was RTX 3070, 8 GiB, UUID `GPU-352aec53-18dd-0961-df17-b193565c24f6`, attested NVIDIA driver version 595.99.02.
7. All 22 completed full prediction files matched their entire canonical oracle. These comprise both CPU paths for both views, both reference profiles, and four C+D GPU observations. Pooled GPU produced no complete prediction.

Peak sampled worker-process-tree RSS was 718,598,144 bytes; worker cgroup charged-memory peak was 689,868,800 bytes. These use different accounting and sampling. No benchmark-worker memory max/OOM event occurred. Maximum sampled whole-device usage was 189 MiB. The controller charged-memory peak was 128 MiB; file-cache reclaim hit its hard boundary without OOM. Polling and telemetry costs are part of the measurement limitations.

## Terminal audit

`terminal-cleanup.json` SHA-256: `31935df9e8cb83e935b137d4fbfbb0dc4a65dc81d266a912f3fee3a7ec5ca94a`.

All 58 recorded host PID/start identities were absent. Qualifier, setup and controls units were unloaded. The screen's failure metadata remains loaded, with MainPID 0, ControlPID 0 and empty ControlGroup. Its worker cgroup was empty and then removed; the probe cgroup was absent. A final read-only device query returned no compute owners and 1 MiB / 8,192 MiB usage. Root accepted release of the 4.125-GiB reservation. No patch, relaunch, additional benchmark, proof or recovery execution followed this failure.
