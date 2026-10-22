# Recovery execution wrapper v2

Status: immutable source preparation for independent review. No v2 runtime, public parameter export, new proof or experiment result exists. A separate parent proof release and fresh aggregate resource check are mandatory. V1 and its successful build remain unchanged.

## Scope and scientific continuity

The only experiment changes are explicit per-run thread allocation (integer N from 1 through 12), the required receipt/quota/environment agreement, fixed process affinity to CPUs 2–13, and reuse of the three exact already-built v1 executables. V2 has no build phase and no freeze/thaw interface. The complete `proofs = []` through pre-report scientific block, `minimum_fee_rows`, support Experiment/Worker classes and remaining helper script are byte-identical to v1. All 65 original source pins and three original lane artifact pins remain enforced. The complete diff is `V1-TO-V2.diff`.

The original protocol still governs synthetic pre-receipt v2 backups, three sequential parameter loads, exactly four genuine proofs, both A-first and B-first orderings using the same authorizations, public-only loser witness reconstruction, exact 2,000,000,000-sompi drainage, the unchanged intended-error guards, and the retained 60,000,000-sompi minimum-claim failure at the recorded 2x/5x fee envelopes. No circuit, wallet, Rust adapter, randomness source, public input, fee, proof count, branch, or acceptance criterion changes. Timing and runtime memory may change with N; new proof bytes may naturally differ because proofs are fresh. No accepted-chain, public archival availability, privacy or cryptographic-security claim follows.

## Executable lineage

The pinned base is `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`. The reviewed v1 manifest is `a78c3dda3fab1d0240c987a34484b3e129ea4b3faf9e2cc18a50287462addbd5`. Successful build documentation is committed at `388cb062dfb0f0bb71f15a9f8e64f37fd59d6a69`; its BUILD-QUALIFICATION.md SHA-256 is `cf0fba0f33dfeb1ef59876c76dabf4ed073ab4491d2fac512106a8467a433e54`. This is source-to-build provenance, not a reproducible-build claim.

| Executable | Bytes | SHA-256 |
| --- | ---: | --- |
| kpi-two-input-wallet | 16072176 | `1ee3835b1b0ed3e4c4ca0ce4f5ee1cd6f85b79d19b2cef10a7402ece42e298a3` |
| kpi-two-input-lifecycle | 15396112 | `67d54d203f5e101deae92c388e0e961132a5896e871215d5e43444343d2382bd` |
| kpi-two-input-recovery-race | 15972072 | `f174d433b8e6c383d8930dabe19a2370835a2d7c494595d40d881f4efdd9f762` |

Each must remain an ordinary file at its exact v1 `build-target/release` path. Both launcher and experiment runner verify lengths and hashes. No rebuilding or substitute executable is allowed by this revision.

## Release and later command

Canonical package: `/home/luke/projects/kpi-orchestration-docs-2026-10-22/research/orchestration/2026-10-22/exit-recovery/implementation-v2`.

Private runtime scope: `/home/luke/projects/kpi-orchestration/2026-10-22/exit-recovery-review/implementation-v2`. Creating this directory, a public-only pinned PK/VK export in `inputs/public-parameters`, and `release.json` is a later attributable execution step. The old build-only receipt does not authorize v2.

Required receipt fields are lane `exit-recovery-review-v2`, approved_by `parent-orchestrator`, authorized_phase `proof`, proof_phase_authorized true, run_authorized true, frozen_evaluation_completed true, fresh_capacity_verified true, max_parallel_provers 1, rayon_threads N, cpu_quota_percent 100*N, cpu_affinity `2-13`, resource_envelope `12GiB-2h-cgroup-v2`, exact reviewed manifest_sha256, and approved_at_utc. These must reflect an actual subsequent parent decision, not this document. Record accompanying capacity and input-export receipts privately. Parent must account for every concurrent lane; 12 GiB is the cap, not estimated actual consumption.

After that authorization only, from Forge, with MANIFEST_SHA and N filled from the reviewed identity and release:

```text
/usr/bin/python3 -B /home/luke/projects/kpi-orchestration-docs-2026-10-22/research/orchestration/2026-10-22/exit-recovery/implementation-v2/execute-gated.py run --manifest-sha256 MANIFEST_SHA --prover-threads N
```

No hidden environment override is used. Outer CLI, parent receipt, service CPUQuota, actual `cpu.max`, service RAYON_NUM_THREADS, runner configuration, and explicit cleared-environment sandbox RAYON_NUM_THREADS must agree. The isolated process guard records N and affinity. `CPUAffinity=2-13` is checked using actual sched_getaffinity in the service, runner and each sandbox; it is inherited process affinity, not a claim of cpuset-controller isolation. CPU quota remains N cores even for N below 12. Thread count is fixed for that run; no live quota retuning or automatic fallback. Four threads remain an available separately released v2 configuration.

## Bounds, qualification and outcomes

One proof worker at a time; maximum N=12; MemoryMax 12 GiB (12884901888 bytes); MemorySwapMax 0; TasksMax 256; RuntimeMaxSec 7200; KillMode control-group; TimeoutStopSec 30; SendSIGKILL yes. The unchanged launcher outside the service has its original 7380-second command timeout and exact-owned-unit cleanup/audit on SIGTERM, interruption or timeout. The two-hour service execution budget excludes its bounded cleanup allowance. No pause/resume, deadline extension or restart logic was added. The unchanged final audit requires an inactive/failed/absent unit and no remaining cgroup PIDs, otherwise the result is blocked for survivors/unknown state.

Actual 2-core v1 build cgroup limits and ordinary stop/child cleanup were qualified. This does not qualify v2's N-core affinity, actual timers, peak memory, forced timeout path, or proof performance. V2 gates refuse before support import/parameter access if actual quota, memory, swap, tasks or affinity mismatch. Parent must authorize any pre-proof runtime qualification separately; preparation performed source parsing/hashing only. A 12-thread run could exceed 12 GiB: budget termination is incomplete resource evidence, never an intended semantic rejection or a proof of failure of recovery. Do not silently retry, raise the cap, reduce threads or discard partial evidence.

Success requires launcher exit zero, owned cleanup complete, and all original experiment report criteria including exactly four proofs, both branches, exact drainage and intended guard errors. Preserve all private runtime receipts on every terminal outcome. No automatic deletion or public export. Report actual cgroup/RSS/time and resource terminations separately from scientific assertions.

Parent plans GPU CPUs 0–1 concurrently with proof CPUs 2–13 only if a fresh aggregate memory/pressure gate permits. Such GPU results are development screening under measured proof load, not uncontended performance or adoption evidence. No freezing is needed or implemented; reserving disjoint CPU affinity does not reserve RAM or remove shared-system contention.
