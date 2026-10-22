> Imported documentation snapshot. [Canonical status and ownership](../../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Current v2 recovery plus one v6 reserve race: implementation v1

Status: **source prepared; not built or executed**. Independent source review and parent resource release must precede build/proof execution. This document is an execution protocol, not a result.

Exclusive detached worktree: `/home/luke/projects/kpi-orchestration/2026-10-22/exit-recovery-review/implementation-v1/worktree` at `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`. Only two additive source files are introduced: `poc/shared-pool/recovery-race.py` and `poc/shared-pool/src/bin/kpi-two-input-recovery-race.rs`. The lane also has a separate `execute-gated.py` launcher outside the worktree. Core wallet, circuit, covenant, replay, helpers, setup, dependencies and old evidence remain unchanged. Preparation edits do not extend to the lead's active worktree.

## Question and fixed workload

Can a wallet with a current v2 backup sealed before receipt create its first exit proof after the original worker disappears, lose one reserve-input race, and settle from public replay without another proof, secret export or privileged intervention? The minimum claim must work as both continuing and terminal exit.

Use only fresh synthetic wallets/ancestry, the existing exact v6 setup and local native validation. No real/test funds, broadcaster, RPC, new setup, cryptographic change, fee repricing or private experiment data is involved.

1. Existing helper creates A and a synthetic 2,000,000,000-sompi reserve. A bootstrap generates proof 1 and a 1,960,000,000-sompi self-note.
2. Create B afterwards, seal its original v2 backup, then A pays B 60,000,000 and retains 1,860,000,000 change using proof 2. Stop A's original prover.
3. Copy the public descriptor/VK/lineage/parents/expected head and exact public PK to distinct ordinary files. Copy each original backup into a separate restoration input. Recovery namespaces cannot access original directories, another backup or network.
4. Restore A, then B, in separate sequential namespaces. The Rust adapter scans and chooses the sole unspent note/index internally; the controller supplies no note, index, request or saved proof. Each produces its first exit proof against the same head H: proofs 3 and 4. A payout = 1,820,000,000; B payout = 20,000,000. Both authorize fee = 40,000,000.
5. Branch H into two counterfactual synthetic histories. In A-first, B's original body loses; in B-first, A's loses. Append the winner, require the stale loser to fail current reserve-lineage continuity, reconstruct current public state and settle the loser's unchanged proof/authorization. No PK or wallet backup is mounted for rebasing. Append and replay the loser. Do not reprove to mask a rebasing failure.
6. Each branch must drain: 2,000,000,000 = 1,840,000,000 native payouts + 160,000,000 pool fees + zero reserve, and both wallet scans show zero remaining liability. Ordinary synthetic funding/founding fees are separate. The branches are alternatives, not two histories accepted on a network.

Exactly four genuine proof requests and three parameter loads. The small adapter calls existing `wallet::Context`, `wallet::Prover`, `replay::replay`, `two_input::settle`, `native::validate` and `native::policy`. It does not change their rules. It compares actual serialized transaction proof/authorization bytes with the input capability after rebasing.

## Pass/fail and nonclaims

Both native-validated histories, both original-backup hash checks and all intended negative causes must pass. Count every failed run; create a fresh run directory for a later retry. No suppressed failure, amended criterion, old proof substitution or replacement setup.

The runner checks these negative cases without additional proofs:

- Each stale loser: `reserve lineage discontinuity`.
- Rebase each already paid winner before drainage: `nullifier spent/zero`.
- Rebase after drainage: `pool drained`.
- Mismatched endpoint count and missing final body: `expected head count mismatch`.
- Missing actual founding parent: `missing funding parent body`.
- Altered VK: `public replay descriptor/VK identity`.
- Wrong candidate pool pin: `candidate descriptor identity mismatch`.
- Damaged genuine proof: a native verification failure specifically prefixed `rebased native verification:`.

Full public replay, not old-context script execution alone, establishes the simulated consumed-outpoint rule. Native validation alone can accept a historically valid body supplied with old input context; that must not count as current acceptance.

The resulting result must retain `chain_acceptance_verified: false`. It does not establish live retry, RPC/finality/freshness, reorg/pruning tolerance, another physical host, durable public distribution, sustained contention fairness, independent human users, privacy or cryptographic assurance. It uses the already documented single-party experimental setup. Existing independent old-version recovery and existing v2 regression evidence remain correctly scoped in [../REPORT.md](../RESEARCH-REVIEW.md).

The immutable 0.6-tKAS minimum is unchanged. Exact actual minimum-claim mining mass is measured for each branch and costed at 100/200/500 sompi per mass. The 0.4 fixed authorization and minimum claim fail the recorded 2x/5x envelope; the runner records and requires that known limitation rather than hiding it. A baseline pass must never be described as qualification for increased fees. Ordinary payout/index discovery remains outside this test.

## Release and resource envelope

The parent must first verify that the frozen 1,024-observer evaluation has completed and inspect fresh Forge capacity. No automatic release exists. The runner separately requires the frozen service to be inactive with successful main exit, plus an explicit parent receipt. Receipt absence or active service causes refusal before key generation/proving/parameter hashing.

The proposed hard envelope is **12 GiB RAM per phase**, superseding the earlier 8-GiB headroom plan. Build and proof are separate unique systemd user services; they must not overlap each other. The parent decides aggregate CPU/RAM scheduling from fresh measurements. This lane makes no assumption that a 12-GiB recovery job can overlap the separate 4-GiB GPU benchmark.

- Build: CPU quota 200%, two Cargo jobs, 12-GiB memory maximum, no swap, 256 tasks, two-hour wall budget.
- Proof run: CPU quota 400%, one prover at a time, four Rayon threads, 12-GiB memory maximum, no swap, 256 tasks, two-hour wall budget.
- Both: `KillMode=control-group`, 30-second stop grace followed by SIGKILL, unique service name and private launch record. A final launcher timeout at two hours plus three minutes invokes only that exact unit's bounded cleanup. An incomplete cleanup audit is followed by a KILL to that same unit, with separate 45/15-second command bounds and at most ten seconds per state query. SIGTERM and keyboard interruption invoke that cleanup too; further termination signals are ignored during its bounded cleanup attempt. No global process-name match is used.

These are generous **offline fixture budgets**, not measurements or cryptographic criteria. A memory/time/task termination means the run is incomplete and needs a resource diagnosis; it must not be reported as failed recovery or a security finding. Approximately 6.4-GiB peak from existing same-v6 evidence and 15–20 minutes for four proofs are planning estimates, excluding a fresh dependency build. `/usr/bin/time -v` records actual per-process RSS/time later. Accepted systemd flags do not establish enforcement: the service entrypoint must read its exact cgroup's `cpu.max`, `memory.max`, `memory.swap.max` and `pids.max` before Cargo or proving. Missing controllers or mismatched values cause refusal. No service or controller qualification has run during preparation; actual timer/stop behavior remains to be qualified in execution.

The runner independently checks its exact run-service cgroup before importing experiment support or reading parameters. Original lifecycle waits remain unchanged; the outer service gives those synchronous calls and namespace processes one finite lifecycle, including bwrap's separate sessions. The launcher preserves stdout, stderr, exact command, release, actual cgroup values and return status under `launches/<UUID>/`.

Use the exclusive `build-target`, locked offline dependency resolution, and Rust 1.95.0. Do not install missing dependencies or share the live target directory. If cache/toolchain or cgroup controllers are unavailable, report that blocker and leave the worktree intact. The public PK is 962,197,520 bytes; input plus recovery copy is approximately 1.93 GB. The launcher requires **20 GiB free disk** before each phase. The build can exceed the proof estimate and is not a performance result.

## Inputs prepared only after release

Parent/export owner must place exactly two public files, `pk.bin` and `vk.bin`, under:

`/home/luke/projects/kpi-orchestration/2026-10-22/exit-recovery-review/implementation-v1/inputs/public-parameters/`

Do not point the runner at a raw private run or active evaluation. It rejects any extra file, symlink or parameter path outside this lane's `inputs` directory. The input directory itself is an explicit public-only export; its creation may read only previously identified public parameter files, never a whole private source directory.

Expected PK SHA-256: `6f95db952f84420717b3b677e1368bc85776791eb1ccf409cb390a4e4fb39593`; expected VK SHA-256: `9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef`. The runner rechecks them; wallet loading additionally checks decoded bytes, validated points and embedded VK. No parameter bytes were accessed during preparation.

Parent writes `release.json` only after actual release, using this schema with truthful timestamp and notes (no active release file is supplied by preparation):

```json
{
  "lane": "exit-recovery-review-v1",
  "approved_by": "parent-orchestrator",
  "approved_at_utc": "ACTUAL UTC ISO TIMESTAMP",
  "run_authorized": true,
  "frozen_evaluation_completed": true,
  "fresh_capacity_verified": true,
  "max_parallel_provers": 1,
  "rayon_threads": 4,
  "resource_envelope": "12GiB-2h-cgroup-v1",
  "notes": "Actual completion evidence and current available CPU/RAM/disk"
}
```

## Commands for the later attributable execution

Run on Forge only after independent review and parent release. The two commands below are supplied but have not been executed. Substitute the exact independently reviewed manifest SHA-256 from the freeze handoff; do not dynamically accept whatever hash is present on disk. Each command checks that hash, all recorded source/artifact hashes, the pinned worktree HEAD, the explicit release, frozen-service completion and disk headroom before launch. It repeats identity and release checks inside the owned service.

```sh
python3 -B /home/luke/projects/kpi-orchestration/2026-10-22/exit-recovery-review/implementation-v1/execute-gated.py \
  build --manifest-sha256 REVIEWED_MANIFEST_SHA256

python3 -B /home/luke/projects/kpi-orchestration/2026-10-22/exit-recovery-review/implementation-v1/execute-gated.py \
  run --manifest-sha256 REVIEWED_MANIFEST_SHA256
```

The build command inside its qualified cgroup is `cargo +1.95.0 build --release --locked --offline --jobs 2 --manifest-path poc/shared-pool/Cargo.toml --bin kpi-two-input-wallet --bin kpi-two-input-lifecycle --bin kpi-two-input-recovery-race`, with `CARGO_TARGET_DIR` fixed to this lane's `build-target`. The subsequent run supplies only the lane's manifest, release, public-only parameter export and those three built binaries to `poc/shared-pool/recovery-race.py`. No broad cargo test, benchmark, setup generation or install is included. The direct runner refuses execution outside the exact gated run-service cgroup.

First inspect build status and its logs. Compilation is a pending qualification step; source preparation does not assert that it passed. After a successful build, the parent must recheck current capacity before choosing the separate proof phase. If compilation/review requires edits, create a new manifest identity and tell reviewers before execution. No change to the original base implementation should be needed. A nonzero phase exit or absent final report is incomplete until the logs distinguish source/runtime errors, an intended semantic rejection, and resource termination.

## Outputs and cleanup

The runner creates a fresh mode-0700 `runs/<UUID>/` under this lane, with a start execution manifest recording source/binary hashes, runner PID, exact cgroup and parent release, parameter/public-copy integrity checks, original-backup seals, process-isolation guards, `/usr/bin/time -v` records, original-worker shutdown ordering, both full synthetic public lineages, negative rejection logs and final `report.json` only on success. Source hashes are checked again before that success report. Each restore exits before the next starts; rebasing processes receive public bytes and the claimant's now-created private capability, but no backup/PK.

All runtime outputs stay private, including synthetic backups, inspection views and unused alternatives. Do not copy raw runtime trees into public evidence. A later report/export must explicitly allowlist public metadata and exclude unused capabilities and secrets. Missing final report is not success; inspect process status and logs before drawing any conclusion.

Normal completion closes the original worker through EOF; other invocations are synchronous. Failure retains artifacts and attempts to close owned workers in `finally`. The outer cgroup contains all descendants if an unchanged worker wait blocks. The launch record provides the exact service and launcher PID. Parent-requested interruption targets only that service (`systemctl --user stop EXACT_RECORDED_UNIT`); its configured stop grace then SIGKILL applies to its entire cgroup. An interruption caught by the launcher performs the same bounded exact-unit cleanup. Final state and recursive `cgroup.procs` membership are audited; survivors or an unverifiable state produce an explicit blocked-cleanup record, never a cleanup-success claim. Neither the frozen evaluation nor unrelated services may be stopped. Preserve all failed/successful records; no automatic deletion, worktree removal, resource release or publishing is part of this protocol.
