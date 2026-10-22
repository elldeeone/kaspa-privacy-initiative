> Imported documentation snapshot. [Canonical status and ownership](../../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Source-only review of the current recovery/race fixture

Status: prepared for independent review. No Python runner import, syntax execution, Cargo invocation, build, proof, benchmark, parameter-file access, service launch or controller qualification occurred. This is a source inspection, not a passing result. The exact frozen files are enumerated in [prepared-manifest.json](prepared-manifest.json).

Base: `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`. The exclusive detached worktree contains only two untracked additions; no tracked source or dependency change. The lane-only launcher is outside the checkout. All source references below are relative to the exclusive worktree unless stated otherwise.

| Required condition | Planned evidence and source boundary |
| --- | --- |
| Current original v2 backup survives receipt without a new export | `poc/shared-pool/recovery-race.py:234` seals B before A's payment; backup hashes are rechecked before and after recovery. `src/bin/kpi-two-input-recovery-race.rs:26` rejects a non-v2 format/profile, scans internally and chooses the only unspent position. |
| First fresh exit after original worker disappearance | Runner stops original A at line 245, records shutdown before restoration at 248, then restores A and B sequentially at 269. Only separately copied public history/parameters and that wallet's original backup enter each recovery namespace. The restored helper receives no controller-supplied note/index, request or fallback proof. |
| Four actual proofs, not repeated M2 | A bootstrap + one A-to-B payment + each wallet's one fresh exit = four. There are three PK loads: original A's persistent worker and the two restored processes. No branch creates another proof. |
| A minimum claim can be winner or loser | Two counterfactual branches at runner line 293 use the same two exit capabilities. A-first makes the minimum claim terminal; B-first makes it continuing. This is an offline deterministic race, not a live contention measurement. |
| Stale loser must really lose current reserve input | The append adapter at Rust line 121 runs full replay, including exact input continuity. Current source rejects discontinuity at `src/two_input/replay.rs:273`. Native script execution supplied with an old context alone would not establish this; it is deliberately insufficient here. |
| Loser can rebuild from public state without changing authorization | Rebase at Rust line 73 receives current public bytes and the claimant's capability, but no backup or PK. It calls unchanged `two_input::settle`, compares actual tx payload/proof bytes at 96–98, native-validates at 101, and reports zero proofs. The runner rechecks proof/auth hashes. |
| No duplicated liability; exact drain | Rebased winner must reject `nullifier spent/zero` (`src/two_input/tree.rs:237`); after drainage rejects `pool drained`. Both branch accounting checks at runner line 329 require 20 tKAS = 18.4 payouts + 1.6 fees + zero reserve, with each wallet scanned to zero. |
| Public data dependence is not hidden | Wrong head, missing final body, missing founding parent, changed VK and wrong candidate pool are required to reject for their specific intended causes, not just any nonzero return. A corrupted genuine proof must fail native verification. |
| Minimum fee limitation remains visible | Current `NOTE_FLOOR=60,000,000`, `FEE=40,000,000` are unchanged (`src/two_input/mod.rs:20–22`). Each branch's actual minimum-exit mass must cover baseline fixed fee and retain failure to fund fee + payout floor at 2x/5x. This is required by runner line 163; no fee-subsidy or repricing path is introduced. |

## Isolation and execution ownership

`two-input-lifecycle.py` remains unchanged. It runs guarded bwrap user/mount/PID/network namespaces with only explicit mounts and captures per-process RSS/time. The new recovery copies are byte-checked and not the same inodes as original files. The controller can orchestrate these fixtures; this is not another physical-host or malicious-controller claim. Synthetic secrets and unused capabilities stay private.

The independent source reviewer identified unbounded reused subprocess/pipe waits. The added lane-only `execute-gated.py` supplies a separate finite cgroup for each build and proof phase: 12 GiB, no swap, 256 tasks, two hours; build CPU 200%/two Cargo jobs, proof CPU 400%/four Rayon threads/one prover. This supersedes the earlier 8-GiB planning headroom, not the older measured RSS. The parent must schedule it against fresh aggregate capacity; overlap with any other lane is not assumed.

The launcher source checks actual cgroup files before work at line 94, handles SIGTERM/interrupt/outer timeout, and targets only its exact UUID service. Cleanup uses bounded stop/KILL commands and retains final service state plus recursive cgroup process membership; unverifiable cleanup or survivors are recorded as blocked. Actual controller enforcement and timer/cleanup behavior have not been qualified. Resource termination is an incomplete experiment, distinct from a semantic recovery failure. These are offline fixture caps; no testnet trial or broadcast is involved.

A reviewed manifest hash, all frozen source/artifact hashes, unchanged HEAD, explicit truthful parent release and successful frozen-service completion are required before either phase. The runner adds its own actual run-cgroup check at line 106. No release file is shipped. Parameter inputs and run/launch/build directories have not been created during preparation.

## Still pending and deliberately outside the result

Independent source review, compilation, runtime controller qualification and the four proof requests all remain pending. A source-ready artifact is not a proof-tested artifact. Source inspection cannot exclude compile/runtime mistakes. No current cryptographic, privacy or live-network guarantee follows from old evidence or this planned run.

Even a future pass closes only the current-v2/v6 composition gap: pre-receipt backup to fresh exit, one lost reserve race, public witness rebuild, minimum-claim both orderings and exact drainage. It does not establish public archive durability, discovery of the correct accepted endpoint, general ordinary native payout/index discovery, execution on another physical host, reorg/pruning resilience, sustained adversarial fairness, stronger-fee usability, or a new production exit architecture. The earlier evidence gaps remain scoped in [../REPORT.md](../RESEARCH-REVIEW.md).
