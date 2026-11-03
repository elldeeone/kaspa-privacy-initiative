> Imported documentation snapshot. [Canonical status and ownership](../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Independent recovery/race source review

**BOUNDED STATIC ACCEPTANCE of the proposed semantic fixture. No concrete blocker found in the assigned composition/negative-control scope.** Compilation, real proof/native results, runtime isolation and resource/cleanup qualification remain pending. This is not execution release or a passing recovery result.

Frozen lane: `/home/luke/projects/kpi-orchestration/2026-10-22/exit-recovery-review/implementation-v1`. Prepared manifest SHA256: `a78c3dda3fab1d0240c987a34484b3e129ea4b3faf9e2cc18a50287462addbd5`. All 65 source and three lane-artifact hashes matched. Base is `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`. Additions: `recovery-race.py` SHA256 `96dae0538fd5eb8baabe5b2f76c8d2715a8f5930b68545cd1d16e076ba7863f2`; `src/bin/kpi-two-input-recovery-race.rs` SHA256 `da5399081f72bcbe91bfd4a781602abd1ad643329f1e16ee719fd3de57ef33c0`.

Review was source-only over Forge SSH. No code import, compilation, build, test, proof generation, runtime setup, parameter read or private evaluation read occurred. Paths below are under the exclusive worktree's `poc/shared-pool/` unless stated otherwise.

## Supported design

| Obligation | Source evidence and conclusion |
|---|---|
| Pre-receipt original backup | Runner lines 233–242 creates/seals B before its incoming payment. Original A is stopped and waited for before any restoration (245–250; reused lifecycle worker stop 238–251). The controller rechecks original hashes (291,376). Copies have separately checked bytes and inodes (132–145,253–264). |
| Own-key fresh recovery | Rust adapter 26–60 requires the current v2 backup/profile, scans internally and chooses the sole unspent position; no note/index/request/old proof is supplied. Restore mounts contain one backup, public H and the public PK only (runner 269–275). Sequential `Experiment.run` returns before the next restore. Source design therefore supports the intended process-isolation claim, not physical-host independence or a malicious-controller guarantee. |
| Exactly four proof requests | Bootstrap and payment are the original worker's only proof requests (227–243); A and B each call `Prover::prove` once after recovery (Rust 59–60; runner 269–290). Each branch subsequently uses existing capabilities. The unchanged Prover validates the resulting native transaction (wallet.rs:726–764). Three parameter loads follow from one original persistent prover plus two restored processes. Counts remain proposed until runtime evidence exists. |
| Both winner orders | Runner 293–342 branches the same H as A-first and B-first. The 0.6-tKAS claim is terminal in A-first and continuing in B-first. Both original candidates were created against H. Full append replay checks the current reserve outpoint, so a historically valid loser body is not mistaken for current acceptance (Rust 121–140; replay.rs:258–300). |
| Unchanged proof/authorization rebase | Rebase mounts have only current public state and the claimant's newly created capability, no wallet backup or PK (307–309). Rust 73–118 binds descriptor and baseline DRAIN mode, calls existing settle against current state, compares actual payload/proof slices to the capability, then native-validates and reports zero proof generation. Runner 310–314 independently compares returned hashes. Settling changes the public witness/current reserve context while retaining authorization, including payout, fee, destination, anchor, nullifiers and cipher binding. |
| Exact drain and liability | Runner 322–332 requires each branch's replay accounting to reconcile 2,000,000,000 initial sompi to 1,840,000,000 paid + 160,000,000 pool fees + zero reserve, with no admissions and both wallet balances zero. Funding/founding fees remain separate. This is two alternative offline histories, not two accepted chain histories. |
| Minimum-claim limitation | Current constants remain 60,000,000 note floor, 10,000,000 payout floor and 40,000,000 fee. Runner 163–175 computes each branch's actual minimum-exit mining-mass costs at 100/200/500 and requires baseline fee coverage while retaining the inability of the minimum claim to cover the 2x/5x fee plus payout floor. It neither reprices the authorization nor silently subsidizes the exit. |

## Negative causes are attributable in source

The runner requires nonzero status **and** the intended error substring (148–153), rather than crediting arbitrary failure. Its chosen mutations reach the expected source checks:

- Stale loser: unchanged old outpoint conflicts with the winner's current reserve (`replay.rs:263–273`).
- Rebased already-paid winner: same anchored authorization reaches spent-nullifier insertion (`tree.rs:222–237`) before backing arithmetic.
- Post-drain rebase: missing reserve is rejected as `pool drained` (Rust adapter 84–93).
- Wrong count or missing last body: `Context::new` checks expected count before replay (`wallet.rs:265–269`).
- Missing founding parent and altered VK: existing replay parent consumption/descriptor checks supply the named causes (`replay.rs:37–44,160–165,235–252`).
- Wrong candidate pool: adapter descriptor comparison rejects before settlement (76–78).
- Damaged proof: only proof bytes change, preserving size/auth/cipher context. Existing settle wraps those bytes; native validation is the intended rejecting stage and is explicitly error-prefixed (Rust 94–105; mod.rs:219–225). This remains a runtime-required control, not a source-certified cryptographic result.

A failed expected-cause assertion must be investigated as an incomplete fixture/control; it must not be relabeled as successful recovery or a security defect. The tests are targeted, not an exhaustive adversarial/interleaving audit.

## Decision boundary

The artifact is suitable to retain for separately released, bounded compilation and execution after the independent lineage/envelope review. This review does not certify its launcher, cgroups, toolchain or source-to-binary attestation. Preserve successful/failing run evidence; no active checkout, prior verdict or historical outcome changes.

Even a future pass establishes only this one current-v2/v6 composition: pre-receipt backup, fresh exit, one lost reserve race, public witness rebuild with unchanged capability, both minimum-claim orderings and exact drain. It does not establish accepted-head discovery, live-chain acceptance, sustained contention fairness, reorg/pruning resilience, durable archival data, ordinary payout/index discovery, increased-fee usability, privacy or cryptographic security.
