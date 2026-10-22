# Recovery v2 resource and semantic delta review

**BOUNDED STATIC ACCEPTANCE. No source blocker found in the frozen execution-only delta.** Reviewed at 2026-10-22T09:27:01.716508+00:00 on Forge. A parent-released N from 1 through 12 can be configured without changing the experiment's scientific criteria. This is not proof execution release, measured resource/performance qualification, or a passing recovery result. No freeze/resume interface is proposed or required under the current schedule.

Scope: `../exit-recovery/implementation-v2/`, against the previously accepted v1 semantic fixture. Only source text, manifests and existing executable hashes were read. No package import, compilation, tests, proofs, parameter/input access, private evaluation access, or service manipulation occurred.

## Identity and semantic continuity

Independently checked all **65 original source pins**, **3 v1 artifact pins**, **6 v2 artifact pins** and **3 built executable sizes/hashes** against current files. The original source/artifact maps exactly equal v1's maps; v1 manifest remains `a78c3dda3fab1d0240c987a34484b3e129ea4b3faf9e2cc18a50287462addbd5`. Worktree HEAD remains `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`. An independently generated three-file text diff exactly equals the published diff.

The scientific body, minimum-fee function, support classes/tail, owned cleanup functions and outer timeout/cleanup tail are byte-identical to v1. Circuit, wallet, Rust adapter, proof/randomness implementation and dependency sources are unchanged; the same previously built executables are reused. Fresh proof bytes need not match earlier runs, and thread allocation can change time and memory.

| Required behavior | Source evidence |
|---|---|
| Exactly four proof requests; original worker ends before sequential restoration | `recovery-race.py:246–310` retains bootstrap/payment, pre-receipt B backup seal, stopped original worker, one fresh proof per restoration and explicit count four. |
| Private input/capability isolation | The scientific mounts are unchanged (`recovery-race.py:271–309,327–334`). The sandbox retains cleared environment and separate user/mount/PID/network namespaces; its only new values are the explicit thread allocation (`two-input-lifecycle.py:33–48,72–90`). No seed, key, backup, capability or public-input change was added. |
| Both winner orders, unchanged proof authorization on rebase, exact drain | `recovery-race.py:313–362` retains A-first/B-first, stale-loser and spent-nullifier checks, zero new rebase proofs, byte-hash checks, 2,000,000,000 = 1,840,000,000 paid + 160,000,000 fees + zero reserve, and zero wallet liabilities. |
| Same intended failures and fee limitation | `recovery-race.py:163–189,363–396` retains intended-error matching and the 60,000,000-sompi minimum's recorded 2x/5x fee failure. Increased threads do not reprice or subsidize the claim. |
| Same claim boundary | `recovery-race.py:397–416` retains offline-only, chain acceptance false, and all nonclaims. A successful build alone supplies no recovery/proof result. |

## Resource agreement and failure handling

The outer CLI requires integer N in 1–12. Its release check strictly binds N, quota 100*N, proof phase, manifest, one prover, fixed affinity and explicit parent authorization (`execute-gated.py:53–87,169–178`). It verifies old/new source identity and exact prebuilt binaries before launch, and repeats inside the unit (`53–70,178–187`). The runner also pins the actual executable paths, sizes and hashes (`recovery-race.py:211–219`).

The owned service sets N, CPUQuota 100*N and CPUAffinity 2–13 (`execute-gated.py:190–207`). Service and runner require actual `cpu.max` quota = N × period, environment N, and actual affinity exactly 2–13, alongside 12 GiB memory, zero swap and 256 tasks (`execute-gated.py:102–120`; `recovery-race.py:119–131`). Missing or mismatched values refuse before support/parameter work. The support allocation is single-use; each cleared-environment sandbox receives and checks the same N and affinity (`two-input-lifecycle.py:22–26,39–45,72–90`). These configure Rayon workers and CPU-time quota, not a claim that every OS thread/process is counted by N or that a cpuset controller reserves those CPUs.

The unchanged service budget is 7,200 seconds, with 30-second stop grace and control-group kill; the outside launcher retains its 7,380-second bound and exact-unit cleanup/audit (`execute-gated.py:23–25,123–166,195–226`). No timer reset, pause, automatic retry, cap increase, live retuning or broad process signal was introduced. Four threads remain a separately released v2 fallback, not an automatic response to failure.

## Release decision

Static configuration-only scaling preserves the protocol and hard limits. Actual N-core affinity/enforcement, peak memory, forced-timeout behavior and proof success remain runtime evidence; the previous two-core build does not establish them. A 12-thread run may hit 12 GiB. Resource termination must be reported as incomplete resource evidence, with artifacts retained, never as an intended semantic rejection or failed recovery. Success requires the original report criteria, launcher success and completed owned cleanup (`PROTOCOL-DELTA.md:41–45`).

Parent retains the fresh aggregate memory/pressure and release decision. CPU 2–13 proof affinity alongside GPU CPU 0–1 does not remove shared-memory/system contention. Any concurrent GPU measurements remain **development screening under measured proof load**, not uncontended or adoption evidence (`PROTOCOL-DELTA.md:47`). This review adds no experiment, retuning, or scientific criterion.

## Reviewed identities

- `prepared-manifest.json`: `d5c0f1810f51f2d75ff3b9391d85840fa952b088e94b8cd978a01f160c2731b7`
- `V1-TO-V2.diff`: `e8d0ac19b8a8cfdaf9b2140fad104f50420c0ae3c55780c140499d51c8d51e82`
- `PROTOCOL-DELTA.md`: `c27e6f532b5cbf3cab8183dcc553f802c4fedc61175f622095cf17c16d647da2`
- `execute-gated.py`: `c620b28eb1c22777294af3eb2e5b5f39811232674fe0c59f793675a2044efb76`
- `recovery-race.py`: `033c937e2ae2ead98286084420d621206610c6e4ff405d4c4f226551870a347d`
- `two-input-lifecycle.py`: `01c6dfb920e996e7b08c51fbd7d764a80eb40530369eb854f9299e9fb21f6a68`

Existing binaries, independently hash-matched without execution:

- Wallet (16,072,176 bytes): `1ee3835b1b0ed3e4c4ca0ce4f5ee1cd6f85b79d19b2cef10a7402ece42e298a3`.
- Lifecycle (15,396,112 bytes): `67d54d203f5e101deae92c388e0e961132a5896e871215d5e43444343d2382bd`.
- Recovery/race (15,972,072 bytes): `f174d433b8e6c383d8930dabe19a2370835a2d7c494595d40d881f4efdd9f762`.
