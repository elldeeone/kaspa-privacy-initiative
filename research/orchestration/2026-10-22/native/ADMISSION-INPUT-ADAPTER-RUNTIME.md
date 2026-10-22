# Admission input adapter: measured native validation controls

**All four fixed cases passed.** The genuine public admission accepted in the unchanged full native validator and both input VMs. A funding-signature-only control then demonstrated reserve-input acceptance while the funding input rejected. Both successor substitutions subsequently produced separately attributed reserve-input rejections. This resolves the two admission attribution gaps for this pinned fixture: VK and code substitution both target the **same successor-output commitment guard**.

No new proof, setup, signing, recovery scenario, privacy evaluation, network transaction or core change occurred. These are offline native validation controls, not new proof or privacy qualification. The earlier [six-executed/two-unexecuted report](CONTINUATION-ADMISSION-CONTROLS.md) remains unchanged; this is a separate four-case result.

## Source, review and binary identity

The [source-only proposal](ADMISSION-INPUT-ADAPTER-PROPOSAL.md) and [independent bounded static review](../statistical/NATIVE-ADMISSION-ADAPTER-REVIEW.md) were frozen before the build. Their documentation commit is `c1e0f25aa1c305bfd29c61398e757b4c1f2d913d`.

| Identity | Pin |
|---|---|
| Protocol checkpoint | `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02` |
| Exact reviewed test-only commit | `fde0c288d42ff58482d8b05df85e033806b64ecb` |
| Native SDK commit | `01b532e8b553523216471682649693af92f0fd16` |
| Proposal manifest SHA256 | `a14dc8a23ec16d105c68de01ee9faa6cae715b00e95d9cc7cf7e9dd42e24cce8` |
| Independent review SHA256 | `ac42155f31d62a5b719f272e520c44b2b0e9633dacdb5d2747079d6da6b1a0b2` |
| Built executable SHA256 | `e41b448143cccc40404ff8978f9c9367ae641dfad19253d8cebed2f15fda9e71` |

Exclusive runtime root: `/home/luke/projects/kpi-orchestration/2026-10-22/native-surface-review/admission-input-adapter-runtime-v2`. Its `worktree/` is detached at the exact reviewed commit and remains clean. The sole proposed source addition is `poc/shared-pool/src/bin/kpi-admission-input-controls.rs`; no compiler-driven edit or later source revision was needed. All 24 proposal pins matched before compilation and again before validation.

A clean, exclusive `target/` built only the selected binary with the unchanged lockfile: `cargo build --locked --offline --release --bin kpi-admission-input-controls -j 8`. Existing source caches were used, but no previous rlibs or native build outputs were reused. Toolchain: Cargo 1.95.0, rustc 1.95.0 (`59807616e1fa2540724bfbac14d7976d7e4a3860`), LLVM 22.1.2, x86_64 Linux. The 13,801,856-byte binary was copied to read-only `bin/kpi-admission-input-controls` and hash-checked after the compiler unit was terminal.

## Executed matrix and attribution

Only the three pinned public lifecycle fixture files from the proposal were read: `lineage.json`, `parents.json`, and `vk.bin` under `poc/shared-pool/evidence/2026-10-20-wallet-lifecycle/positive/`. Admission is `lineage[2]`. Both UTXOs came from their unique referenced public parent outputs, with the original offline DAA-0/non-coinbase/no-covenant-ID context. All four canonical native transactions, original resolved UTXOs and actual engine results are retained in `test-outputs/native.jsonl`.

The unchanged native transaction full hash was exactly `7717bffe80fd65d1545d7928fa10bf0cab062a2608d7653f14552d716cefffc0`, matching the previously retained accepted receipt. Every preliminary gate passed at a 40,000,000-sompi fee. `SkipScriptChecks` was solely that preliminary gate; **full native validation and actual execution of both input VMs were separate mandatory checks**.

| Case, in executed order | Full native validator | Reserve input 0 VM | Funding input 1 VM | Intended evidence |
|---|---|---|---|---|
| Genuine unchanged admission | Accepted | Accepted; 14,929,196 script units | Accepted; 100,001 units | Genuine full-native/proof and per-input baseline |
| Interior funding signature byte changed; framing/SIGHASH_ALL retained | Rejected | Accepted; 14,929,196 units | `EvalFalse`; 100,000 units | Attributed funding failure without reserve-proof failure |
| Output 0 commits to successor with original VK IC points 1/2 exchanged | Rejected | `VerifyError`; 177,362 units | `EvalFalse`; 100,000 units | Reserve rejects substituted successor VK commitment |
| Output 0 commits to successor with two NOPs replaced by `OpFalse, OpDrop` | Rejected | `VerifyError`; 177,362 units | `EvalFalse`; 100,000 units | Reserve rejects substituted successor code commitment |

The full-validator funding control reported `false stack entry at end of script execution`. Both full-validator successor controls reported `script ran, but verification failed`; independently indexed VM outcomes establish which input rejected. Neither parsing, preliminary validation nor the funding-signature rejection was counted as reserve-guard coverage.

Every input VM retained the complete two-input transaction, both original UTXOs, `CovenantsContext::from_tx`, explicit TESTNET sigop cost of 100,000 script units, original allowed input budgets of 30,009,999 and 109,999 script units, and no sequence-commitment accessor. The exact complete-transaction JSON comparison permitted only the declared mutation and derived transaction ID. Proof, authorization, payload/state, current redeem, input-0 bytes, amounts, sequence, outpoints and storage mass were preserved.

Common preserved SHA256 identities across all four cases:

- Genuine existing proof: `fefa5b320bf3111007107d10fb04658de56929492396f2b97e75e7abe2970eeb`.
- Authorization: `88760f9139be9fb7a7bcc24e3909087e1c4859683cadfa78d7faaf9555d074e1`.
- Payload: `89101fb64369b9f4e0b867ba2e842ef70e24e98de0a54d1dfab65daa3a7e2307`.

Source interpretation remains precise: project `two_input/covenant.rs:116-132,568` constructs the expected successor script commitment from the current redeem and supplied successor state, then compares actual output 0. The substituted future redeem/key is **not executed** in these controls. The negative reserve guard precedes the ZK precompile, so those two rejections do not independently reverify the proof. The genuine baseline and the signature-only control's accepted reserve VM do execute the original genuine proof path. This is evidence about these implementation paths, not a cryptographic audit.

## Build, execution resources and cleanup

An earlier wrapper, `admission-input-adapter-runtime-v1`, incorrectly required all rolling memory-PSI averages to equal zero. It stopped before Cargo or native validation when those historical averages were nonzero despite 4,594,511,872 bytes of conservative headroom. That failed preflight was retained unchanged. Its unit used 0.028825 CPU-seconds and peaked at 7,278,592 bytes. It contributes **zero** validation cases.

The orchestrator explicitly authorized a new scheduling-wrapper revision using fresh ten-second pressure intervals, at least 2 GiB unreserved headroom after all caps, no sustained swap-out growth and no new OOM events. Consecutive intervals with at least 1% full-memory stalls would stop/escalate. This changed scheduling only; reviewed source, cases and acceptance criteria were unchanged. The original absolute build deadline remained **2026-10-22 10:46:59 UTC**.

The successful build unit qualified actual limits of 12 CPUs maximum on CPUs 2–13, 12 GiB aggregate RAM, zero swap, 256 PIDs, nice 10 and CPU weight 10. Cargo remained at eight jobs. It started at 09:53:46 UTC, began Cargo at 09:53:57 and completed at 09:56:35. Preflight available RAM was 22,783,004,672 bytes, leaving 5,468,917,760 bytes after the full build and still-reserved GPU caps. The fresh preflight interval had zero full stalls, swap-out growth and OOM growth. During the build, maximum sampled full-stall fraction was 0.2649%, with no sampled swap-out or OOM growth.

After compiler cleanup, the separate test unit qualified 1 CPU on CPU 13, 512 MiB aggregate RAM, zero swap, 64 PIDs, nice 10, CPU weight 10 and a 20-minute maximum. GPU capacity had been released; preflight left 22,355,656,704 bytes after this unit's cap, with zero fresh full stalls/swap-out/OOM growth. The adapter was invoked **once** and ran precisely its four predeclared cases. There were no retries or extra tests for utilization.

| Unit / invocation | Measured CPU time | Peak aggregate memory | Timing |
|---|---:|---:|---|
| `kpi-native-admission-build-v2.service` / `57dbc73038b74a49af11a00fc2fa0eeb` | 1,158.570829 s | 5,445,312,512 bytes | Cargo: 2m37s; controller including qualification: 168.39 s |
| `kpi-native-admission-tests-v1.service` / `3a4fd150e437431ca4921f5d28d59615` | 0.116382 s | 21,090,304 bytes | Four-case binary invocation: 0.03425 s; controller including qualification: 10.18 s |

Fifteen sampled ten-second build intervals averaged 7.46 CPU cores, ranging from 3.07 to 8.09. The whole build unit averaged about 6.88 cores including its qualification time. These are measured workload footprints, not a 12-core utilization claim or a performance benchmark. Both successful units' final cgroup records show zero swap and OOM events.

All three owned cgroup directories, including the failed initial preflight, were absent by the final 10:00:11 UTC cleanup receipt. Build/test MainPIDs were zero, the recorded Cargo PID was absent, and an executable-path scan found no process in this runtime package. Units were explicitly stopped, all native-lane CPU/RAM reservations were released, and raw outputs were preserved. No further run is queued.

## Frozen evidence and remaining limits

Within the runtime root:

| Artifact | SHA256 |
|---|---|
| `RUNTIME-MANIFEST.json` — 28 pinned files | `da6d0233e6f5313ad27765d46113f755c4d78f0c4edc1cc80975a287dd90090b` |
| `SUMMARY.json` | `9f1d2da6c403a38569a291aada6ab72cdaf96afdb2b46bccc502db6ffe905f7c` |
| `outputs/build-result.json` | `599e93ad4e640abec09421a92d74a67839088f3a53faf30d62a6f2034ab5aae3` |
| `test-outputs/result.json` | `37d91ba162fced03ca531e7c31a7c392beb8ae59e09757a368c81ee2a8778adf` |
| `test-outputs/native.jsonl` — actual canonical transactions and VM records | `d4f5b08896dbe91b8f38136a28956aae6f4c9ea81c75fa86cacd8f217d83370e` |
| `CLEANUP.json` | `6a71649a0830cf0e66f2d8a49f9e1ab73caaabffd295f152081fbd60cc3dc1c3` |

The manifest also identifies the separate failed-preflight manifest `ffd5d26f91c41be15853c0e182f1e4b7b094859b4556591669e09dd673c2e264` and its unchanged wrapper. All six old preflight output pins were rechecked before this final freeze. The new scheduling wrapper, runtime controller, logs, samples, binary and unit cleanup records are pinned without importing them into the canonical documentation repository.

This result narrows native-settlement coverage gaps for one historical public admission receipt at the pinned v6 checkpoint. It does not establish fresh chain acceptance/authenticity, global spentness, general equivalence for other covenant contexts, proof soundness, privacy, alternative VK validity or operation under other parameters. The unchanged earlier six-pass/two-unexecuted history and the new four-pass result must remain separate in cumulative accounting.
