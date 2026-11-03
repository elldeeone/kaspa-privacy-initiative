# Mode-1 continuation and admission native controls

**Six of six executed cases passed.** The eight-slot plan produced two accepted genuine-proof baselines, four isolated mode-1 native guard rejections, and **two admission mutations NOT EXECUTED** because the existing validator cannot attribute a multi-input failure to the intended input. No admission negative coverage is claimed.

This is a separate result from [the frozen nine-case lane](NATIVE-GUARD-CONTROLS.md). That package, its code and outputs were preserved unchanged. No new proof, native build, dependency install, private evaluation read, network submission or core protocol change occurred.

## Pinned implementation and public fixtures

- Protocol commit: `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`.
- New worktree base: `dd00ceed35a95d10b6c79b80b744642244cb3226`.
- Test-only source commit: `c430dd8a18d738a2d6ead9246d9650a4c1fe1933`, branch `test/native-continuation-admission-20261022`; three new files under `poc/native-continuation-controls/`. No push.
- Exclusive worktree: `/home/luke/projects/kpi-orchestration/2026-10-22/native-surface-review/continuation-admission-v1/worktree`.
- Exclusive runtime root: `/home/luke/projects/kpi-orchestration/2026-10-22/native-surface-review/continuation-admission-v1`.

All 64 files in the frozen v1 manifest were verified before making new immutable copies of its validator and ID adapter. The 64 source hashes in tracked `poc/shared-pool/native-usage-build.json` also matched this worktree. Reused binary SHA256 values:

| Binary | SHA256 |
|---|---|
| `kpi-two-input-lifecycle` | `67d54d203f5e101deae92c388e0e961132a5896e871215d5e43444343d2382bd` |
| `kpi-native-guard-id` | `36b90d4cd2fbffb08cbe5d7b6146c7adf7cb77620316fd70bfd26617e7c9bbef` |

The exact public fixture pins, relative to `poc/shared-pool/`, are:

| Fixture | SHA256 |
|---|---|
| `evidence/2026-10-20-two-input-tn10/rehearsal/chain-confirmed.json` | `75ad01a25b1c534a59f5690c69556584a72e31cb6afeb914530104f00962b3b8` |
| `evidence/2026-10-20-two-input-tn10/verification-key.json` | `4fd7dc563e4a1f843c99d5517485ba7664a7dcb69057784ca2fac066b20cddaf` |
| `evidence/2026-10-20-wallet-lifecycle/positive/lineage.json` | `06078979ed5c84cf3234fdfee362b75464701cdb514cf205b7ce808ee0a989c5` |
| `evidence/2026-10-20-wallet-lifecycle/positive/parents.json` | `ab5d5e1de6d718dd0d8791cf89251743d1876fba72a958d0eb8082d178637408` |
| `evidence/2026-10-20-wallet-lifecycle/positive/vk.bin` | `9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef` |

Mode-1 uses row 7 of the public rehearsal record: one input, a continuing reserve plus 211,000,000-sompi payout, and two new commitments. The adapter checked that successor CM and NF counts each increase by two and that the reconstructed successor P2SH script matches the actual output. Its accepted native full hash matches the retained row's full hash. This is consistency with a historical record, not a new TN10 acceptance or freshness check.

Admission uses index 2 of the lifecycle positive lineage with two inputs and explicit synthetic ancestry. UTXOs for both baselines are resolved from the exact referenced public prior outputs. Their canonical transaction IDs matched the unchanged ID adapter before native validation.

## Finite matrix and outcomes

Both full-native baselines ran before any negative case. Every executed negative changes one actual output property and refreshes its canonical transaction ID. All input bytes, proof, authorization, payload/state/witness bytes and storage mass remain unchanged. The mode-1 cases have one input, excluding unrelated depositor-signature failures.

| Slot | Case | Outcome and coverage |
|---|---|---|
| 1 | Genuine mode-1 partial payout with two CM appends | **Accepted**, full native/proof validation; 6.61 ms |
| 2 | Genuine two-input admission | **Accepted**, full native/proof and funding-signature validation; 6.33 ms |
| 3 | Mode-1 actual payout output 1 decreased by one sompi | **VM rejected**, payout amount binding; `two_input/covenant.rs:585-590` |
| 4 | Mode-1 actual payout output 1 changed to another public P2PK script | **VM rejected**, destination binding; `covenant.rs:591-595` |
| 5 | Mode-1 reserve output 0 commits to successor with two existing VK IC points exchanged | **VM rejected**, preserved successor VK commitment; `covenant.rs:116-132,568` |
| 6 | Mode-1 reserve output 0 commits to successor with two trailing NOPs replaced by balanced `OpFalse, OpDrop` | **VM rejected**, preserved successor code commitment; same enforcement |
| 7 | Admission successor VK mutation | **NOT EXECUTED**: no existing verified per-input validator adapter |
| 8 | Admission successor code mutation | **NOT EXECUTED**: same attribution blocker |

The successor mutations retain the genuine newly appended CM state. They test that the output cannot substitute other redeem bytes while preserving that state. They do not execute a changed future script or claim a proof under a changed VK.

All four counted rejections reached the native VM and returned `failed to verify the signature script: script ran, but verification failed`. No parsing, ID, mass, depositor-signature or generic prerequisite error was counted. `lifecycle.rs:363-382` calls the direct canonical parser and full validator through `native.rs:334-345`, without replay reconstruction rejecting the mutation first. Exact opcode attribution combines the observed VM error with isolated changes and source ordering; no opcode trace was added. These early guards precede `OpZkPrecompile`, so the negative runs do not separately reverify the proof. The two positive baselines do.

## Why admission mutations remain untested

At the pinned native SDK commit `01b532e8b553523216471682649693af92f0fd16`, `consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs:20-21,181-208` selects parallel script verification when there is more than one input. The aggregate error does not identify which input failed. A successor-output mutation also changes the depositor's `SIGHASH_ALL` message, invalidating its existing signature.

A full-validator rejection would therefore not, by itself, establish the intended admission successor guard. Setting one Rayon worker or running more attempts is not a per-input attribution interface. No existing provenance-verified helper exposing `native::script_units_at(..., 0)` was available; the independent relation lane confirmed its binary excludes native validation. The two slots were marked unexecuted before the first validator invocation. No ambiguous admission mutation was tried, retried or credited.

An isolated reserve-input adapter could use the already-retained genuine admission proof; no fresh proof is intrinsically needed. Such a helper would need separate implementation/build qualification and a positive reserve-input baseline. It was outside this lane's bounded execution and was not built.

## Actual resource envelope and cleanup

Fresh preflight had 22,403,436,544 available bytes, zero memory PSI averages, and 4,552,478,720 bytes headroom after conservatively reserving all recovery 12 GiB, GPU 4.125 GiB and this lane's 0.5 GiB caps. The relation owner confirmed its completed units, cgroups and PIDs were gone. Headroom was refreshed before the negative batch.

Actual in-controller checks confirmed **1 CPU quota, CPU 13 affinity, nice 10, CPU weight 10, 512 MiB aggregate RAM, no swap and 64-task limit**. Children inherit these constraints. Both units used `KillMode=control-group` and `OOMPolicy=stop`; the baseline established a single absolute 20-minute deadline, and the controls unit additionally had a 10-minute limit. The finite case runner checks the original deadline and the root quiet-window marker at case boundaries.

| Unit / invocation | CPU time | Peak aggregate memory |
|---|---:|---:|
| `kpi-native-continuation-v1-baselines.service` / `672b1138d2434981bfc063a447935963` | 0.083776 s | 29,528,064 bytes |
| `kpi-native-continuation-v1-controls.service` / `de0a6c29adae49d49daf4506dd2d67c6` | 0.099104 s | 29,470,720 bytes |

All six native subprocesses together took 0.02924 s. Both final cgroup snapshots show zero swap, OOM and memory-limit events. Systemd removed each completed cgroup before external status capture; absence was recorded and both owned units were explicitly stopped. The 1 CPU / 512 MiB reservation was released. Outputs remain preserved; no other service, global controller, active build output or GPU workload was changed.

## Frozen evidence and limits

Under the runtime root:

- `outputs/summary.json`: SHA256 `638938c3514a43a9c41d2415620781607041dd420c57afc890cf5dc592c49116`.
- `RUNTIME-MANIFEST.json`: SHA256 `ea893526c1c0f61efba7432abbfe9ba74c2e3c129c8475b7023304b34def6f09`; pins 49 code/runtime/binary files.
- `outputs/PLAN.json`, per-case transaction/UTXO files, stdout/stderr, provenance, timings and unit snapshots preserve the six executed results and two explicit non-results.

Self-review checked the positive-baseline prerequisites, single-output mutations, unchanged proof/auth/context, canonical-ID parity, failure classification, refusal to infer admission coverage, no-retry behavior and owned-unit cleanup. This extends executed payout/successor binding coverage to a mode-1 withdrawal with CM appends. It establishes only a valid admission baseline; admission negative attribution, chain authenticity/freshness, nondefault-fee proofs, delivery usability and cryptographic soundness remain outside the result.
