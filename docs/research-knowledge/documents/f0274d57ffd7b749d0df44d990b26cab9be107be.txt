# Native payout and successor guard controls

**Result: 9/9 planned cases passed: two accepted genuine-proof baselines and seven native VM rejections.** This closes the specific actual-payout and successor-commitment coverage gaps identified in [the source review](CURRENT-V6-SETTLEMENT-BINDING.md). It is bounded offline native validation, not fresh chain evidence or a cryptographic soundness audit.

## Identity and ownership

- Protocol checkpoint: `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`.
- Exclusive test worktree: `/home/luke/projects/kpi-orchestration/2026-10-22/native-surface-review/guard-controls-v1/worktree`.
- Test-only commit: `dd00ceed35a95d10b6c79b80b744642244cb3226`, branch `test/native-guard-controls-20261022`. It adds six files under `poc/native-guard-controls/`; no core protocol changes, pushes or shared target writes.
- Runtime root: `/home/luke/projects/kpi-orchestration/2026-10-22/native-surface-review/guard-controls-v1`. All execution and report writing occurred on Forge. No private evaluation, new proof, network submission, funds or participant secrets were used.

The validator is an immutable exclusive copy of the existing `kpi-two-input-lifecycle` release binary, SHA256 `67d54d203f5e101deae92c388e0e961132a5896e871215d5e43444343d2382bd`. Its hash matches tracked `poc/shared-pool/native-usage-build.json` (SHA256 `5293f4a1520860fc0e1f4c8c991d2dd4121118bb8a6710dae42b24f408d9d3d1`). All 64 source hashes in that manifest matched the pinned worktree. No native validator was rebuilt.

`check-native` in `src/two_input/lifecycle.rs:363-382` parses canonical transaction JSON, checks supplied UTXO/outpoint correspondence, and calls `native::validate`; it does **not** reconstruct and reject a changed transaction before the VM. `src/native.rs:334-345` invokes full native validation, including the proof opcode when earlier guards succeed. The dependency is the root-lock-pinned rusty-kaspa `01b532e8b553523216471682649693af92f0fd16`.

## Public input and adapter qualification

Only the tracked `poc/shared-pool/evidence/2026-10-20-wallet-lifecycle/positive/` fixtures were consumed:

| File | SHA256 |
|---|---|
| `lineage.json` | `06078979ed5c84cf3234fdfee362b75464701cdb514cf205b7ce808ee0a989c5` |
| `parents.json` | `ab5d5e1de6d718dd0d8791cf89251743d1876fba72a958d0eb8082d178637408` |
| `vk.bin` | `9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef` |
| `descriptor.json` | `54d5f5687b767d84c626a8ab71763ad983a51626b0c667a44a3c032236a1edf6` |

These are genuine existing proofs and serialized public native transactions with synthetic ancestry. Neither their testnet network label nor this execution establishes TN10 acceptance. UTXO values/scripts were taken from the exact referenced prior public outputs; they were not changed in negative cases. The descriptor was pinned as fixture provenance; it is not an input to the direct native command.

A 14-line Rust adapter supplies the SDK's zero-padded keyed BLAKE3 domain hashes for canonical transaction IDs. Python reproduces the pinned SDK's `consensus/core/src/hashing/tx.rs:51-137,175-236` serialization. The adapter was built in its exclusive target with `cargo +1.95.0 build --release --locked --offline --jobs 1`; all nine resolved dependency identities/checksums were checked against the protocol lockfile, including exact `blake3=1.8.7`. No dependency install or update was needed. Adapter SHA256: `36b90d4cd2fbffb08cbe5d7b6146c7adf7cb77620316fd70bfd26617e7c9bbef`.

Before mutations, all seven untouched fixture transaction IDs matched, and reconstructing the successor script from current redeem bytes plus the public successor state reproduced the actual P2SH output. Native canonical parsing remained the authority for each mutated transaction's refreshed ID. No parser failure was counted as guard coverage.

## Executed matrix

Every negative case preserves the exact original payload, authorization and 128-byte proof. Cases are isolated from depositor signature failures by using single-input payout transactions. Continuing payout is fixture index 5 (reserve output 0, payout output 1); terminal payout is index 6 (payout output 0).

| Case | Mutation or baseline | Outcome / intended enforcement |
|---|---|---|
| Continuing baseline | Unchanged index 5 | Accepted full native validation, including genuine proof; 6.09 ms |
| Continuing amount | Decrease actual output 1 by one sompi; reserve and authorization unchanged | VM verification failure; `two_input/covenant.rs:585-590` |
| Continuing destination | Replace output 1 with another existing public 36-byte P2PK script | VM verification failure; `covenant.rs:591-595` |
| Successor VK | Output 0 commits to successor whose existing canonical IC points 1 and 2 are exchanged | VM verification failure at preserved successor commitment; `covenant.rs:116-132,568` |
| Successor domain | Output 0 commits to successor with one domain byte changed | Same successor commitment rejection |
| Successor code | Output 0 commits to successor with two trailing NOPs replaced by balanced `OpFalse, OpDrop` | Same successor commitment rejection; fixed script length |
| Current redeem/domain | Change one domain byte in the spending redeem script against the unchanged prior UTXO SPK | Native P2SH commitment rejection: false stack entry |
| Terminal baseline | Unchanged index 6 | Accepted full native validation, including genuine proof; 5.84 ms |
| Terminal destination | Replace actual output 0 destination with the public alternate P2PK script | VM verification failure; `covenant.rs:104-110,591-595` |

Six negative results report `failed to verify the signature script: script ran, but verification failed`; the current-redeem case reports `failed to verify the signature script: false stack entry at end of script execution`. Thus canonical parsing, amount/context prerequisites and mass checks did not supply the counted rejection. The exact opcode is not instrumented by this binary: attribution combines the recorded VM failure with the one-field mutation and source ordering. Earlier current-state, witness and authorization bytes are unchanged.

The successor VK case checks immutability of the output commitment. It does not execute the changed future script or claim a proof under its changed key. The current-redeem case intentionally tests the earlier P2SH commitment, not the later covenant domain comparison. Descriptor parsing/replay identity checks were already covered and were not repeated or relabelled as VM evidence.

Negative cases reject before `OpZkPrecompile`; they do not separately reverify the unchanged proof. The two accepted baselines execute the genuine proof through the full native validator. No terminal-amount repeat was added because it was already covered by the earlier suite.

## Resource qualification and cleanup

Fresh preflight had 22,815,657,984 available bytes, zero memory PSI averages, and 6,172,659,712 bytes of conservative headroom after reserving the entire 15.5 GiB concurrent cap budget. Root had released the failed GPU setup reservation; no GPU attempt was active.

Both owned units enforced 4 vCPU quota, affinity CPUs 8–11, **512 MiB aggregate RAM**, no swap, 64 tasks, `KillMode=control-group`, `OOMPolicy=stop`, and a finite deadline. Actual cgroup limits were checked inside the controller before execution. The baseline established a 20-minute overall deadline; controls also had a 10-minute unit limit and checked the original deadline at every case boundary. No repeat loop was used.

| Unit / invocation | CPU time | Peak aggregate memory |
|---|---:|---:|
| `kpi-native-guards-v1-baseline.service` / `e843f1ed02ab46589642b67d0aa4facd` | 2.053182 s | 114,892,800 bytes |
| `kpi-native-guards-v1-controls.service` / `8d8474adcd75414db2c5d7dc2bdfc584` | 0.143060 s | 31,932,416 bytes |

The tiny adapter build took 1.87 s. All nine native validator subprocesses together took 0.03058 s. Final in-unit snapshots recorded zero swap and zero memory-limit/OOM events. Systemd removed each completed cgroup before external cleanup capture; both absent cgroups were recorded and both owned units were explicitly stopped. Raw outputs are retained. No other unit, global controller or active build output was changed.

## Remaining coverage: which evidence would be needed

No additional proof is needed to close the specific guards exercised above. The following narrower coverage extensions remain unexecuted, rather than established acceptance defects. None is authorized as a new run by this report.

| Unexecuted extension | Existing proof or fresh proof? | Required distinction |
|---|---|---|
| Actual payout and successor commitments during mode-1 partial withdrawal, where commitments also append | **Existing public proof is available.** The retained TN10 rehearsal `chain-confirmed.json` row 7 is a single-input, two-output mode-1 payout of 211,000,000 sompi. | This lane used mode-2 DRAIN baselines. A mode-1 extension needs a direct-native positive baseline with its resolved prior UTXO, then isolated output changes; source sharing alone is not that executed evidence. |
| Successor commitment during two-input admission | **Existing admission proof is available** in the same positive lifecycle fixture (index 2). No new proof is intrinsically required. | An output mutation also invalidates the depositor signature. A reserve-input VM adapter using existing `native::script_units_at` would distinguish the intended successor guard from that unrelated signature; the current full-native helper does not expose per-input results. |
| Positive native acceptance with a legitimately authorized fee other than the retained 40,000,000 sompi | **A proof for that authorization is required.** No such fixture was used or located in this bounded lane; an available genuine fixture could suffice, otherwise a new public development proof would be needed. | Editing the authorization fee in an old proof is an invalid-proof control, not positive fee-binding evidence. This is broader fee-policy coverage and is not necessary to establish the current output guards. |

The TN10 row above was inspected as public fixture metadata only after execution; it was not rerun. Its retained file SHA256 is `75ad01a25b1c534a59f5690c69556584a72e31cb6afeb914530104f00962b3b8`. Exact opcode traces would require an instrumented validator, not new proofs; current attribution remains VM errors plus isolated changes and source ordering.

## Stable evidence and remaining boundary

Under the runtime root:

- `outputs/summary.json`: SHA256 `1076736b16da6a67579b5364e4adb93057be1b2a68daea6fee0a1681143b1ad1`.
- `RUNTIME-MANIFEST.json`: SHA256 `fc6989f26df146639804fb0486aeb9c1b1b45e09e7453e7fc23a741d60db3c67`; pins 64 source/runtime/binary files, including per-case transactions, UTXOs, stdout/stderr, timings and resource snapshots.
- `outputs/input-pins.json` retains the full source/fixture provenance; `outputs/baseline/results.json` and `outputs/controls/results.json` distinguish full native acceptance from early VM rejection.

Self-review confirmed that mutated outputs cannot be credited as success, proof/auth bytes stay fixed, old UTXOs stay fixed, current-script and future-script tests are labelled separately, unqualified errors stop rather than retry, and only public fixtures enter the controller. The scoped coverage gap is closed for these fixed cases; chain authentication/freshness, ciphertext usability, private relation completeness and cryptographic soundness retain the boundaries stated in the original review. More identical runs would add utilization without new coverage.
