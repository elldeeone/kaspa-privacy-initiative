# Admission per-input native adapter: source-only proposal

**GO for independent source review; execution remains deferred.** The pinned native SDK exposes enough public API to test the reserve input of the existing genuine admission receipt while retaining the complete two-input transaction and its original UTXOs. A single 246-line test-only binary is proposed. It is **uncompiled and unexecuted**: there are zero new case results, proof generations, chain submissions or changes to production validation.

The prior [continuation/admission report](CONTINUATION-ADMISSION-CONTROLS.md) remains six executed passes and two admission successor mutations **NOT EXECUTED**. Its SHA256 is `62c998e90cfdd9a09cd1065311ed2b1c2dbe217de4ad7e03dcfbc2435490f281`, committed in docs commit `ae1871eabdca7d52ca317b63b6bf8cf2ff13c3e9`. This proposal supplies no retrospective negative admission coverage. It is independent of the rejected recovery-v2 job and contains no recovery wrapper, setup, proving or recovery scenario.

## Immutable review package

- Exclusive package: `/home/luke/projects/kpi-orchestration/2026-10-22/native-surface-review/admission-input-adapter-proposal`.
- Worktree: that package's `worktree/`; branch `test/native-admission-adapter-proposal-20261022`.
- Protocol checkpoint: `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`; test-code base: `c430dd8a18d738a2d6ead9246d9650a4c1fe1933`.
- Proposed test-source commit: `fde0c288d42ff58482d8b05df85e033806b64ecb` (not pushed).
- Sole addition: `poc/shared-pool/src/bin/kpi-admission-input-controls.rs`, SHA256 `54932085b15a44c97669d905643c2c270a7ce555c6cb26ff0a8858bc1ed796e2`.
- `ADAPTER.patch`: SHA256 `9a3c020fc08a39839551e00eb9d97bfdaec1cf1eb8f593d619034e7aca40bfee`.
- `PROPOSAL-MANIFEST.json`: SHA256 `a14dc8a23ec16d105c68de01ee9faa6cae715b00e95d9cc7cf7e9dd42e24cce8`; pins 24 files, including patch, source, fixtures, exact SDK interfaces and prior report.
- Native SDK: `01b532e8b553523216471682649693af92f0fd16`, at `/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e`.

All pinned tracked source/fixture bytes were compared with their Git objects. `native.rs`, `two_input/covenant.rs`, `Cargo.toml` and `Cargo.lock` are unchanged from the protocol checkpoint. `git diff --check` passed; no compiler, formatter, import, validator or proof command was run. The source package and previous runtime packages are separate. All new report/source writes occurred on Forge.

## Public receipt and exact baseline

Only the already-published `poc/shared-pool/evidence/2026-10-20-wallet-lifecycle/positive/` fixture is read by the proposed binary. No arbitrary fixture path or workload argument is accepted.

| File | SHA256 |
|---|---|
| `lineage.json` | `06078979ed5c84cf3234fdfee362b75464701cdb514cf205b7ce808ee0a989c5` |
| `parents.json` | `ab5d5e1de6d718dd0d8791cf89251743d1876fba72a958d0eb8082d178637408` |
| `vk.bin` | `9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef` |

Admission is `lineage[2]`: mode 0, two inputs, one 3,120,000,000-sompi reserve output and a 40,000,000-sompi fee. Its native transaction ID is `b2af5cebd66b8e5593af9fe2ce34226b44d52d8ae1f19310690273f1a79e5ca3`; the previous accepted full-native hash is `7717bffe80fd65d1545d7928fa10bf0cab062a2608d7653f14552d716cefffc0`. Both are asserted before any case.

Each UTXO is resolved from its unique exact referenced public parent output, whose native representation must parse canonically. Input 0 references `5a7c46413e63171420615fdf5fa7df709dd78d234a93d68d294d0ec4ae726b36:0`; input 1 references `71ad573cf68f5bf68e2fb3576fdb81f2fac76a40f2838e4844c3d4b5b05ed9e8:0`. The original public offline context is DAA 0, non-coinbase, no covenant ID. `Utxo::output`, `outpoint` and `entry` preserve value and script and verify the selected outpoint. These synthetic-ancestry entries do not attest to current chain spentness or authentication.

The unchanged successor is reconstructed from the current redeem prefix, actual payload successor state and current redeem suffix. Its SDK P2SH script must equal the actual output before either successor mutation is constructed. This checks the hard-coded v6 layout against the pinned receipt, rather than assuming offsets describe an unrelated script.

## Full-validator and per-input equivalence requirements

Paths in this table are relative to the pinned project or native SDK; their exact hashes are in the manifest.

| Property | Production enforcement and proposed adapter |
|---|---|
| Full transaction acceptance | Project `native.rs:319-345` constructs the TESTNET validator and uses `TxValidationFlags::Full`. The adapter calls this unchanged function separately in **every** case (`adapter:195-201`). |
| Pre-script prerequisites | Adapter `50-58` calls `native::metrics` for the same private amount/shape checks, isolation validation, then populated validation at POV DAA `1,000,000,000` and block DAA `2,000,000,000,000`; fee threshold and sequence accessor are `None`. `SkipScriptChecks` is only a preliminary gate. SDK `tx_validation_in_utxo_context.rs:37-65` still checks maturity, amounts, mass, sequence and covenant context. |
| Actual VM execution | Adapter `61-89,206-221` executes **both** inputs separately only after that gate passes. Each engine sees the complete mutated transaction and both original entries; no input, output, proof or signature is removed to isolate a result. |
| Covenant context | `CovenantsContext::from_tx(&populated)` exactly mirrors SDK `tx_validation_in_utxo_context.rs:176-178`, and is attached to `EngineCtx` just as in `163-174`. No default empty context is assumed. |
| Flags and budget | `EngineFlags { sigop_script_units: Gram(TESTNET_PARAMS.mass_per_sig_op).into() }`; each input retains its own `compute_commit.allowed_script_units()`. This mirrors SDK `163-208`. The receipt's compute budgets remain 3000 and 10. |
| Sequence commitment | Explicit `with_seq_commit_accessor_opt(None)` matches this public offline `native::validate` caller. No external sequence-commitment implementation is invented. |
| Hash/cache context | Fresh signature cache and unsynchronized reused-hash object per input; the full multi-input validator normally uses synchronized cached hashes through Rayon. The algorithms consume the same complete transaction. Cache/thread differences are a source-reasoning claim pending the baseline and attribution controls, not an already-executed equivalence result. |
| Canonical identity and mutation isolation | SDK `Transaction::finalize` refreshes ID; native JSON round-trip must parse. Equality against the original JSON permits only the declared field plus derived ID. Proof, input-0 script, payload/auth/state, values, storage mass, outpoints, sequence and budgets remain unchanged. |

The existing convenience `native::script_units_at` does not explicitly attach a covenant context and uses default flags. The proposal instead constructs the documented public engine with the full validator's explicit context and TESTNET flags. Production code is neither edited nor relaxed.

## Four fixed cases, in mandatory order

All entries below are **expected outcomes**, not execution results. Every case must pass the preliminary gate at the same 40,000,000-sompi fee. No negative case starts unless the preceding case satisfies its whole outcome contract.

| Case | Only mutation | Required full validator | Required input 0 / input 1 VM outcomes |
|---|---|---|---|
| 1. Genuine admission baseline | None | Accept at pinned full hash and fee | Accept / accept |
| 2. Funding-signature attribution | XOR one interior byte at signature-script index 32 of input 1; preserve 66-byte length, push byte 65 and final `SIGHASH_ALL` byte 1 | Reject | Accept / `EvalFalse` |
| 3. Admission successor VK | Output 0 P2SH commits to a same-length successor with original compressed VK IC points 1 and 2 exchanged | Reject | `VerifyError` / `EvalFalse` |
| 4. Admission successor code | Output 0 P2SH commits to a same-length successor whose final two NOPs are replaced by balanced `OpFalse, OpDrop` | Reject | `VerifyError` / `EvalFalse` |

Case 2 is essential: it must demonstrate a genuine reserve-proof acceptance despite an attributed funding-signature failure. Admission's current covenant inspects the funding outpoint, amount, script, coinbase/covenant metadata, sequence, signature length and framing (`two_input/covenant.rs:301-353`), so changing its interior signature bytes should preserve those reserve prerequisites. The native SDK's `OpCheckSig` and Schnorr verifier (`crypto/txscript/src/opcodes/mod.rs:827-848`, `lib.rs:856-874`) make the expected funding failure a signature check rather than malformed push parsing.

Cases 3–4 alter the actual future output commitment, keeping the current redeem, genuine proof, authorization and appended state unchanged. The source target is `two_input/covenant.rs:116-132,568`: preservation of the successor's original code/VK through the output P2SH equality. Their changed output also invalidates the retained funding signature; only **input 0's separate VM rejection** can count toward the intended guard. Aggregate rejection alone remains insufficient. These guards precede the ZK precompile; their negative results would not themselves reverify the genuine proof or execute the candidate future redeem/VK. They test the successor commitment, not correctness of an alternative circuit/key.

## Output and stop contract

The proposed binary emits flushed JSON lines: one plan, four per-case records and a final complete summary only if every case satisfies its contract. Each case records the full canonical transaction, original resolved UTXOs, native full hash, full-validator result, separately labelled preliminary gate, indexed VM accept/error variant/display message and used/allowed script units. Proof, authorization, payload, current redeem and successor SHA256 values identify the unchanged bytes and intended mutation.

`pre_script_gate_is_transaction_acceptance` and `chain_acceptance_verified` are always false. Any fixture/source pin drift, shape/ancestry/round-trip failure, baseline disagreement, wrong VM error, unexpected acceptance or resource termination stops the run without retries. A failed gate cannot earn VM coverage; parser, pre-script or funding failures cannot earn reserve-guard coverage. Partial stdout/stderr must be retained; a fatal record or absent final summary means incomplete. No valid proof or new signature is generated to repair an unexpected result.

## Resource proposal and remaining build requirement

**No resource reservation, build or execution is currently requested to start automatically.** Independent exact-patch review comes first. This binary uses the existing Cargo dependency graph and unchanged lockfile. It may link the native consensus/RocksDB graph; it is not comparable to the earlier tiny standalone ID-helper build.

A later **qualified warm-cache build** could be proposed at at most **2 CPU / 4 GiB aggregate RAM / zero swap / 20 minutes**, using an exclusive target directory, `cargo build --locked --offline --release --bin kpi-admission-input-controls -j 2`, and no dependency install/fetch. The earlier public binary manifest pins its sources and executable, **not a dependency rlib cache**. No cache is presently qualified. An inactive cache would need owner-confirmed inactivity and matching lock/source/toolchain/build provenance before copying it into this lane. Never read or write an active build's outputs. If no suitable cache exists or Cargo requires a cold native dependency rebuild, defer and report the separate cold-build resource requirement; do not silently perform it under this estimate. No new build has been measured.

If a binary is separately built and pinned, the four-case execution proposal is **1 CPU / 512 MiB aggregate / zero swap / 20-minute absolute limit**, CPU 13, nice 10, low CPU weight, with one owned systemd cgroup and controller/children inside the same cap. The previous admission baseline took 6.33 ms and its two-case unit peaked at 29,528,064 bytes; those are historical measurements of another binary, not this adapter's footprint. A root-approved controller must qualify actual memory/swap/CPU limits, preserve outputs, stop at safe case boundaries for any quiet window, and confirm the unit and children are gone on completion. No retry or extra cases for utilization are proposed.

Before either phase, refresh memory PSI and available RAM, account for all remaining reserved caps, require at least 2 GiB unreserved headroom and coordinate CPU allocation with the orchestrator. CPU 0–1 stay reserved for GPU activity. The current source assessment holds **no** execution reservation. A build budget, qualified build inputs and an execution controller remain explicit prerequisites.

Self-review found no production acceptance-path modification, signing/proving route, private-data input, networking or broad workload path in the patch. The proof of feasibility is the existing public API and exact source mapping; successful compilation, actual per-input equivalence, both missing guard outcomes and fresh chain acceptance are all still unverified.
