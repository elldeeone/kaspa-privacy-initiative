# One-v6 compatibility: offline build readiness

**BLOCKED at an offline dependency prerequisite; no build or verification was run.** Reference Cargo metadata resolved 377 packages and 377 nodes and identified the exact `one_v6_reference` binary. Candidate metadata exited **101** because the mounted offline registry could not resolve `k256`. This is an environment/readiness result, not a verifier rejection or a finding of cryptographic incompatibility.

Owner: `/root/compute_plan`. Assessment began **2026-10-22 11:13:29 UTC / 22:13:29 AEDT**, with a fixed **11:33:29 UTC** deadline. Metadata stopped at the decisive failure at **11:18:41 UTC**; source/cleanup clarification finished at 11:22:31 UTC. Root released the 1 CPU / 1 GiB metadata reservation. No GPU reservation or later build allocation exists.

The source worktree is `/home/luke/projects/kpi-one-v6-compatibility-2026-10-22`, at `acba8b04237e62a5bbc3eb93eb10faa1722a59ea`, parent `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`. Its only additions are the two adapter files. All **11** captured source/manifest/lock hashes matched afterward, and Git status remained clean. Adapter semantics belong to the separate source review.

The protocol SHA-256 is `b01cd6bbb4b0d9f097277e5986b0b4de7001b97896f5f74f3777d1ff50919932`; the implementation handoff SHA-256 is `1b0a74e1afe9d56d9bba8a62b23ed83df88ebd398f539fd987542ee2f3ade2dc`. Both were rechecked. Key unchanged inputs:

| Path relative to source worktree | SHA-256 |
| --- | --- |
| `poc/shared-pool/Cargo.toml` | `cfdc8e104c93e4575b1f2cf5d9b441566674b7b801856d18fc7aeb5ba50234f3` |
| `poc/shared-pool/Cargo.lock` | `13007a446f0d9561d50b18897b52a98c951584b2e6c7c721c95580287f5edc64` |
| `poc/takeover/Cargo.toml` | `9c4fdec4e6f70b70d8d5ebf4b9f9f56fbe3db2d257b18ee865d6e2d47d3f0e6a` |
| `poc/takeover/host/Cargo.toml` | `b0d062c0ef1eb1d8db31dac19177034b4c2134ee277a04d8f391dbec47209bf7` |
| `poc/takeover/Cargo.lock` | `6e2715918e0dfb9d1a9968021513065bc6653d8ae22d4b97d9b2d5e7d993e0ea` |

Fresh capacity passed before allocation. Consecutive intervals **11:14:09–11:14:19** and **11:14:19–11:14:29 UTC** each recorded **0% full memory stalls, zero swap-out growth and zero OOM-kill growth**. Host CPU busy was 0.7854% then 0.1927% across 14 logical CPUs. Last MemAvailable was 22,413,377,536 bytes; conservative headroom after the 1 GiB cap was 21,339,635,712 bytes, above the 2 GiB requirement. Existing swap occupancy was about 1.02 GiB; it did not grow through swap-out. Process/unit metadata showed only light background work, including Codex and rclone sync, with old failed units retained as inactive failure records. GPU metadata was RTX 3070, 0%, 1 MiB / 8192 MiB and no compute owners. These are bounded observations from this assessment, not current capacity guarantees.

The implementation's proposed `+1.91.0` toolchain was **not installed** in the inspected toolchain directory. Existing version directories were 1.94.0, 1.95.0, 1.97.1 and stable. No rustup shim or downloader was invoked. Metadata used only these pre-pinned, regular, uid/gid 1000:1000, mode 0755 binaries:

| Existing absolute executable | SHA-256 |
| --- | --- |
| `/home/luke/.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin/cargo` | `828980723df339d62434390e9fb8ef8831036583343ae2316b7ab5646b5c1953` |
| `/home/luke/.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin/rustc` | `d3a664c970a9fd8361b64194861bebc1ae37b9054e5ee3400dc1c9e691797eea` |

Observed Cargo was **1.97.1**, commit `c980f4866141969fab6254a680546a277789d6f0`; rustc was **1.97.1**, commit `8bab26f4f68e0e26f0bb7960be334d5b520ea452`, LLVM 22.1.6. Host and selected target were **x86_64-unknown-linux-gnu**. The bare rustc cfg query identified Linux/GNU, little endian, 64-bit, fxsr/sse/sse2 and unwind; its default debug cfg is not an attestation of a release build. This metadata identity does not silently substitute 1.97.1 for the unrun 1.91.0 build proposal.

Each command had a separate owned systemd unit, **1 CPU / 1 GiB / zero swap / 64 PIDs**, with actual cgroup values recorded. The payload used CPU 0 via taskset; the short timeout launcher could briefly retain affinity 0–13, while the whole unit remained capped at 1 CPU. Each command had a 50-second inner timeout, 4-second kill grace, 55-second systemd runtime cap and 5-second stop limit. The metadata allocation's absolute window was **11:17:19–11:22:19 UTC**, within the overall deadline. At most one unit ran at once.

A new metadata-only controller used Bubblewrap with unshared namespaces/network and cleared environment. Source, the exact toolchain, and existing Cargo registry/git caches were mounted read-only. Only the exclusive receipt directory was writable, with a private Cargo home and separate `reference-target` / `candidate-target` directories. Private artifacts were Cargo's empty package lock, global cache database and two `.rustc_info.json` files; no compiled binary was created. Shared caches, manifests, locks and runtime configuration were not repaired or updated.

Commands were `cargo -Vv`, `rustc -vV`, `rustc --print cfg --target x86_64-unknown-linux-gnu`, and one metadata command per workspace:
`cargo metadata --frozen --offline --format-version 1 --filter-platform x86_64-unknown-linux-gnu --manifest-path <workspace>/Cargo.toml`.
The workspace paths were `poc/shared-pool` and `poc/takeover`. No Cargo tree retry, network resolution, fetch, install, build, check, test, adapter run, build-script execution or verification followed the failure.

| Probe | Exact owned unit | Invocation | Exit | Dispatch-to-cleanup seconds | Cgroup peak bytes |
| --- | --- | --- | ---: | ---: | ---: |
| cargo-version | `kpi-one-v6-meta-cargo-version-111719.service` | `e4754a17ef364d14bb4a8cb6b8e0acc8` | 0 | 0.138713 | 8204288 |
| rustc-version | `kpi-one-v6-meta-rustc-version-111719.service` | `5d917c8c81d24368a7cab2decfe7cff5` | 0 | 0.134515 | 42201088 |
| target-cfg | `kpi-one-v6-meta-target-cfg-111719.service` | `e3fa1cd2ada542cc92a1b2fc57de3cf9` | 0 | 0.139020 | 14876672 |
| reference | `kpi-one-v6-meta-reference-111719.service` | `4426286e85be4af3a33476ed6b9e2fcf` | 0 | 0.462140 | 107991040 |
| candidate | `kpi-one-v6-meta-candidate-111719.service` | `7724872c78b945efa65ed3279958283f` | 101 | 0.250705 | 30990336 |

Total recorded dispatch-to-cleanup time across the five commands was **1.125093 seconds**; the reference metadata unit peaked at **107,991,040 bytes**. These short metadata measurements cannot estimate a full host build. The terminal audit at **11:22:31 UTC** found all **18 recorded PID/start-time identities absent**, all five cgroup paths absent, and MainPID/ControlPID 0 with empty ControlGroup for every unit. Successful units were unloaded; the candidate's failed exit-code record remains loaded without processes. No signal was sent to an unrelated process.

Reference feature evidence: `kpi-shared-pool` has no declared root features; the metadata root feature set is empty and the exact binary is an edition-2024 auto-discovered target. Resolved Ark BN254/Groth16/FF/EC/relations/serialization libraries are 0.6.0 (the separate crypto-primitives macro package is 0.5.0). Effective Groth16 features are default/parallel/rayon/std; crypto primitives include constraints, crh and parallel. Full node feature lists and custom-build target inventory are retained. The 377-package metadata result is a **resolution result**, not a count of exact build units or proof that every build-time source, native tool, header or external asset is available.

Candidate static manifest evidence: the edition-2021 host is an existing member of the takeover host/common workspace. Its direct Ark libraries are 0.5.0; it enables the comparison common crate's circuit/parallel features. The host's unconditional `risc0-zkvm = 3.0.3` dependency leaves defaults enabled; the cached manifest defaults are client/bonsai, and the separate prove/cuda features must not be conflated with those defaults. Client brings build/tool-management dependencies, but that alone does not prove an implicit guest build. The local covenant build script computes and serializes verifier identity constants into OUT_DIR; its inspected source does not itself generate a proof or invoke a guest build/download. No such script was executed. Complete candidate feature unification and transitive build-script/asset closure remain **unqualified**, because resolution failed first. The reference inventory also contains native and RISC Zero custom-build targets; their presence is not an execution result or a completed side-effect audit.

The exact observed candidate chain is:
`kpi-takeover-host → vprogs-zk-backend-risc0-runtime-processor` at `f9b84a863a7c7c20586a9cf947550475e894f72e` → `k256`.
The lock pins **k256 0.13.4**, source `registry+https://github.com/rust-lang/crates.io-index`, checksum **`f6e3919bbaa2945715f0bb6d3934a173d1e9a59ac23767fbaaef277265a7411b`**. A narrow file-metadata check in the exact mounted registry `index.crates.io-1949cf8c6b5b557f` found the sparse/plain index entry, `src/k256-0.13.4` directory (including manifest/checksum file), and `cache/k256-0.13.4.crate` all absent. Cargo's failure demonstrates the missing offline resolution prerequisite; the file checks additionally show no source/archive for that locked version in this cache. Other repositories or alternate cache routes were not searched. No claim is made that k256 is the only remaining gap. The previously noted absent `risc0-bigint2-1.4.14` manifest was not used to infer target relevance or incompatibility.

The paired build is **not ready for allocation**. A later decision must resolve the exact toolchain choice and missing locked dependency in a separately authorized scope, then complete offline closure and transitive build-script/native prerequisite review before any build. Required host-build CPU/RAM/wall budgets remain **unknown** from this metadata-only evidence; no previous unrelated build estimate is transferred. The protocol's later sequential verifier proposal remains **1 CPU / 1 GiB / no swap / five minutes each**, unrun and unauthorized by this assessment.

Raw receipts are frozen under:
`/home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/one-v6-build-readiness`.
Receipt manifest SHA-256: **`0c1287d1c3dfba8531d3f96f2fa6f539c62dc9b829ca9647e0ccb5d04107cecc`** (31 leaves, 2,549,636 bytes).
Primary machine receipts are `capacity.json`, the five `command-logs/*/receipt.json` files, exact stdout/stderr, `source-after-and-k256.json`, `reference-metadata-summary.json`, `terminal-cleanup.json` and `final-assessment.json`. No old GPU/proof/recovery attempt was reopened.
