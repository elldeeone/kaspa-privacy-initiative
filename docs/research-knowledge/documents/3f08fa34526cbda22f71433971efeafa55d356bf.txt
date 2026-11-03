# One-v6 dependency preparation: released standard Cargo path

Root explicitly selected **standard pinned Cargo fetch**, followed by one frozen/offline host metadata check per workspace, in a single bounded acquisition release. Informational compiler/host-target probes are allowed. Dependency compilation, build scripts, check/test/run, guest/proof generation and verifier execution remain excluded. This changes acquisition mechanics and explicitly approves the environment choice; it does not alter the frozen comparison, sources, locks, fixtures or scientific criteria.

The earlier data-only proposal was superseded before execution. Its exact 19,118 bytes are preserved at `/home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/one-v6-dependency-preparation/proposals/data-only-protocol-v1.md`, SHA-256 `53df46b4d35df15849a116820fa29860031958c9e880d4068bcb8f59f42584f3`. No custom package manager, local registry, dependency-source replacement, downloader or transport-meter service was implemented. The direct source-download proposal's transfer-byte caps do not apply to normal Cargo; the released cache/disk, memory, CPU and wall limits below do.

The document-only task started 2026-10-22 11:29:34 UTC, with a 11:44:34 UTC deadline. Root then issued a separate execution release. Actual acquisition began **11:39:57.252534 UTC / 22:39:57 AEDT**, with absolute deadline **11:59:57.252534 UTC** and a monotonic 1,200-second clock. Owner is `/root/compute_plan`.

## Exact immutable inputs and toolchain addendum

Source: `/home/luke/projects/kpi-one-v6-compatibility-2026-10-22`, HEAD `acba8b04237e62a5bbc3eb93eb10faa1722a59ea`, parent `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`. The comparison protocol remains SHA-256 `b01cd6bbb4b0d9f097277e5986b0b4de7001b97896f5f74f3777d1ff50919932`. The prior readiness report remains unchanged at SHA `717e96fc5de24dfeafe4f58bb30215d9f1658ec7c7b335019b2540b1915a8cad`, committed as `fb446459c0ae30a7b2af8edd50dfef681878e993`.

Both original version-4 lockfiles remain immutable:

| Lock | SHA-256 |
| --- | --- |
| `poc/shared-pool/Cargo.lock` | `13007a446f0d9561d50b18897b52a98c951584b2e6c7c721c95580287f5edc64` |
| `poc/takeover/Cargo.lock` | `6e2715918e0dfb9d1a9968021513065bc6653d8ae22d4b97d9b2d5e7d993e0ea` |

All 11 source/manifest/lock pins from readiness are rechecked before launch, between stages and at termination. The prelaunch worktree was clean. No upgrade, lock regeneration, alternate feature selection or repair-on-error is authorized.

The known missing dependency was **k256 0.13.4**, crates.io source, SHA-256 `f6e3919bbaa2945715f0bb6d3934a173d1e9a59ac23767fbaaef277265a7411b`. It is not assumed to be the sole gap. The two locks contain 595 distinct registry name/version/source tuples in total; Cargo fetch selects the locked native-host closure, and the later metadata observations establish what that closure actually contains.

Root explicitly approved the **already installed 1.97.1 toolchain for both host workspaces**. This supersedes the implementation handoff's uninstalled 1.91.0 proposal; it does not claim full build compatibility. The locked Kaspa workspace declares minimum `rust-version = "1.91.0"`; the already resolved reference metadata's highest declared minimum is also 1.91.0. No exact toolchain file was found in the inspected adapter ancestor paths. Candidate transitive/compiler compatibility remains subject to the subsequent observations. A declared rust-version is a minimum, not an exact compiler pin. [Cargo rust-version](https://doc.rust-lang.org/cargo/reference/rust-version.html).

| Absolute executable | Rechecked SHA-256 |
| --- | --- |
| `/home/luke/.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin/cargo` | `828980723df339d62434390e9fb8ef8831036583343ae2316b7ab5646b5c1953` |
| `/home/luke/.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin/rustc` | `d3a664c970a9fd8361b64194861bebc1ae37b9054e5ee3400dc1c9e691797eea` |

The already observed native target is **x86_64-unknown-linux-gnu**. No rustup shim, installation, --ignore-rust-version, source edit or implicit compiler fallback is used.

## Normal commands, source scope and containment

The exact private attempt is:

`/home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/one-v6-dependency-preparation/attempt-20261022T113744Z-dd881d90`

Its `cargo-home/` started empty. No shared-cache seeding or private configuration/credentials copying was needed. Use the source worktree and exact existing toolchain read-only. The only writable bind is this private attempt, containing HOME, Cargo cache, separate reference/candidate target-information directories, logs and receipts. Shared Cargo caches are not mounted. Fetch uses a Bubblewrap sandbox with cleared environment and network access; metadata uses the same scope with the network namespace unshared. Trusted system binaries/libraries, CA certificates, resolver configuration and the loader cache are read-only.

Run the following sequentially, using the absolute Cargo executable shown above:

```text
cargo fetch --locked --target x86_64-unknown-linux-gnu --manifest-path /home/luke/projects/kpi-one-v6-compatibility-2026-10-22/poc/shared-pool/Cargo.toml
cargo fetch --locked --target x86_64-unknown-linux-gnu --manifest-path /home/luke/projects/kpi-one-v6-compatibility-2026-10-22/poc/takeover/Cargo.toml
```

Only if both fetches exit zero, run each of these once:

```text
cargo metadata --frozen --offline --format-version 1 --filter-platform x86_64-unknown-linux-gnu --manifest-path /home/luke/projects/kpi-one-v6-compatibility-2026-10-22/poc/shared-pool/Cargo.toml
cargo metadata --frozen --offline --format-version 1 --filter-platform x86_64-unknown-linux-gnu --manifest-path /home/luke/projects/kpi-one-v6-compatibility-2026-10-22/poc/takeover/Cargo.toml
```

Here `cargo` is command notation only: every recorded/executed argv uses the absolute pinned executable, never PATH lookup or `+toolchain`. The fetch command downloads locked Git/registry dependencies; --locked rejects a required lock change and --target limits acquisition to the selected architecture. Compiler informational/target probes are expected and allowed. No compilation or dependency/build-script execution is requested. [Cargo fetch specification](https://doc.rust-lang.org/cargo/commands/cargo-fetch.html).

Sanitized environment: private HOME and CARGO_HOME; separate private CARGO_TARGET_DIR per workspace; absolute RUSTC/RUSTDOC under the selected toolchain; PATH limited to that toolchain and /usr/bin:/bin; LC_ALL=C; sparse crates.io protocol; CARGO_NET_GIT_FETCH_WITH_CLI=true; CARGO_NET_RETRY=0; CARGO_HTTP_TIMEOUT=60; CARGO_HTTP_SSL_VERIFY=true; empty CARGO_HTTP_PROXY. Metadata additionally has CARGO_NET_OFFLINE=true.

Git uses GIT_CONFIG_NOSYSTEM=1, GIT_CONFIG_GLOBAL=/dev/null, GIT_TERMINAL_PROMPT=0, GIT_ASKPASS=/usr/bin/false, GIT_ALLOW_PROTOCOL=https. GIT_CONFIG_COUNT pins core.hooksPath=/dev/null, an empty credential.helper, protocol.allow=never, protocol.https.allow=always, http.followRedirects=false, submodule.recurse=false, fetch.recurseSubmodules=false, gc.auto=0, maintenance.auto=false and http.sslVerify=true. No agent, tokens, netrc, inherited user configuration, custom helper or credentials are copied. No .gitmodules file existed at the three inspected cached locked commits.

Approved public sources are the crates.io registry (`https://index.crates.io/` and its public `https://static.crates.io/` archives) plus these exact Git sources:

| Git source | Locked commit |
| --- | --- |
| `https://github.com/kaspanet/rusty-kaspa` — reference rev and candidate branch=master source identities | `01b532e8b553523216471682649693af92f0fd16` |
| `https://github.com/kaspanet/vprogs` | `f9b84a863a7c7c20586a9cf947550475e894f72e` |
| `https://github.com/risc0/paritytech-bn` | `22108fe8c6ea1ebc1358fc4fd6854a6bf46e3509` |

The allowlist is established by immutable source/lock configuration and sanitized tools; it is not presented as a host firewall. Retain fetch logs and acquired source identities and stop on unexpected source/download/redirect, authentication or lock changes. This release does not authorize additional endpoints, submodules, LFS, toolchains, guest assets or build-script network activity. Crate archive checksums are validated against their exact locked values, including k256; Git identities remain full commits, not current branch tips.

## Live bounds and evidence

Fresh prelaunch intervals **11:39:10–11:39:20** and **11:39:20–11:39:30 UTC** passed: CPU busy 0.2503% and 0.2359%; both full-stall deltas zero; no swap-out/OOM growth. Last MemAvailable was 22,771,322,880 bytes; conservative headroom after the 1 GiB cap was 21,697,581,056 bytes. Disk free was 274,581,712,896 bytes. Earlier full metadata at 11:35:47 showed 14 CPUs, only light competing activity, and GPU 0% / 1 MiB / no owners. No GPU reservation exists.

Actual unit: `kpi-one-v6-dependencies-v1-113744.service`; invocation `8eb8966fb3364c949e18b0c609e15728`; initial controller PID `1141192`; cgroup `/user.slice/user-1000.slice/user@1000.service/app.slice/kpi-one-v6-dependencies-v1-113744.service`.

The one unit includes its controller and tools: **1 CPU, 1 GiB memory, zero swap, 64 PIDs**, affinity CPU 0. Actual cgroup values cpu.max=100000 100000, memory.max=1073741824, memory.swap.max=0 and pids.max=64 were verified. RuntimeMaxSec=1190, TimeoutStopSec=5, KillMode=control-group, OOMPolicy=stop; file-size limit 512 MiB per file. The controller's fixed monotonic deadline is start+1200 seconds with a 15-second cleanup reserve. Fetch has at most 900 seconds per command subject to that overall deadline; metadata at most 60 seconds each. No retry resets either clock.

Private disk is monitored against **8 GiB**; this is an ordinary sampled stop ceiling, not a filesystem quota or wire-byte claim. Keep raw failure/partial receipts. The controller samples owned cgroup memory/CPU/events/PID-start identities, cache size and host pressure. Stop on errors, integrity changes, deadline/caps, new OOM, less than 2 GiB conservative remaining headroom, or sustained full-stall >=1% / swap-out growth across fresh intervals. Actual resource caps and strict source scope take priority over finishing.

Completion/failure requires exact-unit shutdown and verified owned PID/start-time/cgroup cleanup. No unrelated PID is signalled, failure cache repaired, failed unit blindly retried, or shared cache changed. The first data-only proposal and old failed readiness/GPU attempts remain untouched.

## Subsequent boundaries

Preserve the successful metadata graphs and effective features for the lead's concurrent build-script/native-asset check. In particular, absence of selected RISC Zero prove/CUDA/guest branches must be checked from the actual graph: Cargo --offline alone does not prevent a build script from downloading assets. Any later build requires external network denial.

Acquisition/metadata success does not prove native build readiness or authorize compiling anything. Root's proposed later host-build ceiling is **8 CPUs / 8 GiB / no swap / 20 minutes combined**, sequential exact host binaries with separate targets, subject to fresh capacity and the lead's check. This is a ceiling, not an inferred completion estimate. Later verifier execution remains a separate release, sequential **1 CPU / 1 GiB / no swap / five minutes each**, using the unchanged comparison. Both parked rejected jobs and their wrappers remain excluded.

Runtime results and immutable receipts follow separately after terminal cleanup. No documentation commit is a dependency of the already released acquisition.
