# Current capacity private prover rebuilt exactly

**PASS for the scoped cold source build:** the current private prover was rebuilt
byte-for-byte from the selected 19 public HTTPS-restored source files and
current Cargo.lock-pinned dependencies. The rebuilt ELF SHA256 is
`4ef4fc4f6290bc1c5472e732e118476b6ad20b692438c0957e27cf3f6bc00621`, exactly
the externally selected current executable. Neither executable was run.

This closes the current private-prover source-build gap left by the older
domain's `1662...` rebuild. It does not close the complete W wallet/runtime
software, financial recovery, native acceptance, privacy, or current-state gaps.

## What was actually checked

| Item | Observed result |
| --- | --- |
| Current source selection | 19/19 files match freeze `c341fbfb...` and inventory `ee5d1be3...` |
| Current compact identity | Domain `d55d006a...`, role manifest `d6f0e2bb...`, VK `074c06a5...` |
| Dependencies | 148 current-lock registry packages; 6,590 vendor files authenticated; 6,442 package-content checks |
| Dependency provenance | Only vendor entries from immutable public HTTPS archive `17654e74...`, inventory `d8f96ce9...` |
| Initial compiler state | Empty CARGO_HOME; fresh absent target; original host checkout/cache/targets not mounted |
| Network | New network namespace with loopback only; Cargo `--locked --offline` |
| Actual build | `cargo build --release --locked --offline --bin kpi-private-capacity-prover -j4` |
| ELF comparison | Exact 3,898,832-byte selected current ELF reproduced |
| Compiled build identity | Independently recomputed `fcf6e8c7...` from current sources and actual build-script metadata; matches current role manifest |
| Resources | 32.21 seconds controller wall; 85.47 seconds aggregate cgroup CPU; 1,113,956,352 bytes peak; zero swap and OOM events |

The service's final observations were 32.267 seconds, 85.481 aggregate CPU
seconds and displayed memory peak `1G`. The JSON cgroup counters were sampled
just before the controller exited, explaining the small CPU difference.
Actual caps were 4 CPUs / 6 GiB / zero swap. Compiler warnings were retained;
no Rust source or compiler flags were changed to obtain equality.

## Path and trust boundary

Static inspection of the **current** selected executable found dependency paths
under `/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f` and
installed Rust-source paths under the stable toolchain. The build recreated
that logical registry path using only authenticated copied public vendor
bytes, and kept the preinstalled toolchain's rust-src visible at its observed
logical path. This was grounded in current metadata, rather than copying the
older build05 recipe that hid rust-src.

The original host Cargo cache and checkout objects were absent from the
compiler namespace. The logical `.cargo` pathname existed and contained only
the copied public dependency registry. Literal pathname absence is therefore
**not** claimed. The compiler, Rust sysroot, installed Rust source, OS loader,
linker and libc remain trusted, preinstalled same-host dependencies; they were
not independently bootstrapped or bundled by this experiment.

The selected ELF was used only for hashing and static path inspection. The
current public PK, private backup, note witness, proof, wallet and RPC were not
opened or mounted. The old archive supplied dependencies only: its old prover,
old source, old config and old financial authority were not copied or mounted.

## Retained first launch failure

The first service failed before the helper or compiler ran because systemd
started in `/home/luke` and the helper path was relative. Its 23 ms exit is
retained in `LAUNCH-FAILURE-01.json`. The second service used absolute helper
and inventory paths, a new service identity and fresh output. Source and build
recipe bytes did not change. The first actual compilation produced equality;
there was no mismatch-driven retry or flag search.

## Evidence

- `SOURCE-FREEZE-01.json`: fixed four-payload helper/design selection.
- `CURRENT-SOURCE-FREEZE.json` and `CURRENT-SOURCE-INVENTORY.json`: exact current public selection metadata.
- `build-02/CURRENT-SOURCE-RESTORE.json`, `DEPENDENCIES.json`, `NAMESPACE.json`: authenticated input and namespace checks.
- `build-02/BUILD-COMMAND.json`: exact command, environment, compiler verbose identity and executable hashes.
- `build-02/COMPILED-METADATA.txt` and `COMPILED-BUILD-IDENTITY.json`: actual compiler metadata and independent public identity calculation.
- `build-02/RESULT.json`, `RESOURCES.json`, `SERVICE-EXECUTION.json`, compiler logs: actual outcome and resources.

The public current assets were previously downloaded from the selected
[current capacity recovery release](https://github.com/elldeeone/kaspa-privacy-initiative/releases/tag/native-kas-capacity-recovery-2026-10-23).
Integrity at this observation does not establish independent providers,
long-term retention, a trusted compiler bootstrap, cryptographic correctness,
or general cross-machine reproducibility. Old privacy and cold-build packets
were not edited or reinterpreted.
