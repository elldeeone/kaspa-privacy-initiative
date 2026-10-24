# Current capacity private-prover cold build

This tests whether the **current** `AUTH528_PRIVATE_CAPACITY_EXIT/v1` private
prover can be rebuilt from the publicly restored source bytes, without the
original checkout, Cargo cache, or previous build target. It is separate from
the earlier domain's successful `1662...` build. No financial proof is made.

## External selection

The owner-selected source commit is
`ad18b65e1472d904d0528520104936592cda65b7`. The current public HTTPS restore
supplies the selected 19-file source freeze
`c341fbfbce61ce9d3bf1f198a8ef8be800416d3d99f9910dc0bd0ff0b10160b3`, source
inventory `ee5d1be3c54b6a308daf655c3d4b2cad1465a14ed7b5ec856f089ec595230b17`,
and selected ELF
`4ef4fc4f6290bc1c5472e732e118476b6ad20b692438c0957e27cf3f6bc00621`.
The compact role manifest is
`d6f0e2bbafab39a72106ef0a0ebd6483362a858926117721a8be5aa37a459011`, with
domain `d55d006a9bb253963db4f4e44495e60333df9fcc83c1c3ae220806d0f326a0bb`,
VK SHA256 `074c06a5f21f46c7c87a948c8ca6a0896198cc9fc255b8d5e08cc01ceb73a987`,
and compiled build identity
`fcf6e8c757613e6fea9a5dd776727f1c2456865f1185c545ac9751ef9fb26419`.
These are external trust selections, not authority supplied by a downloaded
program. The public proving key is neither opened nor mounted.

## Dependency and compiler boundary

Only the Cargo.lock registry dependencies may be reused from the immutable old
public software HTTPS archive, SHA256
`17654e748f4c03542646af9d782279cc4e1bd040d5bc97eb0493796515632a46`.
Its authenticated software inventory is
`d8f96ce9f133d846b94ad5219f45d8664acba8972355fccd2d27b3315a06b808`.
Each of the expected 148 registry packages must match the **current** Cargo.lock
checksum and every vendored file's `.cargo-checksum.json`. No old prover source,
program, parameter identity, or financial authority is inherited.

The preinstalled Rust 1.95.0 compiler/toolchain and system loader, linker, libc,
and OS remain trusted. Record compiler identities and tool hashes. This is a
same-host source-availability/reproducibility experiment, not an independently
bootstrapped compiler or cross-platform reproducibility claim.

## One grounded build recipe

The selected current ELF contains dependency paths under
`/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f` and both
canonical `/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library` and installed
Rust-source paths under the stable toolchain. This differs from old build05,
whose exact recreation hid optional rust-src. Preserve a public inspection
receipt and use those observed current paths for the first fixed recipe.

Create a fresh owned source tree from exactly the 19 authenticated HTTPS files,
then add a fixed trusted offline Cargo source configuration. Copy only the
authenticated current-lock dependency files into a new owned vendor tree.
Mount those public files at the observed logical registry location and mount
the trusted toolchain at its observed logical location, with rust-src visible.
Use an empty CARGO_HOME and a nonexistent fresh target, `cargo build --release
--locked --offline --bin kpi-private-capacity-prover -j4`, no Rust flags, and an
unshared network. The original host checkout, original registry/cache, and
prior targets are not mounted. Recreating a logical pathname from public bytes
is explicitly **not** a claim that the literal pathname is absent.

The build runs under 4 CPU / 6 GiB / zero swap. Record actual cgroup caps and
resource use. Inputs contain no backup, witness, PK, RPC configuration, or
private source data. The selected executable is read for digest/path inspection
and comparison only; it is not executed.

## Outcomes and stop rule

Success requires all 19 current source hashes, all current-lock dependency
checksums, the namespace/empty-state checks, a successful offline compilation,
and exact ELF SHA256 equality with the externally selected `4ef4...` bytes.
Compilation without equality is a retained partial result and does not select
or authorize its output. Keep every mismatch or operational failure. A further
build requires a specific public-source or embedded-path diagnosis; do not
cycle layout/flags until something happens to match.

Even exact equality does not establish complete W wallet/runtime recovery,
parameter setup correctness, privacy, current chain state, native acceptance,
financial recovery, or long-term availability.
