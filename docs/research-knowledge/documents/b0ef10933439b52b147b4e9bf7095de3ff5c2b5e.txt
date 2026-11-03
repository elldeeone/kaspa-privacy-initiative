# Scoped publication licensing check

Checked 2026-10-22. This is an evidence-based license inventory for the selected
source and public data, not blanket clearance for every file in the worktrees.
No frozen packet, source file, binary, index or Git history was changed.

The owner-selected publication excludes generated software executables: raw
guest ELF, wrapped guest program, frozen host/native checkers, shared libraries,
SDK workers and Rust toolchains. Existing local artifacts and their original
manifests remain evidence; a publication manifest must identify omitted files
instead of describing the published view as the complete closed packet.

## Source and public data

1. The repository `LICENSE` is Apache-2.0. Imports of external Cargo packages do
   not themselves redistribute those packages' complete source or executable
   files. Cargo manifests and locks retain the exact dependency identities.
2. `poc/s7-owner-lifecycle/proof/host/src/outer_constants.rs:59` explicitly derives
   its conversion from `public-state-native-check/receipt.rs`. That predecessor's
   `NOTICE` identifies adapted vProgs mappings and retains the ISC license.
   The new profile should carry that notice as accompanying material. The
   prepared `THIRD-PARTY-NOTICES.txt` reproduces it exactly and identifies the
   later local changes. [Pinned vProgs license](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/LICENSE).
3. Source-adapted Kaspa validation/policy snippets also need the exact Rusty
   Kaspa ISC notice; the new supplement includes it. This obligation follows
   copied/adapted source, independently of excluding executable binaries.
   [Pinned Rusty Kaspa license](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/LICENSE).
4. Official RISC Zero SDK crates checked locally declare Apache-2.0. The exact
   `risc0-zkvm 3.0.3` source is `fba0c0179f0125afe23bd15eb4c34428aacf5705`;
   `risc0-groth16 3.0.4` is `ba889fc049830b777de63fddbeea5f9776618d7d`.
   The supplement attributes the established exported public VK/control
   parameters and supplies the Apache license text, without assuming that
   mathematical outputs are independently copyrightable.
   [Pinned SDK license](https://github.com/risc0/risc0/blob/ba889fc049830b777de63fddbeea5f9776618d7d/LICENSE).
5. Genuine receipts, seals, input/P/J bytes, generated inner VKs, hashes and
   measurement reports are data outputs, distinct from SDK/toolchain executable
   copies. No separate proof-output distribution restriction was found in the
   inspected exact-version crate manifests, source license headers or pinned
   licenses. This observation is not a claim about all possible legal rights.

The new 16,171-byte supplement has SHA256
`934820cf19871b67db1617f7a834bed012daf7e45c3ea018fb84cd2c5e884df8`.
Its embedded vProgs notice, Rusty Kaspa license and repository Apache license
were checked as exact substrings of their local source files.

## Why executable exclusion matters

The raw guest is compiled software, including RISC Zero runtime, Rust library
code and enabled third-party dependencies. The wrapped program additionally
embeds the SDK's `V1COMPAT_ELF`. The offline target-filtered Cargo graph includes
`subtle 2.6.1`, whose BSD-3-Clause license specifically requires the binary
distribution's accompanying materials to reproduce its notice. The graph also
contains MIT and dual-licensed components, plus build/procedural-macro crates;
a graph inventory is not a precise linker inclusion map.

The native checker graph additionally includes Rusty Kaspa ISC and native
vendor code: RocksDB/LevelDB, Snappy, zstd, zlib, LZ4 and secp256k1. A root
Apache license or an extractor's vProgs-only notice does not constitute a full
native binary notice bundle. Finding GPL/AGPL text inside RocksDB's vendored
source tree does not alone establish a copyleft obligation for these binaries;
the relevant files/build and available license alternatives must be checked.

The stripped local RISC Zero Rust toolchain directory does not contain release
license/COPYRIGHT files. Upstream Rust documents a release-specific
`COPYRIGHT.html` and standard-library-specific `COPYRIGHT-library.html`; an
unrelated installed stable toolchain's copies would not identify this exact
RISC Zero toolchain build. SDK workers/CUDA and compression assets would need
their own complete distribution/provenance review if later selected for
publication. None is covered by this source/public-data supplement.
[Pinned Rust copyright guidance](https://github.com/risc0/rust/blob/r0.1.97.0/COPYRIGHT).

Local source checks used the private task cache at
`/home/luke/projects/kpi-intensive-2026-10-22/lifecycle-outer-target/cargo-home`,
the pinned Rusty Kaspa checkout at
`/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e`,
and original integration helper notices. No dependencies were installed,
downloaded or rebuilt during this audit.
