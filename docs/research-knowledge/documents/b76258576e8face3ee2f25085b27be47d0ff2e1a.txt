# Cold software recovery

This is a public research canary under ADR0057. It restores the existing
compact owner software; it changes no circuit, native policy, key or old package.
Use no funded note, main owner backup or private workload here.

`prepare_bundle.py` copies a fixed public allowlist, exact selected executables
and all Cargo.lock dependencies. It never includes a backup, PK, private history,
witness, map or controller plan. `archive_bundle.py` writes a deterministic
tar.zst plus an exact member allowlist. Neither tool executes downloaded code.

`unpack_bundle.py` requires separate external archive, member-list and typed
inventory anchors before decompression. It accepts only exact regular USTAR
members, canonical headers and zero padding; links, extensions, hidden headers,
duplicate paths, unexpected files and trailing data fail. Extraction never
launches or imports payloads. A separate typed restore follows extraction.

`software_bundle.restore` requires an independently authenticated inventory
digest and restores **only its listed entries**. An unlisted Cargo config,
build script or import-shadow file is never copied into the execution tree.
Declared backup-inode aliases are rejected before public bytes are opened,
including a generator argument and a between-pass replacement.

The clean build uses empty Cargo home/target, an unshared network and no original
repository/cache/target mounts. The selected existing Rust1.95 toolchain and OS
remain trusted dependencies; they are not independently provisioned by this
bundle. The source archive includes dependency source/licenses and exact registry
checksums. Six foreign-platform archives initially missing from the local cache
required explicit checksum-locked crates.io retrieval; the final build is offline.

For the selected release's exact bytes, preserve the original logical dependency
path `/cargo/registry/src/index.crates.io-1949cf8c6b5b557f` and hide the optional
installed rust-src component. Otherwise rustc embeds different panic/source
locations. The first two builds succeeded but produced different executables;
both are retained and were never selected. The third fresh build reproduced
selected ELF `1662fcd9a5b90b8658e07aed2250a4c9c11d2390e80d7addae717090d63fb94d`.
No compiler flag or source/key byte was weakened to obtain the match.

```text
python3 -B run_clean_build.py PUBLIC_BUNDLE EXTERNAL_INVENTORY_SHA NEW_OUTPUT \
  --registry-path-layout --hide-rust-source
```

`run_public_canary.py` mounts only authenticated restored source/runtime and
root's deliberately known public seed fixture. Recognition uses no PK/prover.
An explicitly scheduled proving invocation uses only the compact PK, exact
selected executable and existing owner CLI; its full PK/VK authentication and
parameters-ready handshake precede the backup read. No launcher broadcasts.

The actual HTTPS-restored software and 1,307,894,256-byte compact PK completed
the public canary's terminal proof and native Full: 981,281,800-sompi payout,
18,718,200 exit fee, zero remaining reserve. Including the 217,300-sompi entry
fee, costs were 18,935,500 sompi. The canary was unfunded, its seed deliberately
public and its contexts supplied; no accepted or confirmed payout is claimed.

`reconcile.py` is a strict **future adapter contract**, not an implemented compact
accepted-chain fetcher or an authorization API. It checks pinned founding/birth
anchors, the complete ordered accepted prefix, every reserve query and the
postquery spend/removal frontier. Missing/pruned/reorganized/stale input fails
closed. Public positive controls are fixtures; every actual result keeps
accepted backing, currentness and spend authorization false. A hash, nonce,
timestamp, native Full or empty address response cannot prove current consensus.
An actual future broadcaster must freshly recheck its exact spend point.

Results and fixed source/resource/failure evidence are under
`research/next-session/independent-payments/recovery-software`. Local namespaces
and one provider's retention are not independent consensus, durable availability,
production safety, anonymity or a fee qualification.
