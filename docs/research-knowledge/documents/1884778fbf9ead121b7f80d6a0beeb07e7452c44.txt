# Portable proof-package rechecks

These are source-build and saved-receipt checks. They do not generate a proof,
execute a guest, construct a transaction, or run the parked owner workflow.
Commands are guidance; this publication audit did not run new builds or tests.

The publication deliberately omits generated software executables, raw guest
ELFs and wrapped guest programs. Full local frozen manifests remain unchanged.
Consequently a clone cannot rehash every entry in those original manifests.
Consult the branch's `publication/OMITTED-ARTIFACTS.json` for the canonical
omission list. Do not mistake a successful subset check for a full-packet check.

## Smallest useful check: verify a saved compressed receipt

Use Rust/Cargo 1.95.0 and a fresh target directory outside the checkout. Keep the
existing path dependencies: `poc/accelerated-bn254/common`,
`poc/groth16-comparison/common`, `poc/private-note-proof` and its existing
`poc/takeover/vendor/covenant` dependency. They already exist in the common base.
Each new host manifest and its adjacent `Cargo.lock` must travel together.

An empty cache needs one public dependency fetch; `--offline` works only after
the pinned crates and Git revisions are present. No RISC Zero worker, guest
toolchain, CUDA binary, Groth16 setup assets or private input is needed for this
software-only verification.

For the integration branch's historical state assertion:

```sh
export CARGO_TARGET_DIR=/absolute/new-publication-check-target
cargo +1.95.0 fetch --locked \
  --manifest-path poc/two-v6-state/host/Cargo.toml
cargo +1.95.0 build --offline --locked --release \
  --manifest-path poc/two-v6-state/host/Cargo.toml \
  --bin verify_state_compressed
env -u RISC0_DEV_MODE \
  "$CARGO_TARGET_DIR/release/verify_state_compressed" \
  poc/two-v6-state/evidence/groth16-receipt/groth16-receipt.bin \
  /absolute/new-historical-verification-output
```

For the lifecycle branch's distinct fresh initial pair:

```sh
export CARGO_TARGET_DIR=/absolute/new-publication-check-target
cargo +1.95.0 fetch --locked \
  --manifest-path poc/s7-owner-lifecycle/proof/host/Cargo.toml
cargo +1.95.0 build --offline --locked --release \
  --manifest-path poc/s7-owner-lifecycle/proof/host/Cargo.toml \
  --bin verify_s7_initial_pair_compressed
env -u RISC0_DEV_MODE \
  "$CARGO_TARGET_DIR/release/verify_s7_initial_pair_compressed" \
  poc/s7-owner-lifecycle/proof/evidence/groth16/groth16-receipt.bin \
  /absolute/new-fresh-verification-output
```

Output directories must not exist. These separate binaries retain their
respective compiled image, input/publication and journal identities. The J42
binding-only profile instead builds `verify_compressed` from
`poc/two-v6-binding/host/Cargo.toml`; its receipt is under
`poc/two-v6-binding/evidence/groth16-receipt/`.

The generic native-proof extractor is source-buildable from
`poc/public-receipt-proof-extract/Cargo.toml`. Its CLI requires the externally
selected receipt SHA, image, journal and claim digest before decoding. It only
checks/converts proof data; it does not execute Kaspa's VM. Actual native
execution and full-transaction validation are separate retained experiments.

## Guest source build and identity comparison

Guest rebuilding is optional for saved-receipt verification. It requires the
exact retained guest toolchain and flags; a generic host Rust compiler cannot
target this zkVM correctly. Official release provenance recorded by the local
campaign is:

| Component | Official artifact and SHA-256 |
| --- | --- |
| Guest Rust `r0.1.97.0` | [Linux archive](https://github.com/risc0/rust/releases/download/r0.1.97.0/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz), `100b597d605b706bec94e1d32bfaaf5851df8d75173f986d4b56a3e90916be53` |
| SDK tools `3.0.3` | [Linux archive](https://github.com/risc0/risc0/releases/download/v3.0.3/cargo-risczero-x86_64-unknown-linux-gnu.tgz), `71a0adaa64235be13e9b8471bea5c4ded64bf97c6bd1eb9c2285b966c0b62fee` |

These archives are not included in Git. The official SDK archive's CPU `r0vm`
is distinct from the separately built, locally retained CUDA worker. Rust1.97
with SDK3.0.3 is the configuration measured here; it is not an assertion that
SDK3.0.3 officially guaranteed that later Rust release.

For the fresh profile, first build the ordinary host and run its fully checked
immutable-key preflight:

```sh
cargo +1.95.0 build --offline --locked --release \
  --manifest-path poc/s7-owner-lifecycle/proof/host/Cargo.toml \
  --bin kpi-s7-lifecycle-proof-host
"$CARGO_TARGET_DIR/release/kpi-s7-lifecycle-proof-host" validate-key

RUSTC=/absolute/verified-guest-toolchain/bin/rustc \
RISC0_FEATURE_bigint2=1 \
RUSTFLAGS='-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"' \
  /absolute/verified-guest-toolchain/bin/cargo build --offline --locked --release \
  --target riscv32im-risc0-zkvm-elf \
  --manifest-path poc/s7-owner-lifecycle/proof/guest/Cargo.toml

"$CARGO_TARGET_DIR/release/kpi-s7-lifecycle-proof-host" wrap \
  "$CARGO_TARGET_DIR/riscv32im-risc0-zkvm-elf/release/kpi-s7-lifecycle-guest" \
  /absolute/new-derived-program-directory
```

Keep host and guest environment settings separate. Preserve the exact locks,
static VK/domain/pool ID, checked preflight and original expected image. Compare
the rebuilt raw ELF, wrapped program and image against the original freeze.
Byte-identical rebuilding at a different filesystem path/platform was not
qualified in this audit. A mismatch is a reproduction finding: do not rewrite
the original pins or accept a new image merely to make the check pass.

The original integration profiles have analogous preflight/build commands in
their existing READMEs. Their fixed keys/images/journals must remain separate.
No new GPU proving, setup, funded transaction or owner/replay experiment is
part of these publication instructions.
