# Rechecking the fresh-profile checkpoint

This guide covers `work/s7-owner-lifecycle-20261022`. Record `git rev-parse HEAD`
and read [PUBLICATION.md](PUBLICATION.md) plus the
[omission inventory](publication/OMITTED-ARTIFACTS.json) first. Keep new outputs
outside the retained evidence. Historical absolute-path runners are records of
the original machine, not portable setup scripts.

## 1. Recheck public arithmetic

These Python3 standard-library checks do not verify proofs or execute native
transactions:

```sh
python3 research/intensive-2026-10-22/lifecycle-oracle/initial_four_public_oracle.py --self-check
```

For an independent reconstruction from the checked-in public fixtures:

```sh
python3 research/intensive-2026-10-22/lifecycle-oracle/initial_four_public_oracle.py --public-dir "$PWD/artifacts/initial-four-public-fixture-20261022T1415/public" --output "$(mktemp -d)/public-math"
```

Read the [oracle guide](research/intensive-2026-10-22/lifecycle-oracle/README.md)
for exact P1088/J336 derivation and the count 5/count 7 distinction. The oracle
does not consume the omitted proving key, producer plan or wallet files.

## 2. Build software verifiers and core checks

Use Cargo/Rust 1.95.0 with a separate target directory. Fetch locked public
dependencies once when network access is available; `--offline` assumes that
cache already exists. Caches and generated executables are not distributed.

```sh
export CARGO_TARGET_DIR="$(mktemp -d)"
cargo +1.95.0 test --locked --offline --manifest-path poc/s7-owner-lifecycle/proof/host/Cargo.toml -p kpi-s7-lifecycle-binding
cargo +1.95.0 test --locked --offline --manifest-path poc/s7-owner-lifecycle/proof/host/Cargo.toml -p kpi-s7-lifecycle-state
```

This fresh state suite is narrow; the inherited old-profile reference tests
are not fresh-instance qualification. No setup or proof is generated here.

## 3. Verify the retained compressed receipt on CPU

No GPU, prover worker or guest-toolchain download is needed for this verifier.
Run from the repository root with development mode absent:

```sh
unset RISC0_DEV_MODE
cargo +1.95.0 build --locked --offline --release --manifest-path poc/s7-owner-lifecycle/proof/host/Cargo.toml --bin verify_s7_initial_pair_compressed
"$CARGO_TARGET_DIR/release/verify_s7_initial_pair_compressed" poc/s7-owner-lifecycle/proof/evidence/groth16/groth16-receipt.bin "$(mktemp -d)/verified"
```

It checks the selected fresh image, exact J336, successful claim, empty
assumptions and negative controls. The receipt SHA256 is
`e13eaa36d1149bfe873938acf829a9e47d93a6a8014eb61fdad9cb09c6e273f2`;
J336 SHA256 is `699697f07565d28faad6e45b9e6daa0a09dbcea3f475d51880a75289f7e49b57`.
Software verification does not run native Full or establish chain backing.

## 4. Native checks and regeneration are separate

The native helper source is under `poc/shared-pool/src/bin/`, selected by
the `s7-native-policy` feature. Build the selected checker, rather than using
the excluded historical executable:

```sh
cargo +1.95.0 build --locked --offline --release --manifest-path poc/shared-pool/Cargo.toml --features s7-native-policy --bin kpi_s7_pair_native_check --bin kpi_s7_ordinary_spend_check
```

The native [control plan](research/intensive-2026-10-22/s7-native-policy/CONTROL-PLAN-FINAL.md),
[pair manifest](research/intensive-2026-10-22/s7-native-policy/pair-native-01/MANIFEST.json)
and retained launch metadata identify exact input files and expected outcomes.
Map original absolute locations to the corresponding published relative files,
check their hashes, and use fresh output paths. Do not substitute a new state,
receipt, fee or authorization while calling it a repeat of the old case.

For guest source compilation and proving, use the separate
[proof-build guidance](research/publication-notes/PROOF-BUILD-GUIDANCE.md).
This needs additional pinned official tools/assets. A regenerated randomized
setup has a new VK and is a new experiment. Domain/pool changes must be explicitly
selected and frozen; compiling changed parameters requires a new image freeze. The omitted original
proving key prevents exact-instance proving from this Git view alone. No guide
here implements or substitutes for the parked replay/owner/DRAIN workflow.
