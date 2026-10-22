# Rechecking the public checkpoint

Use this branch for the older development-instance experiments. Use the
[fresh-profile guide](https://github.com/elldeeone/kaspa-privacy-initiative/blob/work/s7-owner-lifecycle-20261022/REPRODUCE.md)
for the separate fresh key/domain/image. Neither guide completes the missing
owner/replay/DRAIN workflow.

## 1. Select the snapshot and evidence

From a clone, select `work/intensive-research-20261022` and record `git rev-parse
HEAD`. Read [PUBLICATION.md](PUBLICATION.md) and the
[omission inventory](publication/OMITTED-ARTIFACTS.json) first. Historical logs
contain machine-specific paths; do not execute their old runner scripts as a
portable setup procedure. Keep new outputs outside the evidence tree.

Existing reports can be inspected without rebuilding or proving. A byte hash
confirms identity, not the truth of a report. Original full manifests include
excluded software binaries and cannot all close against this filtered Git view.

## 2. Run bounded source checks

The observation controls use Python3's standard library and the checked-in
public rehearsal artifacts:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 poc/shared-pool/public_native_observation_tests.py
```

For Rust, install Cargo/Rust 1.95.0 and fetch the locked public dependencies once
when network access is available. `--offline` requires that prior cache; no
cache or prebuilt checker is distributed. Use a separate target directory:

```sh
export CARGO_TARGET_DIR="$(mktemp -d)"
cargo +1.95.0 test --locked --offline --manifest-path poc/two-v6-binding/common/Cargo.toml --features compiled-research-instance
cargo +1.95.0 test --locked --offline --manifest-path poc/two-v6-state/common/Cargo.toml
```

These are the binding/state core regressions. They do not generate a new guest
receipt or run the native transaction validator. The retained integrated-source
observation is [here](research/intensive-2026-10-22/evidence/integrated-state-core-05/README.md).

## 3. Verify the retained compressed state receipt

This CPU-only verifier needs the locked public dependencies, with no GPU,
prover process or guest-toolchain download. Run from the repository root with
`RISC0_DEV_MODE` absent:

```sh
unset RISC0_DEV_MODE
cargo +1.95.0 build --locked --offline --release --manifest-path poc/two-v6-state/host/Cargo.toml --bin verify_state_compressed
"$CARGO_TARGET_DIR/release/verify_state_compressed" poc/two-v6-state/evidence/groth16-receipt/groth16-receipt.bin "$(mktemp -d)/verified"
```

It verifies the selected historical-state image, exact J336, completed claim
and negative controls in software. It does not invoke native Full validation
or establish accepted ancestry. For the separate existing native result, read
the [official Full helper](poc/public-state-consensus-check/README.md). Its
historical `frozen-checker` is excluded from this publication; rebuild from its
source/lock before attempting a repeat with fresh outputs.

## 4. Distinguish verification from regeneration

The package [binding](poc/two-v6-binding/README.md) and
[state](poc/two-v6-state/README.md) READMEs record the original build stages.
Portable [proof-build guidance](https://github.com/elldeeone/kaspa-privacy-initiative/blob/work/s7-owner-lifecycle-20261022/research/publication-notes/PROOF-BUILD-GUIDANCE.md)
describes official toolchain/asset prerequisites. Guest compilation and proving
require additional pinned official tools and substantial resources. Compare
rebuilt key/program/image identities to the original pins; a mismatch is a new
build result, not permission to update the selected experiment.

A newly randomized setup is a new instance. It cannot reproduce an old proof
or substitute for an unavailable original proving key. Retain failures and new
measurements separately; do not overwrite the evidence in this snapshot.
