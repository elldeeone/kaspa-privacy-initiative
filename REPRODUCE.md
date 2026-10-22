# Rechecking the combined source tree

Record `git rev-parse HEAD` and read [PUBLICATION.md](PUBLICATION.md) first.
Use fresh output directories outside frozen evidence. Historical runner scripts
contain machine-specific paths; inspect them before use.

The [original integration guide](https://github.com/elldeeone/kaspa-privacy-initiative/blob/85e39398fd97ff0299e07fad8899cd3f4cc454ac/REPRODUCE.md)
and [fresh-profile guide](https://github.com/elldeeone/kaspa-privacy-initiative/blob/68d7b039f606bd42b39d8d1317c0bfd76c277ae0/REPRODUCE.md)
retain the two snapshot procedures. Their evidence identities remain separate.

Run standard-library public-observation checks from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 poc/shared-pool/public_native_observation_tests.py
```

For Rust, use Cargo/Rust1.95.0. Fetch locked public dependencies once if the cache
is empty; `--offline` requires that cache. Keep the target outside Git:

```sh
export CARGO_TARGET_DIR="$(mktemp -d)"
cargo +1.95.0 test --locked --offline --manifest-path poc/two-v6-binding/common/Cargo.toml --features compiled-research-instance
cargo +1.95.0 test --locked --offline --manifest-path poc/two-v6-state/common/Cargo.toml
cargo +1.95.0 test --locked --offline --manifest-path poc/s7-owner-lifecycle/binding/Cargo.toml --features compiled-research-instance
cargo +1.95.0 test --locked --offline --manifest-path poc/s7-owner-lifecycle/state/Cargo.toml
```

The [portable proof guide](research/publication-notes/PROOF-BUILD-GUIDANCE.md) gives
CPU-only verification of saved compressed receipts. It distinguishes optional
guest rebuilding and image comparison from proof regeneration. A byte hash
establishes identity, not the truth of a report. Source tests do not execute
native Full validation, prove cryptographic correctness or complete owner exits.

The [omission map](publication/OMITTED-ARTIFACTS.json) lists software/parameters
retained locally. No prebuilt checker, GPU worker, toolchain cache or original PK
is distributed through Git. Full historical manifests include these omissions
and cannot all be rehashed from a clone. Frozen branch inventories retain their
original root-document hashes; use the exact source commits to recheck those
entries. A fresh randomized setup has a new VK and experiment identity; domain
and pool changes require explicit selection, and a changed guest requires a new
image freeze. Never update old pins to make a new result appear identical.
