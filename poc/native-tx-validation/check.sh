#!/usr/bin/env bash
set -euo pipefail
kpi_native_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$kpi_native_root/.local/orchard-interop/target}"
kpi_native_manifest="$kpi_native_root/poc/native-tx-validation/Cargo.toml"
python3 "$kpi_native_root/poc/native-tx-validation/check_vectors.py"
cargo +1.95.0 fmt --manifest-path "$kpi_native_manifest" -- --check
cargo +1.95.0 clippy --release --locked --manifest-path "$kpi_native_manifest" --all-targets -- -D warnings
cargo +1.95.0 test --release --locked --manifest-path "$kpi_native_manifest"
