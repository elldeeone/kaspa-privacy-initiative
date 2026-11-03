#!/usr/bin/env bash
set -euo pipefail
kpi_interop_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$kpi_interop_root/.local/orchard-interop/target}"
kpi_interop_manifest="$kpi_interop_root/poc/orchard-interop/Cargo.toml"
python3 "$kpi_interop_root/poc/orchard-interop/check_vectors.py"
cargo +1.95.0 fmt --manifest-path "$kpi_interop_manifest" -- --check
cargo +1.95.0 clippy --release --locked --manifest-path "$kpi_interop_manifest" --all-targets -- -D warnings
cargo +1.95.0 test --release --locked --manifest-path "$kpi_interop_manifest"
