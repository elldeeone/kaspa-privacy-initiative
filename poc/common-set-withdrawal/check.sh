#!/usr/bin/env bash
set -euo pipefail
common_set_repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$common_set_repo"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$common_set_repo/.local/ci-target}"
export PYTHONDONTWRITEBYTECODE=1
cargo +1.97.1 build --locked --release --manifest-path poc/common-set-withdrawal/Cargo.toml
python3 -m unittest discover -s poc/common-set-withdrawal -p 'test_*.py' -q
python3 poc/common-set-withdrawal/check.py
"$CARGO_TARGET_DIR/release/kpi-common-set-withdrawal" verify-public research/common-set-withdrawal-2026-11-05/run
