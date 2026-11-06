#!/usr/bin/env bash
set -euo pipefail
payment_set_repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$payment_set_repo"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$payment_set_repo/.local/ci-target}"
export PYTHONDONTWRITEBYTECODE=1
cargo +1.97.1 build --locked --release --manifest-path poc/payment-set-withdrawal/Cargo.toml
python3 poc/payment-set-withdrawal/check.py
python3 -m unittest discover -s poc/payment-set-withdrawal -p 'test_*.py' -q
cargo +1.97.1 test --locked --release --manifest-path poc/payment-set-withdrawal/Cargo.toml --test relation -- --test-threads=1
"$CARGO_TARGET_DIR/release/kpi-payment-set-withdrawal" verify-public research/payment-set-withdrawal-2026-11-05/run
