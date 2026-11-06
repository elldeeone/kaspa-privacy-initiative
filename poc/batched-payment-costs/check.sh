#!/usr/bin/env bash
set -euo pipefail
batch_cost_repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$batch_cost_repo"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$batch_cost_repo/.local/ci-target}"
export PYTHONDONTWRITEBYTECODE=1
cargo +1.97.1 build --locked --release --manifest-path poc/batched-payment-costs/host/Cargo.toml
python3 poc/batched-payment-costs/check.py
batch_replay_dir="$(mktemp -d "$batch_cost_repo/.local/batched-payment-public-XXXXXX")"
"$CARGO_TARGET_DIR/release/kpi-batched-payment-costs" replay research/batched-payment-costs-2026-11-06/run/program.bin research/batched-payment-costs-2026-11-06/run/core "$batch_replay_dir/replay"
"$CARGO_TARGET_DIR/release/kpi-batched-payment-costs" replay-extras research/batched-payment-costs-2026-11-06/run/program.bin research/batched-payment-costs-2026-11-06/run/core research/batched-payment-costs-2026-11-06/run/extras "$batch_replay_dir/extras"
