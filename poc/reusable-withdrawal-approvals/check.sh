#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
PACKET="$ROOT/research/reusable-withdrawal-approvals-2026-11-06/run"
export CARGO_TARGET_DIR="$ROOT/.local/ci-target"
cargo +1.97.1 build --locked --release --manifest-path poc/reusable-withdrawal-approvals/host/Cargo.toml
python3 poc/reusable-withdrawal-approvals/generate.py --check
python3 poc/reusable-withdrawal-approvals/verify_packet.py "$PACKET"
CHECK_DIR="$(mktemp -d "$ROOT/.local/reusable-approval-public-check.XXXXXX")"
"$CARGO_TARGET_DIR/release/kpi-reusable-withdrawal-approvals" replay "$PACKET/program.bin" "$PACKET/campaign" "$CHECK_DIR/replay"
printf 'Public complete receipts, native transactions and unchanged approvals verified: %s\n' "$CHECK_DIR"
