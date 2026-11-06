#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
PACKET="$ROOT/research/withdrawal-request-and-busy-pool-2026-11-06/run"
export CARGO_TARGET_DIR="$ROOT/.local/ci-target"
cargo +1.97.1 build --locked --release --manifest-path poc/withdrawal-followup/host/Cargo.toml
python3 poc/withdrawal-followup/generate.py --check
python3 poc/withdrawal-followup/verify_packet.py "$PACKET"
CHECK_DIR="$(mktemp -d "$ROOT/.local/withdrawal-public-check.XXXXXX")"
BIN="$CARGO_TARGET_DIR/release/kpi-withdrawal-followup"
"$BIN" replay-busy "$PACKET/pinned.program.bin" "$PACKET/busy" "$CHECK_DIR/busy"
"$BIN" verify-quiet "$PACKET/pinned.program.bin" "$PACKET/quiet" "$PACKET/busy" "$PACKET/network" "$CHECK_DIR/quiet.json"
"$BIN" verify-unequal "$PACKET/unequal/public.json" "$CHECK_DIR/unequal.json"
for MODE in direct onion; do
  "$BIN" verify-logs "$PACKET/network/config.json" "$PACKET/network/$MODE/operator.jsonl" "$CHECK_DIR/$MODE.json"
  python3 poc/withdrawal-followup/verify_blind.py "$PACKET/network/config.json" "$PACKET/network/$MODE/operator.jsonl"
done
printf 'Public proofs, native transactions and observations verified: %s\n' "$CHECK_DIR"
