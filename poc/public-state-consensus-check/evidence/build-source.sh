#!/usr/bin/bash
set -euo pipefail
cargo build --frozen --offline -j 6
cargo test --frozen --offline -j 6 --bin kpi-public-state-consensus-check -- --nocapture
