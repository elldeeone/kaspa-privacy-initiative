#!/usr/bin/bash
set -euo pipefail
/home/luke/.cargo/bin/cargo build --frozen --offline -j 1
/home/luke/.cargo/bin/cargo test --frozen --offline -j 1 --bin kpi-public-receipt-proof-extract -- --nocapture
