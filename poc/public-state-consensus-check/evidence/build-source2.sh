#!/usr/bin/bash
set -euo pipefail
/home/luke/.cargo/bin/cargo build --frozen --offline -j 6
/home/luke/.cargo/bin/cargo test --frozen --offline -j 6 --bin kpi-public-state-consensus-check -- --nocapture
