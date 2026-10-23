#!/bin/bash
set -euo pipefail
/toolchain/bin/cargo test --frozen --offline --release -j4 --manifest-path /workspace/poc/private-exit-proof/Cargo.toml --lib fixture::tests
/toolchain/bin/cargo build --frozen --offline --release -j4 --manifest-path /workspace/poc/private-exit-proof/Cargo.toml --bin kpi-private-exit-proof
