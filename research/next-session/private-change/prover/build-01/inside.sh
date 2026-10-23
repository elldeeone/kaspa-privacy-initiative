#!/bin/bash
set -euo pipefail
/toolchain/bin/cargo build --frozen --offline --release -j8 --manifest-path /workspace/poc/private-cashout-prover/Cargo.toml --bins
