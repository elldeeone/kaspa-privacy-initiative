#!/bin/bash
set -euo pipefail
/toolchain/bin/cargo test --frozen --offline --release -j8 --manifest-path /workspace/poc/private-cashout-prover/Cargo.toml --lib
/toolchain/bin/cargo build --frozen --offline --release -j8 --manifest-path /workspace/poc/private-cashout-prover/Cargo.toml --bins
/usr/bin/python3 /workspace/poc/private-cashout-prover/test_cli.py --binary /target/release/kpi-private-cashout-prover --expected-code parameters_unselected --output /out/cli-unselected
