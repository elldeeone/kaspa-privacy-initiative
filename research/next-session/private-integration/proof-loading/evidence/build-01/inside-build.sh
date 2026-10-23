#!/bin/bash
set -euo pipefail
/usr/bin/time -v /toolchain/bin/cargo build --frozen --offline --release --jobs 4 --target x86_64-unknown-linux-gnu --manifest-path /workspace/poc/selected-development-prover/Cargo.toml
/usr/bin/time -v /toolchain/bin/cargo test --frozen --offline --release --jobs 4 --target x86_64-unknown-linux-gnu --manifest-path /workspace/poc/selected-development-prover/Cargo.toml -- --nocapture --test-threads=1
