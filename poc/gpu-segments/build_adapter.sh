#!/usr/bin/env bash
set -euo pipefail
# Run inside the task-owned pinned CUDA build cache, with this directory at
# /opt/experiment, the original recursion archive at /opt/build and output at
# /opt/experiment-output. No GPU, wallet, provider credential or host install.
export CARGO_HOME=/opt/cargo RUSTUP_HOME=/opt/rustup
export PATH=/opt/cargo/bin:/usr/local/cuda/bin:$PATH
if ! rustc +1.89.0 --version >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -fsS https://sh.rustup.rs -o /tmp/kpi-rustup.sh
  bash /tmp/kpi-rustup.sh -y --profile minimal --default-toolchain 1.89.0
fi
test "$(git -C /tmp/risc0 rev-parse HEAD)" = 14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6
echo '15995a3395e61847c403182721c13c56f8735c8d22ed989dc350c5621d812024  /tmp/risc0/Cargo.lock' | sha256sum --check
# Expose only the already locked JSON dependency to the experiment binary.
# No dependency version/checksum or upstream cryptographic source is changed.
python3 - <<'PY'
from pathlib import Path
import tomllib
p=Path('/tmp/risc0');lock=p/'Cargo.lock';s=lock.read_text()
versions=[x['version'] for x in tomllib.loads(s)['package'] if x['name']=='serde_json']
assert len(versions)==1
manifest=p/'risc0/r0vm/Cargo.toml'
manifest.write_text(manifest.read_text().replace('[dependencies]\n','[dependencies]\nserde_json = "='+versions[0]+'"\n',1))
blocks=s.split('[[package]]')
for i,block in enumerate(blocks):
 if block.startswith('\nname = "risc0-r0vm"\n'):
  assert ' "serde_json",' not in block
  blocks[i]=block.replace(' "serde",\n',' "serde",\n "serde_json",\n',1)
  assert blocks[i]!=block
lock.write_text('[[package]]'.join(blocks))
PY
git -C /tmp/risc0 diff -- Cargo.lock risc0/r0vm/Cargo.toml > /opt/experiment-output/adapter-dependency.diff
export RECURSION_SRC_PATH=/opt/build/recursion_zkr.zip
export NVCC_APPEND_FLAGS=-arch=sm_86
export CC=clang CXX=clang++ CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=/opt/cuda-target
mkdir -p /tmp/risc0/risc0/r0vm/src/bin
cp /opt/experiment/main.rs /tmp/risc0/risc0/r0vm/src/bin/kpi-gpu-segments.rs
cd /tmp/risc0
cargo +1.89.0 build --locked --release -p risc0-r0vm --features cuda,disable-dev-mode --bin kpi-gpu-segments
install -m 0755 /opt/cuda-target/release/kpi-gpu-segments /opt/experiment-output/kpi-gpu-segments
sha256sum /opt/experiment/main.rs /opt/experiment-output/kpi-gpu-segments > /opt/experiment-output/adapter-sha256.txt
