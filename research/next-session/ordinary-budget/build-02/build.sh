#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
  --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
  --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp --tmpfs /cargo \
  --ro-bind /home/luke/.cargo/registry /cargo/registry --ro-bind /home/luke/.cargo/git /cargo/git \
  --ro-bind /home/luke/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu /toolchain --dir /src \
  --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/ordinary-budget/source-03/Cargo.toml /src/Cargo.toml \
  --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/ordinary-budget/source-03/Cargo.lock /src/Cargo.lock \
  --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/ordinary-budget/source-03/src /src/src \
  --bind /home/luke/projects/kpi-intensive-2026-10-22/native-target /target \
  --setenv PATH /toolchain/bin:/usr/bin:/bin --setenv RUSTC /toolchain/bin/rustc \
  --setenv CARGO_HOME /cargo --setenv CARGO_TARGET_DIR /target --setenv TMPDIR /tmp --chdir /src \
  /toolchain/bin/cargo build --frozen --offline --release -j2 --target x86_64-unknown-linux-gnu \
  --features s7-native-policy --manifest-path /src/Cargo.toml --bin "$1"
