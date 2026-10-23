#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp --tmpfs /cargo \
 --ro-bind /home/luke/.cargo/registry /cargo/registry --ro-bind /home/luke/.cargo/git /cargo/git \
 --ro-bind /home/luke/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu /toolchain --dir /src \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/future-exit-feasibility/Cargo.toml /src/Cargo.toml \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/future-exit-feasibility/Cargo.lock /src/Cargo.lock \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/future-exit-feasibility/src /src/src \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/future-exit-target /target \
 --setenv PATH /toolchain/bin:/usr/bin:/bin --setenv RUSTC /toolchain/bin/rustc \
 --setenv CARGO_HOME /cargo --setenv CARGO_TARGET_DIR /target --setenv TMPDIR /tmp --chdir /src \
 /toolchain/bin/cargo build --frozen --offline --release -j6 --target x86_64-unknown-linux-gnu \
 --manifest-path /src/Cargo.toml
