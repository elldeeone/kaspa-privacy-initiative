#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp --tmpfs /cargo --tmpfs /target \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/binding-cargo-home/registry /cargo/registry \
 --ro-bind /home/luke/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu /toolchain \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/proof/build-03/source /workspace --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/proof/build-03/inside.sh /build.sh \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/exact-sha-proof-target/release /target/release \
 --setenv PATH /toolchain/bin:/usr/bin:/bin --setenv RUSTC /toolchain/bin/rustc --setenv CARGO_HOME /cargo \
 --setenv CARGO_TARGET_DIR /target --setenv TMPDIR /tmp --setenv RAYON_NUM_THREADS 4 --chdir /workspace /bin/bash /build.sh
