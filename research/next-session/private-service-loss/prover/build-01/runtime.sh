#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp --tmpfs /cargo --tmpfs /target \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/binding-cargo-home/registry /cargo/registry \
 --ro-bind /home/luke/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu /toolchain \
 --ro-bind '/home/luke/projects/kpi-intensive-2026-10-22/private-service-loss-tn10-01/source-workspace' /workspace --ro-bind '/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-service-loss/prover/build-01/inside.sh' /build.sh \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/private-cashout-prover-target/release /target/release \
 --bind '/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-service-loss/prover/build-01' /out --setenv PATH /toolchain/bin:/usr/bin:/bin --setenv RUSTC /toolchain/bin/rustc \
 --setenv CARGO_HOME /cargo --setenv CARGO_TARGET_DIR /target --setenv TMPDIR /tmp --setenv RAYON_NUM_THREADS 8 \
 --chdir /workspace /usr/bin/time -v -o /out/resources-app.log /bin/bash /build.sh
