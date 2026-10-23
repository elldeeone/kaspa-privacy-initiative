#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-union-target/x86_64-unknown-linux-gnu/release/kpi-future-native-union /union \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-union-target/placeholder-two-PI-vk.bin /placeholder-vk \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/native/inspection-01 /output \
 --chdir /output /union inspect /placeholder-vk /output/results
