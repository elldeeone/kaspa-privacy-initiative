#!/bin/bash
set -euo pipefail
sha256sum --check /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/exit-fee/future-exit/execution-01/identities.txt
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-exit-target/x86_64-unknown-linux-gnu/release/kpi-future-exit-feasibility /probe \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/exit-fee/future-exit/execution-01 /output \
 --chdir /output /probe run /output/results
