#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/private-exit-proof-target/selected-build02/kpi-private-exit-proof /app --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/proof/synthesis-01/spend-fixture.json /fixture.json \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/proof/synthesis-01 /out --setenv RAYON_NUM_THREADS 2 --chdir /out /app check /fixture.json /out/result
