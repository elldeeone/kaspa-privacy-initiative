#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/private-exit-proof-target/selected-build03/kpi-private-exit-proof /app --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/proof/fixtures-01/negative-output-cm.json /fixture.json \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/proof/controls-01/cases/negative-output-cm /out --setenv RAYON_NUM_THREADS 1 --chdir /out \
 /usr/bin/time -v -o /out/resources-app.log /app check-negative /fixture.json /out/result
