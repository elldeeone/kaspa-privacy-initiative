#!/bin/bash
set -euo pipefail
mkdir -p '/home/luke/projects/kpi-intensive-2026-10-22/private-exit-proof-session-01/proofs'
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind '/home/luke/projects/kpi-intensive-2026-10-22/private-exit-proof-target/selected-build03/kpi-private-exit-proof' /app --ro-bind '/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/lifecycle/shape-01/shape-fixture.json' /shape.json \
 --bind '/home/luke/projects/kpi-intensive-2026-10-22/private-exit-proof-session-01' /out --setenv RAYON_NUM_THREADS 14 --setenv PATH /usr/bin:/bin --chdir /out \
 /usr/bin/time -v -o /out/resources-app.log /app session /shape.json /out/setup-01 /out/fresh-key.uncompressed.pk
