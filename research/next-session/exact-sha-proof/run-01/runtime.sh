#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/exact-sha-proof-target/selected-stage01/exact-sha-proof-experiment /runner \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/materialized-01/private-fixture.json /fixture.json \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/exact-sha-proof-target/experiment-stage01 /out \
 --setenv PATH /usr/bin:/bin --setenv RAYON_NUM_THREADS 4 --chdir /tmp \
 /usr/bin/time -v -o /out/resources.log /runner /fixture.json /out/result
