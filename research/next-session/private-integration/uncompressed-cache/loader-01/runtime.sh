#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/uncompressed-prover-target/selected-cache-stage02/cache-prover /runner \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/uncompressed-prover-target/conversion-stage01/selected-development.uncompressed.pk /cache.pk \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/uncompressed-prover-target/cache-loader-stage01 /out \
 --setenv PATH /usr/bin:/bin --setenv RAYON_NUM_THREADS 14 --chdir /tmp \
 /usr/bin/time -v -o /out/resources.log /runner loader-only /cache.pk /out/result
