#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/uncompressed-prover-target/converter-stage01/convert /runner \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/setup-01/new-key-selection.json /selection.json \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/new-development-key-01.pk /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/new-development-key-01.pk \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/uncompressed-prover-target/conversion-stage01 /out \
 --setenv PATH /usr/bin:/bin --setenv RAYON_NUM_THREADS 14 --chdir /tmp \
 /usr/bin/time -v -o /out/resources.log /runner /selection.json /out/selected-development.uncompressed.pk /out/provenance
