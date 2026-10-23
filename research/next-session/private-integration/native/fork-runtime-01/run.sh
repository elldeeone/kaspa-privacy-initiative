#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation /home/luke/projects/kpi-intensive-2026-10-22/continuation \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-union-selected/native-controls-05 /home/luke/projects/kpi-intensive-2026-10-22/future-union-selected/native-controls-05 \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/selected-native-01 /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/selected-native-01 \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/native/fork-runtime-01 /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/native/fork-runtime-01 \
 --setenv PATH /usr/bin:/bin --setenv PYTHONDONTWRITEBYTECODE 1 --setenv RAYON_NUM_THREADS 2 \
 --chdir /home/luke/projects/kpi-intensive-2026-10-22/continuation \
 /usr/bin/time -v /usr/bin/python3 \
 /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/native/source-forks-07/run_controls.py \
 --freeze /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/native/GENUINE-FORK-FREEZE-01.json \
 --reviewed-freeze-sha256 dde66f751aa383057a186f7fb659f4c440467246b615c5ca7e6e50f7be9a53c0 \
 --output /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/native/fork-runtime-01/evaluation
