#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation /home/luke/projects/kpi-intensive-2026-10-22/continuation \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-union-selected/native-controls-05 /home/luke/projects/kpi-intensive-2026-10-22/future-union-selected/native-controls-05 \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/selected-native-01 /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/selected-native-01 \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/native/control-runtime-01 /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/native/control-runtime-01 \
 --setenv PATH /usr/bin:/bin --setenv PYTHONDONTWRITEBYTECODE 1 --setenv RAYON_NUM_THREADS 2 \
 --chdir /home/luke/projects/kpi-intensive-2026-10-22/continuation \
 /usr/bin/time -v /usr/bin/python3 \
 /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/native/source-controls-06/run_controls.py \
 --freeze /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/native/CONTROL-FIXTURE-FREEZE-01.json \
 --reviewed-freeze-sha256 aea1f6eae052ac98ed690f7fb700130a6bc48e6655030add46286b6979e0c526 \
 --output /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/native/control-runtime-01/evaluation
