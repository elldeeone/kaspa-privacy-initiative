#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/source-materialize-01/assemble.py /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/future-lifecycle/assemble.py \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/future-recipient/v2/recipient.py /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/future-recipient/v2/recipient.py \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/selected-native-01 /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/selected-native-01 \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/kpi-future-recipient-crypto /home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/kpi-future-recipient-crypto \
 --setenv PATH /usr/bin:/bin --setenv PYTHONDONTWRITEBYTECODE 1 --setenv RAYON_NUM_THREADS 1 \
 --chdir /home/luke/projects/kpi-intensive-2026-10-22/continuation \
 /usr/bin/time -v /usr/bin/python3 /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/future-lifecycle/assemble.py materialize \
 --crypto /home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/kpi-future-recipient-crypto \
 --native /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/selected-native-01 \
 --vk /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/setup-01/verification-key.bin \
 --backups /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/shape-01/PUBLIC-SYNTHETIC-backups.json \
 --output /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/materialized-01
