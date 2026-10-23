#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/source-execute-01/assemble.py /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/future-lifecycle/assemble.py \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/future-recipient/v2/recipient.py /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/future-recipient/v2/recipient.py \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/selected-native-01 /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/selected-native-01 \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/kpi-future-recipient-crypto /home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/kpi-future-recipient-crypto \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/execute-inside-01.sh /inside.sh \
 --setenv PATH /usr/bin:/bin --setenv PYTHONDONTWRITEBYTECODE 1 --setenv RAYON_NUM_THREADS 1 \
 --chdir /home/luke/projects/kpi-intensive-2026-10-22/continuation /bin/bash /inside.sh
