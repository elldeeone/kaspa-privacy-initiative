#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/source-setup-01/poc/future-lifecycle /workspace \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/materialized-01/private-fixture.json /fixture.json \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/selected-proof-runner-01 /runner \
 --setenv PATH /usr/bin:/bin --setenv RAYON_NUM_THREADS 14 --chdir /workspace \
 /usr/bin/time -v /runner prove /fixture.json \
 /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/proof-01 \
 /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/setup-01/new-key-selection.json
