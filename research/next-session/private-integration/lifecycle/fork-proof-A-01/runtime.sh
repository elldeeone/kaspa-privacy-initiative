#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/setup-01/new-key-selection.json /selection.json \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/forks-materialized-01/A-private-before-reveal/private-fixture.json /fixture.json \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/new-development-key-01.pk /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/new-development-key-01.pk \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/selected-fork-prover-01 /runner \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/fork-proof-A-runtime-01 /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/fork-proof-A-runtime-01 \
 --setenv PATH /usr/bin:/bin --setenv RAYON_NUM_THREADS 7 --chdir /tmp \
 /usr/bin/time -v /runner prove /selection.json /fixture.json /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/fork-proof-A-runtime-01/proof
