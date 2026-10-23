#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/selected-hmac-cost-target/selected-stage01/test-runner /test-runner \
 --setenv RAYON_NUM_THREADS 2 --setenv PATH /usr/bin:/bin \
 /usr/bin/time -v /test-runner --exact cross_language::measure_contract_synthesis --ignored --nocapture --test-threads=1
