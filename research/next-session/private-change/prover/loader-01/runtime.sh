#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind '/home/luke/projects/kpi-intensive-2026-10-22/private-change-prover-target/selected-owner-build02/kpi-private-cashout-prover' /app --ro-bind '/home/luke/projects/kpi-intensive-2026-10-22/private-cashout-public-parameters/b440d08fddcdbbfb7d6b8355ab097a7bedd3fb85b8aa228f07070d4fcb3a91d0/parameters.pk' /parameters.pk --ro-bind '/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-change/prover/parameters-01/public-parameters.json' /manifest.json \
 --ro-bind '/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-service-loss/prover/test_selected_loader.py' /test.py --bind '/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-change/prover/loader-01' /out \
 --setenv PATH /usr/bin:/bin --setenv LANG C.UTF-8 --setenv TZ UTC --setenv RAYON_NUM_THREADS 8 \
 --chdir /out /usr/bin/time -v -o /out/resources-app.log /usr/bin/python3 /test.py \
 --binary /app --manifest /manifest.json --public-pk /parameters.pk --output /out/results
