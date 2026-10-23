#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind "/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/independent-recovery" /source --ro-bind "/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/setup-01/verification-key.bin" /public-vk.bin \
 --bind "/home/luke/projects/kpi-intensive-2026-10-22/recovery-replay-target/scaling-01" /out --setenv PATH /usr/bin:/bin --chdir /source \
 /usr/bin/time -v -o /out/resources.log /usr/bin/python3 -B /source/benchmark.py \
 10000 /public-vk.bin /out/UNPROVED-fixture.json /out/report.json
