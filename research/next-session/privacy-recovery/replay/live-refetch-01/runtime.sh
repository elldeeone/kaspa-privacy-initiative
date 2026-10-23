#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind "/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/independent-recovery" /source --ro-bind "/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/fetch/descriptor-v1.json" /descriptor.json \
 --ro-bind "/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/fetch/vector-refetch-02/network-data/fetch.json" /fetch.json --ro-bind "/home/luke/projects/kpi-intensive-2026-10-22/future-union-selected/native-controls-05" /validator \
 --bind "/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/replay/live-refetch-01" /out --setenv PATH /usr/bin:/bin --chdir /source \
 /usr/bin/time -v -o /out/resources.log /usr/bin/python3 -B /source/run_replay.py \
 /descriptor.json /fetch.json /validator /out/evaluation
