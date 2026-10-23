#!/bin/bash
set -eu
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/privacy-recovery-observer/pilot_observer.py /observer.py \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/observer/pilot-input-01/public-chain.json /input/public-chain.json \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/observer/run-02 /out \
 --setenv PATH /usr/bin:/bin /usr/bin/time -v -o /out/resources.log \
 /usr/bin/python3 -B /observer.py /input/public-chain.json /out/result.json
