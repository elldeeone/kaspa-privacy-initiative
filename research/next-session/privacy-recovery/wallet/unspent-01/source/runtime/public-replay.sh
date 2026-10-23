#!/bin/bash
set -euo pipefail
test "$#" -eq 3
root=/home/luke/projects/kpi-intensive-2026-10-22/continuation
packet="$root/research/next-session/privacy-recovery/wallet/unspent-01"
source="$root/poc/independent-recovery"
/usr/bin/python3 -B "$packet/cgroup.py" "$3"
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind "$source/replay.py" /source/replay.py \
 --ro-bind "$source/policy_template.py" /source/policy_template.py \
 --ro-bind "$source/kpx2-policy-template.bin" /source/kpx2-policy-template.bin \
 --ro-bind "$source/kpx2-policy-template.json" /source/kpx2-policy-template.json \
 --ro-bind "$source/native_validation.py" /source/native_validation.py \
 --ro-bind "$source/run_replay.py" /source/run_replay.py \
 --ro-bind "$1" /descriptor.json --ro-bind "$2" /fetch.json \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/future-union-selected/native-controls-05 /validator \
 --bind "$3" /out --setenv PATH /usr/bin:/bin --chdir /source \
 /usr/bin/time -v -o /out/resources.log /usr/bin/python3 -B /source/run_replay.py \
 /descriptor.json /fetch.json /validator /out/evaluation
