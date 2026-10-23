#!/bin/bash
set -euo pipefail
mode="$1"
backup="$2"
public_out="$3"
descriptor="$4"
fetched="$5"
request="$6"
freeze="$7"
packet=/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/wallet/unspent-01
source=/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/wallet/network-01/source
case "$mode" in
 recover) test "$#" -eq 7 ;;
 prepare-reveal) test "$#" -eq 8 ;;
 *) exit 2 ;;
esac
/usr/bin/python3 -B "$packet/preflight.py" "$@"
/usr/bin/python3 -B "$packet/cgroup.py" "$public_out"
args=(--unshare-all --die-with-parent --new-session --clearenv
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp
 --ro-bind "$source/poc/independent-recovery/wallet.py" /app/poc/independent-recovery/wallet.py
 --ro-bind "$source/poc/independent-recovery/replay.py" /app/poc/independent-recovery/replay.py
 --ro-bind "$source/poc/independent-recovery/policy_template.py" /app/poc/independent-recovery/policy_template.py
 --ro-bind "$source/poc/independent-recovery/kpx2-policy-template.bin" /app/poc/independent-recovery/kpx2-policy-template.bin
 --ro-bind "$source/poc/independent-recovery/kpx2-policy-template.json" /app/poc/independent-recovery/kpx2-policy-template.json
 --ro-bind "$source/poc/future-recipient/v2/recipient.py" /app/poc/future-recipient/v2/recipient.py
 --ro-bind "$descriptor" /descriptor.json --ro-bind "$fetched" /fetch.json
 --ro-bind "$backup" /backup.json
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/kpi-future-recipient-crypto /crypto
 --ro-bind "$request" /request.json --bind "$public_out" /out
 --ro-bind "$packet/client.py" /client.py --ro-bind "$packet/mount_check.py" /mount-check.py
 --setenv PATH /usr/bin:/bin --chdir /app/poc/independent-recovery)
case "$mode" in
 recover) ;;
 prepare-reveal)
  args+=(--ro-bind /home/luke/projects/kpi-intensive-2026-10-22/recovery-native-target/selected-01/kpi-independent-recovery-native /native
          --bind "$8" /private)
  ;;
 *) exit 2 ;;
esac
exec /usr/bin/bwrap "${args[@]}" /bin/bash -c \
 '/usr/bin/python3 -B /mount-check.py "$1" && exec /usr/bin/time -v -o /out/resources.log /usr/bin/python3 -B /client.py /request.json "$1"' \
 cold-client "$mode"
