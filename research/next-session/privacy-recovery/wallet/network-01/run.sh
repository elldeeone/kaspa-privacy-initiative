#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/independent-recovery/wallet.py /app/poc/independent-recovery/wallet.py \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/independent-recovery/replay.py /app/poc/independent-recovery/replay.py \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/independent-recovery/policy_template.py /app/poc/independent-recovery/policy_template.py \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/independent-recovery/kpx2-policy-template.bin /app/poc/independent-recovery/kpx2-policy-template.bin \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/independent-recovery/kpx2-policy-template.json /app/poc/independent-recovery/kpx2-policy-template.json \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/future-recipient/v2/recipient.py /app/poc/future-recipient/v2/recipient.py \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/fetch/descriptor-v1.json /descriptor.json \
 --ro-bind "$1" /backup.json --ro-bind "$3" /fetch.json \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/kpi-future-recipient-crypto /crypto \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/wallet/network-01/request.json /request.json --bind "$2" /out \
 --setenv PATH /usr/bin:/bin --chdir /app/poc/independent-recovery \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/wallet/network-01/mount_check.py /mount-check.py \
 /bin/bash -c '/usr/bin/python3 -B /mount-check.py && exec /usr/bin/time -v -o /out/resources.log /usr/bin/python3 -B /app/poc/independent-recovery/wallet.py < /request.json'
