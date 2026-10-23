#!/bin/bash
set -euo pipefail
test "$#" -eq 1
root=/home/luke/projects/kpi-intensive-2026-10-22/continuation
args=(--unshare-all --die-with-parent --new-session --clearenv
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp)
for name in owner_rules.py owner_runtime.py owner_selection.py receiver_tools.py private_action.py private_wallet.py test_private_wallet.py; do
 args+=(--ro-bind "$root/poc/private-cashout-wallet/$name" "/app/poc/private-cashout-wallet/$name")
done
args+=(--ro-bind "$root/poc/future-recipient/v2/recipient.py" /app/poc/future-recipient/v2/recipient.py
 --ro-bind "$root/poc/independent-recovery/replay.py" /app/poc/independent-recovery/replay.py
 --ro-bind "$root/poc/independent-recovery/policy_template.py" /app/poc/independent-recovery/policy_template.py
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/kpi-future-recipient-crypto /recipient-target/debug/kpi-future-recipient-crypto
 --bind "$1" /out --setenv PATH /usr/bin:/bin --chdir /app/poc/private-cashout-wallet)
exec /usr/bin/bwrap "${args[@]}" /usr/bin/time -v -o /out/resources.log \
 /usr/bin/python3 -B -m unittest discover -s /app/poc/private-cashout-wallet -p test_private_wallet.py -v
