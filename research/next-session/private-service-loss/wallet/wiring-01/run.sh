#!/bin/bash
set -euo pipefail
project_root=/home/luke/projects/kpi-intensive-2026-10-22/continuation
runtime="$project_root/research/next-session/private-service-loss/wallet/runtime"
out="$project_root/research/next-session/private-service-loss/wallet/wiring-01"
args=(--unshare-all --die-with-parent --new-session --clearenv
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp)
for name in owner_rules.py owner_runtime.py owner_selection.py receiver_tools.py private_action.py private_wallet.py; do
 args+=(--ro-bind "$project_root/poc/private-cashout-wallet/$name" "/app/poc/private-cashout-wallet/$name")
done
args+=(--ro-bind "$project_root/poc/future-recipient/v2/recipient.py" /app/poc/future-recipient/v2/recipient.py)
while IFS= read -r relative; do
 args+=(--ro-bind "$project_root/$relative" "/app/$relative")
done < "$runtime/PUBLIC-NETWORK-SOURCES.txt"
while IFS= read -r installed; do
 args+=(--ro-bind "$installed" "$installed")
done < "$runtime/PUBLIC-INSTALLED-SOFTWARE.txt"
args+=(--ro-bind "$project_root/research/next-session/private-service-loss/network/ORDINARY-NETWORK-SOURCE-FREEZE-01.json" /app/research/next-session/private-service-loss/network/ORDINARY-NETWORK-SOURCE-FREEZE-01.json
 --ro-bind "$project_root/research/next-session/private-service-loss/prover/parameters-01/public-parameters.json" /manifest.json
 --ro-bind "$out/check.py" /check.py --bind "$out" /out
 --setenv PATH /usr/bin:/bin --chdir /app/poc/private-cashout-wallet)
exec /usr/bin/bwrap "${args[@]}" /usr/bin/time -v -o /out/resources.log /usr/bin/python3 -B /check.py
