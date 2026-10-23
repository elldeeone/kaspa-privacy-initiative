#!/bin/bash
set -euo pipefail
test "$#" -eq 7
project_root=/home/luke/projects/kpi-intensive-2026-10-22/continuation
runtime="$project_root/research/next-session/private-service-loss/wallet/runtime"
own_backup="$1"
descriptor="$2"
manifest="$3"
fetched="$4"
private_parent="$5"
private_request="$6"
private_metadata="$7"
/usr/bin/python3 -B "$runtime/preflight.py" "$own_backup" "$private_parent" "$private_request" "$private_metadata"
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
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/private-cashout-owner-release-01/crypto /crypto
 --ro-bind "$own_backup" /backup.json --ro-bind "$descriptor" /descriptor.json
 --ro-bind "$manifest" /manifest.json --ro-bind "$fetched" /fetch.json
 --ro-bind "$private_request" /request.json
 --bind "$private_parent" /private --bind "$private_metadata" /metadata
 --setenv PATH /usr/bin:/bin --chdir /app/poc/private-cashout-wallet)
exec /usr/bin/bwrap "${args[@]}" /bin/bash -c \
 'exec /usr/bin/time -v -o /metadata/resources.log /usr/bin/python3 -B /app/poc/private-cashout-wallet/private_wallet.py < /request.json'
