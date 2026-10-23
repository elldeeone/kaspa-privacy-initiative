#!/bin/bash
set -euo pipefail
project_root=/home/luke/projects/kpi-intensive-2026-10-22/continuation
out="$1"
/usr/bin/python3 -B - "$out" <<'PY'
from pathlib import Path
import json,sys
line=next(row for row in Path('/proc/self/cgroup').read_text().splitlines() if row.startswith('0::'))
p=Path('/sys/fs/cgroup')/line[3:].lstrip('/')
values={name:(p/name).read_text().strip() for name in ('cpu.max','memory.max','memory.swap.max')}
(Path(sys.argv[1])/'ACTIVE-CAPS.json').write_text(json.dumps({'observed_active_cgroup_limits':values},indent=2)+'\n')
PY
args=(--unshare-all --die-with-parent --new-session --clearenv
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp)
for name in owner_rules.py owner_runtime.py owner_selection.py receiver_tools.py change_action.py change_wallet.py test_change_wallet.py; do
 args+=(--ro-bind "$project_root/poc/private-change-wallet/$name" "/app/poc/private-change-wallet/$name")
done
while IFS= read -r relative; do
 args+=(--ro-bind "$project_root/$relative" "/app/$relative")
done < "$project_root/research/next-session/private-change/wallet/runtime/PUBLIC-NETWORK-SOURCES.txt"
while IFS= read -r installed; do
 args+=(--ro-bind "$installed" "$installed")
done < "$project_root/research/next-session/private-change/wallet/runtime/PUBLIC-INSTALLED-SOFTWARE.txt"
args+=(--ro-bind "$project_root/research/next-session/private-service-loss/network/ORDINARY-NETWORK-SOURCE-FREEZE-01.json" /app/research/next-session/private-service-loss/network/ORDINARY-NETWORK-SOURCE-FREEZE-01.json
 --ro-bind "$project_root/research/next-session/private-change/wallet/selected-checks-01/check.py" /app/check.py
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/private-wallet-controls-release-01/crypto /private-wallet-controls-release-01/crypto
 --bind "$out" /out --setenv PATH /usr/bin:/bin --chdir /app/poc/private-change-wallet)
exec /usr/bin/bwrap "${args[@]}" /bin/bash -c \
 'set -e; /usr/bin/python3 -B /app/check.py > /out/wiring.json; exec /usr/bin/time -v -o /out/resources.log /usr/bin/python3 -B -m unittest -v test_change_wallet.ChangeControls.test_forward_payment_rejects_known_spent_own_invoice_without_revoking_claims test_change_wallet.ChangeControls.test_duplicate_owned_claims_remain_actionable_and_largest_selected test_change_wallet.BoundaryControls.test_unselected_release_stops_before_any_request_file_read > /out/tests.log 2>&1'
