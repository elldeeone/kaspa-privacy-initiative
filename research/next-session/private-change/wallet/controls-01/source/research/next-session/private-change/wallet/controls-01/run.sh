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
for relative in poc/future-recipient/v2/recipient.py poc/independent-recovery/replay.py poc/independent-recovery/policy_template.py; do
 args+=(--ro-bind "$project_root/$relative" "/app/$relative")
done
args+=(--ro-bind /home/luke/projects/kpi-intensive-2026-10-22/private-wallet-controls-release-01/crypto /private-wallet-controls-release-01/crypto
 --bind "$out" /out --setenv PATH /usr/bin:/bin --chdir /app/poc/private-change-wallet)
exec /usr/bin/bwrap "${args[@]}" /bin/bash -c \
 'exec /usr/bin/time -v -o /out/resources.log /usr/bin/python3 -B -m unittest discover -s /app/poc/private-change-wallet -p test_change_wallet.py -v > /out/tests.log 2>&1'
