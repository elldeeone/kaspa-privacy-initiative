#!/bin/bash
set -euo pipefail
test ! -e /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/new-development-key-01.pk
test ! -e /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/selected-proof-runner-01
/usr/bin/python3 - <<'PY'
from pathlib import Path
import json
p=Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/execution-environment-01.json')
assert not p.exists()
p.write_text(json.dumps({'network_namespace_isolated':True,'PK_file_mounted':False,'prover_executable_mounted':False,'native_and_recipient_crypto_only':True,'checked_before_any_reveal_authorization':True},indent=2)+'\n')
PY
exec /usr/bin/time -v /usr/bin/python3 /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/future-lifecycle/assemble.py execute \
 --crypto /home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/kpi-future-recipient-crypto \
 --native /home/luke/projects/kpi-intensive-2026-10-22/future-lifecycle-target/selected-native-01 \
 --prepared /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/materialized-01 \
 --prefix /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/prefix-01 \
 --proof /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/proof-01 \
 --freeze /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/PRE-EXECUTION-FREEZE-01.json \
 --output /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/execution-01
