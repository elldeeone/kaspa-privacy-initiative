#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
RUN="${1:-$ROOT/research/busy-pool-payment-flow-2026-11-06/run}"
export CARGO_TARGET_DIR="$ROOT/.local/ci-target" RAYON_NUM_THREADS=4 OMP_NUM_THREADS=4
export PYTHONDONTWRITEBYTECODE=1
python3 poc/busy-pool-payment-flow/verify_packet.py "$RUN"
cargo +1.97.1 build --locked --release --manifest-path poc/busy-pool-payment-flow/host/Cargo.toml
"$CARGO_TARGET_DIR/release/kpi-busy-pool-payment-flow" replay \
  "$ROOT/research/reusable-withdrawal-approvals-2026-11-06/run/program.bin" "$RUN"
CHECK_DIR="$(mktemp -d)"
trap 'rm -rf -- "$CHECK_DIR"' EXIT
python3 - "$RUN" "$CHECK_DIR" <<'PY'
import json,sys
from pathlib import Path
run,target=map(Path,sys.argv[1:])
records=json.loads((run/'MAIN.json').read_text())['records']
# This is the already reverified priority transaction's exact public input.
# The wrapper only feeds the existing host guard checker, not a new receipt.
p=target/'priority-withdrawal';p.mkdir()
(p/'HOST-ONLY.json').write_text(json.dumps({'inputBincodeHex':records[3]['inputBincodeHex']}))
PY
"$CARGO_TARGET_DIR/release/kpi-busy-pool-payment-flow" controls "$CHECK_DIR"
python3 poc/busy-pool-payment-flow/views.py "$RUN" "$CHECK_DIR/observer-views.json"
python3 - "$RUN" "$CHECK_DIR/observer-views.json" <<'PY'
import json,sys
from pathlib import Path
sys.path.insert(0,str(Path('poc/busy-pool-payment-flow').resolve()))
from analyse import analyse
run,observed=map(Path,sys.argv[1:])
assert json.loads(observed.read_text())==json.loads((run/'OBSERVER-VIEWS.json').read_text())
assert analyse(run)==json.loads((run/'MEASUREMENTS.json').read_text())
print('Observer views and cost/wait measurements reproduce from retained public inputs.')
PY
python3 poc/busy-pool-payment-flow/analyse.py "$RUN"
if [[ -d "$RUN/cancellation" ]]; then
  python3 poc/busy-pool-payment-flow/verify_cancel.py "$RUN" "$RUN/cancellation/refreshed" \
    "$CARGO_TARGET_DIR/release/kpi-busy-pool-payment-flow" \
    "$ROOT/research/reusable-withdrawal-approvals-2026-11-06/run/program.bin"
fi
