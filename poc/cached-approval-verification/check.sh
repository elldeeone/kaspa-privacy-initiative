#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
evidence="${1:-$repo_root/research/cached-approval-verification-2026-11-07/run}"
replay_output="$(mktemp -d /tmp/kpi-cached-verification-replay.XXXXXX)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/.local/ci-target}"
export RAYON_NUM_THREADS=4
export OMP_NUM_THREADS=4
python3 - "$evidence" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);manifest=json.loads((root/'MANIFEST.json').read_text());seen=set()
for row in manifest['files']:
 rel=pathlib.PurePosixPath(row['path']);assert not rel.is_absolute() and '..' not in rel.parts and 'private' not in rel.parts
 assert row['path'] not in seen;seen.add(row['path']);f=root/rel
 assert f.is_file() and not f.is_symlink();data=f.read_bytes();assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'],f
print(len(seen),'public evidence hashes verified')
PY
cargo +1.97.1 build --locked --release --manifest-path "$repo_root/poc/cached-approval-verification/host/Cargo.toml"
host="$CARGO_TARGET_DIR/release/kpi-cached-approval-verification"
"$host" replay-diagnostic "$evidence/diagnostic/programs/settlement.bin" "$evidence/diagnostic"
"$host" controls "$evidence/diagnostic/cases" "$replay_output/economic.json"
"$host" receipt-controls "$evidence/diagnostic/programs/authorization.bin" "$evidence/diagnostic" "$replay_output/receipt.json"
"$host" native-controls "$evidence/diagnostic/programs/settlement.bin" "$evidence/diagnostic" "$replay_output/native.json"
cargo +1.97.1 build --locked --release --manifest-path "$repo_root/poc/cached-approval-verification/host/Cargo.toml" --no-default-features --features testnet
"$host" replay-combined "$evidence/programs/settlement.bin" "$evidence/combined"
"$host" verify-registration "$evidence/registration/config.json" "$evidence/registration/operator.jsonl" "$replay_output/registration.json"
"$host" replay-live "$evidence/programs/settlement.bin" "$evidence/rehearsal"
printf 'Public replay passed; fresh reports: %s\n' "$replay_output"
