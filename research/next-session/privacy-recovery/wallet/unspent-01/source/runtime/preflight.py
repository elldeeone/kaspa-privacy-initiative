"""Check reviewed public pins and private *metadata*, never backup bytes."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import stat
import sys

mode, backup, public_out, descriptor, fetched, request, freeze = sys.argv[1:8]
private_parent = sys.argv[8] if len(sys.argv) == 9 else None
pins = json.loads(Path(freeze).read_bytes())
assert pins['schema'] == 'kpx2-cold-wallet-runtime-freeze/v1'
for item in pins['public_pins']:
    path = Path(item['path'])
    assert path.is_file() and not path.is_symlink()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256']
paths = {item['path'] for item in pins['public_pins']}
assert all(str(Path(path).absolute()) in paths for path in (descriptor, fetched, request))
wallet_path = Path(pins['archived_wallet_path'])
assert str(wallet_path) in paths
spec = importlib.util.spec_from_file_location('reviewed_wallet_preflight', wallet_path)
wallet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wallet)
backup_path = Path(backup).absolute()
wallet.no_symlinks(backup_path)
wallet.outside_git(backup_path)
assert backup_path.is_file() and stat.S_IMODE(backup_path.stat().st_mode) == 0o600
if mode == 'prepare-reveal':
    assert private_parent is not None
    private = Path(private_parent).absolute()
    wallet.no_symlinks(private)
    wallet.outside_git(private)
    assert private.is_dir() and stat.S_IMODE(private.stat().st_mode) == 0o700
    assert not any(private.iterdir())
else:
    assert mode == 'recover' and private_parent is None
selected_request = wallet.parse_json(Path(request).read_bytes())
selected_descriptor = wallet.parse_json(Path(descriptor).read_bytes())
assert selected_request['op'] == mode
assert selected_request['expected_descriptor_sha256'] == pins['canonical_descriptor_sha256']
assert wallet.descriptor_identity(selected_descriptor) == pins['canonical_descriptor_sha256']
if mode == 'prepare-reveal':
    assert selected_request['disclosure_consent'] == wallet.DISCLOSURE_CONSENT
Path(public_out, 'preflight.json').write_text(json.dumps({
    'passed': True, 'mode': mode, 'public_pins_checked': len(pins['public_pins']),
    'source_freeze_sha256': hashlib.sha256(Path(freeze).read_bytes()).hexdigest(),
    'one_backup_metadata_checked': True, 'backup_bytes_or_hash_read': False,
    'private_output_metadata_checked': private_parent is not None,
    'canonical_descriptor_sha256': pins['canonical_descriptor_sha256'],
}, indent=2) + '\n')
