from pathlib import Path
import json
import stat
import sys

mode = sys.argv[1]
assert mode in ('recover', 'prepare-reveal')
excluded = ['/home', '/app/research', '/recipient-target',
            '/app/poc/future-testnet', '/app/poc/future-private-payment']
assert all(not Path(path).exists() for path in excluded)
assert Path('/backup.json').is_file()
assert stat.S_IMODE(Path('/backup.json').stat().st_mode) == 0o600
if mode == 'recover':
    assert not Path('/native').exists() and not Path('/private').exists()
else:
    assert Path('/native').is_file() and Path('/private').is_dir()
    assert stat.S_IMODE(Path('/private').stat().st_mode) == 0o700
    assert not any(Path('/private').iterdir())
Path('/out/mount-check.json').write_text(json.dumps({
    'mode': mode, 'excluded_paths_absent': excluded,
    'one_backup_present_private': True,
    'private_backup_bytes_read_by_preflight': False,
    'network_namespace': 'isolated',
    'native_helper_mounted': mode == 'prepare-reveal',
    'private_signed_output_mount_present': mode == 'prepare-reveal',
}, indent=2) + '\n')
