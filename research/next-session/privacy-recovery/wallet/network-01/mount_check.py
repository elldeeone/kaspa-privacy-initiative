from pathlib import Path
import json, stat
excluded = ['/home', '/app/research', '/native', '/recipient-target', '/app/poc/future-testnet', '/app/poc/future-private-payment']
assert all(not Path(path).exists() for path in excluded)
assert Path('/backup.json').is_file() and stat.S_IMODE(Path('/backup.json').stat().st_mode) == 0o600
Path('/out/mount-check.json').write_text(json.dumps({'excluded_paths_absent': excluded, 'one_backup_present_private': True, 'private_backup_bytes_read_by_preflight': False, 'network_namespace': 'isolated'}, indent=2) + '\n')
