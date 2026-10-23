"""Host private metadata only, authorized after the confirmed-prefix release.

Do not publish/hash these operational receipts or original private paths.
No backup bytes are read and no owner program/prover is launched here.
"""
import json
import os
from pathlib import Path
import stat
import sys

project_root = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(project_root / 'poc/private-cashout-wallet'))
from owner_rules import outside_git

backup, private_parent, request, metadata = map(Path, sys.argv[1:5])
backup = outside_git(backup)
private_parent = outside_git(private_parent)
request = outside_git(request)
metadata = outside_git(metadata)
assert backup.is_file() and stat.S_IMODE(backup.stat().st_mode) == 0o600
assert request.is_file() and stat.S_IMODE(request.stat().st_mode) == 0o600
assert private_parent.is_dir() and stat.S_IMODE(private_parent.stat().st_mode) == 0o700
assert not any(private_parent.iterdir())
assert metadata.is_dir() and stat.S_IMODE(metadata.stat().st_mode) == 0o700
record = {'mode': 'OWNER_PRIVATE_METADATA_ONLY', 'one_backup_metadata_checked': True,
          'backup_bytes_or_hash_read': False, 'private_output_empty0700': True,
          'private_request_regular0600': True, 'readonly_bind_required': True}
try:
    membership = Path('/proc/self/cgroup').read_text().splitlines()
    relative = next(row[3:] for row in membership if row.startswith('0::'))
    cgroup = Path('/sys/fs/cgroup') / relative.lstrip('/')
    record['observed_cgroup_limits'] = {name: (cgroup / name).read_text().strip()
        for name in ('cpu.max', 'memory.max', 'memory.swap.max')}
except Exception as error:
    record['cgroup_observation_error_type'] = type(error).__name__
descriptor = os.open(metadata / 'PRIVATE-PREFLIGHT.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, 'w') as file:
    json.dump(record, file, sort_keys=True)
    file.write('\n')
