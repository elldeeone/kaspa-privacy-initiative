#!/usr/bin/env python3
"""Fresh no-network namespace entry; exact old application paths and bytes."""
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import time

SCOPE = 'PUBLIC_ONLY_SYNTHETIC_METADATA_NOT_OWNER_OR_RECOVERY_AUTHORITY'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def regular(path):
    for parent in (path, *path.parents):
        need(not parent.is_symlink(), 'public export symlink refused')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'single-link regular public export required')
    return info


started = time.perf_counter()
fds = []
for name in os.listdir('/proc/self/fd'):
    if int(name) > 2:
        try:
            os.readlink('/proc/self/fd/' + name)
        except FileNotFoundError:
            continue
        fds.append(int(name))
need(not fds, 'inherited nonstdio descriptor refused')
request = json.loads(Path('/snapshot-request.json').read_bytes())
need(set(request) == {'schema', 'scope', 'argv', 'output_root', 'synthetic_stubs'}, 'closed execution fields')
need(request['schema'] == 'kpxa-public-pool-execution/v1' and request['scope'] == SCOPE, 'public-only execution scope')
root = Path(request['output_root'])
need(root.is_absolute() and str(PurePosixPath(root)) == str(root) and '..' not in root.parts, 'canonical output root')
need(not root.exists() and not root.is_symlink(), 'old application creates its own fresh output directory')
for name in request['synthetic_stubs']:
    info = regular(Path(name))
    need(info.st_size == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'empty synthetic import metadata required')
child = subprocess.run(request['argv'], stdin=subprocess.DEVNULL, capture_output=True, close_fds=True,
    env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'})
exports = []
if child.returncode == 0:
    need(root.is_dir() and not root.is_symlink(), 'successful application output directory required')
    # This is a new namespace-only tmpfs at the normal output path. No output
    # path, candidate JSON or old source path is rewritten or aliased.
    names = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            p = Path(directory) / name
            need(not p.is_symlink() and stat.S_ISDIR(p.lstat().st_mode), 'public output directory symlink refused')
        for name in files:
            names.append(Path(directory) / name)
    for path in sorted(names):
        need(root in path.parents and str(path.relative_to(root)) != 'POOL-PROVENANCE.json', 'reserved or escaped public export')
        before = regular(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            raw = stream.read()
            after = os.fstat(stream.fileno())
        need((before.st_dev, before.st_ino, before.st_size, before.st_ctime_ns, before.st_mtime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_ctime_ns, after.st_mtime_ns),
             'public export changed during read')
        exports.append({'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                        'base64': base64.b64encode(raw).decode()})
result = {'schema': 'kpxa-public-pool-execution-result/v1', 'scope': SCOPE,
    'returncode': child.returncode, 'stdout_base64': base64.b64encode(child.stdout).decode(),
    'stderr_base64': base64.b64encode(child.stderr).decode(), 'exports': exports,
    'inherited_nonstdio_fds': [], 'namespace_seconds': time.perf_counter() - started,
    'network': 'none', 'private_mounts_or_owner_authority': False}
print(json.dumps(result, sort_keys=True, separators=(',', ':')))
