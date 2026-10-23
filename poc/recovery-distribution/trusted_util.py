"""Fixed public utilities, authenticated before import; no mirror-selected code."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys

VENDOR = Path(__file__).absolute().parent / 'vendor'
PINS = {
    'capsule.py': 'ba6fba072eb00e54297e47473c61ce7ef2230356183c9dfd60d0a8741cc492d2',
    'chunk_public.py': 'c713a4871079acd040f5c434ceed47c4d6f71885c8e5256199a86488a5f724aa',
}


def checked_source(name):
    path = VENDOR / name
    if name not in PINS or any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('trusted-source-path')
    if not stat.S_ISREG(path.lstat().st_mode):
        raise RuntimeError('trusted-source-type')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PINS[name]:
        raise RuntimeError('trusted-source-identity')
    return path, raw


path, owned = checked_source('capsule.py')
name = '_kpi_distribution_public_capsule_ba6f'
spec = importlib.util.spec_from_file_location(name, path)
c = importlib.util.module_from_spec(spec)
sys.modules[name] = c
exec(compile(owned, str(path), 'exec'), c.__dict__)


def fresh_parent(path):
    """Open an output parent through no-follow directory FDs; target stays closed."""
    path = c._path(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise
