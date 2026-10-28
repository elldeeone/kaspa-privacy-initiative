"""METHOD02 stdlib-only host bootstrap; no Original body, RNG or truth IO.

Copied metadata/bootstrap primitives from the already qualified public
build_driver.py d8de726...; delegates all policy to that exact pinned loader.
Call load_guard BEFORE importing generator/native project modules. Initial
entry/helper bytes remain part of the externally selected source closure.
"""
import hashlib
import os
from pathlib import Path
import re
import stat

ROOT = Path(__file__).absolute().parents[3]
BOOTSTRAP = Path('/var/tmp/kpi-root-guard-helper-09.py')
BOOTSTRAP_SHA = '0f8ff562a4364c1db7729d98d7daf57f75ff5e882936e06e9907a4e936bd82fd'
QBUILD = ROOT / '.local/private-batch-history-settlement-candidate-01/public-driver-preparation/build_driver.py'
QBUILD_SHA = 'd8de7262599c0723813486c1cffa4b226052faa5b86886ae2c2a89e54ce39be4'
PRIVATE_ROOTS = (
    Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/mpc-prover-financial-runs/767159332ffa15d5a2dd4447237c78fb02d54165c1193cf313df8a35032824db'),
    Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/mpc-prover-financial-runs/581f4a3324649fe22b204919a57105849fea0d87032ce1b6bf225b83d53fe317'),
    Path('/run/user/1000/kpb-unfunded-batch-components-20261028-05/owners'),
    Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/mpc-prover-financial-runs/0b1f968077d9d4308457b7137f9bcd95c19721340c9acef398e47505276f7d38'),
    Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/owner-wait-toy-runs/fbb5efdf5519eafff4cb775801f80e5be4a414573c4b1d116e2367e7af2875c0'),
    Path('/dev/shm/kpb-public-driver-preparation-Px0Y9O/tls-controls-01/private'),
    Path('/var/tmp/kpi-local-private-payment-01/assets/ingress-runtime/tor-state'),
)


def need(value, message):
    if not value:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def plain(value):
    need(type(value) in (str, Path) or isinstance(value, Path), 'path type')
    path = Path(value)
    need(path.is_absolute() and path == Path(os.path.normpath(path))
         and not any(c in str(path) for c in '\r\n\t\0')
         and not any(p.is_symlink() for p in (path, *path.parents)), 'canonical absolute path')
    return path

def bootstrap_identity(info):
    return tuple(getattr(info, name) for name in
                 ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
                  'st_nlink', 'st_uid', 'st_mode'))

def bootstrap_private_metadata(exclusions):
    roots = tuple(dict.fromkeys(plain(value) for value in exclusions))
    inodes = set()
    def visit(path):
        info = path.lstat(); inodes.add((info.st_dev, info.st_ino))
        if stat.S_ISLNK(info.st_mode):
            target = path.stat(); inodes.add((target.st_dev, target.st_ino))
            need(not stat.S_ISDIR(target.st_mode), 'private bootstrap directory symlink')
        elif stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as entries:
                for entry in entries: visit(Path(entry.path))
    for root in roots:
        need(stat.S_ISDIR(root.lstat().st_mode), 'whole private bootstrap root must exist')
        visit(root)
    return roots, inodes

def bootstrap_public_metadata(path, roots, inodes):
    path = plain(path); info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and all(not path.is_relative_to(root) for root in roots)
         and (info.st_dev, info.st_ino) not in inodes, 'bootstrap public/private metadata exclusion')
    return bootstrap_identity(info)

def refresh_private_metadata(guard):
    for root in guard['m'].GUARD.directories:
        root = plain(root); need(root.is_dir(), 'private metadata root disappeared')
        def failed(error): raise ValueError('private metadata enumeration refused') from error
        for directory, subdirectories, files in os.walk(root, followlinks=False, onerror=failed):
            subdirectories[:] = [name for name in subdirectories if not (Path(directory)/name).is_symlink()]
            for name in files:
                info = (Path(directory)/name).lstat()
                if stat.S_ISREG(info.st_mode): guard['m'].GUARD.inodes.add((info.st_dev, info.st_ino))

def add_exclusions(guard, roots):
    checked = []
    for value in roots:
        path = plain(value)
        need(path.is_dir(), 'whole private exclusion must exist')
        checked.append(path)
    guard['m'].GUARD.directories = tuple(dict.fromkeys((*guard['m'].GUARD.directories, *checked)))
    guard['refresh']()
    refresh_private_metadata(guard)

def load_guard():
    # New private roots are inventoried BEFORE any retained helper body opens.
    roots, inodes = bootstrap_private_metadata(PRIVATE_ROOTS)
    imports = [Path('/var/tmp/kpi-root-guard-helper-' + number + '.py')
               for number in ('01', '03', '04', '05', '06', '07', '08', '09')]
    imports.append(ROOT / 'poc/four-wallet-profile/outer_run.py')
    admitted = {path: bootstrap_public_metadata(path, roots, inodes) for path in imports}
    descriptor = os.open(BOOTSTRAP, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        need(bootstrap_identity(before) == admitted[BOOTSTRAP], 'bootstrap inode before body')
        raw = source.read()
        after = os.fstat(source.fileno())
    need(sha(raw) == BOOTSTRAP_SHA and bootstrap_identity(before) == bootstrap_identity(after),
         'selected unchanged guard09 bootstrap')
    need(all(bootstrap_public_metadata(path, roots, inodes) == identity
             for path, identity in admitted.items()), 'guard import metadata changed')
    guard = {'__file__': str(BOOTSTRAP), '__name__': 'method02_guard09_bootstrap'}
    exec(compile(raw, str(BOOTSTRAP), 'exec'), guard)
    add_exclusions(guard, roots)
    # The existing guard now covers legacy h09 Originals PLUS all six roots.
    # Admit the exact qualified loader through it; do not read a live alias.
    refresh_private_metadata(guard)
    loader_raw = guard['read'](plain(QBUILD), QBUILD_SHA)
    qualified = {'__file__': str(QBUILD), '__name__': 'method02_qualified_guard_library'}
    exec(compile(loader_raw, str(QBUILD), 'exec'), qualified)
    # Return its already-reviewed fresh-each-body wrapper, with no relaxation.
    return qualified['load_guard'](PRIVATE_ROOTS)
