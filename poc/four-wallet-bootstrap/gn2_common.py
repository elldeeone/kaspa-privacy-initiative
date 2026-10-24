"""GN2 strict public encodings and fixed reference bytes; no private IO."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MAX = 2_870_000_000_000_000_000
NOTE_FLOOR = 60_000_000
GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
CLASS = 'TESTNET_REHEARSAL_ONLY_ADR0060'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


class Invalid(ValueError):
    """Category only: exceptions must not interpolate private values."""


def need(value, category):
    if not value:
        raise Invalid(category)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def parse(raw):
    def pairs(rows):
        result = {}
        for key, item in rows:
            need(key not in result, 'duplicate-JSON-key')
            result[key] = item
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Invalid('nonfinite-JSON')))
    except (TypeError, json.JSONDecodeError, UnicodeError):
        raise Invalid('invalid-JSON') from None


def fields(value, names, category):
    need(type(value) is dict and set(value) == set(names), category)


def uint(value, bits=64):
    need(type(value) is int and 0 <= value < 1 << bits, 'unsigned-integer-range')
    return value


def amount(value, positive=False):
    need(type(value) is int and (0 < value if positive else 0 <= value) and value <= MAX,
         'integer-sompi-range')
    return value


def hx(value, width=None):
    need(type(value) is str and len(value) % 2 == 0
         and all(c in '0123456789abcdef' for c in value), 'canonical-hex')
    raw = bytes.fromhex(value)
    need(width is None or len(raw) == width, 'hex-width')
    return raw


def uuid_text(value):
    need(type(value) is str, 'canonical-trial-UUID')
    try:
        item = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise Invalid('canonical-trial-UUID') from None
    need(item.version == 4 and item.variant == uuid.RFC_4122 and str(item) == value,
         'canonical-trial-UUID')
    return value


def checked(value):
    path = Path(value).expanduser().absolute()
    need('..' not in path.parts and all(not p.is_symlink() for p in (path, *path.parents)),
         'unsafe-path')
    return path


def outside(value):
    path = checked(value)
    need(not path.is_relative_to(ROOT), 'private-path-in-project')
    probe = path if path.is_dir() else path.parent
    while not probe.exists():
        probe = probe.parent
    result = subprocess.run(['/usr/bin/git', '-c', 'safe.directory=*', '-C', str(probe),
        'rev-parse', '--is-inside-work-tree'], capture_output=True, text=True, env=CLEAN)
    need(result.returncode != 0 or result.stdout.strip() != 'true', 'private-path-in-Git')
    return path


def regular(value, forbidden=()):
    path = checked(value)
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) not in tuple(forbidden),
         'public-private-alias-or-file-type')
    return path, info


def public_bytes(value, forbidden=()):
    path, before = regular(value, forbidden)
    with path.open('rb') as file:
        need((os.fstat(file.fileno()).st_dev, os.fstat(file.fileno()).st_ino)
             == (before.st_dev, before.st_ino), 'public-file-swapped')
        raw = file.read()
    after = path.stat()
    attributes = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(tuple(getattr(before, k) for k in attributes)
         == tuple(getattr(after, k) for k in attributes), 'public-file-mutated')
    return raw


def write_new(value, raw, mode=0o600):
    path = checked(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, 'wb') as file:
        os.fchmod(file.fileno(), mode)
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def reference(name):
    files = {
        'primitives': ('poc/compact-batch-lifecycle/primitives.py',
            '184463d416a8e3c5605ce929bf2cead378c00e82d3827d30c83f8a6e19de5986'),
        'recipient': ('poc/future-recipient/v2/recipient.py',
            '93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2')}
    relative, expected = files[name]
    module_name = '_gn2_selected_' + name
    if module_name in sys.modules:
        return sys.modules[module_name]
    path = ROOT / relative
    raw = public_bytes(path)
    need(digest(raw) == expected, 'selected-reference-source')
    spec = importlib.util.spec_from_loader(module_name, loader=None)
    module = importlib.util.module_from_spec(spec)
    module.__file__ = str(path)
    sys.modules[module_name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module
