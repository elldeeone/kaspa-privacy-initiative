"""Explicit byte/integer/path rules for the new private owner client."""
from pathlib import Path
import hashlib
import json
import os
import re
import stat
import subprocess

MAX = 2_870_000_000_000_000_000
GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
ROOT = Path(__file__).resolve().parents[2]


class Invalid(ValueError):
    """Secret-free client rejection category."""


def need(condition, category):
    if not condition:
        raise Invalid(category)


def hx(value, width=None):
    need(type(value) is str and re.fullmatch(r'(?:[0-9a-f]{2})*', value) is not None, 'canonical-hex')
    raw = bytes.fromhex(value)
    need(width is None or len(raw) == width, 'hex-width')
    return raw


def integer(value, maximum=MAX):
    need(type(value) is int or type(value) is str and re.fullmatch(r'0|[1-9][0-9]*', value), 'integer-sompi')
    value = int(value)
    need(0 <= value <= maximum, 'integer-range')
    return value


def requested_amount(value):
    """The new owner API has one amount encoding: a JSON integer sompi."""
    need(type(value) is int, 'requested-integer-sompi')
    return integer(value)


def input_metadata(request):
    """Protect the declared own backup from public-path aliases before reads.

    This is an inode/metadata guard, not discovery of arbitrary private files.
    The one-backup readonly namespace and trusted host remain required.
    """
    own = outside_git(request['backup_path'])
    info = own.stat()
    need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
         'backup-permissions')
    names = ['descriptor_path', 'public_manifest_path', 'fetch_path', 'crypto_path']
    names += [name for name in ('recipient_invoice_path', 'public_pk_path',
                               'local_prover_path', 'native_helper_path') if name in request]
    for name in names:
        public = no_symlinks(request[name])
        selected = public.stat()
        need(stat.S_ISREG(selected.st_mode), 'regular-public-input-required')
        need((selected.st_dev, selected.st_ino) != (info.st_dev, info.st_ino),
             'backup-public-path-alias')
        if name == 'recipient_invoice_path':
            need(selected.st_size == 208, 'recipient-invoice-width')


def u32(value):
    need(type(value) is int and 0 <= value < 1 << 32, 'u32')
    return value.to_bytes(4, 'little')


def u64(value):
    need(type(value) is int and 0 <= value < 1 << 64, 'u64')
    return value.to_bytes(8, 'little')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value, 'duplicate-json-field')
            value[key] = item
        return value
    def constant(_):
        raise Invalid('json-nonfinite-constant')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=constant)


def no_symlinks(path):
    path = Path(path).absolute()
    need(not any(item.is_symlink() for item in (path, *path.parents)), 'symlink-path')
    return Path(os.path.normpath(path))


def outside_git(path):
    path = no_symlinks(path)
    probe = path
    while not probe.exists():
        probe = probe.parent
    if not probe.is_dir():
        probe = probe.parent
    result = subprocess.run(['git', '-c', 'safe.directory=*', '-C', str(probe),
                             'rev-parse', '--show-toplevel'], capture_output=True)
    need(result.returncode != 0 and path != ROOT and ROOT not in path.parents,
         'private-material-inside-git')
    return path


def backup(path, descriptor):
    path = outside_git(path)
    need(path.is_file() and stat.S_IMODE(path.stat().st_mode) == 0o600, 'backup-permissions')
    value = parse(path.read_bytes())
    need(type(value) is dict and set(value) == {'schema', 'network_id', 'genesis_hash_hex',
                                             'domain_hex32', 'seed_hex32'}, 'seed-only-backup-fields')
    need(value['schema'] == 'kpx2-tn10-seed-backup/v1', 'backup-schema')
    need(all(value[k] == descriptor[k] for k in ('network_id', 'genesis_hash_hex', 'domain_hex32')),
         'backup-instance')
    return hx(value['seed_hex32'], 32)


def fresh_output(path):
    path = outside_git(path)
    need(not path.exists() and path.parent.is_dir(), 'fresh-private-output-required')
    return path


def write_private(path, value):
    raw = canonical(value) + b'\n' if type(value) is not bytes else value
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as file:
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())
