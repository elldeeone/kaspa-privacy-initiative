"""Trusted stdlib-only metadata and finite public software staging helpers."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
OWNER_NAMES = ('compat', 'contracts', 'local_source', 'no_append', 'owner', 'paths',
               'preparation', 'pricing', 'replay', 'runtime', 'source', 'worker')
CORE_NAMES = ('primitives', 'receiver', 'actions', 'native_runtime', 'history')
PUBLIC_NAMES = ('wire', 'policy', 'virtual')
CHAIN_NAMES = ('chain_replay.py', 'selection.mjs', 'wire.mjs', 'json.mjs',
               'acquire.mjs', 'verify_bundle.mjs')
SDK_DEST = '/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa/'
KINDS = {'source', 'cargo-vendor', 'build-config', 'public-metadata',
         'selected-executable', 'runtime-source', 'public-canary'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def checked(value):
    path = Path(value)
    need('..' not in path.parts, 'canonical-public-path')
    path = path.absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'public-path-symlink')
    return path


def outside(value):
    path = checked(value)
    need(not path.is_relative_to(ROOT), 'private-output-inside-project')
    parent = path if path.is_dir() else path.parent
    while not parent.exists():
        parent = parent.parent
    result = subprocess.run(['/usr/bin/git', '-c', 'safe.directory=*', '-C', str(parent),
        'rev-parse', '--is-inside-work-tree'], capture_output=True, text=True, env=CLEAN)
    need(result.returncode != 0 or result.stdout.strip() != 'true', 'private-output-inside-Git')
    return path


def parse(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate-JSON-field'); value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite-JSON')))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path, forbidden, private_directories=()):
    path = checked(path)
    need(all(not path.is_relative_to(directory) for directory in private_directories),
         'public-candidate-inside-original-private-directory')
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) not in forbidden,
         'public-file-private-alias-or-type')
    return path, info


def read_public(path, forbidden, private_directories=()):
    path, before = regular(path, forbidden, private_directories)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as file:
        opened = os.fstat(file.fileno())
        need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino)
             and (opened.st_dev, opened.st_ino) not in forbidden, 'public-file-swapped-before-read')
        raw = file.read()
        after = os.fstat(file.fileno())
    attributes = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(tuple(getattr(before, k) for k in attributes) == tuple(getattr(after, k) for k in attributes)
         and len(raw) == before.st_size, 'public-file-mutated-during-read')
    return raw


def relative(value):
    need(type(value) is str and value and '\\' not in value and '\0' not in value,
         'public-relative-path')
    path = PurePosixPath(value)
    need(not path.is_absolute() and str(path) == value
         and all(part not in ('.', '..', '') for part in path.parts), 'public-relative-path')
    return value


def mapping(source_kind):
    result = {}
    for directory, names in (('four-wallet-lifecycle', OWNER_NAMES),
            ('compact-batch-lifecycle', CORE_NAMES), ('shared-settlement', PUBLIC_NAMES)):
        for name in names:
            result['runtime-source/poc/' + directory + '/' + name + '.py'] = '/work/poc/' + directory + '/' + name + '.py'
    for name in ('gn2_common.py', 'gn2_backup.py', 'gn2.py'):
        result['runtime-source/poc/four-wallet-bootstrap/' + name] = '/work/poc/four-wallet-bootstrap/' + name
    if source_kind == 'accepted':
        for name in CHAIN_NAMES:
            result['runtime-source/poc/four-wallet-chain/' + name] = '/work/poc/four-wallet-chain/' + name
    for name in ('poc/four-wallet-profile/selection.py', 'poc/future-recipient/v2/recipient.py',
                 'poc/private-cashout-trial/sdk.mjs', 'poc/independent-single-payment/payment.py'):
        result['runtime-source/' + name] = '/work/' + name
    for role in ('prover', 'native-validator', 'node', 'crypto'):
        result['runtime/' + role] = '/runtime/' + role
    for name in ('kaspa.js', 'kaspa_bg.wasm', 'package.json'):
        result['runtime-sdk/' + name] = SDK_DEST + name
    return result


def entries(args, forbidden, private_directories):
    raw = read_public(args.inventory, forbidden, private_directories)
    need(digest(raw) == args.inventory_sha256, 'external-software-inventory-pin')
    value = parse(raw)
    need(type(value) is dict and set(value) == {'schema', 'classification', 'files'}
         and value['schema'] == 'kpx4-public-software-bundle/v1'
         and value['classification'] == 'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY'
         and type(value['files']) is list and value['files'], 'typed-software-inventory')
    root = checked(args.software_root)
    rows, seen = [], set()
    for row in value['files']:
        need(type(row) is dict and set(row) == {'kind', 'path', 'bytes', 'sha256'}, 'typed-software-entry')
        name = relative(row['path'])
        need(name not in seen and row['kind'] in KINDS and type(row['bytes']) is int
             and row['bytes'] >= 0 and type(row['sha256']) is str and len(row['sha256']) == 64
             and all(c in '0123456789abcdef' for c in row['sha256']), 'software-entry-fields')
        seen.add(name)
        path, info = regular(root / name, forbidden, private_directories)
        need(info.st_size == row['bytes'], 'software-entry-length-metadata')
        rows.append((row, path))
    need(set(mapping(args.source_kind)).issubset(seen), 'complete-fixed-owner-runtime-closure')
    # Every listed member's metadata has been checked before the first member
    # byte/hash/copy; exclusions and rows are materialized and reusable.
    return tuple(rows)


def network_page_rows(raw, expected_sha256):
    need(digest(raw) == expected_sha256, 'external-fetch-pin-before-page-staging')
    value = parse(raw)
    need(value['schema'] == 'kpx5-gn2-network-fetch/v1'
         and value['status'] == 'FETCHED_PENDING_REPLAY', 'public-fetch-scope')
    rows = tuple([*value['pages'], *value['current_view']['post_query_delta']['pages']])
    names = [relative(row['path']) for row in rows]
    need(len(names) == len(set(names)), 'duplicate-retained-page-path')
    return tuple(zip(names, rows))
