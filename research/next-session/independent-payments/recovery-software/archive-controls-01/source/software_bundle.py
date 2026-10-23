#!/usr/bin/env python3
"""Public software bytes only; trust comes from an external inventory digest.

No download, import, build, subprocess, backup parser or executable launch API.
The host and the read-only selected installation remain trusted during use.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

KINDS = frozenset({'source', 'cargo-vendor', 'build-config', 'public-metadata',
                   'selected-executable', 'runtime-source', 'public-canary'})


class Invalid(ValueError):
    """Fixed category; never contains a file's unexpected bytes/hash/path."""


def need(condition, code):
    if not condition:
        raise Invalid(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def parse(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: need(False, 'json-constant'))
    except (ValueError, UnicodeDecodeError, RecursionError) as error:
        if isinstance(error, Invalid):
            raise
        raise Invalid('invalid-json') from None


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def relative(value):
    need(type(value) is str and value and '\\' not in value and '\0' not in value,
         'unsafe-relative-path')
    path = PurePosixPath(value)
    need(not path.is_absolute() and path.as_posix() == value
         and all(part not in ('', '.', '..') for part in path.parts),
         'unsafe-relative-path')
    return value


def checked_path(path):
    path = Path(path).absolute()
    need('..' not in path.parts, 'unsafe-public-path')
    need(not any(part.is_symlink() for part in (path, *path.parents)), 'public-symlink')
    return path


def forbidden_metadata(paths):
    """Stat only: reject declared backup aliases BEFORE any public open/read."""
    result = set()
    for name in paths:
        path = checked_path(name)
        info = path.stat()
        need(stat.S_ISREG(info.st_mode), 'forbidden-input-not-regular')
        result.add((info.st_dev, info.st_ino))
    return frozenset(result)


def read_public(path, forbidden=frozenset(), expected_bytes=None):
    path = checked_path(path)
    try:
        before = path.stat()
        need(stat.S_ISREG(before.st_mode), 'public-file-not-regular')
        need((before.st_dev, before.st_ino) not in forbidden, 'public-private-inode-alias')
        if expected_bytes is not None:
            need(before.st_size == expected_bytes, 'public-file-length')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as file:
            opened = os.fstat(file.fileno())
            need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                 'public-file-replaced')
            need((opened.st_dev, opened.st_ino) not in forbidden, 'public-private-inode-alias')
            raw = file.read()
            after = os.fstat(file.fileno())
        need((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
             == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
             and len(raw) == opened.st_size, 'public-file-mutated')
        return raw
    except OSError:
        raise Invalid('public-file-unavailable') from None


def inventory(root, typed_paths):
    """Trusted packer supplies its explicit public allowlist; never recurse secrets."""
    root = checked_path(root)
    rows, seen = [], set()
    for kind, name in typed_paths:
        need(type(kind) is str and kind in KINDS, 'unknown-software-kind')
        name = relative(name)
        need(name not in seen, 'duplicate-software-path')
        seen.add(name)
        raw = read_public(root / name)
        rows.append({'kind': kind, 'path': name, 'bytes': len(raw), 'sha256': digest(raw)})
    need(rows, 'empty-software-inventory')
    return {'schema': 'kpx4-public-software-bundle/v1',
            'classification': 'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY',
            'files': sorted(rows, key=lambda row: row['path'])}


def verify(root, raw_inventory, expected_inventory_sha256, *, forbidden_inputs=()):
    forbidden = forbidden_metadata(forbidden_inputs)
    need(type(expected_inventory_sha256) is str
         and re.fullmatch('[0-9a-f]{64}', expected_inventory_sha256), 'external-inventory-pin')
    need(digest(raw_inventory) == expected_inventory_sha256, 'external-inventory-pin')
    data = parse(raw_inventory)
    need(type(data) is dict and set(data) == {'schema', 'classification', 'files'}
         and data['schema'] == 'kpx4-public-software-bundle/v1'
         and data['classification'] == 'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY'
         and type(data['files']) is list and data['files'], 'software-inventory-schema')
    root = checked_path(root)
    seen, count, total = set(), 0, 0
    for row in data['files']:
        need(type(row) is dict and set(row) == {'kind', 'path', 'bytes', 'sha256'},
             'software-entry-fields')
        name = relative(row['path'])
        need(name not in seen, 'duplicate-software-path')
        seen.add(name)
        need(type(row['kind']) is str and row['kind'] in KINDS and type(row['bytes']) is int and row['bytes'] >= 0
             and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
             'software-entry-types')
        raw = read_public(root / name, forbidden, row['bytes'])
        need(digest(raw) == row['sha256'], 'public-file-digest')
        count += 1
        total += len(raw)
    return {'schema': 'kpx4-software-bundle-integrity/v1', 'files_verified': count,
            'bytes_verified': total, 'inventory_sha256': expected_inventory_sha256,
            'executable_selected_or_launched': False, 'currentness_verified': False,
            'spend_authorized': False}


def restore(root, raw_inventory, expected_inventory_sha256, fresh_output, *, forbidden_inputs=()):
    """Restore ONLY authenticated entries; unlisted files never enter execution.

    The fixed launcher mounts this owned restored tree, NEVER the input bundle.
    Recheck owned bytes while copying rather than relying on a past path hash.
    """
    # Iterators are one-shot: preserve the exact metadata authority in BOTH passes.
    forbidden_inputs = tuple(forbidden_inputs)
    receipt = verify(root, raw_inventory, expected_inventory_sha256,
                     forbidden_inputs=forbidden_inputs)
    forbidden = forbidden_metadata(forbidden_inputs)
    data = parse(raw_inventory)
    fresh_output = checked_path(fresh_output)
    need(not fresh_output.exists(), 'fresh-software-output-required')
    fresh_output.mkdir(parents=True, mode=0o700)
    for row in data['files']:
        raw = read_public(checked_path(root) / row['path'], forbidden, row['bytes'])
        need(digest(raw) == row['sha256'], 'public-file-digest')
        destination = fresh_output / row['path']
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with destination.open('xb') as file:
            file.write(raw)
        destination.chmod(0o500 if row['kind'] == 'selected-executable' else 0o400)
    receipt['only_inventory_entries_restored'] = True
    receipt['unlisted_input_files_copied_or_mounted'] = False
    return receipt
