#!/usr/bin/env python3
"""Immutable public-only namespace mechanics; never a signing authority.

Every input is admitted by unchanged host helper09, copied through a sealed
memfd into a new tmpfs regular file, then the root mount is made read-only.
Eight empty synthetic legacy metadata files satisfy unchanged guard imports.
They are not originals, backups, owners, recovery evidence, or authority.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import runpy
import stat
import subprocess
import time

HELPER = '/var/tmp/kpi-root-guard-helper-09.py'
HELPER_SHA = '0f8ff562a4364c1db7729d98d7daf57f75ff5e882936e06e9907a4e936bd82fd'
STUBS = tuple('/var/tmp/kpi-four-wallet-' + trial + '/owners/' + owner + '/backup.json'
              for trial in ('local-rehearsal-01', 'live-01') for owner in 'ABCD')
SCOPE = 'PUBLIC_ONLY_SYNTHETIC_METADATA_NOT_OWNER_OR_RECOVERY_AUTHORITY'
SUPERVISOR = '/snapshot-supervisor.py'
HELPER_PINS = {
    '/var/tmp/kpi-root-guard-helper-09.py': HELPER_SHA,
    '/var/tmp/kpi-root-guard-helper-08.py': 'd9261c9a1a03f1fd557c26388a09fd46878c24d83fccf8c643a42050e5a4301b',
    '/var/tmp/kpi-root-guard-helper-07.py': '7482cb2570e9231ee793f9a671df6613b68f20e356bde925bc41f7e6ce94b863',
    '/var/tmp/kpi-root-guard-helper-06.py': 'b147ac219d214d0ba9a459a46a1dcd3067e47e4d6e3c6a50eed7ed02bbbe5b94',
    '/var/tmp/kpi-root-guard-helper-05.py': '97a02a5b6105c63b4253c519117b0d3de02c711d53095406521b13a9d7c3b9b0',
    '/var/tmp/kpi-root-guard-helper-04.py': '1f93e06bbe903064d69fc5ce52616255b2f531521c799a72c54da63b3fb57ab5',
    '/var/tmp/kpi-root-guard-helper-03.py': 'b9a71e03764b30d65d56e58443102a2fce27377612abe3340a768288fe6212b4',
    '/var/tmp/kpi-root-guard-helper-01.py': 'e6f443deae2bd461949c383a397603b2cc43a73f5d4acd221f8e2d8307ff0050',
    '/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/four-wallet-profile/outer_run.py':
        'da559335c0e071d15b7daee5cd4d256776295c934d5db569c1e13c3d2bf83195',
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def parse(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def target(value):
    need(type(value) is str and value.startswith('/') and not value.startswith('//')
         and '\\' not in value and '\0' not in value,
         'absolute public target required')
    p = PurePosixPath(value)
    need(str(p) == value and '..' not in p.parts and value != '/', 'canonical public target required')
    need(not any(p == PurePosixPath(root) or PurePosixPath(root) in p.parents
                 for root in ('/proc', '/sys', '/dev', '/out', '/tmp', '/run', '/root')),
         'reserved namespace target')
    need(value not in STUBS and value not in (SUPERVISOR, '/snapshot-request.json'),
         'reserved synthetic metadata/supervisor/request target')
    return value


def sealed(raw, name):
    fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        data = memoryview(raw)
        while data:
            count = os.write(fd, data)
            need(count > 0, 'snapshot write incomplete')
            data = data[count:]
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return fd
    except BaseException:
        os.close(fd)
        raise


def admit(manifest, read, private_directories):
    need(set(manifest) == {'schema', 'scope', 'files', 'argv', 'exports', 'network'}, 'closed snapshot fields')
    need(manifest['schema'] == 'kpxa-public-snapshot-prototype/v1' and manifest['scope'] == SCOPE,
         'explicit public-only snapshot scope')
    need(manifest['network'] == 'none', 'prototype has no network authority')
    need(type(manifest['files']) is list and manifest['files'], 'finite input rows required')
    rows, targets = [], set()
    selected = {}
    source_bytes, source_pins = {}, {}
    try:
        for index, row in enumerate(manifest['files']):
            need(set(row) == {'source', 'target', 'sha256', 'mode'}, 'closed public input row')
            dest = target(row['target'])
            need(dest not in targets, 'duplicate namespace target')
            p = Path(dest)
            need(not any(p == root or root in p.parents for root in private_directories),
                 'public input cannot populate protected roots')
            need(type(row['mode']) is int and row['mode'] in (0o400, 0o500), 'read-only input mode')
            source = row['source']
            need(type(source) is str and source.startswith('/') and not source.startswith('//')
                 and str(PurePosixPath(source)) == source and '..' not in PurePosixPath(source).parts,
                 'absolute selected source required')
            need(source not in source_pins or source_pins[source] == row['sha256'],
                 'one immutable identity per admitted source')
            if source not in source_bytes:
                source_bytes[source] = read(source, row['sha256'])
                source_pins[source] = row['sha256']
            raw = source_bytes[source]
            need(hashlib.sha256(raw).hexdigest() == row['sha256'], 'admitted bytes differ')
            fd = sealed(raw, 'public-snapshot-' + str(index))
            rows.append((dest, row['mode'], fd))
            targets.add(dest)
            selected[dest] = row['sha256']
        need(all(selected.get(path) == pin for path, pin in HELPER_PINS.items()),
             'complete unchanged guard helper chain required')
        need(not any(PurePosixPath(a) in PurePosixPath(b).parents for a in targets for b in targets),
             'file target cannot be another file parent')
        argv = manifest['argv']
        need(type(argv) is list and argv and all(type(v) is str and '\0' not in v for v in argv),
             'explicit finite command required')
        need(argv[0] in targets and next(mode for name, mode, _ in rows if name == argv[0]) == 0o500,
             'entry executable must be admitted')
        exports = manifest['exports']
        need(type(exports) is list and len(set(exports)) == len(exports), 'finite distinct output paths')
        for name in exports:
            p = PurePosixPath(name)
            need(type(name) is str and str(p) == name and p.is_absolute() and '..' not in p.parts
                 and PurePosixPath('/out') in p.parents, 'exports remain inside fresh /out')
        return rows
    except BaseException:
        for _, _, fd in rows:
            os.close(fd)
        raise


def command(rows, request_fd, supervisor_fd, *, output_root, readonly=True):
    # --file creates independent regular nlink=1 tmpfs files. Directly binding
    # a memfd would retain nlink=0 and correctly fail unchanged helper09.
    # The old program must create its normal absent output directory itself.
    # Its otherwise empty parent is the only additional writable tmpfs.
    output_parent = str(PurePosixPath(output_root).parent)
    directories = {'/proc', '/dev', '/out', '/tmp', output_parent}
    directories.update(str(p) for p in PurePosixPath(output_parent).parents if str(p) != '/')
    for name in [dest for dest, _, _ in rows] + list(STUBS) + [SUPERVISOR, '/snapshot-request.json']:
        directories.update(str(p) for p in PurePosixPath(name).parents if str(p) != '/')
    argv = ['/usr/bin/bwrap', '--unshare-all', '--unshare-user', '--disable-userns', '--as-pid-1',
            '--new-session', '--die-with-parent', '--cap-drop', 'ALL',
            '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
            '--setenv', 'TZ', 'UTC', '--setenv', 'PYTHONDONTWRITEBYTECODE', '1', '--tmpfs', '/']
    for directory in sorted(directories, key=lambda p: (len(PurePosixPath(p).parts), p)):
        argv += ['--dir', directory]
    for dest, mode, fd in rows:
        argv += ['--perms', oct(mode)[2:], '--file', str(fd), dest]
    empty = []
    for name in STUBS:
        # bwrap closes each --file source FD after copying it. Each stub needs
        # a distinct sealed FD and becomes a new namespace-only inode.
        fd = sealed(b'', 'synthetic-legacy-metadata-only')
        empty.append(fd)
        argv += ['--perms', '600', '--file', str(fd), name]
    argv += ['--perms', '400', '--file', str(request_fd), '/snapshot-request.json',
             '--perms', '500', '--file', str(supervisor_fd), SUPERVISOR,
             '--proc', '/proc', '--dev', '/dev']
    if readonly:
        argv += ['--remount-ro', '/']
    for directory in sorted({'/out', '/tmp', output_parent}):
        argv += ['--tmpfs', directory]
    argv += ['--chdir', '/', '--',
             '/usr/bin/python3.14', '-I', '-S', '-B', SUPERVISOR]
    return argv, empty


def write_exports(result, directory):
    directory = Path(directory).absolute()
    need(not str(directory).startswith('//') and '..' not in directory.parts
         and str(PurePosixPath(directory)) == str(directory),
         'canonical export directory required')
    need(not directory.exists(), 'fresh export directory required')
    for p in (directory, *directory.parents):
        need(not p.is_symlink(), 'export parent symlink')
    names = [row['path'] for row in result['exports']]
    need(len(names) == len(set(names)), 'duplicate public export')
    for name in names:
        p = PurePosixPath(name)
        need(p.is_absolute() and str(p) == name and '..' not in p.parts
             and PurePosixPath(directory) in p.parents, 'invalid returned export path')
    need(not any(PurePosixPath(a) in PurePosixPath(b).parents for a in names for b in names),
         'export file cannot be parent')
    directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.mkdir(mode=0o700)
    for row in result['exports']:
        path = PurePosixPath(row['path'])
        need(path.is_absolute() and str(path) == row['path'] and '..' not in path.parts
             and PurePosixPath(directory) in path.parents, 'invalid returned export path')
        raw = base64.b64decode(row['base64'], validate=True)
        need(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
             'returned public export changed')
        relative = path.relative_to(directory)
        need(str(relative) != 'POOL-PROVENANCE.json', 'reserved pool provenance receipt')
        dest = directory.joinpath(*relative.parts)
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            raise
    return directory


