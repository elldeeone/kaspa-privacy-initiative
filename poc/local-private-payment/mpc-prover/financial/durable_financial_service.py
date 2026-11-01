#!/usr/bin/env python3
"""Disconnect-safe local supervisor for long financial runs.

This is a liveness boundary, never financial or privacy authority.  A private
one-shot selection is dispatched to a lingering user-systemd *service* (not a
client-owned scope).  The service owns the controller after the launching CLI
and its terminal disappear, writes public heartbeats, and records the child's
exit without reading its private stdout/stderr.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid


RESOURCE_POLICY = {
    'systemd_user_service': True,
    'linger_required': True,
    'outer_memory_max': 'infinity',
    'outer_memory_high': 'infinity',
    'outer_runtime_max': 'infinity',
    'outer_cpu_quota': 'infinity',
    'oom_score_adjust': -250,
    'kill_mode': 'control-group',
    'remain_after_exit': True,
    'inner_program_owns_resource_scope': True,
}
PRODUCTION_MIN_MEM = 17 * 1024**3
KNOWN_ABORTED_RUN_ID = (
    'a86414d108d6886768f367a3384fd24de49d4fde7475d8469d92adee29c0e6ab')
FORBIDDEN_SOURCE05_SHA256 = (
    '0f4f5584e5ed8c4f0763247a6ae16b7f54ba0ae210745f55950ef68d480a4b5a')
FORBIDDEN_OWNER_ROOT = Path(
    '/run/user/1000/kpb-unfunded-batch-components-20261028-05/owners')
FORBIDDEN_OWNER_PATHS = tuple(str(FORBIDDEN_OWNER_ROOT / str(index) / name)
    for index in range(3)
    for name in ('OWNER-PRIVATE-INPUT.txt', 'OWNER-PRIVATE-INPUT-V2.bin'))
REGISTRIES = {
    'FINANCIAL_CONTROLLER': {
        'root': Path('/var/tmp/kpi-durable-financial-service-identity-registry-v1'),
        'root_identity': (64512, 62130614),
        'journal_identity': (64512, 62132849),
        'anchor_identity': (64512, 62132918),
        'lock_identity': (64512, 62132850),
        'tombstones_identity': (64512, 62133205),
    },
    'DURABILITY_PROBE': {
        'root': Path('/var/tmp/kpi-durable-financial-service-probe-registry-v1'),
        'root_identity': (64512, 62132752),
        'journal_identity': (64512, 62132851),
        'anchor_identity': (64512, 62133204),
        'lock_identity': (64512, 62132853),
        'tombstones_identity': (64512, 62133238),
    },
}
HEAVY_PATTERNS = (
    b'mpc-financial', b'build_registered_financial.py', b'cc1plus',
    b'rustc', b'cargo build', b'privacy_launch_test.py',
)
SELECTION_FIELDS = (
    'schema', 'status', 'kind', 'run_id', 'unit_name',
    'working_directory', 'state_root', 'program', 'argv', 'artifacts',
    'public_stage_paths', 'success_marker', 'failure_marker',
    'resource_policy', 'minimum_mem_available_bytes', 'identity', 'authority',
)
IDENTITY_FIELDS = (
    'trial_id', 'attempt_id', 'cohort_id', 'controller_source_sha256',
    'controller_build_sha256', 'owner_input_root_identity_sha256',
    'owner_input_identity_sha256',
    'private_owner_input_bodies_read_or_hashed',
)


class Refused(RuntimeError):
    pass


def need(condition, category):
    if not condition:
        raise Refused('durable-financial-service-' + category)


def fields(value, names, category='exact-fields'):
    need(type(value) is dict and set(value) == set(names), category)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(
            Refused('durable-financial-service-nonfinite-number')))
    need(encoded(value) == raw, 'canonical-json')
    return value


def word(value, category):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
         category)
    return value


def signature(value):
    return tuple(getattr(value, name) for name in (
        'st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
        'st_mode', 'st_nlink', 'st_uid'))


def stable_read(path, maximum=16 << 20, private=False):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(part.is_symlink() for part in (path, *path.parents)),
         'absolute-nonsymlink-leaf')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd); mode = stat.S_IMODE(before.st_mode)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid in (0, os.geteuid())
             and 0 < before.st_size <= maximum and not mode & 0o022,
             'stable-owned-or-system-readonly-leaf')
        if private:
            need(before.st_uid == os.geteuid() and mode == 0o400,
                 'private-selection-mode')
        chunks, remaining = [], before.st_size
        while remaining:
            block = os.read(fd, min(remaining, 1 << 20))
            need(block, 'complete-read')
            chunks.append(block); remaining -= len(block)
        after = os.fstat(fd)
        need(signature(before) == signature(after), 'stable-read')
        return b''.join(chunks)
    finally:
        os.close(fd)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checked_absolute(value, category):
    need(type(value) is str, category)
    path = Path(value)
    need(path.is_absolute() and '..' not in path.parts
         and not any(part.is_symlink() for part in (path, *path.parents)),
         category)
    return path


def option(argv, name):
    positions = [index for index, value in enumerate(argv) if value == name]
    need(len(positions) == 1 and positions[0] + 1 < len(argv),
         'financial-option-' + name.removeprefix('--'))
    return argv[positions[0] + 1]


def validate_selection(value, *, state_must_exist):
    fields(value, SELECTION_FIELDS)
    need(value['schema'] == 'kpb-durable-financial-service-selection/v1'
         and value['status'] == 'FRESH_UNEXECUTED'
         and value['kind'] in ('DURABILITY_PROBE', 'FINANCIAL_CONTROLLER'),
         'selection-schema-status-kind')
    run_id = word(value['run_id'], 'run-id')
    need(value['unit_name'] == 'kpi-durable-financial-' + run_id + '.service',
         'unit-name')
    working = checked_absolute(value['working_directory'],
                               'working-directory')
    state = checked_absolute(value['state_root'], 'state-root')
    need(working.is_dir() and (state.is_dir() if state_must_exist
                              else not state.exists()),
         'working-and-state-roots')
    fields(value['program'], ('path', 'sha256'), 'program-fields')
    program = checked_absolute(value['program']['path'], 'program-path')
    program_raw = stable_read(program, 1 << 30)
    need(sha(program_raw) == word(value['program']['sha256'], 'program-hash'),
         'program-changed')
    argv = value['argv']
    need(type(argv) is list and 2 <= len(argv) <= 256
         and all(type(item) is str and item and '\0' not in item
                 for item in argv)
         and argv[0] == str(program), 'argv')
    artifacts = value['artifacts']
    need(type(artifacts) is list and 2 <= len(artifacts) <= 4096,
         'artifact-count')
    seen = set(); artifact_hashes = set()
    for row in artifacts:
        fields(row, ('path', 'sha256', 'bytes'), 'artifact-fields')
        path = checked_absolute(row['path'], 'artifact-path')
        need(str(path) not in seen and type(row['bytes']) is int
             and row['bytes'] > 0, 'artifact-identity')
        seen.add(str(path)); raw = stable_read(path, 1 << 30)
        need(len(raw) == row['bytes']
             and sha(raw) == word(row['sha256'], 'artifact-hash'),
             'artifact-changed')
        artifact_hashes.add(row['sha256'])
    need(str(program) in seen, 'program-in-artifact-closure')
    stages = value['public_stage_paths']
    need(type(stages) is list and len(stages) in (0, 3)
         and len(set(stages)) == len(stages), 'public-stage-paths')
    for stage in stages:
        checked_absolute(stage, 'public-stage-path')
    success = checked_absolute(value['success_marker'], 'success-marker')
    failure = checked_absolute(value['failure_marker'], 'failure-marker')
    need(success != failure, 'distinct-terminal-markers')
    need(value['resource_policy'] == RESOURCE_POLICY,
         'exact-resource-policy')
    need(type(value['minimum_mem_available_bytes']) is int
         and value['minimum_mem_available_bytes'] >= 0,
         'minimum-memory')
    identity = value['identity']
    fields(identity, IDENTITY_FIELDS, 'identity-fields')
    need(type(identity['trial_id']) is str
         and str(uuid.UUID(identity['trial_id'])) == identity['trial_id'],
         'trial-id')
    for name in ('attempt_id', 'cohort_id', 'controller_source_sha256',
                 'controller_build_sha256',
                 'owner_input_root_identity_sha256'):
        word(identity[name], 'identity-' + name)
    owners = identity['owner_input_identity_sha256']
    need(type(owners) is list and len(owners) == 3
         and len(set(owners)) == 3
         and all(word(owner, 'owner-input-identity') for owner in owners)
         and identity['private_owner_input_bodies_read_or_hashed'] is False,
         'owner-input-identities')
    controller = checked_absolute(argv[1], 'controller-source-path')
    need(str(controller) in seen
         and sha(stable_read(controller, 1 << 30)) ==
            identity['controller_source_sha256']
         and identity['controller_build_sha256'] in artifact_hashes,
         'controller-source-build-binding')
    need(value['authority'] == {
        'financial_qualified': False,
        'privacy_qualified': False,
        'native_or_settlement_authorized': False,
    }, 'non-authorizing-selection')
    if value['kind'] == 'DURABILITY_PROBE':
        need(value['minimum_mem_available_bytes'] == 0 and not stages,
             'probe-boundary')
    else:
        need(value['minimum_mem_available_bytes'] >= PRODUCTION_MIN_MEM
             and len(stages) == 3 and run_id in stages[0]
             and all(run_id in path for path in stages),
             'financial-headroom-and-stages')
        owner_positions = [index for index, item in enumerate(argv)
                           if item == '--owner-input-file']
        owner_paths = [checked_absolute(argv[index + 1], 'owner-input-path')
                       for index in owner_positions]
        need(option(argv, '--run-id') == run_id
             and '--inside-scope' not in argv
             and int(option(argv, '--memory-gib')) >= 64
             and 1 <= int(option(argv, '--cpu-cores')) <= 12
             and len(owner_paths) == 3,
             'financial-outer-command')
        common = Path(os.path.commonpath([str(path) for path in owner_paths]))
        need(identity['owner_input_root_identity_sha256'] ==
             hashlib.sha256(str(common).encode()).hexdigest(),
             'owner-input-root-binding')
        need(run_id != KNOWN_ABORTED_RUN_ID
             and identity['controller_source_sha256'] !=
                FORBIDDEN_SOURCE05_SHA256
             and not any(path.is_relative_to(FORBIDDEN_OWNER_ROOT)
                         for path in owner_paths)
             and common != FORBIDDEN_OWNER_ROOT,
             'known-abort-or-consumed-source-owner-root')
        need(success.name == 'RESULT.json' and failure.name == 'FAILED.json'
             and run_id in str(success) and run_id in str(failure),
             'financial-terminal-markers')
        need(str(Path(argv[1])) in seen, 'controller-source-in-closure')
        # A caller-authored selection cannot establish that the controller build
        # or owner inputs were freshly issued. In addition, any same-UID child
        # could rewrite the user-owned registry. Keep real execution fail-closed
        # until those two authorities are independently admitted and isolated.
        need(False, 'financial-controller-independent-admission-unavailable')
    return value


def read_selection(path, *, state_must_exist=False, expected=None):
    raw = stable_read(Path(path), private=True)
    digest = sha(raw)
    if expected is not None:
        need(digest == word(expected, 'selected-selection-hash'),
             'selection-changed')
    return validate_selection(parse(raw), state_must_exist=state_must_exist), digest


def fsync_parent(path):
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY |
                 os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, value, mode=0o400):
    path = Path(path); raw = encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        at = 0
        while at < len(raw):
            count = os.write(fd, raw[at:])
            need(count > 0, 'complete-write'); at += count
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_parent(path)
    return sha(raw)


def replace_json(path, value, sequence):
    path = Path(path)
    temporary = path.parent / ('.' + path.name + '.' + str(os.getpid()) +
                               '.' + str(sequence))
    raw = encoded(value)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    try:
        at = 0
        while at < len(raw):
            count = os.write(fd, raw[at:])
            need(count > 0, 'complete-replacement-write'); at += count
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path); fsync_parent(path)


def mem_available():
    rows = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        name, value = line.split(':', 1)
        rows[name] = value.strip().split()
    need(rows.get('MemAvailable', [None, None])[1] == 'kB',
         'memavailable-format')
    return int(rows['MemAvailable'][0]) * 1024


def heavy_processes():
    found = []
    for child in Path('/proc').iterdir():
        if not child.name.isdigit() or int(child.name) == os.getpid():
            continue
        try:
            command = (child / 'cmdline').read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if any(pattern in command for pattern in HEAVY_PATTERNS):
            found.append(int(child.name))
    return sorted(found)


def linger_enabled():
    completed = subprocess.run(
        ['loginctl', 'show-user', str(os.geteuid()), '-p', 'Linger',
         '--value'], capture_output=True, text=True)
    return completed.returncode == 0 and completed.stdout.strip() == 'yes'


def resource_guard(selection):
    available = mem_available(); heavy = heavy_processes()
    if selection['kind'] == 'FINANCIAL_CONTROLLER':
        need(available >= selection['minimum_mem_available_bytes'],
             'insufficient-launch-memory-headroom')
        need(not heavy, 'concurrent-heavy-process')
    need(linger_enabled(), 'user-manager-linger-disabled')
    return {'mem_available_bytes': available,
            'minimum_mem_available_bytes':
                selection['minimum_mem_available_bytes'],
            'concurrent_heavy_process_count': len(heavy),
            'guard_only_at_launch_never_aborts_running_job': True}


def _registry_leaf(root_fd, name, identity):
    fd = os.open(name, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW |
                 os.O_CLOEXEC, dir_fd=root_fd)
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
         and (info.st_dev, info.st_ino) == identity,
         'fixed-registry-' + name.lower())
    return fd


def _registry_directory(root_fd, name, identity):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                 os.O_CLOEXEC, dir_fd=root_fd)
    info = os.fstat(fd)
    need(stat.S_ISDIR(info.st_mode) and info.st_nlink >= 2
         and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
         and (info.st_dev, info.st_ino) == identity,
         'fixed-registry-' + name.lower())
    return fd


def _identity_candidates(selection, selection_sha):
    identity = selection['identity']
    return {
        ('selection', selection_sha), ('run', selection['run_id']),
        ('trial', identity['trial_id']), ('attempt', identity['attempt_id']),
        ('cohort', identity['cohort_id']),
        ('owner-root', identity['owner_input_root_identity_sha256']),
        *((('owner', owner) for owner in
           identity['owner_input_identity_sha256'])),
    }


def _claim_identity_tombstones(tombstones_fd, candidates, selection_sha):
    """Consume identities before mutable journal state can be created.

    Tombstone names contain only a domain-separated digest. A partial failure
    intentionally consumes a subset: uncertainty fails closed rather than
    making an identity reusable.
    """
    for tag, value in sorted(candidates):
        fingerprint = hashlib.sha256((tag + '\0' + value).encode()).hexdigest()
        raw = encoded({
            'schema': 'kpb-durable-financial-identity-tombstone/v1',
            'identity_fingerprint_sha256': fingerprint,
            'identity_tag': tag,
            'selection_sha256': selection_sha,
        })
        try:
            fd = os.open(fingerprint + '.json', os.O_WRONLY | os.O_CREAT |
                         os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400,
                         dir_fd=tombstones_fd)
        except FileExistsError:
            raise Refused(
                'durable-financial-service-identity-tombstone-already-exists'
            ) from None
        try:
            at = 0
            while at < len(raw):
                count = os.write(fd, raw[at:])
                need(count > 0, 'complete-tombstone-write')
                at += count
            os.fsync(fd)
        finally:
            os.close(fd)
    os.fsync(tombstones_fd)


def _read_registry_fd(fd):
    info = os.fstat(fd)
    need(info.st_size <= 64 << 20, 'bounded-registry')
    os.lseek(fd, 0, os.SEEK_SET); chunks, remaining = [], info.st_size
    while remaining:
        block = os.read(fd, min(remaining, 1 << 20))
        need(block, 'complete-registry-read')
        chunks.append(block); remaining -= len(block)
    return b''.join(chunks)


def _registry_records(journal_raw, anchor_raw):
    journal_lines = journal_raw.splitlines(keepends=True)
    anchor_lines = anchor_raw.splitlines(keepends=True)
    need(len(journal_lines) == len(anchor_lines), 'registry-anchor-length')
    previous = '0' * 64; records = []; used = set()
    for sequence, (record_raw, anchor_raw) in enumerate(
            zip(journal_lines, anchor_lines)):
        need(record_raw.endswith(b'\n') and anchor_raw.endswith(b'\n'),
             'complete-registry-line')
        record = parse(record_raw); anchor = parse(anchor_raw)
        common = ('schema', 'record_type', 'sequence',
                  'previous_record_sha256', 'run_id',
                  'controller_source_sha256',
                  'owner_input_root_identity_sha256')
        need(record.get('schema') ==
             'kpb-durable-financial-identity-registry-record/v1'
             and record.get('sequence') == sequence
             and record.get('previous_record_sha256') == previous,
             'registry-chain')
        if record.get('record_type') == 'LEGACY_ABORT':
            fields(record, common + ('reason',), 'legacy-abort-fields')
            need(record['reason'] ==
                 'GLOBAL_OOM_CONTROLLER_SCOPE_ABORT_NO_RESULT_OR_FAILED',
                 'legacy-abort-reason')
        else:
            fields(record, common + (
                'selection_sha256', 'trial_id', 'attempt_id', 'cohort_id',
                'controller_build_sha256',
                'owner_input_identity_sha256', 'admission_status'),
                'consumed-record-fields')
            need(record['record_type'] == 'CONSUMED'
                 and record['admission_status'] ==
                    'CONSUMED_BEFORE_STATE_CREATION'
                 and type(record['owner_input_identity_sha256']) is list
                 and len(record['owner_input_identity_sha256']) == 3,
                 'consumed-record')
            for tag, name in (('selection', 'selection_sha256'),
                              ('trial', 'trial_id'),
                              ('attempt', 'attempt_id'),
                              ('cohort', 'cohort_id')):
                need((tag, record[name]) not in used,
                     'registry-duplicate-' + tag)
                used.add((tag, record[name]))
            for owner in record['owner_input_identity_sha256']:
                need(('owner', owner) not in used,
                     'registry-duplicate-owner')
                used.add(('owner', owner))
        for tag, name in (('run', 'run_id'),
                          ('owner-root', 'owner_input_root_identity_sha256')):
            need((tag, record[name]) not in used,
                 'registry-duplicate-' + tag)
            used.add((tag, record[name]))
        digest = sha(record_raw)
        need(anchor == {
            'record_sha256': digest,
            'schema': 'kpb-durable-financial-identity-registry-anchor/v1',
            'sequence': sequence,
        }, 'registry-anchor')
        previous = digest; records.append(record)
    return records, used, previous


def reserve_identity(selection, selection_sha):
    spec = REGISTRIES[selection['kind']]; root = spec['root']
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                      os.O_CLOEXEC)
    try:
        info = os.fstat(root_fd)
        need((info.st_dev, info.st_ino) == spec['root_identity']
             and info.st_uid == os.geteuid()
             and stat.S_IMODE(info.st_mode) == 0o700,
             'fixed-registry-root')
        lock_fd = _registry_leaf(root_fd, 'LOCK', spec['lock_identity'])
        journal_fd = _registry_leaf(root_fd, 'JOURNAL.jsonl',
                                    spec['journal_identity'])
        anchor_fd = _registry_leaf(root_fd, 'ANCHOR.jsonl',
                                   spec['anchor_identity'])
        tombstones_fd = _registry_directory(
            root_fd, 'TOMBSTONES', spec['tombstones_identity'])
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            records, used, previous = _registry_records(
                _read_registry_fd(journal_fd), _read_registry_fd(anchor_fd))
            identity = selection['identity']
            candidate = _identity_candidates(selection, selection_sha)
            need(not candidate.intersection(used),
                 'identity-already-consumed-or-aborted')
            _claim_identity_tombstones(
                tombstones_fd, candidate, selection_sha)
            sequence = len(records)
            record = {
                'schema':
                    'kpb-durable-financial-identity-registry-record/v1',
                'record_type': 'CONSUMED', 'sequence': sequence,
                'previous_record_sha256': previous,
                'selection_sha256': selection_sha,
                'run_id': selection['run_id'],
                'trial_id': identity['trial_id'],
                'attempt_id': identity['attempt_id'],
                'cohort_id': identity['cohort_id'],
                'controller_source_sha256':
                    identity['controller_source_sha256'],
                'controller_build_sha256':
                    identity['controller_build_sha256'],
                'owner_input_root_identity_sha256':
                    identity['owner_input_root_identity_sha256'],
                'owner_input_identity_sha256':
                    identity['owner_input_identity_sha256'],
                'admission_status': 'CONSUMED_BEFORE_STATE_CREATION',
            }
            raw = encoded(record); count = os.write(journal_fd, raw)
            need(count == len(raw), 'atomic-registry-append')
            os.fsync(journal_fd)
            anchor = encoded({
                'schema':
                    'kpb-durable-financial-identity-registry-anchor/v1',
                'sequence': sequence, 'record_sha256': sha(raw),
            })
            count = os.write(anchor_fd, anchor)
            need(count == len(anchor), 'atomic-registry-anchor-append')
            os.fsync(anchor_fd); os.fsync(root_fd)
            return {'sequence': sequence, 'registry_admitted': True,
                    'identities_exported_publicly': False}
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(tombstones_fd); os.close(anchor_fd)
            os.close(journal_fd); os.close(lock_fd)
    finally:
        os.close(root_fd)


def source_sha256():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def launch(selection_path):
    selection_path = Path(selection_path).absolute()
    selection, selection_sha = read_selection(selection_path)
    guard = resource_guard(selection)
    registry = reserve_identity(selection, selection_sha)
    state = Path(selection['state_root'])
    os.mkdir(state, 0o700); os.mkdir(state / 'public', 0o700)
    os.mkdir(state / 'private', 0o700)
    request = {
        'schema': 'kpb-durable-financial-service-request/v1',
        'kind': selection['kind'], 'run_id': selection['run_id'],
        'unit_name': selection['unit_name'],
        'selection_sha256': selection_sha,
        'launcher_source_sha256': source_sha256(),
        'python_runtime_sha256': sha(stable_read(Path(sys.executable).resolve(),
                                                1 << 30)),
        'resource_policy': RESOURCE_POLICY,
        'resource_guard': guard,
        'identity_registry_admitted': registry['registry_admitted'],
        'identity_registry_sequence': registry['sequence'],
        'identity_hashes_or_private_bodies_exported': False,
        'financial_or_privacy_authority': False,
    }
    write_new(state / 'public/REQUEST.json', request)
    python = str(Path(sys.executable).resolve())
    command = [
        'systemd-run', '--user', '--quiet',
        '--unit=' + selection['unit_name'].removesuffix('.service'),
        '--property=Type=exec', '--property=RemainAfterExit=yes',
        '--property=KillMode=control-group', '--property=OOMPolicy=stop',
        '--property=OOMScoreAdjust=-250',
        '--property=MemoryMax=infinity',
        '--property=MemoryHigh=infinity',
        '--property=RuntimeMaxSec=infinity',
        '--property=TimeoutStartSec=infinity',
        '--property=Restart=no', '--property=UMask=0077',
        '--property=StandardOutput=null',
        '--property=StandardError=null',
        '--working-directory=' + selection['working_directory'],
        python, str(Path(__file__).resolve()), '--worker',
        '--selection', str(selection_path),
        '--selection-sha256', selection_sha,
    ]
    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.returncode != 0:
        write_new(state / 'public/DISPATCH-FAILED.json', {
            'schema': 'kpb-durable-financial-service-dispatch-failure/v1',
            'run_id': selection['run_id'], 'unit_name': selection['unit_name'],
            'selection_sha256': selection_sha,
            'systemd_run_exit_code': completed.returncode,
            'selection_consumed': True,
            'financial_or_privacy_authority': False,
        })
        raise Refused('durable-financial-service-systemd-dispatch-failed')
    write_new(state / 'public/DISPATCHED.json', {
        'schema': 'kpb-durable-financial-service-dispatched/v1',
        'run_id': selection['run_id'], 'unit_name': selection['unit_name'],
        'selection_sha256': selection_sha,
        'launcher_process_may_exit': True,
        'service_owned_by_lingering_user_manager': True,
        'selection_consumed': True,
        'financial_or_privacy_authority': False,
    })
    return {'unit_name': selection['unit_name'],
            'selection_sha256': selection_sha,
            'state_root': str(state), 'dispatched': True,
            'financial_or_privacy_authority': False}


def public_phase(paths):
    if not paths:
        return 'NO_STAGE_FOR_DURABILITY_PROBE'
    phases = []
    for name in paths:
        path = Path(name)
        if not path.exists():
            return 'PRE_PUBLIC_STAGE'
        try:
            value = json.loads(stable_read(path, 4096))
        except (Refused, json.JSONDecodeError):
            return 'PUBLIC_STAGE_UNAVAILABLE'
        if type(value) is not dict or value.get('status') != 'running' \
                or type(value.get('phase')) is not str:
            return 'PUBLIC_STAGE_UNAVAILABLE'
        phases.append(value['phase'])
    return phases[0] if len(set(phases)) == 1 else 'PUBLIC_STAGE_DISAGREEMENT'


def worker(selection_path, expected_sha):
    selection, selection_sha = read_selection(
        selection_path, state_must_exist=True, expected=expected_sha)
    state = Path(selection['state_root']); public = state / 'public'
    private = state / 'private'
    request = parse(stable_read(public / 'REQUEST.json', 1 << 20))
    need(request['selection_sha256'] == selection_sha
         and request['unit_name'] == selection['unit_name']
         and request['launcher_source_sha256'] == source_sha256(),
         'worker-request-binding')
    write_new(private / 'CONSUMED.json', {
        'schema': 'kpb-durable-financial-service-consumed/v1',
        'run_id': selection['run_id'], 'selection_sha256': selection_sha,
        'one_shot': True,
    })
    started_ns = time.monotonic_ns()
    with (private / 'controller.stdout').open('xb') as stdout, \
            (private / 'controller.stderr').open('xb') as stderr:
        os.chmod(stdout.name, 0o600); os.chmod(stderr.name, 0o600)
        process = subprocess.Popen(selection['argv'],
            cwd=selection['working_directory'], stdout=stdout, stderr=stderr,
            close_fds=True)
        write_new(public / 'STARTED.json', {
            'schema': 'kpb-durable-financial-service-started/v1',
            'kind': selection['kind'], 'run_id': selection['run_id'],
            'unit_name': selection['unit_name'],
            'selection_sha256': selection_sha,
            'supervisor_pid': os.getpid(), 'child_pid': process.pid,
            'started_monotonic_ns': started_ns,
            'private_stdout_or_stderr_read': False,
            'financial_or_privacy_authority': False,
        })
        sequence = 0
        while process.poll() is None:
            replace_json(public / 'HEARTBEAT.json', {
                'schema': 'kpb-durable-financial-service-heartbeat/v1',
                'run_id': selection['run_id'],
                'unit_name': selection['unit_name'],
                'selection_sha256': selection_sha,
                'sequence': sequence, 'child_alive': True,
                'public_phase': public_phase(selection['public_stage_paths']),
                'observed_monotonic_ns': time.monotonic_ns(),
                'private_stdout_or_stderr_read': False,
            }, sequence)
            sequence += 1; time.sleep(1)
        returncode = process.wait()
    success = Path(selection['success_marker']).is_file()
    failure = Path(selection['failure_marker']).is_file()
    if selection['kind'] == 'DURABILITY_PROBE':
        outcome = ('PROBE_COMPLETE_NOT_FINANCIAL_AUTHORITY'
                   if returncode == 0 and success and not failure else
                   'PROBE_FAILED_NOT_FINANCIAL_AUTHORITY')
    elif returncode == 0 and success and not failure:
        outcome = 'CHILD_EXITED_ZERO_SUCCESS_MARKER_PRESENT'
    elif returncode != 0 and failure and not success:
        outcome = 'CHILD_EXITED_NONZERO_FAILURE_MARKER_PRESENT'
    else:
        outcome = 'INCOMPLETE_NO_QUALIFICATION'
    write_new(public / 'TERMINAL.json', {
        'schema': 'kpb-durable-financial-service-terminal/v1',
        'kind': selection['kind'], 'run_id': selection['run_id'],
        'unit_name': selection['unit_name'],
        'selection_sha256': selection_sha, 'outcome': outcome,
        'child_returncode': returncode,
        'success_marker_present': success,
        'failure_marker_present': failure,
        'heartbeat_count': sequence,
        'terminal_monotonic_ns': time.monotonic_ns(),
        'private_stdout_or_stderr_read': False,
        'financial_qualified': False, 'privacy_qualified': False,
        'native_or_settlement_authorized': False,
    })
    return 0 if returncode == 0 else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--launch', action='store_true')
    mode.add_argument('--worker', action='store_true')
    parser.add_argument('--selection', required=True)
    parser.add_argument('--selection-sha256')
    args = parser.parse_args()
    try:
        if args.launch:
            need(args.selection_sha256 is None,
                 'launcher-does-not-accept-selection-hash')
            print(json.dumps(launch(args.selection), sort_keys=True))
            return 0
        need(args.selection_sha256 is not None,
             'worker-requires-selection-hash')
        return worker(args.selection, args.selection_sha256)
    except (Refused, OSError, ValueError, subprocess.SubprocessError):
        return 78


if __name__ == '__main__':
    raise SystemExit(main())
