#!/usr/bin/env python3
"""Isolated one-shot worker for the six private owner score bundles.

The selected outer runtime must mount exactly three original0400 score bundles
per run at the fixed paths below, this source closure read-only, a private state
directory and a fresh public output directory.  This worker never accepts host
paths and emits no private mask or owner count.
"""
import hashlib
import os
from pathlib import Path
import secrets
import stat

import privacy_codec as codec
import privacy_owner_comparison as comparison
import privacy_source_closure as source_closure


TAG = b'KPBOWNCMP01'
LAUNCH_RECEIPT_FIELDS = (
    'schema', 'comparison_selection_sha256',
    'baseline_run_selection_sha256', 'candidate_run_selection_sha256',
    'owner_comparison_source_sha256',
    'owner_comparison_launcher_source_sha256',
    'source_closure_sha256', 'runtime_identity_sha256',
    'python_runtime_sha256', 'namespace_tool_sha256',
    'root_guard_helper_sha256', 'host_runtime_trust_boundary',
    'step3_terminal_gate', 'baseline_capsule_seal_sha256',
    'candidate_capsule_seal_sha256',
    'baseline_score_bundle_seal_sha256',
    'candidate_score_bundle_seal_sha256', 'public_result',
    'public_result_sha256', 'private_score_bundle_count',
    'network_enabled', 'private_score_bodies_exported',
)
WORKER_CONFIG_FIELDS = tuple(name for name in comparison.CONFIG_FIELDS
                             if name not in (
                                 'baseline_score_bundle_seal_sha256',
                                 'candidate_score_bundle_seal_sha256')) + (
    'source_members',)


def need(condition, category):
    if not condition:
        raise ValueError('privacy-owner-comparison-launch-' + category)


def stable_read(path, mode):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(part.is_symlink() for part in (path, *path.parents)),
         'fixed-nonsymlink-path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as handle:
        before = os.fstat(handle.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == mode,
             'single-link-fixed-mode-leaf')
        raw = handle.read(); after = os.fstat(handle.fileno())
    keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
            'st_mode', 'st_nlink')
    need(all(getattr(before, key) == getattr(after, key) for key in keys)
         and len(raw) == before.st_size, 'stable-leaf')
    return raw


def write_new(path, raw, mode=0o400):
    path = Path(path)
    if type(raw) is not bytes:
        raw = codec.encoded(raw)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def private_seal(raw, salt):
    need(type(salt) is bytes and len(salt) == 32 and salt != bytes(32),
         'fresh-private-seal-salt')
    return hashlib.sha256(TAG + salt + raw).hexdigest()


def require_namespace():
    marker = codec.parse(stable_read('/NAMESPACE.json', 0o400))
    need(marker == {
        'schema': 'kpb-privacy-owner-comparison-namespace/v1',
        'network': 'disabled', 'private_score_bundle_count': 6,
        'truth_or_original_slots': 0,
    }, 'exact-network-off-namespace')
    interfaces = [line.split(':', 1)[0].strip()
                  for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    need(interfaces == ['lo'] and not Path('/home/luke/.codex').exists()
         and not Path('/home/luke/.ssh').exists()
         and not Path('/truth').exists() and not Path('/original').exists(),
         'network-off-no-host-or-truth-roots')
    config = codec.parse(stable_read('/CONFIG.json', 0o400))
    need(type(config) is dict and set(config) == set(WORKER_CONFIG_FIELDS),
         'exact-worker-config')
    need(type(config['source_members']) is list
         and [row['name'] for row in config['source_members']] == list(
            source_closure.ROLE_MEMBERS['owner-comparison-launcher']),
         'exact-source-closure')
    for row in config['source_members']:
        need(set(row) == {'name', 'path', 'sha256'}, 'source-member-fields')
        raw = stable_read(row['path'], 0o400)
        need(hashlib.sha256(raw).hexdigest() == row['sha256'],
             'source-member-hash')
    need(config['owner_comparison_source_sha256'] ==
         next(row['sha256'] for row in config['source_members']
              if row['name'] == 'privacy_owner_comparison.py'),
         'selected-comparison-source')
    need(config['owner_comparison_launcher_source_sha256'] ==
         next(row['sha256'] for row in config['source_members']
              if row['name'] == 'privacy_owner_comparison_launch.py')
         and config['source_closure_sha256']['owner-comparison'] ==
            source_closure.digest('owner-comparison')
         and config['source_closure_sha256'][
            'owner-comparison-launcher'] ==
            source_closure.digest('owner-comparison-launcher'),
         'selected-comparison-launcher-closure')
    return config


def run_worker():
    config = require_namespace()
    write_new('/state/COMPARISON-CLOSED', {
        'comparison_selection_sha256':
            config['comparison_selection_sha256']})
    raw_bundles = {'baseline': [], 'candidate': []}
    salts = {'baseline': [], 'candidate': []}
    values = {'baseline': [], 'candidate': []}
    for arm in ('baseline', 'candidate'):
        for owner in (0, 1, 2):
            raw = stable_read('/scores/' + arm + '/owner-' + str(owner) +
                              '.json', 0o400)
            need(codec.encoded(codec.parse(raw)) == raw,
                 'canonical-private-score-bundle')
            salt = secrets.token_bytes(32)
            raw_bundles[arm].append(private_seal(raw, salt))
            salts[arm].append(salt.hex())
            values[arm].append(codec.parse(raw))
    selected = {**config,
        'baseline_score_bundle_seal_sha256': raw_bundles['baseline'],
        'candidate_score_bundle_seal_sha256': raw_bundles['candidate']}
    selected.pop('source_members')
    result = comparison.compare(selected, values['baseline'],
                                values['candidate'])
    write_new('/state/PRIVATE-SEAL-SALTS.json', {
        'schema': 'kpb-private-score-bundle-seal-salts/v1',
        'comparison_selection_sha256':
            config['comparison_selection_sha256'], 'salts': salts}, 0o400)
    write_new('/out/PUBLIC.json', result)


def launch_receipt(config, result, result_path, result_sha256,
                   launcher_source_sha256):
    """Called by the selected outer runtime after the isolated worker exits."""
    comparison.validate_config({**config,
        'baseline_score_bundle_seal_sha256':
            result['baseline_score_bundle_seal_sha256'],
        'candidate_score_bundle_seal_sha256':
            result['candidate_score_bundle_seal_sha256']})
    codec.word(result_sha256); codec.word(launcher_source_sha256)
    need(launcher_source_sha256 ==
         config['owner_comparison_launcher_source_sha256'],
         'selected-launcher-source')
    need(type(result_path) is str and Path(result_path).is_absolute(),
         'fixed-public-result-path')
    return {
        'schema': 'kpb-privacy-owner-comparison-launch/v1',
        'comparison_selection_sha256':
            config['comparison_selection_sha256'],
        'baseline_run_selection_sha256':
            config['baseline_run_selection_sha256'],
        'candidate_run_selection_sha256':
            config['candidate_run_selection_sha256'],
        'owner_comparison_source_sha256':
            config['owner_comparison_source_sha256'],
        'owner_comparison_launcher_source_sha256': launcher_source_sha256,
        'source_closure_sha256': config['source_closure_sha256'],
        'runtime_identity_sha256': config['runtime_identity_sha256'],
        'python_runtime_sha256': config['python_runtime_sha256'],
        'namespace_tool_sha256': config['namespace_tool_sha256'],
        'root_guard_helper_sha256': config['root_guard_helper_sha256'],
        'host_runtime_trust_boundary':
            config['host_runtime_trust_boundary'],
        'step3_terminal_gate': config['step3_terminal_gate'],
        'baseline_capsule_seal_sha256':
            config['baseline_capsule_seal_sha256'],
        'candidate_capsule_seal_sha256':
            config['candidate_capsule_seal_sha256'],
        'baseline_score_bundle_seal_sha256':
            result['baseline_score_bundle_seal_sha256'],
        'candidate_score_bundle_seal_sha256':
            result['candidate_score_bundle_seal_sha256'],
        'public_result': result_path,
        'public_result_sha256': result_sha256,
        'private_score_bundle_count': 6,
        'network_enabled': False,
        'private_score_bodies_exported': False,
    }


def validate_launch_receipt(value):
    """Field-shaped output cannot replace outer-supervisor authority."""
    codec.fields(value, LAUNCH_RECEIPT_FIELDS)
    need(value['schema'] == 'kpb-privacy-owner-comparison-launch/v1',
         'launch-receipt-schema')
    need(False, 'outer-supervisor-completion-authority-absent')


if __name__ == '__main__':
    try:
        run_worker()
    except BaseException:
        if Path('/out').is_dir() and not Path('/out/FAILURE.json').exists():
            write_new('/out/FAILURE.json', {
                'schema': 'kpb-privacy-owner-comparison-incomplete/v1'})
        raise SystemExit(2)
