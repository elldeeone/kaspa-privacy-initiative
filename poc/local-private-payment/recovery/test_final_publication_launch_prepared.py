#!/usr/bin/env python3
"""Known-public controls. Never selects any actual Original or live state."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import time
import types
from unittest.mock import patch


def run(source_pin, output):
    guard_path = '/var/tmp/kpi-root-guard-helper-09.py'
    real_run_path = runpy.run_path
    read = real_run_path(guard_path)['read']
    directory = Path(__file__).absolute().parent
    source = directory / 'final_publication_launch_prepared.py'
    raw = read(str(source), source_pin)
    module = types.ModuleType('known_public_prepared_controls')
    module.__file__ = str(source)
    exec(compile(raw, str(source), 'exec'), module.__dict__)
    parent = Path('/var/tmp/kpi-local-private-payment-01/publication-release')
    identity = str(time.time_ns())
    fixture = parent / ('prepared-known-public-' + identity)
    fixture.mkdir(mode=0o700)
    checks, reads, commands = [], [], []
    original_files = set()

    def save(path, body, mode=0o400):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body); stream.flush(); os.fsync(stream.fileno())

    def encoded(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'

    def row(path, body):
        return {'source': str(path), 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}

    def make_guard(path):
        guarded = real_run_path(path)
        if path != guard_path:
            return guarded  # The unchanged helper loads its pinned predecessors.
        original_read = guarded['read']
        def public_read(path, expected=None):
            assert Path(path) not in original_files, 'controller opened known-public owner fixture'
            reads.append(str(path))
            return original_read(path, expected)
        guarded['read'] = public_read
        return guarded

    candidate = fixture / 'candidate.bin'
    candidate_raw = b'KNOWN PUBLIC CANDIDATE BYTES\n' * 20
    save(candidate, candidate_raw)
    files = [dict(row(candidate, candidate_raw), path='known-public-candidate.bin')]
    source_rows = []
    for filename, expected in [
        ('publication_literal.py', '0d3d7cbed85da8288040407df8c6038fe58c14782d9af8f1ad8dcc748b1f1c52'),
        ('publication_derived.py', 'e4c466cdbcb849d2249832f4c42efab97ea7d43039a55095948888710b67a489')]:
        body = read(str(directory / filename), expected)
        source_rows.append(dict(row(directory / filename, body),
                               mount='/public/recovery/' + filename, mode='0400'))
    scope = {'schema': 'kpxa-canary-nonchain-creation-context/v1',
        'classification': 'CANARY_ONLY_NONCHAIN_GENUINE_CREATION_OUTPUTS',
        'creation_output_count': 9, 'deposit_sompi': 2_000_000_000,
        'accepted_backing': False, 'recovery_or_signing_authority': False,
        'actual_payout_key_material_covered': 0, 'future_material_covered': False}
    documents = {'ASSETS.json': {}, 'CONTEXT.json': {},
        'HISTORY.json': {'transitions': [], 'genesis': {
            'outputs_hex520': ['00' * 520] * 9, 'deposit_sompi': 2_000_000_000}},
        'CANARY-CONTEXT-SCOPE.json': scope}
    for name, value in documents.items():
        body = encoded(value); path = fixture / name; save(path, body)
        source_rows.append(dict(row(path, body), mount='/public/' + name, mode='0400'))
    release = {'schema': 'kpxa-publication-audit-release/v1', 'domain_hex32': module.DOMAIN,
               'files': files, 'sources': source_rows}
    release_path = fixture / 'release.json'; release_body = encoded(release)
    save(release_path, release_body)
    release_row = row(release_path, release_body)
    base_path = directory / 'final_publication_launch_large.py'
    base_row = row(base_path, read(str(base_path), module.BASE_SHA))

    owners = []
    for index, value in enumerate(['42' * 32, '24' * 32]):
        owner = fixture / ('known-public-owner-' + str(index)) / 'BACKUP.json'
        save(owner, encoded({'schema': 'kpxa-original-seed-backup/v1',
                            'domain_hex32': module.DOMAIN, 'seed_hex32': value}), 0o600)
        original_files.add(owner)
        info = owner.lstat()
        owners.append(types.SimpleNamespace(original=str(owner), original_device=info.st_dev,
            original_inode=info.st_ino, original_bytes=info.st_size, original_ctime_ns=info.st_ctime_ns))

    serial = [0]
    def prepare(selected=release_row, candidate_rows=None):
        serial[0] += 1
        runtime = module.PARENTS[0] / ('prepared-known-public-' + identity + '-' + str(serial[0]))
        with patch.object(module.runpy, 'run_path', make_guard):
            result = module.prepare(files if candidate_rows is None else candidate_rows,
                                    {'fixture': selected}, runtime, base_row)
        # TEST ONLY: redirect the unchanged metadata prefix predicate to a
        # directory containing public, deliberately known seed bytes. No actual
        # private path, Original or financial context is selected by this test.
        result._base.ORIGINAL_PREFIX = fixture
        return result

    real_subprocess_run = subprocess.run
    result_mutation = [None]
    literal_kernel_runs = [0]
    def worker(command, **kwargs):
        commands.append(command)
        mounts = [(command[i + 1], command[i + 2]) for i, item in enumerate(command)
                  if item in ('--bind', '--ro-bind')]
        owner_mounts = [(a, b) for a, b in mounts if b == '/BACKUP.json']
        assert len(owner_mounts) == 1 and Path(owner_mounts[0][0]) in original_files
        assert not any(b in ('/home', '/var', '/root', '/private', '/owner') for _, b in mounts)
        assert '--unshare-all' in command and kwargs['close_fds'] is True
        assert kwargs['stdin'] == subprocess.DEVNULL
        script = command[command.index('/usr/bin/python3') + 2]
        assert script in ('/public/recovery/publication_literal.py', '/public/recovery/publication_derived.py')
        kind = 'derived' if script.endswith('publication_derived.py') else 'literal'
        if kind == 'literal':
            # Genuine unchanged literal checker in the actual empty namespace;
            # its one mounted seed is public fixture data, never an Original.
            literal_kernel_runs[0] += 1
            return real_subprocess_run(command, **kwargs)
        manifest_source = next(a for a, b in mounts if b == '/ALLOWLIST.json')
        manifest = json.loads(Path(manifest_source).read_bytes())
        out = Path(next(a for a, b in mounts if b == '/out'))
        result = {'schema': 'kpxa-derived-export-result/v1', 'status': 'PASS',
            'candidate_count': len(manifest['files']) + 1,
            'candidate_bytes': sum(r['bytes'] for r in manifest['files']) + len(Path(manifest_source).read_bytes()),
            'matched_candidate_count': 0,
            'scope': 'FINITE_RECOVERABLE_DERIVED_BYTES_ONLY_NOT_ALL_SECRETS_OR_PRIVACY_PROOF',
            'literal_seed_coverage': False}
        if result_mutation[0]:
            result_mutation[0](result)
        save(out / 'RESULTS.json', encoded(result))
        return types.SimpleNamespace(returncode=0)

    def rejects(name, operation):
        before = len(commands)
        try:
            operation()
        except (ValueError, OSError, TypeError, KeyError):
            checks.append(name)
            return len(commands) - before
        raise AssertionError('missing refusal: ' + name)

    prepared = prepare()
    initial_reads = reads.count(str(candidate))
    assert initial_reads == 1
    with patch.object(module.subprocess, 'run', worker):
        one = prepared.execute(owners[0], 'fixture', 'audit-known-public-one')
        two = prepared.execute(owners[1], 'fixture', 'audit-known-public-two')
        assert one['summary']['literal_status'] == two['summary']['derived_status'] == 'PASS'
        assert one['public_preparation_provenance'] == two['public_preparation_provenance']
        assert one['public_preparation_provenance']['sealed_storage_or_hostile_host_protection'] is False
        assert reads.count(str(candidate)) == initial_reads
        checks += ['one-public-admission-for-two-owner-pairs', 'separate-unchanged-literal-kernel-namespaces',
                   'same-public-provenance-both-pairs', 'explicit-unsealed-trusted-host-boundary']
        assert rejects('used-worker-identity-refused', lambda: prepared.execute(
            owners[0], 'fixture', 'audit-known-public-one')) == 0
        bad_owner = copy.copy(owners[0]); bad_owner.original_inode += 1
        assert rejects('wrong-owner-metadata-before-namespace', lambda: prepared.execute(
            bad_owner, 'fixture', 'audit-wrong-owner')) == 0
        prepared.close()
        assert rejects('closed-preparation-refused', lambda: prepared.execute(
            owners[0], 'fixture', 'audit-closed')) == 0

    # Real large-file branch: ordinary single-link RO view, no A-sized stage.
    large_path = fixture / 'large-public-candidate.bin'
    large_raw = (b'KNOWN PUBLIC LARGE READONLY VIEW\n' * 40000)[:(1 << 20) + 17]
    assert len(large_raw) > 1 << 20
    save(large_path, large_raw)
    large_rows = [dict(row(large_path, large_raw), path='large-public-candidate.bin')]
    large_release = copy.deepcopy(release); large_release['files'] = large_rows
    body = encoded(large_release); path = fixture / 'large-release.json'; save(path, body)
    large = prepare(row(path, body), large_rows)
    assert large._candidates[0][0] == large_path and large._candidates[0][3] is True
    assert not (large._runtime / 'candidates').exists()
    with patch.object(module.subprocess, 'run', worker):
        result = large.execute(owners[0], 'fixture', 'audit-large-public')
    assert result['public_preparation_provenance']['large_direct_readonly_views'] == 1
    assert result['public_preparation_provenance']['small_candidate_staged_bytes'] == 0
    assert reads.count(str(large_path)) == 1
    checks += ['large-ordinary-singlelink-readonly-view-no-payload-copy',
               'unchanged-literal-kernel-large-file-pass']
    large.close()

    staged = prepare()
    staged._tracked[0][0].chmod(0o600)
    with patch.object(module.subprocess, 'run', worker):
        assert rejects('staged-candidate-metadata-change-before-namespace', lambda: staged.execute(
            owners[0], 'fixture', 'audit-changed-stage')) == 0
    staged.close()
    malformed = prepare()
    result_mutation[0] = lambda result: result.update(candidate_count=True)
    with patch.object(module.subprocess, 'run', worker):
        assert rejects('malformed-derived-result-count-refused', lambda: malformed.execute(
            owners[0], 'fixture', 'audit-bad-count')) == 2
    malformed.close(); result_mutation[0] = None
    changed = copy.deepcopy(release); changed['files'][0]['path'] = 'foreign.bin'
    body = encoded(changed); path = fixture / 'foreign-release.json'; save(path, body)
    rejects('context-release-must-select-exact-same-files', lambda: prepare(row(path, body)))
    need_reads = not any(Path(value) in original_files for value in reads)
    assert need_reads
    report = {'schema': 'kpxa-known-public-prepared-launcher-controls/v1',
        'source_sha256': source_pin, 'base_sha256': module.BASE_SHA,
        'classification': 'KNOWN_PUBLIC_FIXTURES_NOT_ACTUAL_ORIGINAL_OR_FINANCIAL_AUDIT',
        'controls': checks, 'passed': True, 'literal_actual_kernel_runs': literal_kernel_runs[0],
        'derived_results_were_public_typed_mocks': True,
        'controller_original_content_reads': 0,
        'candidate_admissions_per_preparation': 1,
        'actual_original_history_or_network_selected': False}
    body = encoded(report); save(Path(output), body)
    assert read(str(output), hashlib.sha256(body).hexdigest()) == body
    print(json.dumps({'path': str(output), 'bytes': len(body),
                      'sha256': hashlib.sha256(body).hexdigest(), 'controls': len(checks)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    run(args.source_sha256, args.output)
