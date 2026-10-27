#!/usr/bin/env python3
"""Public resource controls; actual-original metadata is replaced by a PUBLIC fixture.

No protected original, node/network or new proof generation is used. Synthetic
scope provenance remains explicitly NOT accepted-node evidence.
"""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
from types import SimpleNamespace

HERE = Path('/var/tmp/kpi-local-private-payment-01/publication-release/final-data-interface-01')
GUARD = '/var/tmp/kpi-root-guard-helper-09.py'
READ = runpy.run_path(GUARD)['read']


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw, mode=0o400):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as target:
        target.write(raw)
    path.chmod(mode)


def run(output):
    assert not output.exists()
    output.mkdir(mode=0o700)
    source = HERE / 'final_publication_launch_large.py'
    raw = READ(str(source))
    api = {'__name__': 'known_public_large_leaf_controls', '__file__': str(source)}
    exec(compile(raw, str(source), 'exec'), api)
    source_sha = sha(raw)
    previous = READ(str(HERE / 'final_publication_launch.py'), 'bfe8b9e38a1c66f627557ec97e0044e7dd9ee73c05b7f4ea654d5ade5b4bb1ab')
    baseline = {node.name: ast.dump(node, include_attributes=False) for node in ast.parse(previous).body if isinstance(node, ast.FunctionDef)}
    current = {node.name: ast.dump(node, include_attributes=False) for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef)}
    unchanged = ['need', 'parse', 'encoded', 'sha', 'attributes', 'original_metadata', 'save',
                 'metadata_json', 'terminal_checkpoint', 'observed_sompi', 'accepted_scope', 'final_scope', 'main']
    assert all(current[name] == baseline[name] for name in unchanged)
    cases = [{'name': 'thirteen-preimage-functions-unchanged-including-private-interface-scope-and-CLI', 'passed': True}]
    guard = runpy.run_path(GUARD)
    actual_read = guard['read']
    reads = []
    def tracked_read(path, expected=None):
        reads.append(str(path))
        return actual_read(path, expected)
    guard['read'] = tracked_read
    def row(path, payload):
        return {'source': str(path), 'path': 'public/' + path.name, 'bytes': len(payload), 'sha256': sha(payload)}
    threshold = api['LARGE_PUBLIC_LEAF']
    assert threshold == 1024 * 1024
    small_bytes = b'KNOWN PUBLIC SMALL ARTIFACT\n'
    small = output / 'small.bin'; save(small, small_bytes)
    boundary_bytes = b'P' * threshold
    large = output / 'large.bin'; save(large, boundary_bytes)
    below_bytes = b'Q' * (threshold - 1)
    below = output / 'below.bin'; save(below, below_bytes)
    stage = output / 'unit-stage'
    before = len(reads)
    small_entry = api['candidate_entry'](guard, row(small, small_bytes), 0, stage)
    assert len(reads) == before + 1 and small_entry[0] == stage / 'candidates/0.bin' and not small_entry[3]
    assert READ(str(small_entry[0]), sha(small_bytes)) == small_bytes
    cases.append({'name': 'small-public-artifact-authenticated-once-and-staged-mode0400', 'passed': True})
    before = len(reads)
    large_entry = api['candidate_entry'](guard, row(large, boundary_bytes), 1, stage)
    assert len(reads) == before + 1 and large_entry[0] == large and large_entry[3]
    assert not (stage / 'candidates/1.bin').exists() and not any(isinstance(v, bytes) for v in large_entry)
    cases.append({'name': 'one-MiB-boundary-binds-exact-host-leaf-without-payload-retention-or-clone', 'passed': True})
    second = api['candidate_entry'](guard, row(large, boundary_bytes), 0, output / 'second-job-stage')
    assert second[0] == large_entry[0] == large and not (output / 'second-job-stage').exists()
    cases.append({'name': 'two-job-plans-share-same-canonical-large-public-leaf', 'passed': True})
    below_entry = api['candidate_entry'](guard, row(below, below_bytes), 2, stage)
    assert not below_entry[3] and READ(str(below_entry[0]), sha(below_bytes)) == below_bytes
    cases.append({'name': 'one-byte-below-threshold-remains-staged', 'passed': True})
    preflight = api['candidate_entry'](guard, row(small, small_bytes), 3, None)
    assert preflight[0] is None
    cases.append({'name': 'public-preflight-discards-small-payload-without-staging', 'passed': True})
    def refused(name, call):
        try:
            call()
        except Exception:
            cases.append({'name': name, 'passed': True})
            return
        raise AssertionError(name)
    for name, change in [('bool-byte-count-refused', lambda v: v.update(bytes=True)),
                         ('wrong-byte-count-refused', lambda v: v.update(bytes=v['bytes'] + 1)),
                         ('malformed-public-pin-refused', lambda v: v.update(sha256='AA' * 32)),
                         ('wrong-public-pin-refused', lambda v: v.update(sha256='00' * 32)),
                         ('relative-public-source-refused', lambda v: v.update(source='relative.bin')),
                         ('parent-path-alias-refused', lambda v: v.update(source=str(output) + '/../small.bin'))]:
        changed = row(small, small_bytes); change(changed)
        refused(name, lambda changed=changed: api['candidate_entry'](guard, changed, 9, stage))
    link_source = output / 'hardlink-source.bin'; save(link_source, small_bytes)
    os.link(link_source, output / 'hardlink-alias.bin')
    refused('public-hardlink-source-refused', lambda: api['candidate_entry'](guard, row(link_source, small_bytes), 9, stage))
    symlink = output / 'symlink-source.bin'; symlink.symlink_to(small)
    refused('public-symlink-source-refused', lambda: api['candidate_entry'](guard, row(symlink, small_bytes), 9, stage))
    mutable = output / 'mutated-after-admission.bin'; save(mutable, boundary_bytes)
    admitted = api['candidate_entry'](guard, row(mutable, boundary_bytes), 5, stage)
    mutable.chmod(0o600)
    with mutable.open('r+b') as target:
        target.write(b'X')
    refused('post-admission-host-metadata-change-refused', lambda: api['check_candidate_metadata'](guard, [admitted]))
    during = output / 'mutated-during-admission.bin'; save(during, small_bytes)
    during_row = row(during, small_bytes)
    mutating_guard = dict(guard)
    def mutate_after_guard_read(path, expected=None):
        payload = actual_read(path, expected)
        during.chmod(0o600)
        with during.open('r+b') as target:
            target.write(b'X')
        return payload
    mutating_guard['read'] = mutate_after_guard_read
    refused('metadata-change-between-whole-SHA-auth-and-return-refused',
            lambda: api['candidate_entry'](mutating_guard, during_row, 8, stage))
    # Exercise the real new mount/worker path with one intentionally PUBLIC seed.
    # The protected original_metadata function itself remains AST-identical and
    # is never called; this replacement stats only the public fixture leaf.
    old_selector = HERE / 'final-scope-public-controls-01/selector-all-public-authentication-before-forbidden-original-metadata-boundary.json'
    release = json.loads(READ(str(old_selector)))
    release['files'].append(row(large, boundary_bytes))
    candidate_rows = [{key: v[key] for key in ('path', 'bytes', 'sha256')} for v in release['files']]
    for selected in release['sources']:
        if selected['mount'] == '/public/CANARY-CONTEXT-SCOPE.json':
            scope = json.loads(READ(selected['source'], selected['sha256']))
            scope['candidate_manifest_sha256'] = sha(encoded(candidate_rows))
            target = output / 'PUBLIC-FIXTURE-SCOPE.json'; payload = encoded(scope); save(target, payload)
            selected.update(source=str(target), bytes=len(payload), sha256=sha(payload))
    selection = output / 'PUBLIC-FIXTURE-RELEASE.json'; payload = encoded(release); save(selection, payload)
    seed = hashlib.sha256(b'KPXA MATCHED21 KNOWN PUBLIC SEED ' + bytes([0])).digest()
    backup = output / 'PUBLIC-FIXTURE-BACKUP.json'
    save(backup, encoded({'schema': 'kpxa-original-seed-backup/v1',
                         'domain_hex32': api['DOMAIN'], 'seed_hex32': seed.hex()}), 0o600)
    def fixture_metadata(_):
        return backup, backup.lstat()
    api['original_metadata'] = fixture_metadata
    api['runpy'] = SimpleNamespace(run_path=lambda path: guard if path == GUARD else runpy.run_path(path))
    identity = 'audit-known-public-' + output.name
    args = SimpleNamespace(release=selection, release_sha256=sha(payload), execute=True, identity=identity)
    before = len(reads)
    summary = api['execute'](args)
    job_reads = reads[before:]
    for selected in release['files']:
        assert job_reads.count(selected['source']) == 1
    assert summary['literal_status'] == summary['derived_status'] == 'PASS'
    assert summary['complete_candidate_payload_list_retained'] is False
    assert summary['large_candidate_direct_readonly_mounts'] == 1
    assert summary['small_candidate_bytes_per_job'] == release['files'][0]['bytes']
    assert summary['nine_job_small_candidate_copy_bytes'] == 9 * release['files'][0]['bytes']
    assert summary['largest_transient_candidate_payload_bytes'] == threshold
    assert summary['additional_large_candidate_copy_bytes_per_job'] == 0
    runtime = Path('/var/tmp/kpi-local-private-payment-01/publication-audits') / identity
    assert (runtime / 'candidates/0.bin').exists() and not (runtime / 'candidates/1.bin').exists()
    cases.append({'name': 'unchanged-literal-derived-public-workers-use-one-large-RO-file-and-one-small-snapshot', 'passed': True})
    cases.append({'name': 'all-candidates-host-h09-authenticated-exactly-once-per-public-job', 'passed': True})
    cases.append({'name': 'exact-nine-times-small-byte-copy-bound-reported', 'passed': True})
    report = {'schema': 'kpxa-final-large-leaf-public-controls/v1', 'status': 'PASS',
        'classification': 'KNOWN_PUBLIC_SYNTHETIC_PROVENANCE_AND_SUPPLIED_COMPONENT_CONTEXT_ONLY',
        'source_sha256': source_sha, 'threshold_bytes': threshold, 'controls': cases,
        'actual_original_metadata_function_called': False, 'protected_originals_read_or_mounted': False,
        'original_metadata_replaced_only_by_public_fixture_leaf': True,
        'new_proof_generation_network_or_publication': False, 'actual_node_acceptance_claim': False,
        'own_exit_count_attestation_performed': False,
        'small_candidate_bytes_per_public_job': summary['small_candidate_bytes_per_job'],
        'nine_job_small_candidate_copy_bytes': summary['nine_job_small_candidate_copy_bytes'],
        'largest_transient_candidate_payload_bytes': summary['largest_transient_candidate_payload_bytes']}
    save(output / 'RESULTS.json', encoded(report))
    print(json.dumps({'status': 'PASS', 'controls': len(cases), 'source_sha256': source_sha,
        'protected_originals_read_or_mounted': False}, sort_keys=True))


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    run(p.parse_args().output)
