#!/usr/bin/env python3
"""Finite one-original audit launcher; no original content or hash enters here.

Execution requires root's exact release selection and independent review GO.
The controller reads only guard-admitted public files and original metadata.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import stat
import subprocess

DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
GUARD = '/var/tmp/kpi-root-guard-helper-09.py'
ORIGINAL_PREFIX = Path('/var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01')
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def need(value):
    if not value:
        raise ValueError('finite-publication-audit-refused')


def parse(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value)
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_float=lambda _: need(False), parse_constant=lambda _: need(False))


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def attributes(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode',
        'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def original_metadata(a):
    path = Path(a.original)
    need(path.is_absolute() and '..' not in path.parts and path.name == 'BACKUP.json')
    # Exact prefix was released by root; this does not discover new originals.
    need(path.is_relative_to(ORIGINAL_PREFIX))
    need(not any(p.is_symlink() for p in (path, *path.parents)))
    info = path.lstat()  # Metadata only. Never open/hash/copy this original.
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o600
         and (info.st_dev, info.st_ino, info.st_size, info.st_ctime_ns) ==
             (a.original_device, a.original_inode, a.original_bytes, a.original_ctime_ns))
    return path, info


def save(path, raw, mode=0o400):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), mode)
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def execute(a):
    read = runpy.run_path(GUARD)['read']
    value = parse(read(str(a.release), a.release_sha256))
    need(type(value) is dict and set(value) == {'schema', 'domain_hex32', 'files', 'sources'}
         and value['schema'] == 'kpxa-publication-audit-release/v1'
         and value['domain_hex32'] == DOMAIN and type(value['files']) is list
         and value['files'] and type(value['sources']) is list and value['sources'])
    rows, candidates, sources, names, mounts = [], [], [], set(), set()
    for row in value['files']:
        need(type(row) is dict and set(row) == {'source', 'path', 'bytes', 'sha256'})
        name = PurePosixPath(row['path'])
        need(type(row['path']) is str and str(name) == row['path'] and not name.is_absolute()
             and name.parts and '..' not in name.parts and '\\' not in row['path']
             and '\0' not in row['path'] and row['path'] not in names)
        names.add(row['path'])
        raw = read(row['source'], row['sha256'])
        need(type(row['bytes']) is int and len(raw) == row['bytes'])
        rows.append({key: row[key] for key in ('path', 'bytes', 'sha256')})
        candidates.append(raw)
    for row in value['sources']:
        need(type(row) is dict and set(row) == {'source', 'mount', 'bytes', 'sha256', 'mode'})
        path = PurePosixPath(row['mount'])
        need(type(row['mount']) is str and str(path) == row['mount']
             and path.is_relative_to('/public') and '..' not in path.parts
             and path != PurePosixPath('/public') and '\\' not in row['mount']
             and '\0' not in row['mount']
             and row['mount'] not in mounts and row['mode'] in ('0400', '0500'))
        mounts.add(row['mount'])
        raw = read(row['source'], row['sha256'])
        need(type(row['bytes']) is int and len(raw) == row['bytes'])
        sources.append((row, raw))
    required = {'/public/recovery/publication_literal.py', '/public/recovery/publication_derived.py',
                '/public/ASSETS.json', '/public/HISTORY.json', '/public/CONTEXT.json',
                '/public/CANARY-CONTEXT-SCOPE.json'}
    need(required <= mounts)
    selected_sources = {row['mount']: raw for row, raw in sources}
    scope = parse(selected_sources['/public/CANARY-CONTEXT-SCOPE.json'])
    need(set(scope) == {'schema', 'classification', 'creation_output_count',
        'deposit_sompi', 'accepted_backing', 'recovery_or_signing_authority',
        'actual_payout_key_material_covered', 'future_material_covered'}
        and scope['schema'] == 'kpxa-canary-nonchain-creation-context/v1'
        and scope['classification'] == 'CANARY_ONLY_NONCHAIN_GENUINE_CREATION_OUTPUTS'
        and type(scope['creation_output_count']) is int and scope['creation_output_count'] == 9
        and type(scope['deposit_sompi']) is int and scope['deposit_sompi'] == 2_000_000_000
        and scope['accepted_backing'] is False and scope['recovery_or_signing_authority'] is False
        and type(scope['actual_payout_key_material_covered']) is int
        and scope['actual_payout_key_material_covered'] == 0
        and scope['future_material_covered'] is False)
    audit_history = parse(selected_sources['/public/HISTORY.json'])
    need(audit_history['transitions'] == []
         and len(audit_history['genesis']['outputs_hex520']) == scope['creation_output_count']
         and audit_history['genesis']['deposit_sompi'] == scope['deposit_sompi'])
    owner, before = original_metadata(a)
    # All public bytes are authenticated before a child can receive the leaf.
    summary = {'schema': 'kpxa-one-leaf-publication-audit/v1', 'release_sha256': a.release_sha256,
        'candidate_file_count': len(rows), 'candidate_bytes': sum(row['bytes'] for row in rows),
        'source_files': len(sources), 'original_content_read_or_hashed_by_controller': False,
        'actual_original_check_executed': False, 'literal_and_derived_are_separate': True,
        'canary_context_classification': scope['classification'],
        'accepted_backing_or_recovery_authority': False,
        'actual_payout_key_material_covered': 0, 'future_material_covered': False}
    if not a.execute:
        return summary
    need(re.fullmatch('audit-[a-z0-9-]{1,64}', a.identity))
    runtime = Path('/var/tmp/kpi-local-private-payment-01/publication-audits') / a.identity
    need(not runtime.exists() and not any(p.is_symlink() for p in (runtime, *runtime.parents)))
    runtime.mkdir(parents=True, mode=0o700)
    common = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
        '--clearenv', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
        '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
        '--ro-bind', '/etc/alternatives', '/etc/alternatives', '--proc', '/proc',
        '--dev', '/dev', '--tmpfs', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'LANG', 'C.UTF-8']
    for index, raw in enumerate(candidates):
        selected = runtime / 'candidates' / (str(index) + '.bin')
        save(selected, raw)
        common += ['--ro-bind', str(selected), '/candidates/' + str(index) + '.bin']
    by_mount = {}
    for index, (row, raw) in enumerate(sources):
        selected = runtime / 'sources' / (str(index) + '.bin')
        save(selected, raw, int(row['mode'], 8))
        common += ['--ro-bind', str(selected), row['mount']]
        by_mount[row['mount']] = row['sha256']
    for kind, schema, result_schema in (
        ('literal', 'kpx8-new-owner-seed-export-allowlist/v1', 'kpxa-literal-seed-export-result/v1'),
        ('derived', 'kpxa-derived-export-candidates/v1', 'kpxa-derived-export-result/v1')):
        need(attributes(original_metadata(a)[1]) == attributes(before))
        raw_manifest = encoded({'schema': schema, 'files': rows})
        manifest = runtime / (kind + '-ALLOWLIST.json')
        save(manifest, raw_manifest)
        out = runtime / (kind + '-out')
        out.mkdir(mode=0o700)
        command = common + ['--ro-bind', str(owner), '/BACKUP.json',
            '--ro-bind', str(manifest), '/ALLOWLIST.json', '--bind', str(out), '/out',
            '/usr/bin/python3', '-B', '/public/recovery/publication_' + kind + '.py',
            '--owner', '/BACKUP.json', '--allowlist', '/ALLOWLIST.json',
            '--allowlist-sha256', sha(raw_manifest), '--candidates', '/candidates',
            '--output', '/out/RESULTS.json']
        if kind == 'derived':
            for option, mount in [('assets', '/public/ASSETS.json'), ('history', '/public/HISTORY.json'),
                                  ('context', '/public/CONTEXT.json')]:
                command += ['--' + option, mount, '--' + option + '-sha256', by_mount[mount]]
        process = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, env=CLEAN)
        need(process.returncode == 0)
        result = parse(read(str(out / 'RESULTS.json')))
        expected_fields = {'schema', 'status', 'candidate_count', 'candidate_bytes',
                           'matched_candidate_count', 'scope'}
        if kind == 'derived':
            expected_fields.add('literal_seed_coverage')
        need(set(result) == expected_fields and result['schema'] == result_schema
             and result['status'] == 'PASS' and type(result['matched_candidate_count']) is int
             and result['matched_candidate_count'] == 0
             and result['candidate_count'] == len(rows) + 1
             and result['candidate_bytes'] == summary['candidate_bytes'] + len(raw_manifest))
        if kind == 'derived':
            need(result['literal_seed_coverage'] is False
                 and result['scope'] == 'FINITE_RECOVERABLE_DERIVED_BYTES_ONLY_NOT_ALL_SECRETS_OR_PRIVACY_PROOF')
        else:
            need(result['scope'] == 'LITERAL_SEED_CANARY_ONLY_NOT_SECURITY_OR_PRIVACY_PROOF')
        need(attributes(original_metadata(a)[1]) == attributes(before))
        summary[kind + '_status'] = result['status']
    summary.update({'actual_original_check_executed': True, 'one_original_leaf_read_only_per_namespace': True,
                    'parent_sibling_root_or_home_mounted': False, 'private_values_paths_hashes_or_indices_exported': False})
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--release', required=True, type=Path)
    p.add_argument('--release-sha256', required=True)
    p.add_argument('--original', required=True)
    for name in ('device', 'inode', 'bytes', 'ctime-ns'):
        p.add_argument('--original-' + name, required=True, type=int)
    p.add_argument('--identity')
    p.add_argument('--execute', action='store_true')
    try:
        print(json.dumps(execute(p.parse_args()), sort_keys=True))
    except Exception:
        p.exit(2, 'Finite publication audit refused; no private material exported.\n')


if __name__ == '__main__':
    main()
