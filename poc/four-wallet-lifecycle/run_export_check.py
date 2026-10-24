#!/usr/bin/env python3
"""Stage finite public bytes and run one-backup publication audit offline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

from installation import (CLEAN, checked, digest, entries, need, outside, parse,
                          read_public, regular, relative)

HERE = Path(__file__).resolve().parent
FIXED = {'poc/four-wallet-lifecycle/installation.py':
             '5158c1e39038454a6db1d7426acea39672283e9cc19cffdc9832499526b302b9',
    'poc/four-wallet-lifecycle/contracts.py':
             'b00cf22e66dbda5b3f2083c36529319d32997879b6ef24ab78e96e55ffaf0938',
    'poc/four-wallet-lifecycle/paths.py':
             '4f1a7444c99a245bfda194602c6f8676d1f35b0a03b0e1ab5accf399de3d35f7',
    'poc/four-wallet-profile/selection.py':
             '425469f9e5ed012d43132ae17ac965f7c1bc3b0fdacd7a2ecf8a36a881d90553',
    'poc/four-wallet-bootstrap/gn2_common.py':
             '2f0742ef22eec589978cbc55df20e7acc1c3a95458c46a77b311fc647dcf037b',
    'poc/four-wallet-bootstrap/gn2_backup.py':
             '8fdf5e01d9b81c99802406276704ddaacd4927d4f48b8432240ec18e6a17efc0'}
SCHEMA = 'kpx6-owner-public-export-candidates/v1'
CLASS = 'FINITE_PUBLIC_EXPORT_CANDIDATES_NOT_SECRET_COMPLETENESS_PROOF'


def copy_stable(path, row, forbidden, directories, target=None):
    path, before = regular(path, forbidden, directories)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    output, count, hasher = None, 0, hashlib.sha256()
    try:
        if target is not None:
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            output = target.open('xb')
        with os.fdopen(descriptor, 'rb') as file:
            opened = os.fstat(file.fileno())
            need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino)
                 and (opened.st_dev, opened.st_ino) not in forbidden, 'public-member-swapped')
            while True:
                chunk = file.read(1024 * 1024)
                if not chunk:
                    break
                count += len(chunk); hasher.update(chunk)
                if output is not None:
                    output.write(chunk)
            after = os.fstat(file.fileno())
    finally:
        if output is not None:
            output.close()
    keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(tuple(getattr(before, key) for key in keys) == tuple(getattr(after, key) for key in keys)
         and count == before.st_size == row['bytes'] and hasher.hexdigest() == row['sha256'],
         'selected-stable-public-bytes')
    if target is not None:
        target.chmod(0o400)


def candidate_rows(raw, expected, root, forbidden, directories):
    need(digest(raw) == expected, 'external-candidate-manifest-pin')
    value = parse(raw)
    need(type(value) is dict and set(value) == {'schema', 'classification', 'files'}
         and value['schema'] == SCHEMA and value['classification'] == CLASS
         and type(value['files']) is list and value['files'], 'finite-public-candidate-manifest')
    result, seen = [], set()
    for row in value['files']:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'finite-candidate-row')
        name = relative(row['path'])
        need(name not in seen and type(row['bytes']) is int and row['bytes'] >= 0
             and type(row['sha256']) is str and len(row['sha256']) == 64
             and all(c in '0123456789abcdef' for c in row['sha256']), 'finite-candidate-fields')
        path, info = regular(checked(root) / name, forbidden, directories)
        need(info.st_size == row['bytes'], 'finite-candidate-size')
        seen.add(name); result.append((row, path))
    return tuple(result)


def count_only_report(report, candidates, returncode):
    names = {'schema', 'passed', 'candidate_file_count', 'candidate_bytes',
        'matched_candidate_file_count', 'selected_public_metadata_file_count',
        'matched_public_metadata_file_count', 'scope', 'finite_public_allowlist_is_primary_boundary',
        'general_transformed_secret_absence_proven', 'secret_values_hashes_or_match_locations_exported',
        'PK_prover_native_VM_network_or_other_backup_required'}
    need(type(report) is dict and set(report) == names
         and report['schema'] == 'kpx6-owner-public-export-check/v1'
         and type(report['passed']) is bool
         and report['scope'] == 'OWN_TWO_ORIGINAL_KEYS_EXACT_RAW_HEX_BASE64_ENCODINGS_ONLY'
         and report['finite_public_allowlist_is_primary_boundary'] is True
         and report['general_transformed_secret_absence_proven'] is False
         and report['secret_values_hashes_or_match_locations_exported'] is False
         and report['PK_prover_native_VM_network_or_other_backup_required'] is False,
         'strict-count-only-audit-receipt')
    for name in ('candidate_file_count', 'candidate_bytes', 'matched_candidate_file_count',
                 'selected_public_metadata_file_count', 'matched_public_metadata_file_count'):
        need(type(report[name]) is int and report[name] >= 0, 'integer-audit-count')
    need(report['candidate_file_count'] == len(candidates)
         and report['candidate_bytes'] == sum(row['bytes'] for row, _ in candidates)
         and 0 <= report['matched_candidate_file_count'] <= len(candidates)
         and report['selected_public_metadata_file_count'] == 3
         and 0 <= report['matched_public_metadata_file_count'] <= 3
         and report['passed'] == (report['matched_candidate_file_count']
                                  == report['matched_public_metadata_file_count'] == 0)
         and report['passed'] is (returncode == 0), 'isolated-export-count-consistency')
    return report


def run(args):
    backup = outside(args.backup); own = backup.stat()
    need(stat.S_ISREG(own.st_mode) and stat.S_IMODE(own.st_mode) == 0o600, 'original-backup-mode')
    forbidden = set(); originals = []
    directories = tuple(outside(path) for path in args.exclude_private_dir)
    for value in args.exclude_private_file:
        path = outside(value); info = path.stat()
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
             and any(path.is_relative_to(directory) for directory in directories),
             'declared-original-backup-and-directory')
        forbidden.add((info.st_dev, info.st_ino)); originals.append(path)
    need(len(originals) == len(forbidden) and len(forbidden) >= 4
         and len(set(directories)) == len(directories) and len(directories) >= 4
         and (own.st_dev, own.st_ino) in forbidden, 'four-distinct-original-backup-exclusions')
    forbidden = frozenset(forbidden)
    controller = outside(args.controller)
    need(not controller.exists(), 'fresh-audit-controller')
    checker = checked(args.checker)
    installation = HERE / 'installation.py'
    for path in (args.financial_profile, args.inventory, args.candidates, checker, installation):
        regular(path, forbidden, directories)
    software = entries(args, forbidden, directories)
    raw_candidates = read_public(args.candidates, forbidden, directories)
    candidates = candidate_rows(raw_candidates, args.candidates_sha256, args.candidate_root,
                                forbidden, directories)
    selected_sources = []
    for name, expected in FIXED.items():
        path = installation if name.endswith('/installation.py') else checked(args.software_root) / ('runtime-source/'+name)
        _, info = regular(path, forbidden, directories)
        selected_sources.append((name, path, {'bytes': info.st_size, 'sha256': expected}))
    _, info = regular(checker, forbidden, directories)
    selected_sources.append(('poc/four-wallet-lifecycle/check_export.py', checker,
                             {'bytes': info.st_size, 'sha256': args.checker_sha256}))
    # All originals, public headers, selected software and candidate metadata
    # have now been guarded before the first selected member byte/hash/copy.
    for row, path in software:
        copy_stable(path, row, forbidden, directories)
    profile = read_public(args.financial_profile, forbidden, directories)
    need(digest(profile) == args.financial_sha256, 'external-financial-profile-pin')
    for row, path in candidates:
        copy_stable(path, row, forbidden, directories)
    for _, path, row in selected_sources:
        copy_stable(path, row, forbidden, directories)
    controller.mkdir(parents=True, mode=0o700)
    root = controller / 'software'; root.mkdir(mode=0o700)
    source_rows = []
    for name, path, row in selected_sources:
        copy_stable(path, row, forbidden, directories, root / name)
        source_rows.append({'path': name, 'bytes': row['bytes'], 'sha256': row['sha256'],
                            'kind': 'runtime-source'})
    source_doc = {'schema': 'kpx4-public-software-bundle/v1',
                  'classification': 'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY',
                  'files': sorted(source_rows, key=lambda row: row['path'])}
    source_raw = (json.dumps(source_doc, sort_keys=True, separators=(',', ':'))+'\n').encode()
    (controller / 'AUDIT-SOFTWARE.json').write_bytes(source_raw)
    (controller / 'financial-profile.json').write_bytes(profile)
    (controller / 'CANDIDATES.json').write_bytes(raw_candidates)
    candidate_root = controller / 'candidates'; candidate_root.mkdir(mode=0o700)
    for row, path in candidates:
        copy_stable(path, row, forbidden, directories, candidate_root / row['path'])
    for name in ('AUDIT-SOFTWARE.json', 'financial-profile.json', 'CANDIDATES.json'):
        (controller / name).chmod(0o400)
    output = controller / 'client-output'; output.mkdir(mode=0o700)
    if not args.execute:
        return {'prepared': True, 'executed': False, 'original_backup_bytes_read': False,
                'candidate_file_count': len(candidates)}
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--ro-bind', str(root), '/work',
        '--ro-bind', str(candidate_root), '/candidates', '--ro-bind', str(backup), '/private/backup.json',
        '--ro-bind', str(controller / 'AUDIT-SOFTWARE.json'), '/software.json',
        '--ro-bind', str(controller / 'financial-profile.json'), '/profile.json',
        '--ro-bind', str(controller / 'CANDIDATES.json'), '/candidates.json',
        '--bind', str(output), '/out', '--chdir', '/work/poc/four-wallet-lifecycle',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC',
        '/usr/bin/python3', '-B', '/work/poc/four-wallet-lifecycle/check_export.py',
        '--backup', '/private/backup.json', '--financial-profile', '/profile.json',
        '--financial-sha256', args.financial_sha256, '--software-inventory', '/software.json',
        '--software-sha256', digest(source_raw), '--software-root', '/work',
        '--candidates', '/candidates.json', '--candidates-sha256', args.candidates_sha256,
        '--candidate-root', '/candidates', '--trial-id', args.trial_id,
        '--output', '/out/RESULTS.json']
    result = subprocess.run(command, capture_output=True, text=True, env=dict(CLEAN))
    (controller / 'PRIVATE-STDOUT.log').write_text(result.stdout)
    (controller / 'PRIVATE-STDERR.log').write_text(result.stderr)
    need(result.returncode in (0, 2) and (output / 'RESULTS.json').is_file(), 'isolated-export-check-incomplete')
    report = parse((output / 'RESULTS.json').read_bytes())
    return count_only_report(report, candidates, result.returncode)


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('controller', type=Path)
    for name in ('backup', 'software-root', 'inventory', 'financial-profile', 'candidates', 'candidate-root'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--checker', type=Path, default=HERE / 'check_export.py')
    for name in ('inventory-sha256', 'financial-sha256', 'candidates-sha256', 'checker-sha256', 'trial-id'):
        parser.add_argument('--'+name, required=True)
    for name in ('exclude-private-file', 'exclude-private-dir'):
        parser.add_argument('--'+name, type=Path, action='append', default=[])
    parser.add_argument('--execute', action='store_true')
    parser.set_defaults(source_kind='local')
    return parser.parse_args()


if __name__ == '__main__':
    try:
        result = run(arguments()); print(json.dumps(result, sort_keys=True))
        raise SystemExit(0 if result.get('passed', True) else 2)
    except Exception:
        print(json.dumps({'error': 'owner-public-export-launch-incomplete', 'passed': False}))
        raise SystemExit(1)
