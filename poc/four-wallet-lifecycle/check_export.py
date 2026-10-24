#!/usr/bin/env python3
"""One-owner finite publication check; never export a secret or its hash."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

from contracts import financial, own_backup
from installation import checked, digest, need, parse, read_public, regular, relative

CANDIDATE_SCHEMA = 'kpx6-owner-public-export-candidates/v1'
CANDIDATE_CLASS = 'FINITE_PUBLIC_EXPORT_CANDIDATES_NOT_SECRET_COMPLETENESS_PROOF'
SOFTWARE_CLASS = 'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY'
PURE_PATHS = frozenset(('poc/four-wallet-lifecycle/check_export.py',
    'poc/four-wallet-lifecycle/installation.py', 'poc/four-wallet-lifecycle/contracts.py',
    'poc/four-wallet-lifecycle/paths.py', 'poc/four-wallet-profile/selection.py',
    'poc/four-wallet-bootstrap/gn2_common.py', 'poc/four-wallet-bootstrap/gn2_backup.py'))
CHUNK_BYTES = 1024 * 1024


def hex_digest(value):
    need(type(value) is str and len(value) == 64
         and all(c in '0123456789abcdef' for c in value), 'canonical-external-digest')
    return value


def rows(raw, expected, root, forbidden=(), private_directories=(), *, software=False):
    need(digest(raw) == hex_digest(expected), 'external-finite-manifest-pin')
    value = parse(raw)
    need(type(value) is dict and set(value) == {'schema', 'classification', 'files'}
         and value['schema'] == ('kpx4-public-software-bundle/v1' if software else CANDIDATE_SCHEMA)
         and value['classification'] == (SOFTWARE_CLASS if software else CANDIDATE_CLASS)
         and type(value['files']) is list and value['files'], 'strict-finite-manifest')
    root = checked(root)
    result, names = [], set()
    for row in value['files']:
        need(type(row) is dict and set(row) == ({'path', 'bytes', 'sha256', 'kind'} if software
                                              else {'path', 'bytes', 'sha256'}),
             'strict-finite-member')
        name = relative(row['path'])
        need(name not in names and type(row['bytes']) is int and row['bytes'] >= 0,
             'unique-finite-member-size')
        hex_digest(row['sha256'])
        if software:
            need(row['kind'] == 'runtime-source', 'pure-software-source-only')
        path, info = regular(root / name, forbidden, private_directories)
        need(info.st_size == row['bytes'], 'finite-member-metadata-size')
        names.add(name); result.append((row, path))
    if software:
        need(names == PURE_PATHS, 'exact-pure-audit-software-closure')
    return tuple(result)


def stream(path, row, forbidden=(), private_directories=(), *, patterns=(), destination=None):
    """Hash stable bytes and optionally scan/copy; keep only bounded overlap."""
    path, before = regular(path, forbidden, private_directories)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    output = None
    if destination is not None:
        output = Path(destination).open('xb')
    hasher, count, tail, found = hashlib.sha256(), 0, b'', False
    overlap = max((len(value) for value in patterns), default=1) - 1
    try:
        with os.fdopen(descriptor, 'rb') as file:
            opened = os.fstat(file.fileno())
            need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino)
                 and (opened.st_dev, opened.st_ino) not in forbidden, 'finite-member-swapped')
            while True:
                chunk = file.read(CHUNK_BYTES)
                if not chunk:
                    break
                hasher.update(chunk); count += len(chunk)
                if output is not None:
                    output.write(chunk)
                window = tail + chunk
                found = found or any(value in window for value in patterns)
                tail = window[-overlap:] if overlap else b''
            after = os.fstat(file.fileno())
    finally:
        if output is not None:
            output.close()
    attributes = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(tuple(getattr(before, key) for key in attributes)
         == tuple(getattr(after, key) for key in attributes)
         and count == row['bytes'] == before.st_size
         and hasher.hexdigest() == row['sha256'], 'stable-selected-finite-member')
    return found, count


def secret_patterns(backup):
    result = set()
    for key in (backup.seed, backup.funding_key):
        result.update((key, key.hex().encode(), key.hex().upper().encode()))
        for encode in (base64.b64encode, base64.urlsafe_b64encode):
            value = encode(key); result.update((value, value.rstrip(b'=')))
    return tuple(result)


def read_backup(path):
    # Called only after all public identities and bytes have been authenticated.
    raw = read_public(path, ())
    return raw


def run(args):
    trial = uuid.UUID(args.trial_id)
    need(type(args.trial_id) is str and str(trial) == args.trial_id
         and trial.version == 4 and trial.variant == uuid.RFC_4122, 'canonical-trial-UUID')
    backup = checked(args.backup); info = backup.stat()
    need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
         'one-original-backup-mode')
    forbidden = frozenset(((info.st_dev, info.st_ino),)); directories = (backup.parent,)
    for path in (args.financial_profile, args.software_inventory, args.candidates):
        regular(path, forbidden, directories)
    raw_software = read_public(args.software_inventory, forbidden, directories)
    software = rows(raw_software, args.software_sha256, args.software_root,
                    forbidden, directories, software=True)
    raw_candidates = read_public(args.candidates, forbidden, directories)
    candidates = rows(raw_candidates, args.candidates_sha256, args.candidate_root,
                      forbidden, directories)
    # Every selected member's metadata precedes any member byte/hash.
    for row, path in software:
        stream(path, row, forbidden, directories)
    raw_profile = read_public(args.financial_profile, forbidden, directories)
    selected = financial(raw_profile, args.financial_sha256)
    for row, path in candidates:
        stream(path, row, forbidden, directories)
    output = checked(args.output)
    need(not output.exists(), 'fresh-count-only-output')
    need(not output.is_relative_to(backup.parent)
         and all(output != path for _, path in (*software, *candidates)), 'separate-audit-output')
    own = own_backup(read_backup(backup), selected.domain, args.trial_id)
    patterns = secret_patterns(own)
    metadata_matches = sum(any(value in raw for value in patterns)
                           for raw in (raw_candidates, raw_software, raw_profile))
    leaked, size = 0, 0
    for row, path in candidates:
        found, count = stream(path, row, forbidden, directories, patterns=patterns)
        leaked += int(found); size += count
    result = {'schema': 'kpx6-owner-public-export-check/v1', 'passed': leaked == metadata_matches == 0,
        'candidate_file_count': len(candidates), 'candidate_bytes': size,
        'matched_candidate_file_count': leaked,
        'selected_public_metadata_file_count': 3,
        'matched_public_metadata_file_count': metadata_matches,
        'scope': 'OWN_TWO_ORIGINAL_KEYS_EXACT_RAW_HEX_BASE64_ENCODINGS_ONLY',
        'finite_public_allowlist_is_primary_boundary': True,
        'general_transformed_secret_absence_proven': False,
        'secret_values_hashes_or_match_locations_exported': False,
        'PK_prover_native_VM_network_or_other_backup_required': False}
    raw = (json.dumps(result, sort_keys=True, separators=(',', ':'))+'\n').encode()
    with output.open('xb') as file:
        file.write(raw)
    output.chmod(0o400)
    return result


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('backup', 'financial-profile', 'software-inventory', 'software-root',
                 'candidates', 'candidate-root', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    for name in ('financial-sha256', 'software-sha256', 'candidates-sha256', 'trial-id'):
        parser.add_argument('--'+name, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    try:
        result = run(arguments()); print(json.dumps(result, sort_keys=True))
        raise SystemExit(0 if result['passed'] else 2)
    except Exception:
        print(json.dumps({'error': 'owner-public-export-check-incomplete', 'passed': False}))
        raise SystemExit(1)
