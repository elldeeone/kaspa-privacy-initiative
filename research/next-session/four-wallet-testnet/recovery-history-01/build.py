#!/usr/bin/env python3
"""Copy a finite selected public terminal-history handoff; never run its payloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import types

PROFILE = '41c60779f005ebdae27e9f154950478fb7ae8bf613dec7bf9753056600cb6b5a'
GUARD = 'da559335c0e071d15b7daee5cd4d256776295c934d5db569c1e13c3d2bf83195'
BASE_INDEX = 'c6a706e05653aa1da1196fbc05668d46e4138f3fadd1e816e10b439e12009ece'
BUILD = '5b4596050e976e7e45f94e75fe6a134f793c36e23424f593be5d01724d1f1a79'


def need(value, message):
    if not value:
        raise ValueError(message)


def attrs(info):
    return tuple(getattr(info, name) for name in
                 ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def bootstrap(project, roots):
    """Only stat the eight originals before reading the pinned public guard."""
    roots = tuple(Path(root).absolute() for root in roots)
    need(len(roots) == len(set(roots)) == 2, 'two-original-trial-selectors')
    identities, directories = set(), []
    for root in roots:
        for role in 'ABCD':
            folder = root / 'owners' / role
            path = folder / 'backup.json'
            need(not any(p.is_symlink() for p in (path, *path.parents)), 'original-metadata-path')
            info = path.stat()
            need(folder.is_dir() and stat.S_ISREG(info.st_mode), 'original-metadata-type')
            identities.add((info.st_dev, info.st_ino)); directories.append(folder)
    need(len(identities) == 8, 'eight-original-file-identities')
    path = project / 'poc/four-wallet-profile/outer_run.py'
    before = path.stat()
    need(not any(p.is_symlink() for p in (path, *path.parents))
         and stat.S_ISREG(before.st_mode) and (before.st_dev, before.st_ino) not in identities
         and all(not path.is_relative_to(folder) for folder in directories), 'public-guard-source')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as file:
        need(attrs(os.fstat(file.fileno())) == attrs(before), 'guard-opened-inode')
        raw = file.read()
        need(attrs(os.fstat(file.fileno())) == attrs(before), 'guard-stable-inode')
    need(len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == GUARD, 'guard-pin')
    module = types.ModuleType('_kpx6_terminal_public_guard')
    module.__file__ = str(path); sys.modules[module.__name__] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    module.GUARD = module.PublicGuard(roots)
    return module


def relative(value):
    need(type(value) is str and value and '\\' not in value and '\0' not in value,
         'public-object-relative-path')
    path = PurePosixPath(value)
    need(not path.is_absolute() and str(path) == value
         and all(part not in ('', '.', '..') for part in path.parts), 'public-object-relative-path')
    return value


def build(args):
    project = Path(args.project_root).absolute()
    guard = bootstrap(project, args.exclude_private_root)
    guard.read(Path(__file__), args.builder_sha256)
    helper_path = project / 'research/next-session/four-wallet-testnet/recovery-bundle-01/build.py'
    helper_raw = guard.read(helper_path, BUILD)
    helper = types.ModuleType('_kpx6_existing_public_object_builder')
    helper.__file__ = str(helper_path); sys.modules[helper.__name__] = helper
    exec(compile(helper_raw, str(helper_path), 'exec'), helper.__dict__)
    selection = guard.parse(guard.read(args.selection, args.selection_sha256))
    need(selection['schema'] == 'kpx6-terminal-public-recovery-selection/v1', 'finite-selection-schema')
    base_root = helper.checked(selection['base_objects_directory'])
    base_raw = guard.read(base_root / 'RECOVERY-OBJECTS.json', BASE_INDEX)
    base = guard.parse(base_raw)
    need(base['financial_profile_sha256'] == PROFILE and len(base['assets']) == 7, 'unchanged-seven-assets')
    descriptor = selection['descriptor']; fetch = selection['fetch']
    descriptor_raw = guard.read(descriptor['path'], descriptor['sha256'])
    fetch_raw = guard.read(fetch['path'], fetch['sha256']); fetched = guard.parse(fetch_raw)
    need(fetched['schema'] == 'kpx5-gn2-network-fetch/v1'
         and fetched['status'] == 'FETCHED_PENDING_REPLAY'
         and fetched['network_id'] == 'testnet-10'
         and fetched['financial_profile_sha256'] == PROFILE
         and fetched['descriptor_file_sha256'] == descriptor['sha256'], 'selected-live-fetch-joins')
    coverage = fetched['coverage']
    need(coverage['complete'] is True and coverage['frontier_seen'] is True
         and coverage['pruned'] is False and coverage['missing'] == [], 'retained-fetch-coverage')
    need(fetched['descriptor'] == guard.parse(descriptor_raw), 'exact-descriptor-content-join')
    rows, sources = [], {}
    def add(name, kind, path, digest, size):
        name = relative(name)
        need(name not in sources and type(size) is int and size >= 0
             and type(digest) is str and len(digest) == 64
             and all(c in '0123456789abcdef' for c in digest), 'finite-public-object-row')
        rows.append({'id': name, 'kind': kind, 'bytes': size, 'sha256': digest}); sources[name] = Path(path)
    for row in base['assets']:
        add(row['id'], row['kind'], base_root / relative(row['id']), row['sha256'], row['bytes'])
    add('accepted-history/descriptor.json', 'actual-live-public-descriptor', descriptor['path'],
        descriptor['sha256'], len(descriptor_raw))
    add('accepted-history/fetch.json', 'actual-live-terminal-prefix-fetch', fetch['path'],
        fetch['sha256'], len(fetch_raw))
    page_rows = [*fetched['pages'], *fetched['current_view']['post_query_delta']['pages']]
    bundle = helper.checked(selection['bundle_directory'])
    for row in page_rows:
        name = relative(row['path'])
        add('accepted-history/' + name, 'actual-live-retained-Full-page-gzip', bundle / name,
            row['gzip_sha256'], row['gzip_bytes'])
    for row in selection['public_receipts']:
        add('accepted-history/receipts/' + relative(row['name']), 'actual-live-public-verification-receipt',
            row['path'], row['sha256'], row['bytes'])
    need(selection['public_receipts'], 'externally-selected-terminal-verification-receipt')
    # Every selected member is excluded by original metadata before any copy.
    for row in rows:
        _, info = guard.GUARD.metadata(sources[row['id']])
        need(info.st_size == row['bytes'], 'selected-object-size-before-first-copy')
    output = guard.fresh(args.output); objects = output / 'objects'; objects.mkdir(mode=0o700)
    for row in rows:
        helper.stream(guard, sources[row['id']], row['sha256'], row['bytes'], objects / row['id'])
    index = dict(base)
    index['classification'] = 'PREPARED_PUBLIC_OBJECTS_NOT_PROVIDER_OR_RETENTION_QUALIFICATION'
    index['assets'] = sorted(rows, key=lambda row: row['id'])
    index['previous_prepared_index_sha256'] = BASE_INDEX
    index['accepted_history'] = {'available': True, 'network_id': 'testnet-10',
        'descriptor_id': 'accepted-history/descriptor.json', 'descriptor_sha256': descriptor['sha256'],
        'fetch_id': 'accepted-history/fetch.json', 'fetch_sha256': fetch['sha256'],
        'retained_Full_page_count': len(page_rows),
        'verification_receipt_ids': ['accepted-history/receipts/' + row['name']
                                     for row in selection['public_receipts']],
        'authority': 'Exact retained public bytes; terminal acceptance and payout claims require the selected independent replay receipts.',
        'availability_scope': 'Local prepared copies only; no independent provider or retention qualification.'}
    index_raw = helper.encoded(index); helper.save(objects / 'RECOVERY-OBJECTS.json', index_raw)
    result = {'schema': 'kpx6-terminal-public-recovery-build/v1', 'passed': True,
        'selection_sha256': args.selection_sha256, 'builder_sha256': args.builder_sha256,
        'previous_prepared_index_sha256': BASE_INDEX, 'index_sha256': helper.sha(index_raw),
        'index_bytes': len(index_raw), 'asset_count': len(rows), 'asset_bytes': sum(row['bytes'] for row in rows),
        'unchanged_base_assets': 7, 'retained_Full_page_count': len(page_rows),
        'all_copied_assets_streamed_and_fully_hashed': True,
        'original_backup_contents_read_or_hashed': False, 'wallet_or_prover_or_payload_executed': False,
        'network_used_or_objects_uploaded': False, 'independent_storage_or_retention_verified': False,
        'terminal_semantics_reexecuted_by_packager': False}
    helper.save(output / 'RESULTS.json', helper.encoded(result))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root', type=Path, required=True)
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--builder-sha256', required=True)
    parser.add_argument('--exclude-private-root', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    build(parser.parse_args())
