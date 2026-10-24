#!/usr/bin/env python3
"""Stage a finite public owner runtime; read no owner backup or proving key."""
import argparse
import json
from pathlib import Path

from compat import SOURCES
from contracts import (BACKUP_SOURCES, FINANCIAL_SOURCE, FINANCIAL_SOURCE_SHA256, GENESIS_SOURCES,
                       financial)
from installation import (ROOT, checked, digest, mapping, need, outside,
                          parse, read_public, regular)

SDK_ROOT = Path('/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa')
SDK = {'kaspa.js': '6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
       'kaspa_bg.wasm': 'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
       'package.json': '8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0'}


def pinned_document(path, expected, forbidden, directories):
    raw = read_public(path, forbidden, directories)
    need(digest(raw) == expected, 'external-public-document-pin')
    return raw, parse(raw)


def stage(args):
    destination = outside(args.output)
    need(not destination.exists(), 'fresh-public-runtime-destination')
    forbidden = set(); directories = tuple(outside(p) for p in args.exclude_private_dir)
    for path in args.exclude_private_file:
        path = outside(path); info = path.stat()
        forbidden.add((info.st_dev, info.st_ino))
    forbidden = frozenset(forbidden)
    for path in (args.financial_profile, args.artifacts, args.source_freeze, args.manifest, FINANCIAL_SOURCE):
        regular(path, forbidden, directories)
    if args.source_kind == 'accepted':
        need(args.chain_freeze is not None and args.chain_freeze_sha256 is not None,
             'selected-chain-source-freeze')
        regular(args.chain_freeze, forbidden, directories)
    raw_profile = read_public(args.financial_profile, forbidden, directories)
    profile = financial(raw_profile, args.financial_sha256)
    _, frozen = pinned_document(args.source_freeze, args.source_freeze_sha256, forbidden, directories)
    need(frozen['schema'] == 'kpx6-four-wallet-lifecycle-source-freeze/v1', 'selected-owner-source-freeze')
    pins = {row['path']: row for row in frozen['files']}
    for directory, names in SOURCES.values():
        for name, sha in names.items():
            pins[directory + '/' + name + '.py'] = {'sha256': sha}
    pins['poc/four-wallet-profile/selection.py'] = {'sha256': FINANCIAL_SOURCE_SHA256}
    for name, sha in {**BACKUP_SOURCES, **GENESIS_SOURCES}.items():
        pins['poc/four-wallet-bootstrap/' + name + '.py'] = {'sha256': sha}
    pins['poc/future-recipient/v2/recipient.py'] = {
        'sha256': '93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2'}
    pins['poc/private-cashout-trial/sdk.mjs'] = {
        'sha256': '7e09cb2316dd08072fa4d29e221020215f137e68f761937d7cc0751ee1678e63'}
    if args.source_kind == 'accepted':
        _, chain = pinned_document(args.chain_freeze, args.chain_freeze_sha256, forbidden, directories)
        for row in chain['files']:
            pins[row['path']] = row
    _, artifacts = pinned_document(args.artifacts, args.artifacts_sha256, forbidden, directories)
    need(artifacts['schema'] == 'kpx6-four-wallet-public-runtime-artifact-inventory/v1'
         and artifacts['financial_profile_sha256'] == profile.profile_sha256,
         'selected-financial-runtime-artifacts')
    roles = {row['basename']: row for row in artifacts['files']}
    selected = []
    for name in mapping(args.source_kind):
        if name.startswith('runtime-source/'):
            relative = name[len('runtime-source/'):]
            need(relative in pins, 'every-owner-source-selected')
            selected.append((name, ROOT / relative, 'runtime-source', pins[relative]['sha256']))
        elif name.startswith('runtime-sdk/'):
            basename = name[len('runtime-sdk/'):]
            need(basename in SDK, 'selected-SDK-member')
            selected.append((name, SDK_ROOT / basename, 'runtime-source', SDK[basename]))
        else:
            basename = name[len('runtime/'):]
            need(basename in profile.executables and basename in roles, 'selected-executable-role')
            row = roles[basename]
            need(row['bytes'] == profile.executables[basename]['bytes']
                 and row['sha256'] == profile.executables[basename]['sha256'], 'exact-executable-artifact-join')
            selected.append((name, Path(row['path']), 'selected-executable', row['sha256']))
    selected.extend((('selection/financial-profile.json', args.financial_profile, 'public-metadata', profile.profile_sha256),
                     ('selection/compact-public-parameters.json', args.manifest, 'public-metadata',
                      profile.parameter_manifest_sha256)))
    for _, path, _, _ in selected:
        regular(path, forbidden, directories)
    # Metadata of every explicit source/runtime member precedes any member copy.
    destination.mkdir(parents=True, mode=0o700)
    rows = []
    for name, path, kind, sha in selected:
        raw = read_public(path, forbidden, directories)
        need(digest(raw) == sha, 'exact-selected-public-member-bytes')
        target = destination / name; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open('xb') as file:
            file.write(raw)
        target.chmod(0o500 if kind == 'selected-executable' else 0o400)
        rows.append({'kind': kind, 'path': name, 'bytes': len(raw), 'sha256': sha})
    inventory = {'schema': 'kpx4-public-software-bundle/v1',
        'classification': 'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY',
        'files': sorted(rows, key=lambda row: row['path'])}
    raw = (json.dumps(inventory, sort_keys=True, separators=(',', ':'))+'\n').encode()
    with (destination / 'SOFTWARE-BUNDLE.json').open('xb') as file:
        file.write(raw)
    return {'public_software_files': len(rows), 'public_software_bytes': sum(row['bytes'] for row in rows),
            'inventory_sha256': digest(raw), 'financial_profile_sha256': profile.profile_sha256,
            'original_backup_or_PK_bytes_read': False,
            'prover_native_VM_or_network_executed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'financial-profile', 'artifacts', 'source-freeze', 'manifest'):
        parser.add_argument('--'+name, type=Path, required=True)
    for name in ('financial', 'artifacts', 'source-freeze'):
        parser.add_argument('--'+name+'-sha256', required=True)
    parser.add_argument('--source-kind', choices=('local', 'accepted'), required=True)
    parser.add_argument('--chain-freeze', type=Path); parser.add_argument('--chain-freeze-sha256')
    for name in ('exclude-private-file', 'exclude-private-dir'):
        parser.add_argument('--'+name, type=Path, action='append', default=[])
    try:
        print(json.dumps(stage(parser.parse_args()), sort_keys=True))
    except Exception:
        print(json.dumps({'error':'public-runtime-staging-incomplete','private_owner_bytes_read':False}))
        raise SystemExit(1)
