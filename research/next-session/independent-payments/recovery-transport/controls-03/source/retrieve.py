"""Restore selected public recovery material from release assets, CAS or offline.

Publication roots and software selections are supplied from outside the source.
All success receipts remain historical byte-integrity results, never currentness.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from trusted_util import c, checked_source
from public_fetch import fetch_object, safe_url

KINDS = c.SMALL_KINDS | {'capsule_index', 'chunk_index', 'public_parameter_chunk',
                       'notice', 'transport_source', 'transport_source_inventory'}


def selected_publication(publication_path, expected_sha, selection, forbidden_paths=()):
    raw = c.read_public(publication_path, forbidden_paths, maximum=1_048_576)
    c.need(c.sha(raw) == expected_sha, 'external-publication-root-mismatch')
    value = c.parse(raw)
    c.exact(value, {'schema', 'classification', 'role', 'domain_hex32',
        'parameter_manifest_sha256', 'vk_sha256', 'whole_parameters', 'capsule_sha256',
        'assets', 'current_state_verified', 'spend_authorized', 'publication_authorized'},
        'publication-fields')
    c.need(value['schema'] == 'kpx4-public-recovery-distribution/v1'
        and value['classification'] == 'PUBLIC_UNSAFE_CANARY_DEVELOPMENT_PARAMETERS_DO_NOT_FUND'
        and value['current_state_verified'] is False and value['spend_authorized'] is False
        and value['publication_authorized'] is False, 'publication-scope')
    c.need(value['role'] == selection.role and value['domain_hex32'] == selection.domain_hex32
        and value['parameter_manifest_sha256'] == selection.parameters_manifest_sha256
        and value['vk_sha256'] == selection.vk_sha256, 'publication-static-selection')
    c.exact(value['whole_parameters'], {'bytes', 'sha256'}, 'publication-whole-fields')
    c.need(value['whole_parameters'] == {'bytes': selection.public_parameters_bytes,
        'sha256': selection.public_parameters_sha256}, 'publication-whole-selection')
    c.hx(value['capsule_sha256'], 32, 'publication-capsule-root')
    c.need(type(value['assets']) is list and 1 <= len(value['assets']) <= 1000,
           'publication-assets')
    names = set()
    for row in value['assets']:
        c.exact(row, {'kind', 'basename', 'bytes', 'sha256'}, 'asset-fields')
        c.need(row['kind'] in KINDS and type(row['basename']) is str and
            re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,199}', row['basename']) is not None
            and row['basename'] not in names, 'safe-unique-asset-basename')
        names.add(row['basename'])
        c.uint(row['bytes'], 'asset-length', positive=True)
        c.hx(row['sha256'], 32, 'asset-SHA256')
    c.need([r['basename'] for r in value['assets']] == sorted(names), 'asset-order')
    for kind in c.SMALL_KINDS | {'capsule_index', 'chunk_index'}:
        c.need(sum(row['kind'] == kind for row in value['assets']) == 1,
               'required-unique-public-object')
    capsule = next(row for row in value['assets'] if row['kind'] == 'capsule_index')
    c.need(capsule['sha256'] == value['capsule_sha256'], 'capsule-asset-binding')
    return value


def chunk_index(raw, selection):
    # The same fixed positional contract as the pinned unchanged c713 restorer.
    value = c.parse(raw)
    c.exact(value, {'schema', 'object_bytes', 'object_sha256', 'chunk_bytes', 'chunks'},
            'chunk-index-fields')
    c.need(value['schema'] == 'kpx4-public-object-chunks/v1'
        and value['object_bytes'] == selection.public_parameters_bytes
        and value['object_sha256'] == selection.public_parameters_sha256
        and type(value['chunk_bytes']) is int and value['chunk_bytes'] == 1_073_741_824,
        'chunk-index-external-whole-anchor')
    count = (selection.public_parameters_bytes + 1_073_741_823) // 1_073_741_824
    c.need(type(value['chunks']) is list and len(value['chunks']) == count, 'chunk-count')
    for i, row in enumerate(value['chunks']):
        c.exact(row, {'index', 'offset', 'bytes', 'sha256', 'basename'}, 'chunk-fields')
        for name in ('index', 'offset', 'bytes'):
            c.uint(row[name], 'chunk-integer')
        c.hx(row['sha256'], 32, 'chunk-SHA256')
        c.need(row['index'] == i and row['offset'] == i * 1_073_741_824
            and row['bytes'] == min(1_073_741_824, selection.public_parameters_bytes - row['offset'])
            and row['basename'] == f"chunk-{i:08d}-{row['sha256']}.bin", 'chunk-position')
    return value


def locations(sources, row, allowed_hosts):
    result = []
    for source in sources:
        c.exact(source, {'kind', 'base'}, 'public-source-fields')
        c.need(source['kind'] in ('release', 'cas'), 'public-source-kind')
        safe_url(source['base'], allowed_hosts)
        suffix = row['basename'] if source['kind'] == 'release' else 'objects/sha256/' + row['sha256']
        result.append(source['base'].rstrip('/') + '/' + suffix)
    return result


def retrieve(publication_path, expected_publication_sha, selection, sources, output,
             allowed_hosts, forbidden_paths=(), *, mode='recognition'):
    forbidden_paths = tuple(forbidden_paths)
    c._metadata_forbidden(forbidden_paths)
    c.need(type(selection) is c.TrustedSelection, 'external-trusted-selection-required')
    c.need(mode in ('recognition', 'spend_material'), 'public-material-mode')
    publication = selected_publication(publication_path, expected_publication_sha,
                                       selection, forbidden_paths)
    output = c._path(output)
    c.need(not output.exists() and not any(p.is_symlink() for p in output.parents),
           'fresh-retrieval-output')
    output.mkdir(mode=0o700)
    objects = output / 'cas' / 'objects' / 'sha256'
    objects.mkdir(parents=True, mode=0o700)
    fetched = []

    def get(row):
        destination = objects / row['sha256']
        if not destination.exists():
            receipt = fetch_object(locations(sources, row, allowed_hosts), row['bytes'],
                row['sha256'], destination, allowed_hosts, forbidden_paths)
            fetched.append({'kind': row['kind'], 'integrity': receipt})
        return destination

    for kind in sorted(c.SMALL_KINDS | {'capsule_index'}):
        get(next(row for row in publication['assets'] if row['kind'] == kind))
    capsule_path = objects / publication['capsule_sha256']
    preflight = c.stage_capsule(capsule_path, publication['capsule_sha256'], selection,
        [output / 'cas'], output / 'recognition', forbidden_paths, mode='recognition')
    staged = preflight
    if mode == 'spend_material':
        index_row = next(row for row in publication['assets'] if row['kind'] == 'chunk_index')
        index_path = get(index_row)
        index = chunk_index(c.read_public(index_path, forbidden_paths, maximum=1_048_576), selection)
        directory = output / 'chunks'
        directory.mkdir(mode=0o700)
        for row in index['chunks']:
            asset = next((a for a in publication['assets'] if a['basename'] == row['basename']), None)
            c.need(asset is not None and asset['kind'] == 'public_parameter_chunk'
                and asset['bytes'] == row['bytes'] and asset['sha256'] == row['sha256'],
                'selected-chunk-asset-binding')
            source = get(asset)
            os.link(source, directory / row['basename'], follow_symlinks=False)
        tool, _ = checked_source('chunk_public.py')
        checked_source('capsule.py')
        command = [sys.executable, '-B', str(tool), 'restore', '--manifest', str(index_path),
            '--expected-bytes', str(selection.public_parameters_bytes), '--expected-sha256',
            selection.public_parameters_sha256, '--mirror', str(directory), '--output',
            str(objects / selection.public_parameters_sha256)]
        for path in forbidden_paths:
            command.extend(['--forbidden', str(path)])
        child = subprocess.run(command, capture_output=True, text=True,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'})
        c.need(child.returncode == 0, 'selected-whole-reassembly-incomplete')
        staged = c.stage_capsule(capsule_path, publication['capsule_sha256'], selection,
            [output / 'cas'], output / 'spend-material', forbidden_paths, mode='spend_material')
    receipt = {'schema': 'kpx4-public-release-CAS-restoration/v1', 'mode': mode,
        'publication_sha256': expected_publication_sha, 'capsule_sha256': publication['capsule_sha256'],
        'objects': fetched, 'capsule': staged.public_receipt(),
        'downloaded_software_executed': False, 'current_state_verified': False,
        'spend_authorized': False, 'independent_provider_or_retention_verified': False}
    (output / 'PUBLIC-RESULT.json').write_bytes(c.encoded(receipt) + b'\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publication', type=Path, required=True)
    parser.add_argument('--expected-publication-sha256', required=True)
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--expected-selection-sha256', required=True)
    parser.add_argument('--source-kind', choices=('release', 'cas'), required=True)
    parser.add_argument('--source', action='append', required=True)
    parser.add_argument('--allowed-host', action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mode', choices=('recognition', 'spend_material'), default='recognition')
    parser.add_argument('--forbidden', action='append', default=[], type=Path)
    args = parser.parse_args()
    try:
        raw = c.read_public(args.selection, args.forbidden, maximum=65536)
        c.need(c.sha(raw) == args.expected_selection_sha256, 'external-selection-root-mismatch')
        selection = c.TrustedSelection.from_dict(c.parse(raw))
        result = retrieve(args.publication, args.expected_publication_sha256, selection,
            [{'kind': args.source_kind, 'base': url} for url in args.source], args.output,
            args.allowed_host, args.forbidden, mode=args.mode)
        print(json.dumps(result, sort_keys=True))
    except (c.Invalid, OSError):
        print(json.dumps({'status': 'PUBLIC_RECOVERY_MATERIAL_INCOMPLETE',
            'current_state_verified': False, 'spend_authorized': False}))
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
