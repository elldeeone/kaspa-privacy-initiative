"""Retrieve only current-profile bytes against a root-selected publication pin.

No old capsule financial schema, history interpretation or downloaded execution.
The current wallet must select/replay actual W state through its separate API.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from prepare import DOMAIN, MANIFEST, PK, PK_BYTES, PROVER, VK, TOOLS, encoded, public_bytes, need


def run(command):
    child = subprocess.run(command, capture_output=True, text=True,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'})
    need(child.returncode == 0, 'selected-byte-tool-incomplete')
    return json.loads(child.stdout)


def restore(publication, expected_publication_sha256, base, output, transport, hosts):
    raw = public_bytes(publication, expected_publication_sha256)
    value = json.loads(raw)
    need(encoded(value) == raw, 'canonical-publication')
    need(value['schema'] == 'kpi-current-profile-public-byte-distribution/v1'
        and value['classification'] == 'UNFUNDED_CURRENT_CAP_PROFILE_DO_NOT_FUND'
        and value['program_label'] == 'AUTH528_PRIVATE_CAPACITY_EXIT/v1'
        and value['domain_hex32'] == DOMAIN and value['role'] == 'compact2'
        and value['role_manifest_sha256'] == MANIFEST and value['vk_sha256'] == VK
        and value['whole_PK'] == {'bytes': PK_BYTES, 'sha256': PK}
        and value['selected_prover_sha256'] == PROVER,
        'external-current-profile-pins')
    need(value['old_D35_capsule_or_software_authority_reused'] is False
        and value['financial_replay_or_selection_authority'] is False
        and value['current_state_verified'] is False and value['spend_authorized'] is False,
        'byte-only-financial-boundary')
    rows = value['assets']
    need(type(rows) is list and 1 <= len(rows) < 1000, 'asset-count')
    names = set()
    for row in rows:
        need(type(row) is dict and set(row) == {'kind', 'basename', 'bytes', 'sha256'}, 'asset-fields')
        need(type(row['basename']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,199}',
            row['basename']) and row['basename'] not in names, 'safe-unique-basename')
        need(type(row['kind']) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,80}', row['kind']), 'asset-kind')
        need(type(row['bytes']) is int and 0 < row['bytes'] < 1 << 64, 'asset-length')
        need(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'asset-digest')
        names.add(row['basename'])
    for kind in ('current_role_manifest', 'current_chunk_index', 'selected_current_prover',
                 'current_software_source_inventory'):
        need(sum(row['kind'] == kind for row in rows) == 1, 'required-current-object')
    need(any(row['kind'] == 'selected_current_prover' and row['sha256'] == PROVER for row in rows),
         'selected-current-prover-root')
    for name, pin in TOOLS.items():
        public_bytes(Path(transport) / name, pin)
    output = Path(output).absolute()
    need(not output.exists() and not any(p.is_symlink() for p in output.parents), 'fresh-output')
    output.mkdir(mode=0o700)
    assets = output / 'assets'
    assets.mkdir(mode=0o700)
    fetcher = Path(transport) / 'public_fetch.py'
    host_flags = [item for host in hosts for item in ('--allowed-host', host)]
    receipts = []

    def get(row):
        path = assets / row['basename']
        receipt = run([sys.executable, '-B', str(fetcher), '--url', base.rstrip('/') + '/' + row['basename'],
            '--expected-bytes', str(row['bytes']), '--expected-sha256', row['sha256'],
            '--output', str(path), *host_flags])
        receipts.append({'kind': row['kind'], 'basename': row['basename'], 'integrity': receipt})
        return path

    manifest_row = next(row for row in rows if row['kind'] == 'current_role_manifest')
    need(manifest_row['sha256'] == MANIFEST, 'manifest-asset-root')
    get(manifest_row)
    index_row = next(row for row in rows if row['kind'] == 'current_chunk_index')
    index_path = get(index_row)
    index_raw = public_bytes(index_path, index_row['sha256'])
    index = json.loads(index_raw)
    need(encoded(index) == index_raw and index['schema'] == 'kpx4-public-object-chunks/v1'
        and index['object_bytes'] == PK_BYTES and index['object_sha256'] == PK
        and type(index['chunk_bytes']) is int and index['chunk_bytes'] == 1_073_741_824,
        'chunk-index-whole-current-profile')
    need(type(index['chunks']) is list and len(index['chunks']) == 2, 'current-chunk-count')
    directory = output / 'chunks'
    directory.mkdir(mode=0o700)
    for i, chunk in enumerate(index['chunks']):
        need(set(chunk) == {'index', 'offset', 'bytes', 'sha256', 'basename'}
            and all(type(chunk[k]) is int for k in ('index', 'offset', 'bytes'))
            and chunk['index'] == i and chunk['offset'] == i * 1_073_741_824
            and chunk['bytes'] == min(1_073_741_824, PK_BYTES - chunk['offset'])
            and type(chunk['sha256']) is str and re.fullmatch('[0-9a-f]{64}', chunk['sha256'])
            and chunk['basename'] == f"chunk-{i:08d}-{chunk['sha256']}.bin", 'ordered-current-chunk')
        row = next((row for row in rows if row['basename'] == chunk['basename']), None)
        need(row is not None and row['kind'] == 'current_public_PK_chunk'
            and row['sha256'] == chunk['sha256'] and row['bytes'] == chunk['bytes'], 'current-chunk-asset')
        path = get(row)
        os.link(path, directory / row['basename'], follow_symlinks=False)
    restored = output / 'public-parameters.pk'
    assembly = run([sys.executable, '-B', str(Path(transport) / 'vendor/chunk_public.py'), 'restore',
        '--manifest', str(index_path), '--expected-bytes', str(PK_BYTES), '--expected-sha256', PK,
        '--mirror', str(directory), '--output', str(restored)])
    already = {row['basename'] for row in receipts}
    for row in rows:
        if row['basename'] not in already:
            get(row)
    result = {'schema': 'kpi-current-profile-HTTPS-byte-restoration/v1',
        'publication_sha256': expected_publication_sha256, 'domain_hex32': DOMAIN,
        'role_manifest_sha256': MANIFEST, 'whole_PK_bytes': PK_BYTES, 'whole_PK_sha256': PK,
        'selected_prover_sha256': PROVER, 'assembly': assembly, 'assets': receipts,
        'old_capsule_financial_authority_used': False, 'financial_material_complete': False,
        'current_state_verified': False, 'spend_authorized': False,
        'downloaded_selected_prover_or_source_executed': False,
        'independent_operator_or_retention_verified': False}
    (output / 'PUBLIC-RESULT.json').write_bytes(encoded(result) + b'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publication', required=True, type=Path)
    parser.add_argument('--expected-publication-sha256', required=True)
    parser.add_argument('--release-base', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--transport-directory', required=True, type=Path)
    parser.add_argument('--allowed-host', action='append', required=True)
    args = parser.parse_args()
    try:
        result = restore(args.publication, args.expected_publication_sha256,
            args.release_base, args.output, args.transport_directory, args.allowed_host)
        print(json.dumps(result, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError):
        print(json.dumps({'status': 'CURRENT_PROFILE_PUBLIC_BYTES_INCOMPLETE',
                          'financial_material_complete': False, 'current_state_verified': False}))
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
