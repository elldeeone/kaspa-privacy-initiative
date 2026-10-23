#!/usr/bin/env python3
"""Verify this finite public packet, including superseded execution sources.

This checks recorded byte identities. It does not authenticate a financial
instance, execute proofs, establish chain currentness or prove correctness.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[3]
PHASE = 'research/next-session/compact-batch/'


def need(value, reason):
    if not value:
        raise ValueError(reason)


def read(name):
    relative = PurePosixPath(name)
    need(not relative.is_absolute() and '..' not in relative.parts
         and str(relative) == name, 'noncanonical-public-path')
    path = ROOT / name
    need(path.is_file() and path.resolve() == path, 'missing-or-symlink-public-file')
    return path.read_bytes()


def identity(raw):
    return len(raw), hashlib.sha256(raw).hexdigest()


def main():
    manifest_name, list_name = PHASE + 'ROOT-MANIFEST.json', PHASE + 'ROOT-FILES.txt'
    manifest = json.loads(read(manifest_name))
    need(manifest['schema'] == 'kpx4-matched-batch-publication/v1', 'root-schema')
    raw_list = read(list_name)
    need(hashlib.sha256(raw_list).hexdigest() == manifest['file_list_sha256'], 'root-list-sha256')
    names = raw_list.decode().splitlines()
    need(names == sorted(set(names)), 'root-list-order-or-duplicate')
    available = set(names)
    entries = manifest['files']
    need(len(entries) == len({e['path'] for e in entries}), 'root-entry-duplicate')
    need(set(names) == {manifest_name, list_name} | {e['path'] for e in entries}, 'root-list-coverage')
    for entry in entries:
        need(identity(read(entry['path'])) == (entry['bytes'], entry['sha256']),
             'current-payload-mismatch:' + entry['path'])

    need(manifest['source_supersession_path'] in available, 'unlisted-supersession')
    supersession = json.loads(read(manifest['source_supersession_path']))
    versions = {e['current_path']: e for e in supersession['files']}
    need(len(supersession['files']) == len(versions) == 4 and set(versions) == {
        'poc/recovery-portability/' + name for name in
        ('capsule.py', 'https_mirror.py', 'pack_local.py', 'chunk_public.py')},
        'unexpected-source-supersession')
    for name, version in versions.items():
        need(name in available and version['exact_historical_archive_path'] in available,
             'unlisted-source-version')
        need(identity(read(name))[1] == version['current_sha256'], 'current-version-mismatch')
        need(identity(read(version['exact_historical_archive_path']))[1]
             == version['historical_sha256'], 'historical-preimage-mismatch')
    historical = set()
    for name in manifest['historical_packet_manifests']:
        need(name in available, 'unlisted-historical-manifest')
        for entry in json.loads(read(name))['files']:
            need(entry['path'] in available, 'unlisted-historical-payload')
            if identity(read(entry['path'])) == (entry['bytes'], entry['sha256']):
                continue
            version = versions.get(entry['path'])
            need(version is not None and entry['sha256'] == version['historical_sha256'],
                 'unexplained-historical-source-change:' + entry['path'])
            need(identity(read(version['exact_historical_archive_path']))
                 == (entry['bytes'], entry['sha256']), 'historical-source-size-or-sha256')
            historical.add(entry['path'])
    print(json.dumps({'status': 'PUBLIC_PACKET_BYTES_VERIFIED', 'files': len(names),
                      'historically_superseded_current_source_paths': len(historical),
                      'proof_chain_privacy_or_provider_validation': False}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError) as error:
        raise SystemExit('PUBLIC_PACKET_INCOMPLETE: ' + str(error)) from None
