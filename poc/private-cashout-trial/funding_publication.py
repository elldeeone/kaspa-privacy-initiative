#!/usr/bin/env python3
"""Omit the ordinary trial-directory field from an immutable public funding packet."""
import argparse
import json
from pathlib import Path

import funding_packet as funding

SOURCE = funding.ROOT / 'research/next-session/private-service-loss/live/funding-03'
SOURCE_MANIFEST = 'f09b8b0046b9c8351439f54b432c5fbcf57ce13c2b5a6aa480f8e43bd5bef2c5'


def export(output):
    raw = (SOURCE / 'MANIFEST.json').read_bytes()
    funding.need(funding.sha(raw) == SOURCE_MANIFEST, 'sealed-funding-source-manifest')
    manifest = json.loads(raw)
    funding.need(not output.exists() and not any(path.is_symlink() for path in (output, *output.parents)),
                 'fresh-path-free-publication')
    payloads = {}
    for row in manifest['files']:
        relative = Path(row['path'])
        funding.need(not relative.is_absolute() and '..' not in relative.parts, 'sealed-relative-path')
        source = SOURCE / relative
        funding.need(not source.is_symlink() and source.is_file(), 'sealed-regular-file')
        blob = source.read_bytes()
        funding.need(len(blob) == row['bytes'] and funding.sha(blob) == row['sha256'], 'sealed-source-payload')
        if row['path'] == 'originals/release.json':
            value = json.loads(blob)
            funding.need(funding.sha(blob) == funding.RELEASE_SHA
                         and value.pop('trial_directory') == str(funding.SOURCE), 'single-ordinary-path-projection')
            blob = funding.encoded({'schema': 'kpx3-public-ordinary-funding-release-selection/v1',
                'original_release_sha256': funding.RELEASE_SHA, 'selection': value,
                'omitted_field_names': ['trial_directory']})
            payloads['originals/release-selection.json'] = blob
        else:
            payloads[row['path']] = blob
    payloads['PUBLICATION-ADDENDUM.json'] = funding.encoded({
        'schema': 'kpx3-public-funding-projection/v1', 'source_sealed_manifest_sha256': SOURCE_MANIFEST,
        'original_sealed_packet_preserved_unchanged': True, 'funding_facts_or_evidence_recomputed': False,
        'sole_projection': 'Original release trial_directory omitted; all other source payloads byte-identical',
        'source_release_sha256': funding.RELEASE_SHA, 'raw_global_pages_or_owner_private_data_added': False})
    output.mkdir(parents=True)
    files = []
    for name, blob in sorted(payloads.items()):
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as file:
            file.write(blob)
        files.append({'path': name, 'bytes': len(blob), 'sha256': funding.sha(blob)})
    with (output / 'MANIFEST.json').open('xb') as file:
        file.write(funding.encoded({'schema': 'kpx3-path-free-funding-publication/v1', 'files': files,
            'projection_source_sha256': funding.sha(Path(__file__).read_bytes()),
            'source_sealed_manifest_sha256': SOURCE_MANIFEST}))
    return {'manifest_sha256': funding.sha((output / 'MANIFEST.json').read_bytes()), 'payloads': len(files)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('new_output', type=Path)
    print(json.dumps(export(parser.parse_args().new_output), sort_keys=True))
