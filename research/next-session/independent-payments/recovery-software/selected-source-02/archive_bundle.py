#!/usr/bin/env python3
"""Deterministic PUBLIC software archive from an externally pinned finite list.

This packs bytes only and never extracts, imports or executes archive payloads.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

from software_bundle import encoded, need, read_public, verify


def archive(bundle, inventory_sha256, output):
    need(output.is_absolute() and not output.exists(), 'fresh-public-archive-output')
    output.mkdir(parents=True, mode=0o700)
    raw_inventory = read_public(bundle / 'SOFTWARE-BUNDLE.json')
    verify(bundle, raw_inventory, inventory_sha256)
    rows = json.loads(raw_inventory)['files']
    # Only these public metadata sidecars accompany the typed source/runtime list.
    for name in ('SOFTWARE-BUNDLE.json', 'EXTERNAL-SELECTION.json', 'DEPENDENCY-ACQUISITION.json'):
        raw = read_public(bundle / name)
        rows.append({'kind': 'public-metadata', 'path': name,
                     'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    rows.sort(key=lambda row: row['path'])
    need(len(set(row['path'] for row in rows)) == len(rows), 'duplicate-archive-member')
    destination = output / 'software-bundle.tar.zst'
    process = subprocess.Popen(['/usr/bin/zstd', '-q', '-T2', '-3', '--no-progress',
                                '-o', str(destination)], stdin=subprocess.PIPE,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        with tarfile.open(mode='w|', fileobj=process.stdin, format=tarfile.USTAR_FORMAT) as tar:
            for row in rows:
                raw = read_public(bundle / row['path'], expected_bytes=row['bytes'])
                need(hashlib.sha256(raw).hexdigest() == row['sha256'], 'archive-input-changed')
                info = tarfile.TarInfo(row['path'])
                info.size = len(raw)
                info.mode = 0o500 if row['kind'] == 'selected-executable' else 0o400
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ''
                tar.addfile(info, io.BytesIO(raw))
        process.stdin.close()
        stderr = process.stderr.read()
        code = process.wait()
        need(code == 0 and not stderr, 'archive-compression-failed')
    finally:
        if process.poll() is None:
            process.terminate(); process.wait()
    members = {'schema': 'kpx4-software-archive-members/v1',
               'typed_software_inventory_sha256': inventory_sha256,
               'contains_backup_PK_private_witness_history_or_controller_plan': False,
               'members': rows}
    raw = encoded(members)
    (output / 'ARCHIVE-MEMBERS.json').write_bytes(raw)
    archive_raw = read_public(destination)
    result = {'schema': 'kpx4-public-software-archive/v1',
              'software_inventory_sha256': inventory_sha256,
              'archive_sha256': hashlib.sha256(archive_raw).hexdigest(),
              'archive_bytes': len(archive_raw), 'archive_member_count': len(rows),
              'member_allowlist_sha256': hashlib.sha256(raw).hexdigest(),
              'payload_bytes': sum(row['bytes'] for row in rows),
              'automatic_executable_selection_or_execution': False,
              'trusted_compiler_and_OS_not_bundled': True,
              'independent_provider_or_longterm_retention_claimed': False}
    (output / 'ARCHIVE.json').write_bytes(encoded(result))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('externally_selected_inventory_sha256')
    parser.add_argument('fresh_public_output', type=Path)
    args = parser.parse_args()
    print(json.dumps(archive(args.bundle, args.externally_selected_inventory_sha256,
                             args.fresh_public_output), sort_keys=True))
