#!/usr/bin/env python3
"""Strict PUBLIC USTAR/zstd byte restore; no extractall or payload execution."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

from software_bundle import (KINDS, Invalid, checked_path, digest, encoded,
                             forbidden_metadata, need, parse, read_public,
                             relative, verify)

SIDECARS = {'SOFTWARE-BUNDLE.json', 'EXTERNAL-SELECTION.json', 'DEPENDENCY-ACQUISITION.json'}


def unpack(archive, member_inventory, expected_archive_sha256, expected_archive_bytes,
           expected_member_inventory_sha256, expected_software_inventory_sha256,
           fresh_output, *, forbidden_inputs=()):
    """All digest/length authority must come from outside the downloaded bundle."""
    forbidden_inputs = tuple(forbidden_inputs)
    forbidden = forbidden_metadata(forbidden_inputs)
    for value in (expected_archive_sha256, expected_member_inventory_sha256,
                  expected_software_inventory_sha256):
        need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'external-archive-selection')
    need(type(expected_archive_bytes) is int and 0 < expected_archive_bytes < 1 << 64,
         'external-archive-length')
    # Both input identities are guarded BEFORE either public content-open.
    for source in (archive, member_inventory):
        info = checked_path(source).stat()
        need((info.st_dev, info.st_ino) not in forbidden, 'public-private-inode-alias')
    raw_members = read_public(member_inventory, forbidden)
    need(digest(raw_members) == expected_member_inventory_sha256, 'external-member-list-pin')
    members = parse(raw_members)
    need(type(members) is dict and set(members) == {'schema', 'typed_software_inventory_sha256',
         'contains_backup_PK_private_witness_history_or_controller_plan', 'members'}
         and members['schema'] == 'kpx4-software-archive-members/v1'
         and members['typed_software_inventory_sha256'] == expected_software_inventory_sha256
         and members['contains_backup_PK_private_witness_history_or_controller_plan'] is False
         and type(members['members']) is list and members['members'], 'archive-member-list-schema')
    expected = {}
    for row in members['members']:
        need(type(row) is dict and set(row) == {'kind', 'path', 'bytes', 'sha256'}, 'archive-member-fields')
        name = relative(row['path'])
        need(name not in expected, 'duplicate-archive-member-selection')
        need(type(row['kind']) is str and row['kind'] in KINDS and type(row['bytes']) is int and 0 <= row['bytes'] < 1 << 64
             and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
             'archive-member-selection-types')
        expected[name] = row
    need(SIDECARS <= expected.keys(), 'required-archive-metadata')
    # This exact USTAR format permits no extension headers or hidden trailing tar.
    tar_bytes = sum(512 + ((row['bytes'] + 511) // 512) * 512 for row in expected.values()) + 1024
    tar_bytes = ((tar_bytes + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
    compressed = read_public(archive, forbidden, expected_archive_bytes)
    need(digest(compressed) == expected_archive_sha256, 'external-archive-pin')
    fresh_output = checked_path(fresh_output)
    need(not fresh_output.exists(), 'fresh-unpack-output-required')
    fresh_output.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as decoded:
        source.write(compressed); source.seek(0)
        del compressed
        process = subprocess.Popen(['/usr/bin/zstd', '-q', '-d', '-c'], stdin=source,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            total = 0
            while True:
                chunk = process.stdout.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                need(total <= tar_bytes, 'noncanonical-or-overlong-tar')
                decoded.write(chunk)
            need(process.wait() == 0 and total == tar_bytes, 'incomplete-or-noncanonical-tar')
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate(); process.wait()
        decoded.seek(0)
        seen, end = set(), 0
        try:
            with tarfile.open(mode='r:', fileobj=decoded) as tar:
                for member in tar:
                    name = relative(member.name)
                    need(name in expected and name not in seen, 'unlisted-or-duplicate-tar-member')
                    row = expected[name]
                    need(member.type == tarfile.REGTYPE and member.sparse is None
                         and not member.pax_headers and member.offset_data - member.offset == 512
                         and member.linkname == '', 'tar-links-directories-or-extensions-forbidden')
                    mode = 0o500 if row['kind'] == 'selected-executable' else 0o400
                    need(member.size == row['bytes'] and member.mode == mode
                         and member.uid == member.gid == member.mtime == 0
                         and member.uname == member.gname == '', 'noncanonical-tar-member-metadata')
                    canonical = tarfile.TarInfo(name)
                    canonical.size, canonical.mode = row['bytes'], mode
                    canonical.uid = canonical.gid = canonical.mtime = 0
                    canonical.uname = canonical.gname = ''
                    position = decoded.tell()
                    decoded.seek(member.offset)
                    header = decoded.read(512)
                    decoded.seek(position)
                    need(header == canonical.tobuf(format=tarfile.USTAR_FORMAT,
                                                   encoding='utf-8', errors='strict'),
                         'noncanonical-ustar-header')
                    destination = fresh_output / name
                    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    hasher, size = hashlib.sha256(), 0
                    reader = tar.extractfile(member)
                    need(reader is not None, 'tar-file-reader')
                    with reader, destination.open('xb') as target:
                        while True:
                            chunk = reader.read(1 << 20)
                            if not chunk:
                                break
                            size += len(chunk); hasher.update(chunk); target.write(chunk)
                    need(size == row['bytes'] and hasher.hexdigest() == row['sha256'], 'tar-member-digest-or-length')
                    destination.chmod(mode)
                    seen.add(name)
                    end = member.offset_data + ((member.size + 511) // 512) * 512
            need(seen == expected.keys(), 'missing-selected-tar-member')
            decoded.seek(end)
            padding = decoded.read()
            need(len(padding) >= 1024 and not any(padding), 'trailing-tar-or-nonzero-padding')
        except (tarfile.TarError, OSError, EOFError):
            raise Invalid('invalid-public-tar') from None
    software_raw = read_public(fresh_output / 'SOFTWARE-BUNDLE.json', forbidden)
    receipt = verify(fresh_output, software_raw, expected_software_inventory_sha256,
                     forbidden_inputs=forbidden_inputs)
    software = parse(software_raw)
    need({row['path'] for row in software['files']} | SIDECARS == seen,
         'archive-must-match-typed-software-and-fixed-metadata')
    # Exact selected metadata must agree, rather than introducing new authority.
    for row in software['files']:
        need(row == expected[row['path']], 'typed-software-member-mismatch')
    return {'schema': 'kpx4-public-software-unpack/v1',
            'archive_sha256': expected_archive_sha256, 'archive_bytes': expected_archive_bytes,
            'member_inventory_sha256': expected_member_inventory_sha256,
            'typed_software_inventory_sha256': expected_software_inventory_sha256,
            'members_restored': len(seen), 'typed_files_verified': receipt['files_verified'],
            'only_regular_exact_selected_members': True, 'payload_executed_or_imported': False,
            'backup_contents_or_PK_read': False, 'currentness_verified': False, 'spend_authorized': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('member_inventory', type=Path)
    parser.add_argument('expected_archive_sha256')
    parser.add_argument('expected_archive_bytes', type=int)
    parser.add_argument('expected_member_inventory_sha256')
    parser.add_argument('expected_software_inventory_sha256')
    parser.add_argument('fresh_output', type=Path)
    parser.add_argument('--forbidden-input', type=Path, action='append', default=[])
    args = parser.parse_args()
    try:
        result = unpack(args.archive, args.member_inventory, args.expected_archive_sha256,
                        args.expected_archive_bytes, args.expected_member_inventory_sha256,
                        args.expected_software_inventory_sha256, args.fresh_output,
                        forbidden_inputs=args.forbidden_input)
        print(json.dumps(result, sort_keys=True))
    except (Invalid, OSError) as error:
        print(json.dumps({'error': str(error) if isinstance(error, Invalid) else 'public-file-unavailable'}))
        raise SystemExit(1)
