#!/usr/bin/env python3
"""Byte-preserving public archive parts; no owner, chain or download authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import stat

DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
PART_BYTES = 256 * 1024 * 1024
ASSET_LIMIT = 1 << 31
OUTPUT_PARENTS = (
    Path('/var/tmp/kpi-local-private-payment-01/publication-release'),
    Path('/dev/shm/kpi-local-private-payment-publication-01'),
)
LOCAL_ONLY = (
    Path('/var/tmp/kpi-owner-private-lifecycle-01/private'),
    Path('/var/tmp/kpi-local-original-metadata-01'),
    Path('/var/tmp/kpi-local-private-payment-01/publication-contexts'),
)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def uint(value, positive=False):
    need(type(value) is int and (1 if positive else 0) <= value < 1 << 64,
         'exact positive integer required' if positive else 'exact integer required')
    return value


def pin(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
         'canonical SHA256 required')


def part_size(value):
    uint(value, True)
    need(value < ASSET_LIMIT, 'every part must be strictly below 2GiB')
    return value


def canonical(value):
    need(type(value) is str and value.startswith('/') and not value.startswith('//')
         and str(PurePosixPath(value)) == value and '..' not in PurePosixPath(value).parts
         and '\\' not in value and '\0' not in value, 'canonical absolute path required')
    return Path(value)


def validate_manifest(value):
    need(type(value) is dict and set(value) == {'schema', 'domain_hex32', 'part_bytes', 'archive', 'parts'},
         'closed part manifest required')
    need(value['schema'] == 'kpxa-public-recovery-data-parts/v1' and value['domain_hex32'] == DOMAIN,
         'selected public archive domain required')
    width = part_size(value['part_bytes'])
    archive = value['archive']
    need(type(archive) is dict and set(archive) == {'name', 'bytes', 'sha256'}
         and archive['name'] == 'data.tar', 'logical canonical archive required')
    total = uint(archive['bytes'], True)
    pin(archive['sha256'])
    parts = value['parts']
    count = (total + width - 1) // width
    need(type(parts) is list and len(parts) == count, 'exact nonempty part count required')
    offset = 0
    for index, row in enumerate(parts):
        need(type(row) is dict and set(row) == {'name', 'bytes', 'sha256'}, 'closed part row required')
        need(row['name'] == 'data.tar.part-%05d' % index, 'ordered canonical part name required')
        size = uint(row['bytes'], True)
        need(size == min(width, total - offset) and size < ASSET_LIMIT, 'exact part extent required')
        pin(row['sha256'])
        offset += size
    need(offset == total, 'complete archive extent required')
    return value


def manifest_for_bytes(raw, width=PART_BYTES):
    """Pure known-public-byte API. A manifest does not authenticate its own source."""
    need(type(raw) is bytes and raw, 'nonempty immutable public bytes required')
    width = part_size(width)
    view = memoryview(raw)
    parts = []
    for index, offset in enumerate(range(0, len(raw), width)):
        piece = view[offset:offset + width]
        parts.append({'name': 'data.tar.part-%05d' % index, 'bytes': len(piece), 'sha256': sha(piece)})
    return validate_manifest({'schema': 'kpxa-public-recovery-data-parts/v1', 'domain_hex32': DOMAIN,
                              'part_bytes': width,
                              'archive': {'name': 'data.tar', 'bytes': len(raw), 'sha256': sha(raw)},
                              'parts': parts})


def fresh_output(value):
    output = canonical(str(value))
    need(output.parent in OUTPUT_PARENTS and not output.exists(), 'fresh exact public output parent required')
    for path in (output, *output.parents):
        need(not path.is_symlink(), 'public output symlink refused')
    info = output.parent.lstat()
    need(stat.S_ISDIR(info.st_mode), 'existing exact public output parent required')
    if output.parent == OUTPUT_PARENTS[1]:
        need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
             'owned0700 public tmpfs parent required')
    return output


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        view = memoryview(raw)
        while view:
            count = stream.write(view)
            need(count is not None and count > 0, 'incomplete public part write')
            view = view[count:]
        stream.flush()
        os.fsync(stream.fileno())


def split_archive(archive, expected, expected_bytes, output, width=PART_BYTES):
    source = canonical(str(archive))
    need(source.name == 'data.tar' and not any(source == p or p in source.parents for p in LOCAL_ONLY),
         'explicit public canonical archive source required')
    pin(expected)
    uint(expected_bytes, True)
    part_size(width)
    destination = fresh_output(output)
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    # Unchanged guard09 performs origin/alias/stability checks before any part is
    # emitted. The one admitted immutable bytes object is the sole data source.
    raw = read(str(source), expected)
    need(len(raw) == expected_bytes and sha(raw) == expected, 'selected whole archive identity differs')
    manifest = manifest_for_bytes(raw, width)
    destination.mkdir(mode=0o700)
    view = memoryview(raw)
    offset = 0
    for row in manifest['parts']:
        piece = view[offset:offset + row['bytes']]
        write_new(destination / row['name'], piece)
        offset += row['bytes']
    need(offset == len(raw), 'incomplete archive split')
    body = encoded(manifest)
    write_new(destination / 'DATA-PARTS.json', body)
    return {'schema': 'kpxa-public-data-archive-split-result/v1',
            'manifest': {'path': str(destination / 'DATA-PARTS.json'), 'bytes': len(body), 'sha256': sha(body)},
            'archive': manifest['archive'], 'part_count': len(manifest['parts']), 'part_bytes': width,
            'new_codec_or_archive_bytes': False, 'source_archive_retained': True,
            'additional_part_file_bytes': len(raw), 'admitted_archive_memory_bytes': len(raw),
            'owner_private_network_or_publication_action': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--archive-bytes', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--part-bytes', type=int, default=PART_BYTES)
    args = parser.parse_args()
    try:
        print(encoded(split_archive(args.archive, args.archive_sha256, args.archive_bytes,
                                    args.output, args.part_bytes)).decode(), end='')
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit('Public archive split refused; no private or network action performed')
