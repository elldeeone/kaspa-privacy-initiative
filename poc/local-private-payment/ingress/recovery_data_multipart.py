#!/usr/bin/env python3
"""Resource-only multipart acquisition of the unchanged public-data archive.

Uses the pinned existing TorTLS transport and complete container/page verifier.
Downloaded data is never executed. Ephemeral parts are authenticated then
appended to one retained archive; decoded gzip chunks are hashed and discarded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import types

GUARD = '/var/tmp/kpi-root-guard-helper-09.py'
BASE_SHA = 'aa4c01b423a656e2005d18e316521383daad5efd4cfdb8d82804d6a0348cfac7'
DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
OUTPUT_BASE = Path('/var/tmp/kpi-local-private-payment-01/recovery-data-multipart-downloads')
TMPFS_OUTPUT_BASE = Path('/dev/shm/kpi-local-private-payment-recovery-data-01')
METADATA = ('DATA-INVENTORY.json', 'PACKET.json', 'SHA256SUMS')
MAX_ASSET_BYTES_EXCLUSIVE = 1 << 31
ROOT_SCHEMA = 'kpxa-root-multipart-public-recovery-data-download-selection/v1'
RECEIPT_SCHEMA = 'kpxa-downloaded-multipart-public-recovery-data-receipt/v1'
CLASSIFICATION = 'ACTUAL_TOR_TLS_MULTIPART_PUBLIC_DATA_DOWNLOAD_INVENTORY_AND_DECODED_PAGES_VERIFIED'
_base = None


def need(condition, label='multipart-public-data-acquisition-refused'):
    if not condition:
        raise ValueError(label)


def get_base():
    global _base
    if _base is None:
        if Path(__file__).absolute() == Path('/multipart-downloader.py'):
            need(not Path('/home').exists() and not Path('/var').exists(), 'finite-empty-filesystem-required')
            path = Path('/data-verifier.py')
            raw = path.read_bytes()  # Only the separately pinned staged public source.
        else:
            path = Path(__file__).absolute().with_name('recovery_data_download.py')
            raw = runpy.run_path(GUARD)['read'](str(path), BASE_SHA)
        need(hashlib.sha256(raw).hexdigest() == BASE_SHA, 'frozen-base-source-identity')
        module = types.ModuleType('pinned_public_data_verifier')
        module.__file__ = str(path)
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        _base = module
    return _base


def origin(row, remote_name):
    value = row['origin_url']
    prefix = 'https://github.com/elldeeone/kaspa-privacy-initiative/releases/download/'
    need(type(value) is str and value.isascii() and value.startswith(prefix), 'selected-repository-release-only')
    suffix = value[len(prefix):].split('/')
    need(len(suffix) == 2 and re.fullmatch('[A-Za-z0-9_.-]+', suffix[0])
         and suffix[0] not in {'.', '..'} and suffix[1] == remote_name, 'exact-release-asset-origin')
    return value.rsplit('/', 1)[0]


def artifact_row(row):
    b = get_base()
    need(type(row) is dict and set(row) == {'name', 'origin_url', 'bytes', 'sha256'}
         and type(row['name']) is str and b.pin(row['sha256'])
         and 0 < b.uint(row['bytes']) < MAX_ASSET_BYTES_EXCLUSIVE, 'strict-under-2GiB-artifact-pin')


def selection(raw):
    b = get_base()
    value = b.parse(raw)
    need(type(value) is dict and set(value) == {'schema', 'domain_hex32', 'part_bytes', 'archive', 'parts', 'artifacts'}
         and value['schema'] == ROOT_SCHEMA and value['domain_hex32'] == DOMAIN, 'exact-multipart-root-selection')
    part_bytes = b.uint(value['part_bytes'])
    need(0 < part_bytes < MAX_ASSET_BYTES_EXCLUSIVE, 'strict-under-2GiB-part-size')
    archive = value['archive']
    need(type(archive) is dict and set(archive) == {'name', 'bytes', 'sha256'}
         and archive['name'] == 'data.tar' and b.uint(archive['bytes']) > 0
         and b.pin(archive['sha256']), 'exact-logical-archive-pin')
    parts = value['parts']
    expected_count = (archive['bytes'] + part_bytes - 1) // part_bytes
    need(type(parts) is list and len(parts) == expected_count and parts, 'exact-deterministic-part-count')
    prefixes, total = set(), 0
    for index, row in enumerate(parts):
        artifact_row(row)
        expected_name = 'data.tar.part-%05d' % index
        expected_size = min(part_bytes, archive['bytes'] - index * part_bytes)
        need(row['name'] == expected_name and row['bytes'] == expected_size, 'exact-ordered-part-name-and-size')
        prefixes.add(origin(row, expected_name))
        total += row['bytes']
    need(total == archive['bytes'], 'parts-equal-whole-archive-length')
    metadata = value['artifacts']
    need(type(metadata) is list and len(metadata) == len(METADATA), 'exact-three-metadata-artifacts')
    names = set()
    for row in metadata:
        artifact_row(row)
        need(row['name'] in METADATA and row['name'] not in names, 'distinct-metadata-artifacts')
        names.add(row['name'])
        remote_name = 'DATA-SHA256SUMS' if row['name'] == 'SHA256SUMS' else row['name']
        prefixes.add(origin(row, remote_name))
    need(names == set(METADATA) and len(prefixes) == 1, 'single-root-selected-public-release')
    return value


def validate_output(output, *, create_parent=False):
    b = get_base()
    output = b.absolute(str(output))
    need(output.parent in {OUTPUT_BASE, TMPFS_OUTPUT_BASE}
         and re.fullmatch('acquisition-[0-9]{2}', output.name)
         and not output.exists() and not output.is_symlink(), 'fresh-approved-output-identity')
    need(not any(path.is_symlink() for path in (output, *output.parents)), 'output-symlink-forbidden')
    if create_parent:
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = output.parent.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
         and stat.S_IMODE(info.st_mode) == 0o700, 'output-parent-must-be-owned-mode0700-directory')
    need(not any(path.is_symlink() for path in (output, *output.parents)), 'output-symlink-forbidden')
    return output


def capacity_preflight(parent, plan):
    # The uncompressed canonical tar bounds its extracted payload bytes. Reserve
    # A + U conservatively as 2*A, plus one part, metadata and small receipt/source
    # overhead. This is a logical byte estimate, not a universal physical-space
    # bound: filesystem block rounding/directories can require more. Root must
    # keep measured headroom. It does not change the financial-trial rules.
    required = (2 * plan['archive']['bytes'] + min(plan['part_bytes'], plan['archive']['bytes'])
                + sum(row['bytes'] for row in plan['artifacts']) + (1 << 20))
    space = os.statvfs(parent)
    available = space.f_bavail * space.f_frsize
    need(available >= required, 'insufficient-selected-filesystem-capacity')
    return {'available_bytes': available, 'required_bytes': required}


def assemble_parts(archive, plan, origins, proxy_port):
    """At most one ephemeral part beside the single assembled archive."""
    b = get_base()
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    total, digest = 0, hashlib.sha256()
    temporary = archive.parent / 'part-in-progress.tmp'
    with os.fdopen(fd, 'wb') as destination:
        for row in plan['parts']:
            b.download(row['origin_url'], temporary, row['bytes'], row['sha256'], origins, proxy_port)
            # download() authenticated this regular, singly linked ephemeral
            # file. Stream its exact bytes; never retain a second N-part set.
            count = 0
            with temporary.open('rb') as source:
                while chunk := source.read(1 << 20):
                    count += len(chunk)
                    total += len(chunk)
                    need(count <= row['bytes'] and total <= plan['archive']['bytes'], 'part-or-archive-overrun')
                    destination.write(chunk)
                    digest.update(chunk)
            need(count == row['bytes'], 'whole-authenticated-part-length')
            temporary.unlink()
            print(json.dumps({'stage': 'authenticated-part-appended', 'part': row['name'],
                              'bytes': row['bytes']}), flush=True)
        need(total == plan['archive']['bytes'] and digest.hexdigest() == plan['archive']['sha256'],
             'whole-concatenated-archive-identity')
        destination.flush()
        os.fsync(destination.fileno())
    os.chmod(archive, 0o400, follow_symlinks=False)


def acquire(output, host_root, plan, proxy_port):
    b = get_base()
    need(list(output.iterdir()) == [], 'fresh-empty-multipart-acquisition-root')
    capacity_preflight(output, plan)
    downloads = output / 'downloads'
    downloads.mkdir(mode=0o700)
    metadata = {row['name']: row for row in plan['artifacts']}
    origins = {row['origin_url'] for row in [*plan['artifacts'], *plan['parts']]}
    for name in METADATA:
        row = metadata[name]
        b.download(row['origin_url'], downloads / name, row['bytes'], row['sha256'], origins, proxy_port)
        print(json.dumps({'stage': 'authenticated-metadata-acquisition', 'artifact': name,
                          'bytes': row['bytes']}), flush=True)
    artifacts = {**metadata, 'data.tar': plan['archive']}
    # Small authenticated metadata is checked before transferring the archive.
    rows = b.inventory_rows((downloads / 'DATA-INVENTORY.json').read_bytes())
    b.packet_metadata((downloads / 'PACKET.json').read_bytes(), artifacts, rows)
    assemble_parts(downloads / 'data.tar', plan, origins, proxy_port)
    # The frozen verifier rechecks the assembled whole file before any raw tar
    # header walk and preserves all roles, page arrays and gzip decoded checks.
    members, decoded = b.verify_downloads(downloads, output / 'data', artifacts)
    def retained(name):
        return {'path': str(host_root / 'downloads' / name), 'bytes': metadata[name]['bytes'],
                'sha256': metadata[name]['sha256']}
    receipt = {'schema': RECEIPT_SCHEMA, 'classification': CLASSIFICATION, 'transport': 'TOR_SOCKS5H_TLS',
        'archive': {'path': str(host_root / 'downloads/data.tar'), 'bytes': plan['archive']['bytes'],
                    'sha256': plan['archive']['sha256'], 'part_bytes': plan['part_bytes'],
                    'parts': [row['name'] for row in plan['parts']]},
        'inventory': retained('DATA-INVENTORY.json'), 'packet': retained('PACKET.json'),
        'artifacts': [dict(name=name, origin_url=metadata[name]['origin_url'], retained=True, **retained(name))
                      for name in METADATA]
                     + [dict(row, retained=False) for row in plan['parts']],
        'files': [{'member': name, 'path': str(host_root / 'data' / name), 'bytes': row['bytes'],
                   'sha256': row['sha256']} for name, row in sorted(members.items())],
        'pages': [{'packet_path': row['packet_path'],
                   'compressed': {'path': str(host_root / 'data' / row['packet_path']),
                                  'bytes': row['gzip_bytes'], 'sha256': row['gzip_sha256']},
                   'decoded': {'bytes': row['decoded_bytes'], 'sha256': row['decoded_sha256'], 'retained': False}}
                  for row in decoded]}
    raw = b.encoded(receipt)
    b.save_new(output / 'MULTIPART-DATA-DOWNLOAD-RECEIPT.json', raw)
    print(json.dumps({'receipt': str(host_root / 'MULTIPART-DATA-DOWNLOAD-RECEIPT.json'),
                      'sha256': b.sha(raw), 'files': len(members), 'pages': len(decoded),
                      'network_artifacts': len(plan['parts']) + len(METADATA)}), flush=True)


def sandbox_command(source, base_source, selected, output, host_root, proxy_port):
    return ['/usr/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-uts',
        '--new-session', '--die-with-parent', '--ro-bind', '/usr', '/usr',
        '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
        '--dir', '/etc', '--dir', '/etc/ssl', '--ro-bind', '/etc/ssl/certs', '/etc/ssl/certs',
        '--ro-bind', '/etc/ld.so.cache', '/etc/ld.so.cache', '--proc', '/proc', '--dev', '/dev',
        '--tmpfs', '/tmp', '--dir', '/acquisition', '--bind', str(output), '/acquisition',
        '--ro-bind', str(source), '/multipart-downloader.py',
        '--ro-bind', str(base_source), '/data-verifier.py',
        '--ro-bind', str(selected), '/release-selection.json', '--chdir', '/',
        '/usr/bin/python3', '-B', '/multipart-downloader.py', '--child', '--output', '/acquisition',
        '--release-selection', '/release-selection.json', '--host-root', str(host_root),
        '--proxy-port', str(proxy_port)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--source-sha256')
    parser.add_argument('--release-selection')
    parser.add_argument('--release-selection-sha256')
    parser.add_argument('--output')
    parser.add_argument('--host-root', help=argparse.SUPPRESS)
    parser.add_argument('--proxy-port', type=int, default=19050)
    args = parser.parse_args()
    try:
        b = get_base()
        if args.child:
            need(args.output == '/acquisition' and args.release_selection == '/release-selection.json'
                 and args.host_root is not None and Path(__file__).absolute() == Path('/multipart-downloader.py')
                 and not Path('/home').exists() and not Path('/var').exists(), 'finite-empty-filesystem-child')
            plan = selection(Path(args.release_selection).read_bytes())
            acquire(Path(args.output), b.absolute(args.host_root), plan, args.proxy_port)
        elif args.execute:
            need(b.pin(args.source_sha256) and b.pin(args.release_selection_sha256), 'external-source-and-selection-pins')
            output = b.absolute(args.output)
            need(output.parent in {OUTPUT_BASE, TMPFS_OUTPUT_BASE} and re.fullmatch('acquisition-[0-9]{2}', output.name)
                 and not output.exists() and not any(p.is_symlink() for p in (output, *output.parents)),
                 'fresh-public-multipart-acquisition-location')
            read = runpy.run_path(GUARD)['read']
            raw_source = read(str(Path(__file__).absolute()), args.source_sha256)
            raw_base = read(str(Path(__file__).absolute().with_name('recovery_data_download.py')), BASE_SHA)
            raw_selection = read(str(b.absolute(args.release_selection)), args.release_selection_sha256)
            plan = selection(raw_selection)
            validate_output(output, create_parent=True)
            capacity = capacity_preflight(output.parent, plan)
            print(json.dumps(dict(stage='selected-filesystem-capacity-preflight', **capacity)), flush=True)
            source_stage = output.parent / (output.name + '-source.py')
            base_stage = output.parent / (output.name + '-base.py')
            selection_stage = output.parent / (output.name + '-selection.json')
            b.save_new(source_stage, raw_source)
            b.save_new(base_stage, raw_base)
            b.save_new(selection_stage, raw_selection)
            output.mkdir(mode=0o700)
            command = sandbox_command(source_stage, base_stage, selection_stage, output, output, args.proxy_port)
            raise SystemExit(subprocess.run(command, env={'PATH': '/usr/bin:/bin'}).returncode)
        else:
            print(json.dumps({'status': 'PREPARED_NOT_DOWNLOADED', 'receipt_schema': RECEIPT_SCHEMA,
                              'base_source_sha256': BASE_SHA, 'financial_or_portable_replay_verified': False}))
    except Exception:
        parser.exit(2, 'Multipart public data download refused or incomplete; no acquisition receipt issued.\n')


if __name__ == '__main__':
    main()
