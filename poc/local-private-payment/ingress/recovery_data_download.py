#!/usr/bin/env python3
"""Fresh TorTLS acquisition and byte verification of a public recovery-data packet.

This is a container/page decoder, not a financial, native-VM, chain-currentness
or portable-replay verifier. It never executes downloaded objects or follows
producer host selectors. The frozen software/ExitPK downloader is unchanged.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import secrets
import stat
import subprocess
import tarfile
from urllib.parse import urljoin, urlsplit
import zlib

GUARD = '/var/tmp/kpi-root-guard-helper-09.py'
DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
OUTPUT_BASE = Path('/var/tmp/kpi-local-private-payment-01/recovery-data-downloads')
ASSETS = ('data.tar', 'DATA-INVENTORY.json', 'PACKET.json', 'SHA256SUMS')
REMOTE_NAMES = {name: name for name in ASSETS}
REMOTE_NAMES['SHA256SUMS'] = 'DATA-SHA256SUMS'  # Preserve the existing software release asset.
KINDS = {'public-metadata', 'public-source', 'public-evidence', 'full-source-page'}
ROLES = {'terminalhandoff', 'activation', 'history', 'context', 'currententry',
         'replayresults', 'fetch', 'selection', 'descriptor', 'assets', 'parameters', 'accounting'}
RECEIPT_SCHEMA = 'kpxa-downloaded-public-recovery-data-receipt/v1'
CLASSIFICATION = 'ACTUAL_TOR_TLS_PUBLIC_DATA_DOWNLOAD_INVENTORY_AND_DECODED_PAGES_VERIFIED'
REDIRECT_CODES = {301, 302, 303, 307, 308}


def need(value, label='public-data-acquisition-refused'):
    if not value:
        raise ValueError(label)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-JSON-field')
            result[key] = value
        return result
    def finite(value):
        result = float(value)
        need(math.isfinite(result), 'nonfinite-JSON-number')
        return result
    def invalid(_):
        raise ValueError('nonfinite-JSON-number')
    return json.loads(raw, object_pairs_hook=pairs, parse_float=finite, parse_constant=invalid)


def pin(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def uint(value):
    need(type(value) is int and 0 <= value < 1 << 64, 'uint64-required')
    return value


def relative(value):
    need(type(value) is str and value and re.fullmatch('[A-Za-z0-9_./-]+', value),
         'canonical-relative-path-required')
    name = PurePosixPath(value)
    need(not name.is_absolute() and str(name) == value and name.parts
         and all(part not in ('.', '..') and not part.startswith('.') for part in name.parts),
         'unsafe-relative-path')
    return value


def member_paths(names):
    need(len(names) == len(set(names)), 'duplicate-member-path')
    selected = set(names)
    for name in names:
        relative(name)
        need(all(str(parent) not in selected for parent in PurePosixPath(name).parents
                 if str(parent) != '.'), 'regular-member-ancestor-collision')


def absolute(value):
    need(type(value) is str and '\0' not in value and '\\' not in value)
    path = Path(value)
    need(path.is_absolute() and '..' not in path.parts and str(path) == value)
    return path


def selection(raw):
    value = parse(raw)
    need(type(value) is dict and set(value) == {'schema', 'domain_hex32', 'artifacts'}
         and value['schema'] == 'kpxa-root-public-recovery-data-download-selection/v1'
         and value['domain_hex32'] == DOMAIN and type(value['artifacts']) is list
         and len(value['artifacts']) == len(ASSETS), 'exact-root-download-selection')
    by_name, prefixes = {}, set()
    for row in value['artifacts']:
        need(type(row) is dict and set(row) == {'name', 'origin_url', 'bytes', 'sha256'}
             and row['name'] in ASSETS and row['name'] not in by_name
             and uint(row['bytes']) > 0 and pin(row['sha256']), 'exact-four-artifact-pins')
        origin = row['origin_url']
        need(type(origin) is str and origin.isascii(), 'public-release-origin-required')
        prefix = 'https://github.com/elldeeone/kaspa-privacy-initiative/releases/download/'
        need(origin.startswith(prefix), 'selected-repository-release-only')
        suffix = origin[len(prefix):]
        parts = suffix.split('/')
        need(len(parts) == 2 and re.fullmatch('[A-Za-z0-9_.-]+', parts[0])
             and parts[0] not in {'.', '..'} and parts[1] == REMOTE_NAMES[row['name']], 'canonical-release-asset-URL')
        prefixes.add(origin.rsplit('/', 1)[0])
        by_name[row['name']] = dict(row)
    need(set(by_name) == set(ASSETS) and len(prefixes) == 1, 'single-selected-release-required')
    return by_name


def safe_url(value, origins, *, initial=False):
    need(type(value) is str and value.isascii() and not any(c.isspace() for c in value)
         and '\\' not in value and '\0' not in value, 'unsafe-transfer-URL')
    url = urlsplit(value)
    need(url.scheme == 'https' and url.hostname in {'github.com', 'release-assets.githubusercontent.com'}
         and url.netloc == url.hostname and url.username is None and url.password is None
         and not url.fragment and url.port is None, 'HTTPS-allowlist-required')
    if initial or url.hostname == 'github.com':
        need(value in origins and not url.query, 'exact-selected-origin-required')
    else:
        need(url.path.startswith('/github-production-release-asset/'), 'release-CDN-path-required')
    return value


def curl_config(url, isolation):
    need('"' not in url and '\\' not in url and '\n' not in url and '\r' not in url)
    # Signed CDN queries and fresh local Tor isolation labels never enter argv/logs.
    return ('url = "' + url + '"\nproxy-user = "<torS0X>0:' + isolation + '"\n').encode()


def response_location(raw):
    need(len(raw) >= 3 and raw[-3:].isdigit(), 'missing-HTTP-status')
    code = int(raw[-3:])
    blocks = [part for part in raw[:-3].replace(b'\r\n', b'\n').split(b'\n\n')
              if part.startswith(b'HTTP/')]
    need(blocks, 'missing-HTTP-headers')
    lines = blocks[-1].split(b'\n')
    need(int(lines[0].split()[1]) == code, 'HTTP-status-disagreement')
    locations = [line.split(b':', 1)[1].strip().decode('ascii') for line in lines[1:]
                 if line.lower().startswith(b'location:')]
    need(len(locations) <= 1, 'ambiguous-HTTP-redirect')
    return code, locations[0] if locations else None


def authenticate_file(path, size, expected):
    uint(size)
    need(pin(expected), 'SHA256-required')
    digest, total = hashlib.sha256(), 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == size,
             'regular-whole-file-required')
        while chunk := source.read(4 << 20):
            total += len(chunk)
            digest.update(chunk)
    need(total == size and digest.hexdigest() == expected, 'whole-public-file-identity')


def download(origin, destination, size, expected, origins, proxy_port=19050):
    safe_url(origin, origins, initial=True)
    need(type(proxy_port) is int and 0 < proxy_port < 65536)
    uint(size)
    need(size > 0 and pin(expected))
    current, visited = origin, set()
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        for _ in range(5):
            safe_url(current, origins)
            need(current not in visited, 'redirect-cycle')
            visited.add(current)
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            result = subprocess.run([
                '/usr/bin/curl', '-q', '--silent', '--show-error', '--fail',
                '--proto', '=https', '--proto-redir', '=https', '--noproxy', '',
                '--socks5-hostname', f'127.0.0.1:{proxy_port}', '--config', '-',
                '--max-filesize', str(size), '--dump-header', '-', '--write-out', '%{http_code}',
                '--output', f'/proc/self/fd/{fd}',
            ], input=curl_config(current, secrets.token_hex(32)), pass_fds=(fd,),
               env={'PATH': '/usr/bin:/bin'}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            need(result.returncode == 0, 'Tor-TLS-transfer-failed-no-direct-fallback')
            code, location = response_location(result.stdout)
            if code == 200:
                need(location is None, 'unexpected-success-location')
                os.fsync(fd)
                break
            need(code in REDIRECT_CODES and location is not None, 'unexpected-HTTP-status')
            current = safe_url(urljoin(current, location), origins)
        else:
            need(False, 'redirect-boundary-exceeded')
    finally:
        os.close(fd)
    authenticate_file(destination, size, expected)
    os.chmod(destination, 0o400, follow_symlinks=False)


def save_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as target:
        os.fchmod(target.fileno(), 0o400)
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def inventory_rows(raw):
    value = parse(raw)
    fields = {'schema', 'domain_hex32', 'files', 'file_count', 'payload_bytes',
              'all_payload_members_regular_mode0400', 'proving_key_or_runtime_executable_roles_supported',
              'private_owner_inputs_selected'}
    need(type(value) is dict and set(value) == fields
         and value['schema'] == 'kpxa-public-recovery-data-inventory/v1'
         and value['domain_hex32'] == DOMAIN and type(value['files']) is list and value['files']
         and value['all_payload_members_regular_mode0400'] is True
         and value['proving_key_or_runtime_executable_roles_supported'] is False
         and value['private_owner_inputs_selected'] is False, 'exact-public-data-inventory')
    rows = {}
    for row in value['files']:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'kind'}
             and row['kind'] in KINDS and pin(row['sha256']), 'exact-data-inventory-row')
        name = relative(row['path'])
        uint(row['bytes'])
        need(name not in rows and name not in ASSETS and PurePosixPath(name).parts[0] != 'audit-only',
             'duplicate-or-reserved-member')
        rows[name] = dict(row)
    member_paths([*rows, *ASSETS])
    need([row['path'] for row in value['files']] == sorted(rows)
         and uint(value['file_count']) == len(rows)
         and uint(value['payload_bytes']) == sum(row['bytes'] for row in rows.values()),
         'inventory-counts-or-order')
    return rows


def identity(value, name, artifact):
    need(type(value) is dict and set(value) == {'path', 'bytes', 'sha256'}
         and value['path'] == name and uint(value['bytes']) == artifact['bytes']
         and value['sha256'] == artifact['sha256'], 'packet-artifact-identity')


def packet_metadata(raw, artifacts, rows):
    value = parse(raw)
    fields = {'schema', 'domain_hex32', 'classification', 'inventory', 'archive', 'roles', 'pages',
              'declared_terminal_shape', 'source_bytes_reserialized', 'decoded_pages_in_archive',
              'chain_native_or_cryptographic_acceptance_verified_by_packager',
              'currentness_independent_administration_or_offhost_execution_claimed',
              'private_original_backups_or_owner_inputs_read'}
    need(type(value) is dict and set(value) == fields
         and value['schema'] == 'kpxa-public-recovery-data-packet/v1'
         and value['domain_hex32'] == DOMAIN
         and value['classification'] == 'OPAQUE_PUBLIC_BYTE_CONTAINER_WITH_METADATA_SHAPE_PREFLIGHT_ONLY',
         'exact-public-data-packet')
    for flag in fields - {'schema', 'domain_hex32', 'classification', 'inventory', 'archive',
                          'roles', 'pages', 'declared_terminal_shape'}:
        need(value[flag] is False, 'packet-evidence-boundary-required')
    identity(value['inventory'], 'DATA-INVENTORY.json', artifacts['DATA-INVENTORY.json'])
    archive = value['archive']
    need(type(archive) is dict and set(archive) == {'path', 'bytes', 'sha256', 'members'}
         and uint(archive['members']) == len(rows) + 1, 'packet-archive-member-count')
    identity({k: archive[k] for k in ('path', 'bytes', 'sha256')}, 'data.tar', artifacts['data.tar'])
    need(type(value['roles']) is dict and set(value['roles']) == ROLES, 'exact-packet-role-set')
    paths = []
    for role, entry in value['roles'].items():
        need(type(entry) is dict and set(entry) == {'path', 'bytes', 'sha256'}, 'exact-role-identity')
        name = relative(entry['path'])
        need(name in rows and rows[name]['kind'] != 'full-source-page', 'role-must-select-payload')
        identity(entry, name, rows[name])
        paths.append(name)
    need(len(set(paths)) == len(ROLES) and value['roles']['fetch']['path'] == 'chain/fetch.json',
         'distinct-role-paths-and-fixed-fetch')
    declared = value['declared_terminal_shape']
    need(type(declared) is dict and set(declared) == {'accepted_protocol_transactions', 'payments',
         'native_exits', 'reserve_sompi', 'head_outpoint'}
         and uint(declared['accepted_protocol_transactions']) == 16
         and uint(declared['payments']) == 6 and uint(declared['native_exits']) == 9
         and uint(declared['reserve_sompi']) == 0 and declared['head_outpoint'] is None,
         'declared-terminal-container-shape')
    need(type(value['pages']) is list, 'packet-page-list-required')
    return value


def canonical_header(name, size):
    member = tarfile.TarInfo(relative(name))
    member.size, member.mode = size, 0o400
    member.uid = member.gid = member.mtime = 0
    member.uname = member.gname = ''
    return member.tobuf(format=tarfile.USTAR_FORMAT, encoding='utf-8', errors='strict')


def unpack(archive, output, rows, inventory_raw):
    """Walk raw headers: no extension/link filtering hidden by a tar library."""
    need(not output.exists(), 'fresh-unpack-root-required')
    expected = dict(rows)
    expected['DATA-INVENTORY.json'] = {'bytes': len(inventory_raw), 'sha256': sha(inventory_raw)}
    order = sorted(expected)
    output.mkdir(mode=0o700)
    with archive.open('rb') as source:
        for name in order:
            header = source.read(512)
            need(header == canonical_header(name, expected[name]['bytes']),
                 'exact-sorted-regular-canonical-USTAR-header')
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            digest, remaining = hashlib.sha256(), expected[name]['bytes']
            with os.fdopen(fd, 'wb') as destination:
                os.fchmod(destination.fileno(), 0o400)
                while remaining:
                    chunk = source.read(min(remaining, 1 << 20))
                    need(chunk, 'truncated-USTAR-member')
                    destination.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            need(digest.hexdigest() == expected[name]['sha256'], 'USTAR-member-whole-byte-identity')
            padding = (-expected[name]['bytes']) % 512
            need(source.read(padding) == bytes(padding), 'nonzero-USTAR-member-padding')
        trailer_start = source.tell()
        trailer_size, nonzero = 0, False
        while chunk := source.read(1 << 20):
            trailer_size += len(chunk)
            nonzero |= any(chunk)
        canonical_size = ((trailer_start + 1024 + tarfile.RECORDSIZE - 1)
                          // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
        need(trailer_size >= 1024 and not nonzero
             and trailer_start + trailer_size == canonical_size,
             'exact-zero-USTAR-trailer-no-extra-members')
    return expected


def page_records(fetch, packet, rows):
    need(type(fetch) is dict and fetch.get('schema') == 'kpxa-gn3-network-fetch/v1'
         and type(fetch.get('pages')) is list and fetch['pages']
         and type(fetch.get('current_view')) is dict
         and type(fetch['current_view'].get('post_query_delta')) is dict
         and type(fetch['current_view']['post_query_delta'].get('pages')) is list,
         'both-fetch-page-lists-required')
    expected = {}
    for record in [*fetch['pages'], *fetch['current_view']['post_query_delta']['pages']]:
        need(type(record) is dict and set(record) == {'path', 'request', 'decoded_sha256',
             'decoded_bytes', 'gzip_sha256', 'gzip_bytes', 'encoding'}, 'exact-fetch-page-record')
        name = 'chain/' + relative(record['path'])
        need(name not in expected and pin(record['decoded_sha256']) and pin(record['gzip_sha256'])
             and type(record['encoding']) is str and record['encoding'], 'unique-page-identities')
        uint(record['decoded_bytes'])
        uint(record['gzip_bytes'])
        need(name in rows and rows[name]['kind'] == 'full-source-page'
             and rows[name]['bytes'] == record['gzip_bytes']
             and rows[name]['sha256'] == record['gzip_sha256'], 'exact-compressed-page-membership')
        expected[name] = dict(record)
    need({name for name, row in rows.items() if row['kind'] == 'full-source-page'} == set(expected),
         'extra-or-missing-full-source-page')
    page_map = []
    for name, record in sorted(expected.items()):
        page_map.append({'packet_path': name, 'gzip_bytes': record['gzip_bytes'],
                         'gzip_sha256': record['gzip_sha256'], 'decoded_bytes': record['decoded_bytes'],
                         'decoded_sha256': record['decoded_sha256']})
    # bool cannot stand in for integer lengths, even where Python equality agrees.
    for row in packet['pages']:
        need(type(row) is dict and set(row) == {'packet_path', 'gzip_bytes', 'gzip_sha256',
             'decoded_bytes', 'decoded_sha256'}, 'exact-packet-page-fields')
        uint(row['gzip_bytes'])
        uint(row['decoded_bytes'])
    need(packet['pages'] == page_map, 'packet-and-both-fetch-page-arrays-must-agree')
    return expected


def decode_page(compressed, record):
    """Authenticate all decoded bytes without retaining a second page copy."""
    authenticate_file(compressed, record['gzip_bytes'], record['gzip_sha256'])
    count, digest = 0, hashlib.sha256()
    try:
        # GzipFile decodes every concatenated member, accepts gzip zero
        # padding, and refuses non-gzip trailing data, matching builder239bb.
        with gzip.GzipFile(filename=str(compressed), mode='rb') as source:
            while chunk := source.read(1 << 20):
                count += len(chunk)
                need(count <= record['decoded_bytes'], 'decoded-page-exceeds-pinned-length')
                digest.update(chunk)
                # Discard each chunk after hashing. The producer's separate
                # decoded-object audit is not claimed by this acquisition.
        need(count == record['decoded_bytes'] and digest.hexdigest() == record['decoded_sha256'],
             'all-gzip-members-decoded-whole-byte-identity')
    except (OSError, EOFError, zlib.error) as error:
        raise ValueError('invalid-or-incomplete-gzip-page') from error


def verify_downloads(downloads, data, artifacts):
    """Public fixture API. Returns verified maps, never an acquisition receipt."""
    for name in ASSETS:
        row = artifacts[name]
        authenticate_file(downloads / name, row['bytes'], row['sha256'])
    expected_sums = ''.join(artifacts[name]['sha256'] + '  ' + name + '\n'
                            for name in ASSETS[:3]).encode()
    need((downloads / 'SHA256SUMS').read_bytes() == expected_sums, 'exact-authenticated-SHA256SUMS')
    inventory_raw = (downloads / 'DATA-INVENTORY.json').read_bytes()
    rows = inventory_rows(inventory_raw)
    packet = packet_metadata((downloads / 'PACKET.json').read_bytes(), artifacts, rows)
    members = unpack(downloads / 'data.tar', data, rows, inventory_raw)
    fetch = parse((data / 'chain/fetch.json').read_bytes())
    pages = page_records(fetch, packet, rows)
    decoded_rows = []
    for name, record in sorted(pages.items()):
        decode_page(data / name, record)
        decoded_rows.append({'packet_path': name,
                             'gzip_bytes': record['gzip_bytes'], 'gzip_sha256': record['gzip_sha256'],
                             'decoded_bytes': record['decoded_bytes'], 'decoded_sha256': record['decoded_sha256']})
    return members, decoded_rows


def acquire(output, host_root, selected, proxy_port):
    need(list(output.iterdir()) == [], 'fresh-empty-acquisition-root-required')
    downloads = output / 'downloads'
    downloads.mkdir(mode=0o700)
    origins = {row['origin_url'] for row in selected.values()}
    for name in ASSETS:
        row = selected[name]
        download(row['origin_url'], downloads / name, row['bytes'], row['sha256'], origins, proxy_port)
        print(json.dumps({'stage': 'authenticated-network-acquisition', 'artifact': name,
                          'bytes': row['bytes']}), flush=True)
    members, decoded = verify_downloads(downloads, output / 'data', selected)
    def retained(name):
        return {'path': str(host_root / 'downloads' / name), 'bytes': selected[name]['bytes'],
                'sha256': selected[name]['sha256']}
    receipt = {'schema': RECEIPT_SCHEMA, 'classification': CLASSIFICATION, 'transport': 'TOR_SOCKS5H_TLS',
        'inventory': retained('DATA-INVENTORY.json'), 'packet': retained('PACKET.json'),
        'artifacts': [dict(name=name, origin_url=selected[name]['origin_url'], **retained(name)) for name in ASSETS],
        'files': [{'member': name, 'path': str(host_root / 'data' / name), 'bytes': row['bytes'],
                   'sha256': row['sha256']} for name, row in sorted(members.items())],
        'pages': [{'packet_path': row['packet_path'],
                   'compressed': {'path': str(host_root / 'data' / row['packet_path']),
                                  'bytes': row['gzip_bytes'], 'sha256': row['gzip_sha256']},
                   'decoded': {'bytes': row['decoded_bytes'], 'sha256': row['decoded_sha256'],
                               'retained': False}}
                  for row in decoded]}
    raw = encoded(receipt)
    save_new(output / 'DATA-DOWNLOAD-RECEIPT.json', raw)
    print(json.dumps({'receipt': str(host_root / 'DATA-DOWNLOAD-RECEIPT.json'),
                      'sha256': sha(raw), 'files': len(members), 'pages': len(decoded), 'artifacts': 4}), flush=True)


def sandbox_command(source, selected, output, host_root, proxy_port):
    return ['/usr/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-uts',
        '--new-session', '--die-with-parent', '--ro-bind', '/usr', '/usr',
        '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
        '--dir', '/etc', '--dir', '/etc/ssl', '--ro-bind', '/etc/ssl/certs', '/etc/ssl/certs',
        '--ro-bind', '/etc/ld.so.cache', '/etc/ld.so.cache', '--proc', '/proc', '--dev', '/dev',
        '--tmpfs', '/tmp', '--dir', '/acquisition', '--bind', str(output), '/acquisition',
        '--ro-bind', str(source), '/downloader.py', '--ro-bind', str(selected), '/release-selection.json',
        '--chdir', '/', '/usr/bin/python3', '-B', '/downloader.py', '--child', '--output', '/acquisition',
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
        if args.child:
            need(args.output == '/acquisition' and args.release_selection == '/release-selection.json'
                 and args.host_root is not None and Path(__file__).absolute() == Path('/downloader.py')
                 and not Path('/home').exists() and not Path('/var').exists(), 'finite-empty-filesystem-child')
            selected = selection(Path(args.release_selection).read_bytes())
            acquire(Path(args.output), absolute(args.host_root), selected, args.proxy_port)
        elif args.execute:
            need(pin(args.source_sha256) and pin(args.release_selection_sha256), 'external-source-and-selection-pins')
            output = absolute(args.output)
            need(output.parent == OUTPUT_BASE and re.fullmatch('acquisition-[0-9]{2}', output.name)
                 and not output.exists() and not any(p.is_symlink() for p in (output, *output.parents)),
                 'fresh-public-data-acquisition-location')
            read = runpy.run_path(GUARD)['read']
            raw_source = read(str(Path(__file__).absolute()), args.source_sha256)
            raw_selection = read(str(absolute(args.release_selection)), args.release_selection_sha256)
            selection(raw_selection)
            OUTPUT_BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
            source_stage = OUTPUT_BASE / (output.name + '-source.py')
            selection_stage = OUTPUT_BASE / (output.name + '-selection.json')
            save_new(source_stage, raw_source)
            save_new(selection_stage, raw_selection)
            output.mkdir(mode=0o700)
            raise SystemExit(subprocess.run(sandbox_command(source_stage, selection_stage, output, output,
                                                           args.proxy_port), env={'PATH': '/usr/bin:/bin'}).returncode)
        else:
            print(json.dumps({'status': 'PREPARED_NOT_DOWNLOADED', 'receipt_schema': RECEIPT_SCHEMA,
                              'assets': ASSETS, 'financial_or_native_or_portable_replay_verified': False}))
    except Exception:
        # Do not echo HTTP headers, signed redirect queries, source selectors,
        # retained decoded data, or curl diagnostics even on transport failure.
        parser.exit(2, 'Public data download refused or incomplete; no acquisition receipt issued.\n')


if __name__ == '__main__':
    main()
