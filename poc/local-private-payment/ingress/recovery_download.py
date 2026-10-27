#!/usr/bin/env python3
"""Acquire the selected public recovery release over Tor, then authenticate it.

The execution child sees an empty filesystem with public OS dependencies, this
source and a fresh acquisition output. No old software, wallet, private parent,
backup, log or local PK path is mounted. A receipt is written only after actual
network downloads and exact archive/inventory/ExitPK verification succeed.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import secrets
import stat
import subprocess
import sys
import tarfile
from urllib.parse import urljoin, urlsplit

GUARD = '/var/tmp/kpi-root-guard-helper-09.py'
DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
PREFIX = 'https://github.com/elldeeone/kaspa-privacy-initiative/releases/download/native-kas-local-payment-research-2026-10-25/'
SOFTWARE = {'name': 'software.tar', 'bytes': 29_849_600,
            'sha256': 'd85ad87f7b3094c5ee8747ba8f3c5e774895bd63f958fd1ca5fd845b1095d89a'}
EXIT = {'name': 'parameters.pk', 'bytes': 591_206_448,
        'sha256': 'fc531fcdb192dba2123bb13a02f78aa019cd5299e6905ad7ab4a5c6afdf481b1'}
INVENTORY_SHA = '707cff8442c1617fc526d9d83659dcdba32d966d4dc89d0f1f27aee825822376'
INVENTORY_BYTES = 3594
ALLOWED_HOSTS = {'github.com', 'release-assets.githubusercontent.com'}
REDIRECT_CODES = {301, 302, 303, 307, 308}


def need(value, label='recovery-download-refused'):
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
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_float=lambda _: need(False), parse_constant=lambda _: need(False))


def pin(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def safe_name(value):
    need(type(value) is str and re.fullmatch('[A-Za-z0-9_./-]+', value) is not None)
    name = PurePosixPath(value)
    need(not name.is_absolute() and name.parts and '..' not in name.parts and str(name) == value)
    return value


def absolute(value):
    need(type(value) is str and '\x00' not in value and '\\' not in value)
    path = Path(value)
    need(path.is_absolute() and '..' not in path.parts and str(path) == value)
    return path


def safe_url(value, *, initial=False):
    need(type(value) is str and value.isascii() and not any(c.isspace() for c in value)
         and '\\' not in value and '\x00' not in value)
    url = urlsplit(value)
    need(url.scheme == 'https' and url.hostname in ALLOWED_HOSTS
         and url.netloc == url.hostname and url.username is None and url.password is None
         and not url.fragment and url.port is None)
    if initial or url.hostname == 'github.com':
        need(value in {PREFIX + SOFTWARE['name'], PREFIX + EXIT['name']} and not url.query)
    else:
        need(url.path.startswith('/github-production-release-asset/'))
    return value


def curl_config(url, isolation):
    # Signed CDN queries and local isolation labels enter stdin, never argv/logs.
    need('"' not in url and '\\' not in url and '\n' not in url and '\r' not in url)
    return ('url = "' + url + '"\nproxy-user = "<torS0X>0:' + isolation + '"\n').encode()


def response_location(raw):
    # curl writes only headers plus the final status, never the downloaded body.
    need(len(raw) >= 3 and raw[-3:].isdigit(), 'missing-HTTP-status')
    code = int(raw[-3:])
    blocks = raw[:-3].replace(b'\r\n', b'\n').split(b'\n\n')
    blocks = [part for part in blocks if part.startswith(b'HTTP/')]
    need(blocks, 'missing-HTTP-headers')
    lines = blocks[-1].split(b'\n')
    need(int(lines[0].split()[1]) == code, 'HTTP-status-disagreement')
    locations = [line.split(b':', 1)[1].strip().decode('ascii') for line in lines[1:]
                 if line.lower().startswith(b'location:')]
    need(len(locations) <= 1, 'ambiguous-HTTP-redirect')
    return code, locations[0] if locations else None


def authenticate_file(path, size, expected):
    need(type(size) is int and size > 0 and pin(expected))
    digest = hashlib.sha256()
    total = 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == size)
        while chunk := source.read(4 * 1024 * 1024):
            total += len(chunk)
            digest.update(chunk)
    need(total == size and digest.hexdigest() == expected, 'downloaded-public-file-identity')


def download(origin, destination, size, expected, proxy_port=19050):
    safe_url(origin, initial=True)
    need(type(proxy_port) is int and 0 < proxy_port < 65536)
    current, visited = origin, set()
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        for _ in range(5):
            safe_url(current)
            need(current not in visited, 'redirect-cycle')
            visited.add(current)
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            # No -L, retry, cookies, netrc, config, Authorization, ambient proxy
            # bypass, local target DNS or TLS-verification override is present.
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
            current = safe_url(urljoin(current, location))
        else:
            need(False, 'redirect-boundary-exceeded')
    finally:
        os.close(fd)
    authenticate_file(destination, size, expected)
    os.chmod(destination, 0o400, follow_symlinks=False)


def inventory_rows(raw, expected_sha=INVENTORY_SHA, expected_bytes=INVENTORY_BYTES):
    need(len(raw) == expected_bytes and sha(raw) == expected_sha, 'authenticated-inventory-required')
    value = parse(raw)
    need(value['schema'] == 'kpxa-recovery-software-inventory/v1'
         and value['domain_hex32'] == DOMAIN and value['PKs_included'] is False
         and value['payload_file_count'] == 22 and len(value['files']) == 22)
    rows = {}
    for row in value['files']:
        need(set(row) == {'path', 'bytes', 'sha256', 'mode'}
             and type(row['bytes']) is int and row['bytes'] > 0
             and pin(row['sha256']) and row['mode'] in {'0400', '0500'})
        name = safe_name(row['path'])
        need(name not in rows and name != 'INVENTORY.json')
        rows[name] = row
    rows['INVENTORY.json'] = {'path': 'INVENTORY.json', 'bytes': len(raw),
                              'sha256': expected_sha, 'mode': '0400'}
    return rows


def save_new(path, raw, mode=0o400):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as target:
        os.fchmod(target.fileno(), mode)
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def unpack(archive, output, *, inventory_sha=INVENTORY_SHA, inventory_bytes=INVENTORY_BYTES):
    need(not output.exists(), 'fresh-unpack-directory-required')
    # Caller has authenticated the complete tar acquisition before this parser.
    with tarfile.open(archive, mode='r:') as tar:
        members = tar.getmembers()
        need(len(members) == 23 and len({m.name for m in members}) == 23,
             'exact-23-distinct-USTAR-members')
        offset = 0
        for member in members:
            safe_name(member.name)
            need(member.type == tarfile.REGTYPE and not member.pax_headers
                 and member.uid == member.gid == member.mtime == 0
                 and member.uname == member.gname == '' and member.linkname == ''
                 and member.offset == offset and member.size > 0, 'plain-finite-USTAR-files-only')
            tar.fileobj.seek(member.offset + 257)
            need(tar.fileobj.read(8) == b'ustar\x0000', 'USTAR-header-required')
            offset += 512 + ((member.size + 511) // 512) * 512
        tar.fileobj.seek(offset)
        trailer = tar.fileobj.read()
        need(len(trailer) >= 1024 and not any(trailer), 'zero-USTAR-trailer-required')
        by_name = {m.name: m for m in members}
        need('INVENTORY.json' in by_name)
        raw_inventory = tar.extractfile(by_name['INVENTORY.json']).read()
        rows = inventory_rows(raw_inventory, inventory_sha, inventory_bytes)
        need(set(by_name) == set(rows), 'archive-inventory-exact-correspondence')
        output.mkdir(mode=0o700)
        for name, row in sorted(rows.items()):
            member = by_name[name]
            need(member.size == row['bytes'] and member.mode == int(row['mode'], 8),
                 'archive-size-mode-correspondence')
            raw = tar.extractfile(member).read()
            need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'archive-leaf-identity')
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            save_new(target, raw, int(row['mode'], 8))
    return rows


def acquire(output, host_root, proxy_port):
    output, host_root = absolute(str(output)), absolute(str(host_root))
    need(list(output.iterdir()) == [], 'fresh-empty-acquisition-root-required')
    downloads = output / 'downloads'
    downloads.mkdir(mode=0o700)
    artifacts = []
    for artifact in (SOFTWARE, EXIT):
        destination = downloads / artifact['name']
        download(PREFIX + artifact['name'], destination, artifact['bytes'], artifact['sha256'], proxy_port)
        artifacts.append({'path': str(host_root / 'downloads' / artifact['name']),
            'sha256': artifact['sha256'], 'bytes': artifact['bytes'], 'origin_url': PREFIX + artifact['name']})
        print(json.dumps({'stage': 'authenticated-network-acquisition', 'artifact': artifact['name'],
                          'bytes': artifact['bytes']}), flush=True)
    rows = unpack(downloads / SOFTWARE['name'], output / 'software')
    files = [{'path': str(host_root / 'software' / name), 'sha256': row['sha256'], 'bytes': row['bytes']}
             for name, row in sorted(rows.items())]
    files.append({'path': str(host_root / 'downloads' / EXIT['name']),
                  'sha256': EXIT['sha256'], 'bytes': EXIT['bytes']})
    receipt = {'schema': 'kpxa-downloaded-recovery-receipt/v1',
        'classification': 'ACTUAL_TOR_TLS_DOWNLOAD_AND_INVENTORY_VERIFIED',
        'transport': 'TOR_SOCKS5H_TLS',
        'inventory': {'path': str(host_root / 'software/INVENTORY.json'), 'sha256': INVENTORY_SHA},
        'artifacts': artifacts, 'files': files}
    raw = encoded(receipt)
    save_new(output / 'DOWNLOAD-RECEIPT.json', raw)
    print(json.dumps({'receipt': str(host_root / 'DOWNLOAD-RECEIPT.json'),
                      'sha256': sha(raw), 'files': len(files), 'artifacts': len(artifacts)}), flush=True)


def sandbox_command(source, output, host_root, proxy_port):
    # Starting from empty root excludes ALL guard directories and the whole old
    # compound/private parents; none are mounted, enumerated or read by the child.
    return ['/usr/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-uts',
        '--new-session', '--die-with-parent', '--ro-bind', '/usr', '/usr',
        '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
        '--dir', '/etc', '--dir', '/etc/ssl', '--ro-bind', '/etc/ssl/certs', '/etc/ssl/certs',
        '--ro-bind', '/etc/ld.so.cache', '/etc/ld.so.cache', '--proc', '/proc', '--dev', '/dev',
        '--tmpfs', '/tmp', '--dir', '/acquisition', '--bind', str(output), '/acquisition',
        '--ro-bind', str(source), '/downloader.py', '--chdir', '/',
        '/usr/bin/python3', '-B', '/downloader.py', '--child', '--output', '/acquisition',
        '--host-root', str(host_root), '--proxy-port', str(proxy_port)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--source-sha256')
    parser.add_argument('--output')
    parser.add_argument('--host-root', help=argparse.SUPPRESS)
    parser.add_argument('--proxy-port', type=int, default=19050)
    args = parser.parse_args()
    try:
        if args.child:
            need(args.output == '/acquisition' and args.host_root is not None
                 and Path(__file__).absolute() == Path('/downloader.py')
                 and not Path('/home').exists() and not Path('/var').exists(),
                 'finite-empty-filesystem-child-required')
            acquire(Path(args.output), Path(args.host_root), args.proxy_port)
        elif args.execute:
            need(pin(args.source_sha256), 'reviewed-downloader-source-pin-required')
            output = absolute(args.output)
            need(output.parent == Path('/var/tmp/kpi-local-private-payment-01/recovery-downloads')
                 and re.fullmatch('acquisition-[0-9]{2}', output.name), 'fresh-public-acquisition-location')
            need(not output.exists() and not any(p.is_symlink() for p in (output, *output.parents)))
            h = runpy.run_path(GUARD)
            raw = h['read'](str(Path(__file__).absolute()), args.source_sha256)
            # Stage only this reviewed public source outside the acquisition root.
            stage = output.parent / (output.name + '-source.py')
            output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            save_new(stage, raw)
            output.mkdir(mode=0o700)
            command = sandbox_command(stage, output, output, args.proxy_port)
            raise SystemExit(subprocess.run(command, env={'PATH': '/usr/bin:/bin'}).returncode)
        else:
            print(json.dumps({'status': 'PREPARED_NOT_DOWNLOADED', 'software': SOFTWARE,
                'exit': EXIT, 'inventory_sha256': INVENTORY_SHA,
                'receipt_schema': 'kpxa-downloaded-recovery-receipt/v1'}))
    except Exception:
        # Never echo signed redirect queries, HTTP headers or child diagnostics.
        parser.exit(2, 'Recovery download refused or incomplete; no acquisition receipt issued.\n')


if __name__ == '__main__':
    main()
