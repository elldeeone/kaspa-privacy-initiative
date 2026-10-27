"""Public synthetic transport/archive controls; no release acquisition claim."""
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import recovery_download as d


def fixture(change=None, inventory_change=None):
    payload = {f'fixture/{i:02d}.bin': bytes([i]) + b'public fixture' for i in range(22)}
    rows = [{'path': name, 'bytes': len(raw), 'sha256': d.sha(raw), 'mode': '0400'}
            for name, raw in payload.items()]
    inventory = {'schema': 'kpxa-recovery-software-inventory/v1', 'domain_hex32': d.DOMAIN,
                 'PKs_included': False, 'payload_file_count': 22, 'files': rows}
    if inventory_change:
        inventory_change(inventory)
    raw_inventory = d.encoded(inventory)
    payload['INVENTORY.json'] = raw_inventory
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(payload.items()):
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(raw), 0o400
            if change:
                change(member)
            archive.addfile(member, io.BytesIO(raw) if member.isreg() else None)
    return output.getvalue(), raw_inventory


class RecoveryDownloadControls(unittest.TestCase):
    def test_allowlisted_TLS_redirects_only(self):
        origin = d.PREFIX + 'software.tar'
        self.assertEqual(d.safe_url(origin, initial=True), origin)
        signed = 'https://release-assets.githubusercontent.com/github-production-release-asset/1/fixture?sig=public-fixture'
        self.assertEqual(d.safe_url(signed), signed)
        for url in ['http://github.com/a', 'https://github.com.evil.invalid/a',
                    'https://release-assets.githubusercontent.com.evil.invalid/github-production-release-asset/a',
                    'https://user:pass@github.com/a', 'https://github.com:443/a',
                    'https://release-assets.githubusercontent.com/other/a',
                    'https://github.com/other/repository/releases/download/a/b',
                    signed + '#fragment', origin + '?token=fixture']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                d.safe_url(url)

    def test_duplicate_redirect_location_rejected(self):
        with self.assertRaises(ValueError):
            d.response_location(b'HTTP/2 302\r\nLocation: a\r\nLocation: b\r\n\r\n302')

    def test_stream_download_remote_DNS_and_no_signed_URL_in_argv(self):
        body = b'public downloaded fixture'
        signed = 'https://release-assets.githubusercontent.com/github-production-release-asset/1/fixture?sig=fixture-token'
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            class Result:
                returncode = 0
            result = Result()
            fd = kwargs['pass_fds'][0]
            if len(calls) == 1:
                result.stdout = ('HTTP/2 302\r\nLocation: ' + signed + '\r\n\r\n302').encode()
            else:
                os.write(fd, body)
                result.stdout = b'HTTP/2 200\r\nContent-Length: 25\r\n\r\n200'
            return result

        with tempfile.TemporaryDirectory() as root, patch('recovery_download.subprocess.run', run):
            target = Path(root) / 'software.tar'
            d.download(d.PREFIX + 'software.tar', target, len(body), d.sha(body))
            self.assertEqual(target.read_bytes(), body)
        self.assertEqual(len(calls), 2)
        for argv, kwargs in calls:
            self.assertEqual(argv[:2], ['/usr/bin/curl', '-q'])
            self.assertIn('--socks5-hostname', argv)
            self.assertEqual(argv[argv.index('--noproxy') + 1], '')
            self.assertNotIn('-L', argv)
            self.assertNotIn('--insecure', argv)
            self.assertNotIn('--retry', argv)
            self.assertFalse(any('sig=' in value for value in argv))
            self.assertEqual(kwargs['env'], {'PATH': '/usr/bin:/bin'})
        self.assertIn(signed.encode(), calls[1][1]['input'])

    def test_proxy_failure_has_no_retry_or_success(self):
        class Failure:
            returncode = 7
        with tempfile.TemporaryDirectory() as root, patch('recovery_download.subprocess.run', return_value=Failure()) as run:
            with self.assertRaises(ValueError):
                d.download(d.PREFIX + 'software.tar', Path(root) / 'software.tar', 1, d.sha(b'x'))
            self.assertEqual(run.call_count, 1)
            self.assertFalse((Path(root) / 'DOWNLOAD-RECEIPT.json').exists())

    def test_downloaded_bytes_must_match_pin(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / 'public.bin'
            target.write_bytes(b'public fixture')
            with self.assertRaises(ValueError):
                d.authenticate_file(target, len(b'public fixture'), d.sha(b'wrong fixture'))

    def unpack_fixture(self, change=None, inventory_change=None):
        raw, inventory = fixture(change, inventory_change)
        with tempfile.TemporaryDirectory() as root:
            archive = Path(root) / 'software.tar'
            archive.write_bytes(raw)
            return d.unpack(archive, Path(root) / 'unpacked',
                            inventory_sha=d.sha(inventory), inventory_bytes=len(inventory))

    def test_exact_inventory_fixture_unpacks_23_leaves(self):
        rows = self.unpack_fixture()
        self.assertEqual(len(rows), 23)
        self.assertIn('INVENTORY.json', rows)

    def test_tar_links_traversal_and_modes_rejected(self):
        def symlink(member):
            if member.name == 'fixture/00.bin':
                member.type, member.linkname, member.size = tarfile.SYMTYPE, '/private/seed', 0
        def traversal(member):
            if member.name == 'fixture/00.bin':
                member.name = '../outside.bin'
        def executable(member):
            if member.name == 'fixture/00.bin':
                member.mode = 0o500
        for change in [symlink, traversal, executable]:
            with self.subTest(change=change.__name__), self.assertRaises(ValueError):
                self.unpack_fixture(change)

    def test_tar_inventory_member_hash_substitution_rejected(self):
        def substitute(inventory):
            inventory['files'][0]['sha256'] = d.sha(b'other public fixture')
        with self.assertRaises(ValueError):
            self.unpack_fixture(inventory_change=substitute)

    def test_sandbox_contains_only_public_runtime_source_fresh_output(self):
        command = d.sandbox_command(Path('/public-source.py'), Path('/fresh-output'), Path('/host-root'), 19050)
        self.assertIn('--unshare-pid', command)
        self.assertIn('--unshare-user', command)
        self.assertNotIn('--ro-bind', command[command.index('--chdir'):])
        mounts = [command[i + 1] for i, value in enumerate(command) if value in {'--bind', '--ro-bind'}]
        self.assertEqual(set(mounts), {'/usr', '/lib', '/lib64', '/etc/ssl/certs',
                                     '/etc/ld.so.cache', '/public-source.py', '/fresh-output'})
        self.assertNotIn('/', mounts)
        self.assertFalse(any(value.startswith('/home/') or 'private' in value for value in mounts))
