"""Known-public synthetic controls. No release download or financial claim."""
import copy
import gzip
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import recovery_data_download as d

PREFIX = 'https://github.com/elldeeone/kaspa-privacy-initiative/releases/download/public-fixture/'
DECODED = b'{"public":"first member"}\n{"public":"second member"}\n'


def fixture(*, inventory_change=None, packet_change=None, fetch_change=None,
            member_change=None, tar_change=None, page_blob=None, extra_page=False):
    main_blob = page_blob if page_blob is not None else (
        gzip.compress(b'{"public":"first member"}\n', mtime=0)
        + gzip.compress(b'{"public":"second member"}\n', mtime=0) + b'\0' * 5)
    post_decoded = b'[]\n'
    post_blob = gzip.compress(post_decoded, mtime=0)
    def record(name, raw, decoded):
        return {'path': name, 'request': {'synthetic': True}, 'decoded_sha256': d.sha(decoded),
                'decoded_bytes': len(decoded), 'gzip_sha256': d.sha(raw), 'gzip_bytes': len(raw),
                'encoding': 'gzip-json-array'}
    main = record('attempt-001/cached/00000.json.gz', main_blob, DECODED)
    post = record('attempt-001/post-query/pages/00000.json.gz', post_blob, post_decoded)
    fetch = {'schema': 'kpxa-gn3-network-fetch/v1', 'pages': [main],
             'current_view': {'post_query_delta': {'pages': [post]}}, 'elapsed_seconds': 0.125}
    if fetch_change:
        fetch_change(fetch)
    role_names = {role: ('chain/fetch.json' if role == 'fetch' else 'meta/' + role + '.json') for role in d.ROLES}
    payload = {name: b'{}\n' for name in role_names.values()}
    payload['chain/fetch.json'] = d.encoded(fetch)
    payload['chain/' + main['path']] = main_blob
    payload['chain/' + post['path']] = post_blob
    payload['public/empty.bin'] = b''
    page_names = {'chain/' + main['path'], 'chain/' + post['path']}
    if extra_page:
        payload['chain/unselected.json.gz'] = post_blob
        page_names.add('chain/unselected.json.gz')
    rows = [{'path': name, 'bytes': len(raw), 'sha256': d.sha(raw),
             'kind': 'full-source-page' if name in page_names else 'public-evidence'}
            for name, raw in sorted(payload.items())]
    inventory = {'schema': 'kpxa-public-recovery-data-inventory/v1', 'domain_hex32': d.DOMAIN,
                 'files': rows, 'file_count': len(rows), 'payload_bytes': sum(row['bytes'] for row in rows),
                 'all_payload_members_regular_mode0400': True,
                 'proving_key_or_runtime_executable_roles_supported': False,
                 'private_owner_inputs_selected': False}
    if inventory_change:
        inventory_change(inventory)
    inventory_raw = d.encoded(inventory)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted({**payload, 'DATA-INVENTORY.json': inventory_raw}.items()):
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(raw), 0o400
            if member_change:
                member_change(member)
            archive.addfile(member, io.BytesIO(raw) if member.isreg() else None)
    archive_raw = output.getvalue()
    if tar_change:
        archive_raw = tar_change(archive_raw)
    artifacts = {name: {'name': name, 'origin_url': PREFIX + d.REMOTE_NAMES[name], 'bytes': len(raw), 'sha256': d.sha(raw)}
                 for name, raw in [('data.tar', archive_raw), ('DATA-INVENTORY.json', inventory_raw)]}
    by_path = {row['path']: row for row in rows}
    packet = {'schema': 'kpxa-public-recovery-data-packet/v1', 'domain_hex32': d.DOMAIN,
              'classification': 'OPAQUE_PUBLIC_BYTE_CONTAINER_WITH_METADATA_SHAPE_PREFLIGHT_ONLY',
              'inventory': {'path': 'DATA-INVENTORY.json', 'bytes': len(inventory_raw), 'sha256': d.sha(inventory_raw)},
              'archive': {'path': 'data.tar', 'bytes': len(archive_raw), 'sha256': d.sha(archive_raw),
                          'members': len(rows) + 1},
              'roles': {role: {key: by_path[name][key] for key in ('path', 'bytes', 'sha256')}
                        for role, name in role_names.items()},
              'pages': [{'packet_path': 'chain/' + record['path'], 'gzip_bytes': record['gzip_bytes'],
                         'gzip_sha256': record['gzip_sha256'], 'decoded_bytes': record['decoded_bytes'],
                         'decoded_sha256': record['decoded_sha256']}
                        for record in sorted([main, post], key=lambda row: row['path'])],
              'declared_terminal_shape': {'accepted_protocol_transactions': 16, 'payments': 6,
                                          'native_exits': 9, 'reserve_sompi': 0, 'head_outpoint': None},
              'source_bytes_reserialized': False, 'decoded_pages_in_archive': False,
              'chain_native_or_cryptographic_acceptance_verified_by_packager': False,
              'currentness_independent_administration_or_offhost_execution_claimed': False,
              'private_original_backups_or_owner_inputs_read': False}
    if packet_change:
        packet_change(packet)
    packet_raw = d.encoded(packet)
    blobs = {'data.tar': archive_raw, 'DATA-INVENTORY.json': inventory_raw, 'PACKET.json': packet_raw}
    artifacts['PACKET.json'] = {'name': 'PACKET.json', 'origin_url': PREFIX + 'PACKET.json',
                               'bytes': len(packet_raw), 'sha256': d.sha(packet_raw)}
    sums = ''.join(artifacts[name]['sha256'] + '  ' + name + '\n' for name in d.ASSETS[:3]).encode()
    blobs['SHA256SUMS'] = sums
    artifacts['SHA256SUMS'] = {'name': 'SHA256SUMS', 'origin_url': PREFIX + 'DATA-SHA256SUMS',
                             'bytes': len(sums), 'sha256': d.sha(sums)}
    return blobs, artifacts


def write_fixture(root, blobs):
    downloads = root / 'downloads'
    downloads.mkdir()
    for name, raw in blobs.items():
        (downloads / name).write_bytes(raw)
    return downloads


class PublicDataDownloadControls(unittest.TestCase):
    def verify(self, **changes):
        blobs, artifacts = fixture(**changes)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            members, pages = d.verify_downloads(write_fixture(root, blobs), root / 'data', artifacts)
            self.assertEqual((root / 'data/public/empty.bin').read_bytes(), b'')
            self.assertFalse((root / 'audit-only').exists())
            return members, pages

    def test_exact_inventory_pages_finite_timing_empty_file_and_concatenated_gzip(self):
        members, pages = self.verify()
        self.assertEqual(len(members), 16)
        self.assertEqual(len(pages), 2)
        self.assertIn((len(DECODED), d.sha(DECODED)),
                      [(row['decoded_bytes'], row['decoded_sha256']) for row in pages])
        self.assertIn((3, d.sha(b'[]\n')),
                      [(row['decoded_bytes'], row['decoded_sha256']) for row in pages])

    def test_duplicate_JSON_and_nonfinite_numbers_refused(self):
        for raw in [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                d.parse(raw)
        self.assertEqual(d.parse(b'{"seconds":0.125}'), {'seconds': 0.125})
        for value in [False, True, -1, 1.0, 1 << 64]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                d.uint(value)

    def test_root_selection_requires_four_exact_same_release_origins(self):
        _, artifacts = fixture()
        value = {'schema': 'kpxa-root-public-recovery-data-download-selection/v1',
                 'domain_hex32': d.DOMAIN, 'artifacts': list(artifacts.values())}
        self.assertEqual(set(d.selection(d.encoded(value))), set(d.ASSETS))
        for mutation in [lambda v: v['artifacts'].pop(),
                         lambda v: v['artifacts'][0].update(bytes=True),
                         lambda v: v['artifacts'][0].update(origin_url=PREFIX + 'data.tar?token=fixture'),
                         lambda v: v['artifacts'][0].update(origin_url=PREFIX.replace('public-fixture', 'different') + 'data.tar'),
                         lambda v: v['artifacts'][0].update(origin_url='file:///public/data.tar')]:
            changed = copy.deepcopy(value)
            mutation(changed)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                d.selection(d.encoded(changed))

    def test_TLS_redirect_scope_is_exact_and_credentials_queries_stay_in_stdin(self):
        origins = {PREFIX + d.REMOTE_NAMES[name] for name in d.ASSETS}
        signed = 'https://release-assets.githubusercontent.com/github-production-release-asset/1/fixture?sig=public-token'
        self.assertEqual(d.safe_url(signed, origins), signed)
        for value in ['http://github.com/a', PREFIX + 'other.tar', PREFIX + 'data.tar?token=fixture',
                      'https://user:pass@github.com/a', 'https://github.com:443/a',
                      signed + '#fragment', signed.replace('githubusercontent.com', 'githubusercontent.com.evil.invalid'),
                      'https://release-assets.githubusercontent.com/other/a']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                d.safe_url(value, origins)
        calls, body = [], b'public downloaded fixture'
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            class Result:
                returncode = 0
            result = Result()
            if len(calls) == 1:
                result.stdout = ('HTTP/2 302\r\nLocation: ' + signed + '\r\n\r\n302').encode()
            else:
                os.write(kwargs['pass_fds'][0], body)
                result.stdout = b'HTTP/2 200\r\n\r\n200'
            return result
        with tempfile.TemporaryDirectory() as temporary, patch.object(d.subprocess, 'run', run):
            d.download(PREFIX + 'data.tar', Path(temporary) / 'data.tar', len(body), d.sha(body), origins)
        self.assertEqual(len(calls), 2)
        for argv, kwargs in calls:
            self.assertEqual(argv[:2], ['/usr/bin/curl', '-q'])
            self.assertEqual(argv[argv.index('--socks5-hostname') + 1], '127.0.0.1:19050')
            self.assertEqual(argv[argv.index('--noproxy') + 1], '')
            self.assertEqual(kwargs['env'], {'PATH': '/usr/bin:/bin'})
            self.assertFalse(any('sig=' in value or '<torS0X>' in value for value in argv))
            for flag in ['-L', '--location', '--retry', '--insecure', '-k', '--netrc']:
                self.assertNotIn(flag, argv)
        self.assertIn(signed.encode(), calls[1][1]['input'])
        self.assertNotEqual(calls[0][1]['input'].split(b'proxy-user')[1], calls[1][1]['input'].split(b'proxy-user')[1])

    def test_ambiguous_redirect_and_proxy_failure_have_no_retry_or_receipt(self):
        with self.assertRaises(ValueError):
            d.response_location(b'HTTP/2 302\r\nLocation: a\r\nLocation: b\r\n\r\n302')
        class Failure:
            returncode = 7
        with tempfile.TemporaryDirectory() as temporary, patch.object(d.subprocess, 'run', return_value=Failure()) as run:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                d.download(PREFIX + 'data.tar', root / 'data.tar', 1, d.sha(b'x'), {PREFIX + 'data.tar'})
            self.assertEqual(run.call_count, 1)
            self.assertFalse((root / 'DATA-DOWNLOAD-RECEIPT.json').exists())

    def test_external_artifact_pin_corruption_fails(self):
        blobs, artifacts = fixture()
        blobs['PACKET.json'] += b' '
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                d.verify_downloads(write_fixture(root, blobs), root / 'data', artifacts)

    def test_authenticated_sums_must_exactly_match_three_artifacts(self):
        blobs, artifacts = fixture()
        blobs['SHA256SUMS'] += b'\n'
        artifacts['SHA256SUMS'].update(bytes=len(blobs['SHA256SUMS']), sha256=d.sha(blobs['SHA256SUMS']))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                d.verify_downloads(write_fixture(root, blobs), root / 'data', artifacts)

    def test_inventory_paths_duplicates_order_counts_and_reserved_names_refused(self):
        mutations = [lambda v: v['files'][0].update(path='../outside'),
                     lambda v: v['files'][0].update(path='/absolute'),
                     lambda v: v['files'][0].update(path='audit-only/page'),
                     lambda v: v['files'][0].update(path='PACKET.json'),
                     lambda v: v['files'].append(v['files'][0]),
                     lambda v: v['files'].reverse(),
                     lambda v: v.update(file_count=True),
                     lambda v: v.update(payload_bytes=v['payload_bytes'] + 1),
                     lambda v: v['files'][0].update(bytes=True),
                     lambda v: v['files'][0].update(sha256=d.sha(b'substitution'))]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.verify(inventory_change=mutation)
        with self.assertRaises(ValueError):
            d.member_paths(['public/a', 'public/a/child'])

    def test_tar_modes_links_traversal_extensions_and_extra_members_refused(self):
        def mode(member):
            member.mode = 0o500
        def link(member):
            member.type, member.linkname, member.size = tarfile.SYMTYPE, '/unmounted/private', 0
        def traversal(member):
            member.name = '../outside'
        def extension(member):
            member.type, member.size = tarfile.XHDTYPE, 0
        for mutation in [mode, link, traversal, extension]:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.verify(member_change=mutation)
        for change in [lambda raw: raw + b'nonzero',
                       lambda raw: raw + bytes(tarfile.RECORDSIZE),
                       lambda raw: raw[:-1],
                       lambda raw: raw[:512] + raw,
                       lambda raw: raw[:100] + b'X' + raw[101:]]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify(tar_change=change)

    def test_packet_roles_domain_and_evidence_boundaries_refused_on_mismatch(self):
        for mutation in [lambda v: v.update(domain_hex32='0' * 64),
                         lambda v: v['roles']['history'].update(sha256='0' * 64),
                         lambda v: v['archive'].update(members=True),
                         lambda v: v.update(decoded_pages_in_archive=True),
                         lambda v: v['declared_terminal_shape'].update(reserve_sompi=False)]:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.verify(packet_change=mutation)

    def test_both_page_arrays_and_packet_map_must_match(self):
        for mutation in [lambda v: v['current_view']['post_query_delta'].update(pages=[]),
                         lambda v: v['pages'].append(dict(v['pages'][0])),
                         lambda v: v['pages'][0].update(path='../outside'),
                         lambda v: v['pages'][0].update(decoded_bytes=True),
                         lambda v: v['pages'][0].update(gzip_sha256='0' * 64)]:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.verify(fetch_change=mutation)
        with self.assertRaises(ValueError):
            self.verify(extra_page=True)
        with self.assertRaises(ValueError):
            self.verify(packet_change=lambda v: v['pages'].pop())

    def test_all_gzip_members_lengths_hashes_truncation_and_trailing_data(self):
        for raw in [gzip.compress(DECODED, mtime=0) + b'non-gzip',
                    gzip.compress(DECODED, mtime=0)[:-3],
                    gzip.compress(DECODED + b'extra', mtime=0),
                    gzip.compress(b'wrong bytes', mtime=0)]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.verify(page_blob=raw)

    def test_mock_acquisition_receipt_is_data_specific_and_only_after_verification(self):
        blobs, artifacts = fixture()
        def fake_download(origin, target, size, expected, origins, port):
            target.write_bytes(blobs[target.name])
        with tempfile.TemporaryDirectory() as temporary, patch.object(d, 'download', fake_download), patch('builtins.print'):
            root = Path(temporary)
            d.acquire(root, root, artifacts, 19050)
            receipt = d.parse((root / 'DATA-DOWNLOAD-RECEIPT.json').read_bytes())
            self.assertEqual(set(receipt), {'schema', 'classification', 'transport', 'inventory', 'packet', 'artifacts', 'files', 'pages'})
            self.assertEqual(receipt['schema'], d.RECEIPT_SCHEMA)
            self.assertEqual(receipt['classification'], d.CLASSIFICATION)
            self.assertEqual(receipt['transport'], 'TOR_SOCKS5H_TLS')
            self.assertEqual(len(receipt['artifacts']), 4)
            self.assertEqual(len(receipt['files']), 16)
            self.assertEqual(len(receipt['pages']), 2)
            self.assertTrue(all(set(row['decoded']) == {'bytes', 'sha256', 'retained'}
                                and row['decoded']['retained'] is False for row in receipt['pages']))
            self.assertFalse((root / 'audit-only').exists())
            self.assertFalse((root / 'DOWNLOAD-RECEIPT.json').exists())
        bad, artifacts = fixture(page_blob=b'not gzip')
        def bad_download(origin, target, size, expected, origins, port):
            target.write_bytes(bad[target.name])
        with tempfile.TemporaryDirectory() as temporary, patch.object(d, 'download', bad_download), patch('builtins.print'):
            root = Path(temporary)
            with self.assertRaises(ValueError):
                d.acquire(root, root, artifacts, 19050)
            self.assertFalse((root / 'DATA-DOWNLOAD-RECEIPT.json').exists())

    def test_sandbox_mounts_only_runtime_reviewed_source_selection_and_fresh_output(self):
        command = d.sandbox_command(Path('/reviewed-source.py'), Path('/reviewed-selection.json'),
                                    Path('/fresh-output'), Path('/host-root'), 19050)
        mounts = [command[i + 1] for i, value in enumerate(command) if value in {'--bind', '--ro-bind'}]
        self.assertEqual(set(mounts), {'/usr', '/lib', '/lib64', '/etc/ssl/certs', '/etc/ld.so.cache',
                                      '/reviewed-source.py', '/reviewed-selection.json', '/fresh-output'})
        self.assertIn('--unshare-pid', command)
        self.assertIn('--unshare-user', command)
        self.assertNotIn('/', mounts)
        self.assertFalse(any(value.startswith('/home/') or 'private' in value for value in mounts))


if __name__ == '__main__':
    unittest.main()
