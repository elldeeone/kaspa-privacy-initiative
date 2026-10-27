"""Public synthetic multipart controls; no actual release acquisition."""
import copy
import gzip
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

import recovery_data_multipart as m
from test_recovery_data_download import fixture, PREFIX, DECODED

b = m.get_base()


def multipart_fixture(**changes):
    blobs, artifacts = fixture(**changes)
    archive = blobs.pop('data.tar')
    part_bytes = 4096  # Deliberately small public fixture, not a production limit.
    parts = []
    for index, offset in enumerate(range(0, len(archive), part_bytes)):
        name = 'data.tar.part-%05d' % index
        raw = archive[offset:offset + part_bytes]
        blobs[name] = raw
        parts.append({'name': name, 'origin_url': PREFIX + name, 'bytes': len(raw), 'sha256': b.sha(raw)})
    value = {'schema': m.ROOT_SCHEMA, 'domain_hex32': m.DOMAIN, 'part_bytes': part_bytes,
             'archive': {'name': 'data.tar', 'bytes': len(archive), 'sha256': b.sha(archive)},
             'parts': parts, 'artifacts': [artifacts[name] for name in m.METADATA]}
    return archive, blobs, value


def fake_transport(blobs, calls):
    def download(origin, destination, size, expected, origins, proxy_port):
        calls.append((origin, destination.name))
        b.safe_url(origin, origins, initial=True)
        raw = blobs[origin.rsplit('/', 1)[1]]
        b.save_new(destination, raw)
        b.authenticate_file(destination, size, expected)
    # Remote alias and local sums name differ deliberately.
    blobs = {**blobs, 'DATA-SHA256SUMS': blobs['SHA256SUMS']}
    return download


class MultipartPublicDataControls(unittest.TestCase):
    def test_tmpfs_or_disk_output_requires_exact_owned0700_parent_and_fresh_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / 'approved-tmpfs-parent'
            with patch.object(m, 'TMPFS_OUTPUT_BASE', parent):
                output = parent / 'acquisition-01'
                self.assertEqual(m.validate_output(output, create_parent=True), output)
                self.assertEqual(parent.stat().st_mode & 0o7777, 0o700)
                for name in ['acquisition-1', 'acquisition-001', 'other-01']:
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        m.validate_output(parent / name)
                with self.assertRaises(ValueError):
                    m.validate_output(Path(temporary) / 'other-parent/acquisition-01')
                for mode in [0o755, 0o777, 0o1700]:
                    parent.chmod(mode)
                    with self.subTest(mode=mode), self.assertRaises(ValueError):
                        m.validate_output(output)
                parent.chmod(0o700)
                real_lstat = Path.lstat
                def wrong_owner(path):
                    if path == parent:
                        info = real_lstat(path)
                        return types.SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1)
                    return real_lstat(path)
                with patch.object(Path, 'lstat', wrong_owner), self.assertRaises(ValueError):
                    m.validate_output(output)
                output.mkdir()
                with self.assertRaises(ValueError):
                    m.validate_output(output)
                output.rmdir()
                output.symlink_to(parent / 'nonexistent-target')
                with self.assertRaises(ValueError):
                    m.validate_output(output)
                output.unlink()
                link = Path(temporary) / 'linked-parent'
                link.symlink_to(parent, target_is_directory=True)
                with patch.object(m, 'TMPFS_OUTPUT_BASE', link), self.assertRaises(ValueError):
                    m.validate_output(link / 'acquisition-01')

    def test_capacity_preflight_accounts_for_archive_extraction_and_one_part(self):
        _, _, value = multipart_fixture()
        required = (2 * value['archive']['bytes'] + min(value['part_bytes'], value['archive']['bytes'])
                    + sum(row['bytes'] for row in value['artifacts']) + (1 << 20))
        for available in [0, required - 1]:
            space = types.SimpleNamespace(f_bavail=available, f_frsize=1)
            with patch.object(m.os, 'statvfs', return_value=space), self.assertRaises(ValueError):
                m.capacity_preflight(Path('/public-fixture'), value)
        with patch.object(m.os, 'statvfs', return_value=types.SimpleNamespace(f_bavail=required, f_frsize=1)):
            self.assertEqual(m.capacity_preflight(Path('/public-fixture'), value),
                             {'available_bytes': required, 'required_bytes': required})

    def test_exact_partition_pins_and_order_are_required(self):
        _, _, value = multipart_fixture()
        selected = m.selection(b.encoded(value))
        self.assertEqual(selected['archive'], value['archive'])
        mutations = [lambda v: v['parts'].reverse(),
                     lambda v: v['parts'].pop(),
                     lambda v: v['parts'].append(v['parts'][0]),
                     lambda v: v['parts'][0].update(name='data.tar.part-00001'),
                     lambda v: v['parts'][0].update(bytes=v['part_bytes'] - 1),
                     lambda v: v.update(part_bytes=False),
                     lambda v: v.update(part_bytes=1 << 31),
                     lambda v: v['archive'].update(bytes=True),
                     lambda v: v['archive'].update(name='other.tar'),
                     lambda v: v['artifacts'].pop(),
                     lambda v: v['artifacts'][0].update(bytes=1 << 31),
                     lambda v: v['parts'][0].update(sha256='bad')]
        for mutation in mutations:
            changed = copy.deepcopy(value)
            mutation(changed)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                m.selection(b.encoded(changed))

    def test_remote_origin_scope_alias_and_release_must_match(self):
        _, _, value = multipart_fixture()
        for mutation in [lambda v: v['parts'][0].update(origin_url='file:///local/archive'),
                         lambda v: v['parts'][0].update(origin_url=PREFIX + v['parts'][0]['name'] + '?token=fixture'),
                         lambda v: v['parts'][0].update(origin_url=PREFIX.replace('public-fixture', 'other') + v['parts'][0]['name']),
                         lambda v: v['artifacts'][-1].update(origin_url=PREFIX + 'SHA256SUMS'),
                         lambda v: v['parts'][0].update(origin_url='https://user:pass@github.com/a')]:
            changed = copy.deepcopy(value)
            mutation(changed)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                m.selection(b.encoded(changed))

    def test_same_pinned_transport_preserves_TorTLS_redirect_controls_for_parts(self):
        _, _, value = multipart_fixture()
        origins = {row['origin_url'] for row in value['parts'] + value['artifacts']}
        body, calls = b'public part', []
        signed = 'https://release-assets.githubusercontent.com/github-production-release-asset/1/fixture?sig=fixture-token'
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
        with tempfile.TemporaryDirectory() as temporary, patch.object(b.subprocess, 'run', run):
            b.download(value['parts'][0]['origin_url'], Path(temporary) / 'part.tmp', len(body), b.sha(body), origins)
        self.assertEqual(len(calls), 2)
        for argv, kwargs in calls:
            self.assertEqual(argv[argv.index('--socks5-hostname') + 1], '127.0.0.1:19050')
            self.assertEqual(kwargs['env'], {'PATH': '/usr/bin:/bin'})
            self.assertEqual(argv[argv.index('--noproxy') + 1], '')
            self.assertFalse(any('sig=' in item for item in argv))
            for flag in ['-L', '--retry', '--insecure', '--netrc']:
                self.assertNotIn(flag, argv)
        self.assertIn(signed.encode(), calls[1][1]['input'])

    def test_assembled_exact_archive_uses_one_ephemeral_part_and_no_part_copies(self):
        archive, blobs, value = multipart_fixture()
        plan = m.selection(b.encoded(value))
        calls, seen = [], []
        download = fake_transport(blobs, calls)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def bounded_download(*args):
                self.assertFalse((root / 'part-in-progress.tmp').exists())
                self.assertFalse(list(root.glob('data.tar.part-*')))
                download(*args)
                seen.append((root / 'part-in-progress.tmp').stat().st_size)
            with patch.object(b, 'download', bounded_download), patch('builtins.print'):
                m.assemble_parts(root / 'data.tar', plan, {row['origin_url'] for row in plan['parts']}, 19050)
            self.assertEqual((root / 'data.tar').read_bytes(), archive)
            self.assertEqual((root / 'data.tar').stat().st_mode & 0o777, 0o400)
            self.assertFalse((root / 'part-in-progress.tmp').exists())
            self.assertEqual(list(root.iterdir()), [root / 'data.tar'])
        self.assertEqual(len(calls), len(plan['parts']))
        self.assertLessEqual(max(seen), plan['part_bytes'])

    def test_success_receipt_distinguishes_network_parts_and_retained_archive(self):
        archive, blobs, value = multipart_fixture()
        plan = m.selection(b.encoded(value))
        calls = []
        with tempfile.TemporaryDirectory() as temporary, patch.object(b, 'download', fake_transport(blobs, calls)), patch('builtins.print'):
            root = Path(temporary)
            m.acquire(root, root, plan, 19050)
            receipt = b.parse((root / 'MULTIPART-DATA-DOWNLOAD-RECEIPT.json').read_bytes())
            self.assertEqual(set(receipt), {'schema', 'classification', 'transport', 'archive', 'inventory', 'packet', 'artifacts', 'files', 'pages'})
            self.assertEqual(receipt['schema'], m.RECEIPT_SCHEMA)
            self.assertEqual(receipt['classification'], m.CLASSIFICATION)
            self.assertEqual(receipt['transport'], 'TOR_SOCKS5H_TLS')
            self.assertEqual(receipt['archive']['sha256'], b.sha(archive))
            self.assertEqual(receipt['archive']['parts'], [row['name'] for row in plan['parts']])
            self.assertEqual(len(receipt['artifacts']), len(plan['parts']) + 3)
            self.assertEqual(len(receipt['files']), 16)
            self.assertEqual(len(receipt['pages']), 2)
            for row in receipt['artifacts'][:3]:
                self.assertIs(row['retained'], True)
                self.assertTrue(Path(row['path']).is_file())
            for row in receipt['artifacts'][3:]:
                self.assertIs(row['retained'], False)
                self.assertNotIn('path', row)
            self.assertFalse(any(row['name'] == 'data.tar' for row in receipt['artifacts']))
            self.assertTrue(all(row['decoded']['retained'] is False and 'path' not in row['decoded'] for row in receipt['pages']))
            self.assertFalse((root / 'audit-only').exists())
            self.assertFalse((root / 'downloads/part-in-progress.tmp').exists())
            self.assertFalse((root / 'DATA-DOWNLOAD-RECEIPT.json').exists())
            self.assertFalse((root / 'DOWNLOAD-RECEIPT.json').exists())

    def test_proxy_failure_no_retry_fallback_or_receipt(self):
        _, _, value = multipart_fixture()
        plan = m.selection(b.encoded(value))
        class Failure:
            returncode = 7
        with tempfile.TemporaryDirectory() as temporary, patch.object(b.subprocess, 'run', return_value=Failure()) as run:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                m.acquire(root, root, plan, 19050)
            self.assertEqual(run.call_count, 1)
            self.assertFalse((root / 'MULTIPART-DATA-DOWNLOAD-RECEIPT.json').exists())

    def test_corrupt_part_and_inconsistent_whole_pin_fail_before_tar_parse(self):
        for change in ['part', 'whole']:
            _, blobs, value = multipart_fixture()
            if change == 'part':
                name = value['parts'][0]['name']
                blobs[name] = b'X' + blobs[name][1:]
            else:
                value['archive']['sha256'] = b.sha(b'wrong whole archive')
                # Keep metadata declaration joined so the whole concat check,
                # not early PACKET consistency, is the decisive failure.
                packet = b.parse(blobs['PACKET.json'])
                packet['archive']['sha256'] = value['archive']['sha256']
                blobs['PACKET.json'] = b.encoded(packet)
                value['artifacts'][1].update(bytes=len(blobs['PACKET.json']), sha256=b.sha(blobs['PACKET.json']))
            plan = m.selection(b.encoded(value))
            with tempfile.TemporaryDirectory() as temporary, patch.object(b, 'download', fake_transport(blobs, [])), patch.object(b, 'verify_downloads') as verify, patch('builtins.print'):
                root = Path(temporary)
                with self.assertRaises(ValueError):
                    m.acquire(root, root, plan, 19050)
                verify.assert_not_called()
                self.assertFalse((root / 'MULTIPART-DATA-DOWNLOAD-RECEIPT.json').exists())

    def test_base_tar_page_and_gzip_rejections_remain_enforced(self):
        cases = [{'page_blob': b'not gzip'},
                 {'page_blob': gzip.compress(b'wrong decoded bytes', mtime=0)},
                 {'page_blob': gzip.compress(DECODED, mtime=0) + b'non-gzip'},
                 {'page_blob': gzip.compress(DECODED, mtime=0)[:-3]},
                 {'fetch_change': lambda v: v['current_view']['post_query_delta'].update(pages=[])},
                 {'packet_change': lambda v: v['roles']['history'].update(sha256='0' * 64)},
                 {'tar_change': lambda raw: raw + b'nonzero'}]
        for change in cases:
            _, blobs, value = multipart_fixture(**change)
            plan = m.selection(b.encoded(value))
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary, patch.object(b, 'download', fake_transport(blobs, [])), patch('builtins.print'):
                root = Path(temporary)
                with self.assertRaises(ValueError):
                    m.acquire(root, root, plan, 19050)
                self.assertFalse((root / 'MULTIPART-DATA-DOWNLOAD-RECEIPT.json').exists())

    def test_nonempty_acquisition_root_refused_without_network(self):
        _, _, value = multipart_fixture()
        with tempfile.TemporaryDirectory() as temporary, patch.object(b, 'download') as download:
            root = Path(temporary)
            (root / 'existing-public-file').write_bytes(b'fixture')
            with self.assertRaises(ValueError):
                m.acquire(root, root, m.selection(b.encoded(value)), 19050)
            download.assert_not_called()

    def test_base_dependency_must_match_frozen_whole_source_pin(self):
        with patch.object(m, '_base', None), patch.object(m.runpy, 'run_path', return_value={'read': lambda *args: b'raise RuntimeError("must not execute")'}):
            with self.assertRaises(ValueError):
                m.get_base()

    def test_empty_filesystem_mounts_only_public_runtime_two_sources_selection_output(self):
        command = m.sandbox_command(Path('/multipart.py'), Path('/base.py'), Path('/selection.json'),
                                    Path('/fresh-output'), Path('/host-root'), 19050)
        mounts = [command[i + 1] for i, item in enumerate(command) if item in {'--bind', '--ro-bind'}]
        self.assertEqual(set(mounts), {'/usr', '/lib', '/lib64', '/etc/ssl/certs', '/etc/ld.so.cache',
                                      '/multipart.py', '/base.py', '/selection.json', '/fresh-output'})
        self.assertIn('--unshare-pid', command)
        self.assertNotIn('/', mounts)
        self.assertFalse(any(item.startswith('/home/') or 'private' in item for item in mounts))


if __name__ == '__main__':
    unittest.main()
