import copy
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from software_bundle import Invalid, digest, encoded, restore
from unpack_bundle import unpack


class UnpackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.counter = 0
        payload = {'runtime/prover': b'\x7fELF PUBLIC INERT NEVER EXECUTE',
                   'prover/Cargo.toml': b'PUBLIC INERT BUILD SOURCE'}
        files = [{'path': name, 'kind': 'selected-executable' if name.startswith('runtime/') else 'source',
                  'bytes': len(raw), 'sha256': digest(raw)} for name, raw in sorted(payload.items())]
        software = {'schema': 'kpx4-public-software-bundle/v1',
                    'classification': 'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY', 'files': files}
        payload.update({'SOFTWARE-BUNDLE.json': encoded(software),
                        'EXTERNAL-SELECTION.json': b'{"PUBLIC_FIXTURE_ONLY":true}',
                        'DEPENDENCY-ACQUISITION.json': b'{"PUBLIC_FIXTURE_ONLY":true}'})
        self.payload = payload
        self.rows = sorted(files + [{'path': name, 'kind': 'public-metadata',
                                    'bytes': len(payload[name]), 'sha256': digest(payload[name])}
                                   for name in payload if name not in {row['path'] for row in files}],
                           key=lambda row: row['path'])
        self.software_sha = digest(encoded(software))
        self.members = {'schema': 'kpx4-software-archive-members/v1',
            'typed_software_inventory_sha256': self.software_sha,
            'contains_backup_PK_private_witness_history_or_controller_plan': False, 'members': self.rows}

    def tearDown(self):
        self.temp.cleanup()

    def tar(self, mutate=None, *, duplicate=False, extra=False, format=tarfile.USTAR_FORMAT):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w', format=format) as output:
            for i, row in enumerate(self.rows):
                info = tarfile.TarInfo(row['path'])
                info.size = row['bytes']; info.mode = 0o500 if row['kind'] == 'selected-executable' else 0o400
                info.uid = info.gid = info.mtime = 0; info.uname = info.gname = ''
                if mutate and i == len(self.rows) - 1: mutate(info)
                raw = self.payload[row['path']]
                if info.type != tarfile.REGTYPE:
                    info.size = 0
                output.addfile(info, io.BytesIO(raw))
            if duplicate:
                info = tarfile.TarInfo(self.rows[-1]['path']);info.size = len(raw);info.mode = 0o500
                output.addfile(info, io.BytesIO(raw))
            if extra:
                info = tarfile.TarInfo('UNLISTED');info.size = 1;info.mode = 0o400
                output.addfile(info, io.BytesIO(b'X'))
        return data.getvalue()

    def inputs(self, raw_tar=None, members=None, compressed_override=None):
        self.counter += 1
        case = self.base / ('case-' + str(self.counter)); case.mkdir()
        raw_tar = self.tar() if raw_tar is None else raw_tar
        compressed = subprocess.run(['/usr/bin/zstd', '-q', '-c'], input=raw_tar,
                                    capture_output=True, check=True).stdout
        if compressed_override is not None: compressed = compressed_override
        archive = case / 'public.tar.zst';archive.write_bytes(compressed)
        member_file = case / 'members.json';member_raw = encoded(self.members if members is None else members)
        member_file.write_bytes(member_raw)
        return [archive, member_file, digest(compressed), len(compressed), digest(member_raw),
                self.software_sha, case / 'unpacked']

    def test_valid_exact_restore_no_execution_then_separate_typed_restore(self):
        args = self.inputs()
        result = unpack(*args)
        self.assertEqual(result['members_restored'], len(self.rows))
        self.assertFalse(result['payload_executed_or_imported'])
        self.assertFalse(result['spend_authorized'])
        target = self.base / 'typed'
        raw = (args[-1] / 'SOFTWARE-BUNDLE.json').read_bytes()
        result = restore(args[-1], raw, self.software_sha, target)
        self.assertEqual(result['files_verified'], 2)
        self.assertFalse((target / 'EXTERNAL-SELECTION.json').exists())
        self.assertEqual((target / 'runtime/prover').stat().st_mode & 0o777, 0o500)

    def test_wrong_archive_pin_before_decompress(self):
        args = self.inputs();args[2] = '00' * 32
        with patch('unpack_bundle.subprocess.Popen') as child:
            with self.assertRaisesRegex(Invalid, '^external-archive-pin$'): unpack(*args)
            child.assert_not_called()

    def test_wrong_member_or_typed_inventory_pin(self):
        args = self.inputs();args[4] = '00' * 32
        with self.assertRaisesRegex(Invalid, '^external-member-list-pin$'): unpack(*args)
        args = self.inputs();args[5] = '00' * 32
        with self.assertRaisesRegex(Invalid, '^archive-member-list-schema$'): unpack(*args)

    def test_declared_backup_hardlink_alias_before_any_content_open(self):
        args = self.inputs();backup = self.base / 'PUBLIC-NONSEED-SENTINEL';os.link(args[0], backup)
        with patch('software_bundle.os.open') as opened:
            with self.assertRaisesRegex(Invalid, '^public-private-inode-alias$'):
                unpack(*args, forbidden_inputs=(value for value in [backup]))
            opened.assert_not_called()

    def test_member_inventory_backup_alias_before_archive_read(self):
        args = self.inputs();backup = self.base / 'PUBLIC-MEMBER-SENTINEL';os.link(args[1], backup)
        with patch('software_bundle.os.open') as opened:
            with self.assertRaisesRegex(Invalid, '^public-private-inode-alias$'):
                unpack(*args, forbidden_inputs=(value for value in [backup]))
            opened.assert_not_called()

    def test_member_path_traversal_absolute_and_aliases(self):
        for value in ('../escape', '/absolute', './runtime/prover', 'runtime//prover', 'runtime/../escape'):
            with self.subTest(path=value):
                members = copy.deepcopy(self.members);members['members'][-1]['path'] = value
                with self.assertRaisesRegex(Invalid, '^unsafe-relative-path$'):
                    unpack(*self.inputs(members=members))

    def test_symlink_hardlink_and_directory_headers(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE):
            with self.subTest(kind=kind):
                def mutate(info): info.type = kind;info.linkname = '../PUBLIC-NONSEED'
                with self.assertRaisesRegex(Invalid, '^tar-links-directories-or-extensions-forbidden$'):
                    unpack(*self.inputs(self.tar(mutate)))

    def test_duplicate_effective_path_and_unlisted_member(self):
        for options in ({'duplicate': True}, {'extra': True}):
            with self.subTest(options=options), self.assertRaisesRegex(Invalid, '^unlisted-or-duplicate-tar-member$'):
                unpack(*self.inputs(self.tar(**options)))

    def test_duplicate_member_selection(self):
        members = copy.deepcopy(self.members);members['members'].append(members['members'][0])
        with self.assertRaisesRegex(Invalid, '^duplicate-archive-member-selection$'):
            unpack(*self.inputs(members=members))

    def test_member_digest_and_header_size_mismatch(self):
        members = copy.deepcopy(self.members);members['members'][-1]['sha256'] = '00' * 32
        with self.assertRaisesRegex(Invalid, '^tar-member-digest-or-length$'):
            unpack(*self.inputs(members=members))
        def shorter(info): info.size -= 1
        with self.assertRaisesRegex(Invalid, '^noncanonical-tar-member-metadata$'):
            unpack(*self.inputs(self.tar(shorter)))

    def test_corrupt_header_checksum(self):
        raw = bytearray(self.tar());raw[0] ^= 1
        with self.assertRaisesRegex(Invalid, '^invalid-public-tar$'):
            unpack(*self.inputs(bytes(raw)))

    def test_pax_extension_and_gnu_longname_not_allowed(self):
        def pax(info): info.pax_headers = {'comment': 'PUBLIC INERT EXTENSION'}
        with self.assertRaisesRegex(Invalid, '^tar-links-directories-or-extensions-forbidden$'):
            unpack(*self.inputs(self.tar(pax, format=tarfile.PAX_FORMAT)))
        ustar = self.tar()
        with tarfile.open(fileobj=io.BytesIO(ustar)) as source:
            original_last = source.getmembers()[-1].offset
        original = self.rows[-1]['path']
        long_name = 'runtime/' + 'A' * 120
        self.payload[long_name] = self.payload.pop(original)
        self.rows[-1]['path'] = long_name
        gnu = self.tar(format=tarfile.GNU_FORMAT)
        with tarfile.open(fileobj=io.BytesIO(gnu)) as source:
            last = source.getmembers()[-1]
            segment = gnu[last.offset:last.offset_data + ((last.size + 511) // 512) * 512]
        # Keep every earlier header canonical so this tests the actual extension.
        mixed = ustar[:original_last] + segment
        mixed += bytes(((len(mixed) + 1024 + 10239) // 10240) * 10240 - len(mixed))
        with self.assertRaisesRegex(Invalid, '^tar-links-directories-or-extensions-forbidden$'):
            unpack(*self.inputs(mixed))

    def test_noncanonical_header_with_valid_checksum(self):
        raw = bytearray(self.tar())
        header = bytearray(raw[:512])
        end = header.index(0)
        header[end + 1:end + 12] = b'PUBLIC_JUNK'
        header[148:156] = b'        '
        header[148:156] = ('%06o\0 ' % sum(header)).encode('ascii')
        raw[:512] = header
        with self.assertRaisesRegex(Invalid, '^noncanonical-ustar-header$'):
            unpack(*self.inputs(bytes(raw)))

    def test_truncated_compressed_and_tar_stream(self):
        compressed = subprocess.run(['/usr/bin/zstd', '-q', '-c'], input=self.tar(), capture_output=True).stdout
        with self.assertRaisesRegex(Invalid, '^incomplete-or-noncanonical-tar$'):
            unpack(*self.inputs(compressed_override=compressed[:-8]))
        with self.assertRaisesRegex(Invalid, '^incomplete-or-noncanonical-tar$'):
            unpack(*self.inputs(self.tar()[:1024]))

    def test_hidden_second_tar_or_overlong_uncompressed_stream(self):
        with self.assertRaisesRegex(Invalid, '^noncanonical-or-overlong-tar$'):
            unpack(*self.inputs(self.tar() + self.tar()))

    def test_nonzero_trailing_padding(self):
        raw = bytearray(self.tar());raw[-1] = 1
        with self.assertRaisesRegex(Invalid, '^trailing-tar-or-nonzero-padding$'):
            unpack(*self.inputs(bytes(raw)))

    def test_hidden_empty_global_header_and_file_padding(self):
        raw = self.tar()
        hidden = tarfile.TarInfo('PUBLIC_EMPTY_GLOBAL_HEADER')
        hidden.type = tarfile.XGLTYPE; hidden.size = 0
        header = hidden.tobuf(format=tarfile.USTAR_FORMAT)
        with self.assertRaisesRegex(Invalid, '^skipped-or-noncontiguous-tar-header$'):
            unpack(*self.inputs(header + raw[:-512]))
        with tarfile.open(fileobj=io.BytesIO(raw)) as source:
            first = source.getmembers()[0]
        changed = bytearray(raw);changed[first.offset_data + first.size] = 1
        with self.assertRaisesRegex(Invalid, '^nonzero-tar-file-padding$'):
            unpack(*self.inputs(bytes(changed)))

    def test_unhashable_kind_is_fixed_typed_rejection(self):
        members = copy.deepcopy(self.members);members['members'][-1]['kind'] = {}
        with self.assertRaisesRegex(Invalid, '^archive-member-selection-types$'):
            unpack(*self.inputs(members=members))

    def test_existing_output_or_symlink_parent(self):
        args = self.inputs();args[-1].mkdir()
        with self.assertRaisesRegex(Invalid, '^fresh-unpack-output-required$'): unpack(*args)
        (self.base / 'linked').symlink_to(self.base, target_is_directory=True)
        args[-1] = self.base / 'linked/other'
        with self.assertRaisesRegex(Invalid, '^public-symlink$'): unpack(*args)


if __name__ == '__main__':
    unittest.main(verbosity=2)
