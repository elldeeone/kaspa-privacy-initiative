"""Public synthetic guard and real minimal-namespace controls; no GPU proving."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock

import outer


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class OuterTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='kpx8-public-outer-controls-')
        self.base = Path(self.directory.name)
        self.private = self.base / 'declared-synthetic-private'
        self.private.mkdir()
        self.guard = outer.Guard([self.private], required=[self.private])

    def tearDown(self):
        self.directory.cleanup()

    def leaf(self, name, raw):
        p = self.base / name
        p.write_bytes(raw)
        return p

    def module(self):
        return outer.helper(self.guard)

    def job(self, op='execute', host=None):
        program = self.leaf('program-fixture', b'PUBLIC-SYNTHETIC-NOT-A-GUEST')
        projection = self.leaf('projection-fixture', b'\x11' * 10973)
        component = '22' * 32
        image = '33' * 32
        journal = self.leaf('journal-fixture', b'KPX8JR01' + bytes.fromhex(outer.DOMAIN)
                            + bytes.fromhex(component) + bytes.fromhex(digest(projection.read_bytes())))
        if host is None:
            host = self.leaf('host-fixture', b'PUBLIC-SYNTHETIC-NOT-AN-EXECUTABLE')
        rows = {'host': host, 'program': program, 'journal': journal}
        rows['projection' if op in ('execute', 'prove') else 'receipt'] = (
            projection if op in ('execute', 'prove') else self.leaf('receipt-fixture', b'PUBLIC-RECEIPT'))
        job = {'schema': outer.SCHEMA, 'domain_hex32': outer.DOMAIN,
               'component_profile_sha256': component, 'image_id_hex32': image,
               'files': {name: {'path': str(path), 'sha256': digest(path.read_bytes())}
                         for name, path in rows.items()}}
        return job

    def test_all_required_private_parents_must_be_covered(self):
        other = self.base / 'another-private'
        other.mkdir()
        with self.assertRaisesRegex(ValueError, 'whole-lifecycle'):
            outer.Guard([self.private], required=[self.private, other])
        self.assertEqual(len(outer.Guard([self.base], required=[self.private, other]).directories), 1)

    def test_private_direct_and_single_link_moved_file_refused_before_open(self):
        p = self.private / 'synthetic-canary'
        p.write_bytes(b'PUBLIC-SYNTHETIC-CANARY')
        self.guard.refresh()
        moved = self.base / 'moved-canary'
        p.rename(moved)
        with mock.patch('outer.os.open', side_effect=AssertionError('must not open')):
            with self.assertRaisesRegex(ValueError, 'public-private-alias'):
                outer.read(self.guard, moved)
        self.assertEqual(moved.stat().st_nlink, 1)

    def test_hardlink_symlink_late_private_and_fifo_refused_before_open(self):
        private = self.private / 'late-canary'
        private.write_bytes(b'PUBLIC-SYNTHETIC-CANARY')
        hard = self.base / 'hard'
        os.link(private, hard)
        link = self.base / 'link'
        link.symlink_to(private)
        fifo = self.base / 'fifo'
        os.mkfifo(fifo)
        with mock.patch('outer.os.open', side_effect=AssertionError('must not open')):
            for path in (private, hard, link, fifo):
                with self.subTest(path=path.name), self.assertRaises(ValueError):
                    outer.read(self.guard, path)

    def test_selected_bytes_exact_hash_and_noncanonical_path(self):
        p = self.leaf('public', b'PUBLIC')
        self.assertEqual(outer.read(self.guard, p, digest(b'PUBLIC')), b'PUBLIC')
        with self.assertRaisesRegex(ValueError, 'external-public-selector-hash'):
            outer.read(self.guard, p, digest(b'OTHER'))
        with self.assertRaisesRegex(ValueError, 'canonical-public-path'):
            outer.read(self.guard, self.base / 'x/../public')

    def test_changed_file_after_metadata_is_rejected_before_first_byte(self):
        p = self.leaf('public', b'PUBLIC')
        original = self.guard.metadata
        def changed(path):
            result = original(path)
            p.write_bytes(b'CHANGED')
            return result
        with mock.patch.object(self.guard, 'metadata', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'public-open-race'):
                outer.read(self.guard, p)

    def test_selection_exact_roles_duplicate_json_and_domains(self):
        module = self.module()
        job = self.job()
        p = self.leaf('job', json.dumps(job).encode())
        self.assertEqual(outer.selected(self.guard, module, p, digest(p.read_bytes()), 'execute'), job)
        for changed in (
            {**job, 'domain_hex32': '44' * 32},
            {**job, 'extra': True},
            {**job, 'files': {**job['files'], 'receipt': job['files']['program']}},
        ):
            raw = json.dumps(changed).encode()
            p.write_bytes(raw)
            with self.assertRaises(ValueError):
                outer.selected(self.guard, module, p, digest(raw), 'execute')
        raw = json.dumps(job)
        p.write_text('{"schema":"duplicate",' + raw[1:])
        with self.assertRaisesRegex(ValueError, 'duplicate-JSON'):
            outer.selected(self.guard, module, p, digest(p.read_bytes()), 'execute')

    def test_late_selector_alias_prevents_any_runtime_member_read(self):
        module = self.module()
        job = self.job()
        job['files']['projection']['path'] = str(self.private / 'late-private')
        (self.private / 'late-private').write_bytes(b'PUBLIC-SYNTHETIC')
        with mock.patch.object(module, 'staged', side_effect=AssertionError('no staging')):
            with self.assertRaises(ValueError):
                outer.stage(self.guard, module, job, 'execute', self.base / 'out')
        self.assertFalse((self.base / 'out').exists())

    def test_stream_checks_entire_asset_and_excludes_private_alias(self):
        p = self.leaf('compression', b'A' * (8 * 1024 * 1024 + 3))
        _, info = outer.stream_selected(self.guard, p, digest(p.read_bytes()))
        self.assertEqual(info.st_size, 8 * 1024 * 1024 + 3)
        with p.open('r+b') as f:
            f.seek(-1, os.SEEK_END)
            f.write(b'B')
        with self.assertRaisesRegex(ValueError, 'whole-selected-compression'):
            outer.stream_selected(self.guard, p, digest(b'A' * (8 * 1024 * 1024 + 3)))

    def test_stage_new_cli_and_cpu_mount_boundary_without_launch(self):
        module = self.module()
        job = self.job()
        worker = self.leaf('worker', b'PUBLIC-CPU-WORKER')
        module.TOOLS = self.base
        worker.rename(self.base / 'r0vm')
        module.CPU_WORKER_SHA = digest(b'PUBLIC-CPU-WORKER')
        output, command, plan = outer.stage(self.guard, module, job, 'execute', self.base / 'out')
        self.assertEqual(command[-5:], ['/host', 'execute', '/program', '/projection', '/out/result'])
        self.assertIn('--unshare-all', command)
        self.assertIn('--clearenv', command)
        self.assertNotIn('--dev-bind', command)
        self.assertNotIn('RISC0_DEV_MODE', command)
        self.assertNotIn(str(self.private), command)
        self.assertNotIn(str(outer.ROOT), command)
        self.assertFalse(plan['worker_started'])
        self.assertFalse((output / 'PROCESS-RESOURCES.json').exists())

    def test_real_cpu_namespace_omits_host_home_private_repo_network_and_devices(self):
        module = self.module()
        # This selected host is a public synthetic checker, not R0 execution.
        script = '''#!/usr/bin/python3
import hashlib,json,os,socket,sys
from pathlib import Path
assert len(sys.argv)==5 and sys.argv[1]=='execute'
assert os.environ['RISC0_PROVER']=='ipc' and os.environ['RISC0_SERVER_PATH']=='/worker'
assert os.environ['HOME']=='/scratch/home' and os.environ['GITHUB_TOKEN']==''
assert 'RISC0_DEV_MODE' not in os.environ
assert not Path('/home/luke').exists()
assert not Path('HOST_PRIVATE').exists() and not Path('HOST_REPO').exists()
assert not list(Path('/dev').glob('nvidia*'))
try: socket.create_connection(('1.1.1.1',443),timeout=0.1)
except OSError: pass
else: raise AssertionError('network reachable')
j=Path('/journal').read_bytes();out=Path(sys.argv[4]);out.mkdir()
(out/'journal.bin').write_bytes(j)
(out/'report.json').write_text(json.dumps({'genuine_nine_G16_public_guest_execution_passed':True,
 'image_id_hex32':'33'*32,'journal_sha256':hashlib.sha256(j).hexdigest(),
 'public_synthetic_isolation_only_not_R0':True}))
'''.replace('HOST_PRIVATE', str(self.private)).replace('HOST_REPO', str(outer.ROOT))
        host = self.leaf('public-synthetic-host', script.encode())
        host.chmod(0o500)
        job = self.job(host=host)
        worker = self.leaf('r0vm', b'PUBLIC-UNEXECUTED-WORKER')
        module.TOOLS = self.base
        module.CPU_WORKER_SHA = digest(worker.read_bytes())
        output, command, plan = outer.stage(self.guard, module, job, 'execute', self.base / 'isolated')
        result = outer.execute(self.guard, module, output, command, plan)
        self.assertTrue(result['worker_completed'])
        self.assertTrue(result['worker_report']['public_synthetic_isolation_only_not_R0'])
        self.assertEqual(result['resources']['returncode'], 0)

    def test_compression_report_without_journal_hash_requires_exact_journal_file(self):
        module = self.module()
        job = self.job()
        worker = self.leaf('r0vm', b'PUBLIC-UNEXECUTED-WORKER')
        module.TOOLS = self.base
        module.CPU_WORKER_SHA = digest(worker.read_bytes())
        output, command, plan = outer.stage(self.guard, module, job, 'execute', self.base / 'compress-fixture')
        plan['op'] = 'compress'
        report = {'same_claim_genuine_Groth16_compression_verified': True,
                  'image_id_hex32': plan['image_id_hex32']}
        def public_report_only(_command, _output, **_kwargs):
            result = output / 'public-output' / 'result'
            result.mkdir()
            (result / 'journal.bin').write_bytes((output / 'journal').read_bytes())
            (result / 'report.json').write_text(json.dumps(report))
            return {'returncode': 0, 'public_synthetic_only': True}
        with mock.patch.object(module, 'call', side_effect=public_report_only):
            result = outer.execute(self.guard, module, output, command, plan)
        self.assertFalse(result['worker_journal_report_compared'])
        self.assertTrue(result['exact_external_journal_matched'])
        (output / 'RESULT.json').unlink()
        (output / 'public-output/result/journal.bin').write_bytes(b'WRONG')
        with mock.patch.object(module, 'call', return_value={'returncode': 0}):
            with self.assertRaisesRegex(ValueError, 'external-public-selector-hash'):
                outer.execute(self.guard, module, output, command, plan)
        report['journal_sha256'] = '00' * 32
        (output / 'public-output/result/report.json').write_text(json.dumps(report))
        with mock.patch.object(module, 'call', return_value={'returncode': 0}):
            with self.assertRaisesRegex(ValueError, 'returned-report-selected-journal'):
                outer.execute(self.guard, module, output, command, plan)


if __name__ == '__main__':
    unittest.main()
