"""Controls for the source-only static observer entrypoint."""

import fcntl
import inspect
import os
import subprocess
import sys
import unittest

import privacy_observer_static_entrypoint as entrypoint
from test_privacy_fd40_archive import ArchiveFixture


class ObserverStaticEntrypointControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = ArchiveFixture(
            valid_public_state=True, repeat_ciphertext=True)

    def _run(self, value, *, forge_zero_open_phase=False):
        source = os.memfd_create(
            'kpb-static-observer-fd40',
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        source_read = None
        output_read, output_write = os.pipe2(os.O_CLOEXEC)
        try:
            os.write(source, value)
            fcntl.fcntl(source, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                        fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            os.lseek(source, 0, os.SEEK_SET)
            source_read = os.open('/proc/self/fd/' + str(source),
                                  os.O_RDONLY | os.O_CLOEXEC)
            script = (
                'import os,sys\n'
                'os.dup2(int(sys.argv[1]),40,inheritable=True)\n'
                'os.dup2(int(sys.argv[2]),62,inheritable=True)\n'
                'import privacy_observer_static_entrypoint as e\n'
                + ("e.capture._private_completion_phase_partition="
                   "lambda *_:{'schema':'forged','coverage_summary':{},"
                   "'views':[{'view_index':i,'step2_open_fields':[],"
                   "'deferred_step3_open_fields':[]} for i in range(4)]}\n"
                   if forge_zero_open_phase else '') +
                'raise SystemExit(e.run())\n')
            result = subprocess.run(
                [sys.executable, '-c', script,
                 str(source_read), str(output_write)],
                pass_fds=(source_read, output_write),
                cwd=os.path.dirname(__file__),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=30)
        finally:
            if source_read is not None:
                os.close(source_read)
            os.close(source)
            os.close(output_write)
        try:
            emitted = os.read(output_read, 1)
        finally:
            os.close(output_read)
        return result, emitted

    def test_complete_archive_builds_models_then_refuses_configured0(self):
        result, emitted = self._run(self.fixture.value)
        self.assertEqual(result.returncode, entrypoint.CONFIGURED0_EXIT,
                         result.stderr.decode(errors='replace'))
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, entrypoint.CONFIGURED0_MESSAGE)
        self.assertEqual(emitted, b'')

    def test_malformed_fd40_never_becomes_configured_refusal_or_output(self):
        result, emitted = self._run(bytes(512))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(result.returncode, entrypoint.CONFIGURED0_EXIT)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(emitted, b'')

    def test_forged_zero_open_phase_cannot_reach_fd62(self):
        result, emitted = self._run(
            self.fixture.value, forge_zero_open_phase=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(result.returncode, entrypoint.CONFIGURED0_EXIT)
        self.assertIn(b'observer-static-native-fd62-authority-required',
                      result.stderr)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(emitted, b'')

    def test_entrypoint_and_parser_keep_static_selected_surface_narrow(self):
        signature = inspect.signature(entrypoint.run)
        self.assertEqual(tuple(signature.parameters), ())
        root = os.path.dirname(__file__)
        with open(os.path.join(root, 'privacy_observer_static_entrypoint.py'),
                  encoding='utf-8') as source:
            entry_source = source.read()
        with open(os.path.join(root, 'privacy_fd40_archive.py'),
                  encoding='utf-8') as source:
            archive_source = source.read()
        self.assertNotIn('test_only_encode', entry_source)
        self.assertNotIn('os.write(62', entry_source)
        self.assertNotIn('import mmap', archive_source)
        self.assertNotIn('import privacy_capture_producer', archive_source)


if __name__ == '__main__':
    unittest.main()
