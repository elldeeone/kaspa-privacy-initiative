#!/usr/bin/env python3
"""Authenticated privacy-launch lineage receiver controls."""

from pathlib import Path
import array
import fcntl
import hashlib
import os
import socket
import struct
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent / 'mpc-prover' / 'financial'
SANITIZE = os.environ.get('KPI_SANITIZE') == '1'


class OwnerScoreLineageSourceReceiverControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(
            prefix='kpb-lineage-receiver-control-')
        cls.root = Path(cls.temp.name)
        cls.selection = cls.root / 'selection.bin'
        cls.selection.write_bytes(b'exact-diagnostic-selection\n')
        cls.selection.chmod(0o400)
        cls.control = cls.root / 'receiver-control'
        sanitizer_flags = (
            ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            if SANITIZE else [])
        command = [
            'c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-ffunction-sections', '-fdata-sections',
            *sanitizer_flags,
            '-I', str(HERE), '-I', str(FINANCIAL.parent),
            str(HERE /
                'privacy_owner_score_lineage_source_receiver_control.cpp'),
            '-Wl,--gc-sections', '-lcrypto', '-o', str(cls.control),
        ]
        built = subprocess.run(command, capture_output=True, text=True,
                               check=False)
        if built.returncode != 0:
            raise AssertionError(built.stdout + built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def compile(self, output, source):
        return subprocess.run([
            'c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-I', str(HERE), '-I', str(FINANCIAL.parent),
            '-c', str(source), '-o', str(output),
        ], capture_output=True, text=True, check=False)

    def test_receiver_accepts_only_the_live_registered_prelaunch_binding(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-lineage-receiver-surface-') as raw:
            root = Path(raw)
            source = root / 'surface.cpp'
            source.write_text(r'''
#include "privacy_owner_score_lineage_source_authority.hpp"
#include "financial/registered_selected_producer_run_binding.hpp"
#include <concepts>
using namespace kpb::measurement::score_output_lineage_source;
using Binding = kpi::mpc::financial::registered_driver::
    RegisteredSelectedProducerPrelaunchBindingAuthority;
using Signature = AuthenticatedPrivacyLaunchLineageSourceAuthority (*)(
    Binding&);
static_assert(std::same_as<
    decltype(&PrivacyLaunchLineageSourceReceiverBridge::receive),
    Signature>);
static_assert(kOwnerScoreLineageSourceStatus.credentialed_receiver_transport_core);
static_assert(!kOwnerScoreLineageSourceStatus.authenticated_python_receiver);
static_assert(kOwnerScoreLineageSourceStatus.outer_attempt_source_join);
static_assert(!kOwnerScoreLineageSourceStatus.selected_callsite);
static_assert(!kOwnerScoreLineageSourceStatus.configured);
int main() {}
''', encoding='utf-8')
            compiled = self.compile(root / 'surface.o', source)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_receiver_contract_has_no_caller_lineage_values(self):
        source = (HERE /
                  'privacy_owner_score_lineage_source_contract.hpp').read_text(
                      encoding='utf-8')
        receiver = source.split(
            'class PrivacyLaunchLineageSourceReceiverBridge final {', 1)[1]
        receiver = receiver.split('};', 1)[0]
        self.assertIn(
            'RegisteredSelectedProducerPrelaunchBindingAuthority&', receiver)
        for forbidden in (
                'std::string', 'std::span', 'Digest', 'Public', 'int',
                'path', 'bytes', 'attempt'):
            self.assertNotIn(forbidden, receiver)

    def test_receiver_implementation_is_required_before_status_can_advance(self):
        implementation = HERE / (
            'privacy_owner_score_lineage_source_receiver.cpp')
        self.assertTrue(implementation.is_file())
        source = implementation.read_text(encoding='utf-8')
        for required in (
                'SOCK_SEQPACKET', 'SO_PASSCRED', 'SCM_CREDENTIALS',
                'SCM_RIGHTS', 'MSG_CMSG_CLOEXEC', 'waitpid',
                'F_DUPFD_CLOEXEC', 'F_GET_SEALS',
                'outer-attempt-source-authority-missing'):
            self.assertIn(required, source)

    def test_status_surface_control(self):
        result = subprocess.run(
            [str(self.control)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_removed_lineage_binding_fixture_cannot_be_reintroduced_by_macro(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-lineage-hostile-macro-') as raw:
            root = Path(raw)
            source = root / 'hostile.cpp'
            source.write_text(r'''
#define KPB_OWNER_SCORE_LINEAGE_SOURCE_RECEIVER_TEST_SETUP
#include "financial/registered_selected_producer_run_binding.hpp"
using Binding = kpi::mpc::financial::registered_driver::
    RegisteredSelectedProducerPrelaunchBindingAuthority;
auto hostile() { return &Binding::test_only_lineage_binding; }
''', encoding='utf-8')
            compiled = self.compile(root / 'hostile.o', source)
            self.assertNotEqual(compiled.returncode, 0)
            self.assertIn('test_only_lineage_binding', compiled.stderr)

    def test_binding_sources_have_no_lineage_fixture_declaration(self):
        for path in (
                FINANCIAL / 'registered_selected_producer_run_binding.hpp',
                FINANCIAL / 'registered_selected_producer_run_binding.cpp'):
            source = path.read_text(encoding='utf-8')
            self.assertNotIn('test_only_lineage_binding', source)
            self.assertNotIn(
                'KPB_OWNER_SCORE_LINEAGE_SOURCE_RECEIVER_TEST_SETUP', source)

    def test_python_fixed_fd_worker_sends_one_sealed_archive(self):
        import privacy_launch as launch

        selection_fd = os.open(
            self.selection, os.O_RDONLY | os.O_CLOEXEC)
        parent, child = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        child.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        session = bytes(range(32))
        selection_sha = hashlib.sha256(
            self.selection.read_bytes()).digest()
        expected_archive = b'credentialed-python-lineage-archive'
        pid = os.fork()
        if pid == 0:
            try:
                parent.close()
                os.dup2(selection_fd,
                        launch.OWNER_SCORE_LINEAGE_SELECTION_FD)
                os.dup2(child.fileno(),
                        launch.OWNER_SCORE_LINEAGE_CONTROL_FD)
                child.close()
                os.close(selection_fd)
                launch.admitted_owner_score_lineage_source = (
                    lambda *_args, **_kwargs: (None, expected_archive))
                launch.owner_score_lineage_worker()
                os._exit(0)
            except BaseException:
                os._exit(91)
        child.close()
        os.close(selection_fd)
        offer = (launch.OWNER_SCORE_LINEAGE_OFFER_MAGIC + session +
                 selection_sha)
        self.assertEqual(parent.send(offer), len(offer))
        packet, ancillary, flags, _ = parent.recvmsg(
            launch.OWNER_SCORE_LINEAGE_RESPONSE_BYTES,
            socket.CMSG_SPACE(struct.calcsize('3i')) +
            socket.CMSG_SPACE(struct.calcsize('i')),
            socket.MSG_CMSG_CLOEXEC)
        self.assertEqual(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 0)
        self.assertEqual(packet[:8], launch.OWNER_SCORE_LINEAGE_RESPONSE_MAGIC)
        self.assertEqual(packet[8:40], session)
        self.assertEqual(int.from_bytes(packet[40:48], 'little'),
                         len(expected_archive))
        rights = []
        credentials = []
        for level, kind, data in ancillary:
            self.assertEqual(level, socket.SOL_SOCKET)
            if kind == socket.SCM_RIGHTS:
                values = array.array('i')
                values.frombytes(data[:len(data) - len(data) % values.itemsize])
                rights.extend(values)
            elif kind == socket.SCM_CREDENTIALS:
                credentials.append(struct.unpack('3i', data))
            else:
                self.fail(f'unexpected cmsg {kind}')
        self.assertEqual(credentials, [(pid, os.getuid(), os.getgid())])
        self.assertEqual(len(rights), 1)
        received = rights[0]
        try:
            self.assertEqual(os.pread(received, len(expected_archive), 0),
                             expected_archive)
            self.assertEqual(
                fcntl.fcntl(received, fcntl.F_GETFL) & os.O_ACCMODE,
                os.O_RDONLY)
            seals = fcntl.fcntl(received, fcntl.F_GET_SEALS)
            self.assertEqual(
                seals & (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                         fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL),
                fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        finally:
            os.close(received)
            parent.close()
        waited, status = os.waitpid(pid, 0)
        self.assertEqual(waited, pid)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 0)


if __name__ == '__main__':
    unittest.main()
