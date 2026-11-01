#!/usr/bin/env python3
"""Real-fork controls for the retained parent supervisor channel."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent


class RegisteredSupervisorParentTransportControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-supervisor-parent-transport-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DKPI_REGISTERED_IDENTITY_UNFUNDED_SETUP',
            '-DKPI_REGISTERED_ATTEMPT_TEST_SETUP',
            '-DKPI_REGISTERED_PARENT_FORK_TEST_SETUP',
            '-DKPI_REGISTERED_SUPERVISOR_TRANSPORT_TEST_SETUP',
            str(HERE / 'registered_supervisor_parent_transport_test.cpp'),
            str(FINANCIAL / 'registered_parent_role_fork.cpp'),
            str(FINANCIAL / 'registered_projection_route.cpp'),
            str(FINANCIAL / 'registered_supervisor_parent_transport.cpp'),
            str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            '-I', str(FINANCIAL), '-lcrypto', '-pthread',
            '-o', str(cls.binary),
        ], capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_case(self, scenario):
        result = subprocess.run(
            [str(self.binary), scenario], capture_output=True, text=True,
            timeout=20, check=False)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_genuine_three_party_proposals_receive_linear_approvals(self):
        self.run_case('happy')

    def test_mixed_selection_refuses_and_kills_children(self):
        self.run_case('mixed')

    def test_wrong_role_proposal_refuses(self):
        self.run_case('wrong-role')

    def test_wrong_approval_ack_refuses(self):
        self.run_case('wrong-ack')

    def test_duplicate_proposal_refuses(self):
        self.run_case('duplicate-proposal')

    def test_duplicate_ack_refuses(self):
        self.run_case('duplicate-ack')

    def test_surface_has_no_raw_fd_packet_or_receipt_factory(self):
        source = Path(self.temporary.name) / 'surface.cpp'
        source.write_text(r'''
#include "registered_parent_role_fork.hpp"
#include <concepts>
using namespace kpi::mpc::financial::registered_driver;
template<class T> concept RawSend = requires(T& value, int fd) {
    value.send(fd);
};
template<class T> concept ReceiptFactory = requires(
        kpi::mpc::financial::attempt_supervisor::PublicApproval value) {
    T::from_receipt(value);
};
static_assert(!std::default_initializable<RegisteredSupervisorParentTransport>);
static_assert(!RawSend<RegisteredSupervisorParentTransport>);
static_assert(!ReceiptFactory<RegisteredSupervisorParentTransport>);
int main() { return 0; }
''', encoding='utf-8')
        result = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-fsyntax-only', str(source), '-I', str(FINANCIAL),
        ], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)

    def test_transport_friend_name_cannot_be_defined_by_hostile_tu(self):
        source = Path(self.temporary.name) / 'hostile-friend.cpp'
        source.write_text(r'''
#include "registered_parent_role_fork.hpp"
namespace kpi::mpc::financial::registered_driver {
class RegisteredSupervisorParentTransport final {};
}
''', encoding='utf-8')
        result = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-fsyntax-only', str(source), '-I', str(FINANCIAL),
        ], capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('redefinition', result.stderr)


if __name__ == '__main__':
    unittest.main()
