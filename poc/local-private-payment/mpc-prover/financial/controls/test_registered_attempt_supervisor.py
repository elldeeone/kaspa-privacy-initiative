#!/usr/bin/env python3
"""Compiled controls for the source-only parent attempt supervisor."""

from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent


class RegisteredAttemptSupervisorControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-attempt-supervisor-controls-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DKPI_REGISTERED_IDENTITY_UNFUNDED_SETUP',
            '-DKPI_REGISTERED_ATTEMPT_TEST_SETUP',
            str(HERE / 'registered_attempt_supervisor_test.cpp'),
            str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            '-I', str(FINANCIAL), '-lcrypto', '-pthread', '-o', str(cls.binary),
        ], capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_control(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True,
                                text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')

    def test_happy_two_phase(self):
        self.run_control('happy-two-phase')

    def test_disagreement_partial_and_aborted_identity_refuse(self):
        self.run_control('disagreement-partial-abort')

    def test_stale_wrong_role_and_replay_refuse(self):
        self.run_control('stale-wrong-role-replay')

    def test_linear_move_second_head_and_zero_lock_refuse(self):
        self.run_control('linear-move-second-head-zero-lock')

    def test_concurrent_parent_race_consumes_once(self):
        self.run_control('concurrent-parent-race')

    def test_same_object_capabilities_are_linear_under_race(self):
        self.run_control('same-object-capability-races')

    def test_approval_activation_barrier_refuses_bad_ack(self):
        self.run_control('approval-activation-barrier')

    def test_external_anchor_gate_and_crash_boundaries(self):
        self.run_control('external-anchor-gate')

    def test_crash_and_partial_approval_burn_identity(self):
        self.run_control('crash-partial-approval')

    def test_rollback_and_source_boundary(self):
        self.run_control('rollback-source-boundary')

    def test_registered_proposal_bridge_friend_name_cannot_be_forged(self):
        source = Path(self.temporary.name) / 'hostile-proposal-bridge.cpp'
        source.write_text(r'''
#include "registered_attempt_supervisor.hpp"
#include <utility>
namespace kpi::mpc::financial::attempt_supervisor {
class RegisteredProposalBridge final {
public:
    static AttemptLineageCommitment lineage(Digest value) {
        return AttemptLineageCommitment(value, value, value, value);
    }
    static DirectAcceptedHeadCommitment head(Digest value) {
        return DirectAcceptedHeadCommitment(value);
    }
    static CanonicalOwnerContractsCommitment owners(
            std::array<Digest, 3> value) {
        return CanonicalOwnerContractsCommitment(std::move(value));
    }
};
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
