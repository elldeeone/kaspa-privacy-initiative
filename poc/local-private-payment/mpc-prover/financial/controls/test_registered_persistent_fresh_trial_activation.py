#!/usr/bin/env python3
"""Controls for pre-identity persistent-process topology activation."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
LOCAL_PAYMENT = MPC.parent
TRIAL = LOCAL_PAYMENT / 'private_batch_trial'
REPO = LOCAL_PAYMENT.parents[1]
VENDOR = REPO / '.local' / 'mpc-prover-vendor' / 'MP-SPDZ'
PREFIX = VENDOR.parent / 'prefix' / 'usr' / 'include'
SANITIZE = os.environ.get('KPI_SANITIZE') == '1'


class RegisteredPersistentFreshTrialActivationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-persistent-fresh-activation-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        sanitizer_flags = (
            ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            if SANITIZE else [])
        compiled = subprocess.run([
            'g++', '-std=c++20', '-O1', '-g0', '-Wall', '-Wextra',
            '-Werror', '-pedantic', '-Wno-overloaded-virtual',
            '-Wno-psabi', '-Wno-mismatched-new-delete', '-march=native',
            '-ffunction-sections', '-fdata-sections',
            *sanitizer_flags,
            '-DKPI_REGISTERED_PARENT_FORK_TEST_SETUP',
            '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
            '-DKPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP',
            '-DKPI_FRESH_OWNER_ISSUANCE_TEST_SETUP',
            '-DKPI_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_TEST_SETUP',
            '-DKPI_REGISTERED_PERSISTENT_FRESH_ACTIVATION_TEST_SETUP',
            '-DKPB_SELECTED_PRODUCER_ACTIVATION_TEST_SETUP',
            str(HERE /
                'registered_persistent_fresh_trial_activation_test.cpp'),
            str(FINANCIAL / 'registered_parent_role_fork.cpp'),
            str(FINANCIAL /
                'registered_persistent_fresh_trial_activation.cpp'),
            str(FINANCIAL /
                'registered_selected_producer_activation.cpp'),
            str(FINANCIAL /
                'registered_selected_parent_orchestrator.cpp'),
            str(FINANCIAL /
                'registered_selected_producer_run_binding.cpp'),
            str(FINANCIAL / 'registered_preidentity_ready.cpp'),
            str(FINANCIAL / 'registered_projection_route.cpp'),
            str(FINANCIAL / 'registered_parent_role_delivery_bridge.cpp'),
            str(FINANCIAL / 'registered_driver_bridge.cpp'),
            str(FINANCIAL / 'registered_capture_session.cpp'),
            str(FINANCIAL / 'baseline_public_effects_collector.cpp'),
            str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            str(FINANCIAL / 'docker_monotonic_anchor_client.cpp'),
            str(FINANCIAL / 'fresh_owner_trial_issuance.cpp'),
            str(TRIAL /
                'privacy_registered_fresh_trial_capture_topology_reservation.cpp'),
            str(TRIAL /
                'privacy_registered_fresh_trial_capture_topology_permit.cpp'),
            str(TRIAL /
                'privacy_fresh_owner_transactional_replay_authority.cpp'),
            str(TRIAL / 'privacy_capture_hook.cpp'),
            str(TRIAL / 'privacy_measurement_authority.cpp'),
            str(TRIAL /
                'privacy_owner_score_lineage_source_authority.cpp'),
            str(TRIAL /
                'privacy_owner_score_lineage_prelaunch_source.cpp'),
            str(TRIAL /
                'privacy_owner_score_lineage_source_receiver.cpp'),
            str(TRIAL /
                'privacy_p1_mascot_fresh_prep_directory_authority.cpp'),
            str(TRIAL /
                'privacy_prelaunch_policy_domain_authority.cpp'),
            '-I', str(MPC), '-I', str(TRIAL), '-I', str(VENDOR),
            '-I', str(PREFIX), '-I', str(PREFIX / 'x86_64-linux-gnu'),
            str(VENDOR / 'libSPDZ.so'),
            '-Wl,--gc-sections', '-Wl,-rpath,' + str(VENDOR),
            '-lcrypto', '-pthread',
            '-o', str(cls.binary),
        ], capture_output=True, text=True, check=False, timeout=120)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)
        worker_source = TRIAL / (
            'privacy_owner_score_lineage_source_test_worker.cpp')
        selected_worker_source = Path(cls.temporary.name) / (
            'selected-lineage-worker.cpp')
        selected_worker_source.write_text(
            worker_source.read_text(encoding='utf-8').replace(
                '22222222-2222-4222-8222-222222222222',
                '11111111-1111-4111-8111-111111111111'),
            encoding='utf-8')
        cls.worker = Path(cls.temporary.name) / 'selected-lineage-worker'
        worker_compiled = subprocess.run([
            'g++', '-std=c++20', '-O1', '-g0', '-Wall', '-Wextra',
            '-Werror', '-pedantic', '-I', str(TRIAL),
            str(selected_worker_source), '-o', str(cls.worker),
        ], capture_output=True, text=True, check=False, timeout=60)
        if worker_compiled.returncode:
            raise AssertionError(
                worker_compiled.stdout + worker_compiled.stderr)
        cls.worker.chmod(0o500)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_scenario(self, scenario):
        result = subprocess.run(
            [str(self.binary), scenario, str(self.worker)],
            capture_output=True, text=True,
            timeout=30, check=False)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_topology_writers_and_state_pairs_are_retained_until_typed_abort(self):
        self.run_scenario('prepared-abort')

    def test_mismatched_writer_refuses_before_issuance_claim(self):
        self.run_scenario('mismatched-writer')

    def test_post_ack_channel_close_still_pidfd_settles_all_children(self):
        self.run_scenario('post-ack-close')

    def test_moved_pending_authority_and_result_cannot_replay(self):
        self.run_scenario('residual-replay')

    def test_post_settle_bad_alloc_cannot_erase_process_abort_evidence(self):
        self.run_scenario('post-settle-bad-alloc')

    def test_partial_scm_rights_send_settles_all_exact_children(self):
        self.run_scenario('partial-scm-rights')

    def test_partial_scm_rights_ack_settles_all_exact_children(self):
        self.run_scenario('partial-scm-ack')

    def test_parent_cannot_re_report_a_different_command_after_first_ack(self):
        self.run_scenario('parent-re-report')

    def test_activation_command_cannot_replay_as_retention_probe(self):
        self.run_scenario('replayed-command')

    def test_swapped_capture_slot_is_rejected_with_the_same_received_fds(self):
        self.run_scenario('swapped-slot')

    def test_swapped_round_is_rejected_before_retention_ack(self):
        self.run_scenario('swapped-round')

    def test_same_fd_with_wrong_fingerprint_metadata_is_rejected(self):
        self.run_scenario('same-fd-wrong-metadata')

    def test_metadata_discard_after_first_ack_prevents_activation(self):
        self.run_scenario('metadata-drop-after-ack')

    def test_role_program_success_and_production_status_remain_closed(self):
        self.run_scenario('status')

    def test_selected_join_burns_invalid_full_plan_and_typed_aborts_stage1(self):
        self.run_scenario('selected-invalid-plan')

    def test_selected_join_retains_topology_policy_prep_and_kpbosl_source(self):
        self.run_scenario('selected-source-success')

    def test_selected_join_refuses_cross_trial_source_and_typed_aborts(self):
        self.run_scenario('selected-cross-trial')

    def test_selected_join_replay_burns_source_policy_and_activation(self):
        self.run_scenario('selected-replay')

    def test_no_raw_pid_signal_or_public_descriptor_activation_path(self):
        implementation = (
            (FINANCIAL / 'registered_parent_role_fork.cpp').read_text() +
            (FINANCIAL /
             'registered_persistent_fresh_trial_activation.cpp').read_text()
        )
        self.assertNotIn('::kill(', implementation)
        self.assertNotIn('SYS_kill', implementation)
        self.assertIn('SCM_RIGHTS', implementation)
        self.assertIn('MSG_CMSG_CLOEXEC', implementation)
        self.assertIn('SYS_pidfd_send_signal', implementation)

    def test_no_legacy_public_plan_can_mint_writerless_authority(self):
        header = (FINANCIAL / 'registered_parent_role_fork.hpp').read_text()
        implementation = (
            FINANCIAL / 'registered_persistent_fresh_trial_activation.cpp'
        ).read_text()
        selected = header[
            header.index(
                'class RegisteredPersistentWriterlessRoundPlanAuthority'):
            header.index(
                'class RegisteredPersistentTopologyActivationAuthority')
        ]
        self.assertNotIn('test_only_mint', selected)
        self.assertNotIn(
            'RegisteredPersistentWriterlessRoundPlanAuthority::test_only_mint',
            implementation)

        with tempfile.TemporaryDirectory(
                prefix='kpb-writerless-legacy-mint-') as directory:
            source = Path(directory) / 'hostile.cpp'
            source.write_text(r'''
#include "registered_parent_role_fork.hpp"
using namespace kpi::mpc::financial::registered_driver;
int main() {
    auto forged = RegisteredPersistentWriterlessRoundPlanAuthority::
        test_only_mint(PublicParentRoleForkPlan{});
    (void)forged;
}
''')
            compiled = subprocess.run([
                'g++', '-std=c++20', '-O1', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-DKPI_REGISTERED_PARENT_FORK_TEST_SETUP',
                '-DKPI_REGISTERED_PERSISTENT_FRESH_ACTIVATION_TEST_SETUP',
                str(source), '-fsyntax-only', '-I', str(FINANCIAL),
                '-I', str(MPC), '-I', str(TRIAL), '-I', str(VENDOR),
                '-I', str(PREFIX),
                '-I', str(PREFIX / 'x86_64-linux-gnu'),
            ], capture_output=True, text=True, check=False, timeout=60)
            self.assertNotEqual(compiled.returncode, 0,
                                compiled.stdout + compiled.stderr)
            self.assertIn('test_only_mint',
                          compiled.stdout + compiled.stderr)


if __name__ == '__main__':
    unittest.main()
