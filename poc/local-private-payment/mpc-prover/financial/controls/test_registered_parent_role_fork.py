#!/usr/bin/env python3
"""Compiled controls for the parent-owned exact-three-role fork topology."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
SANITIZE = os.environ.get('KPI_SANITIZE') == '1'


class RegisteredParentRoleForkControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-registered-parent-role-fork-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        sanitizer_flags = (
            ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            if SANITIZE else [])
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            *sanitizer_flags,
            '-DKPI_REGISTERED_PARENT_FORK_TEST_SETUP',
            '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
            '-DKPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP',
            str(HERE / 'registered_parent_role_fork_test.cpp'),
            str(FINANCIAL / 'registered_parent_role_fork.cpp'),
            str(FINANCIAL / 'registered_projection_route.cpp'),
            str(FINANCIAL / 'registered_parent_role_delivery_bridge.cpp'),
            str(FINANCIAL / 'registered_driver_bridge.cpp'),
            str(FINANCIAL / 'registered_capture_session.cpp'),
            str(FINANCIAL / 'baseline_public_effects_collector.cpp'),
            str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            str(FINANCIAL / 'docker_monotonic_anchor_client.cpp'),
            str(FINANCIAL.parent.parent / 'private_batch_trial' /
                'privacy_capture_hook.cpp'),
            '-I', str(FINANCIAL), '-lcrypto', '-pthread',
            '-o', str(cls.binary),
        ], capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_scenario(self, scenario):
        result = subprocess.run(
            [str(self.binary), scenario], capture_output=True, text=True,
            timeout=20, check=False)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_exact_three_roles_use_authenticated_inherited_channels(self):
        self.run_scenario('valid')

    def test_role_zero_only_projection_route_is_bound_to_actual_fork(self):
        self.run_scenario('projection-route')

    def test_projection_route_writer_replay_burns_fork_plan(self):
        self.run_scenario('projection-route-replay')

    def test_stale_projection_route_round_burns_fork_plan(self):
        self.run_scenario('projection-route-stale-round')

    def test_baseline_candidate_projection_route_substitution_refuses(self):
        self.run_scenario('projection-route-arm-substitution')

    def test_wrong_parent_route_mixup_poisons_binding(self):
        self.run_scenario('projection-route-mixup')

    def test_missing_parent_route_binding_refuses_join(self):
        self.run_scenario('projection-route-missing-parent')

    def test_wrong_parent_route_peer_fingerprint_refuses_before_offer(self):
        self.run_scenario('projection-route-wrong-peer-fingerprint')

    def test_already_closed_parent_route_peer_refuses_before_offer(self):
        self.run_scenario('projection-route-peer-already-closed')

    def test_reused_parent_route_peer_fd_refuses_before_offer(self):
        self.run_scenario('projection-route-peer-fd-reused')

    def test_partial_fork_closes_channels_and_reaps_without_raw_signal(self):
        self.run_scenario('partial-fork')

    def test_partial_pidfd_open_settles_every_child_without_raw_signal(self):
        self.run_scenario('partial-pidfd-open')

    def test_pre_identity_reservation_aborts_with_complete_typed_evidence(self):
        self.run_scenario('pre-identity-reservation-abort')

    def test_process_reservation_issues_one_topology_permit(self):
        self.run_scenario('process-first-topology-permit')

    def test_pre_identity_children_allowlist_inherited_descriptors(self):
        self.run_scenario('pre-identity-child-fd-allowlist')

    def test_wrong_role_offer_refuses_and_burns_plan(self):
        self.run_scenario('wrong-role')

    def test_completion_replay_refuses_and_poisons_parent_join(self):
        self.run_scenario('completion-replay')

    def test_zero_length_seqpacket_record_is_not_child_eof(self):
        self.run_scenario('zero-record-eof')

    def test_capture_fd_mixup_refuses_and_burns_plan(self):
        self.run_scenario('fd-mixup')

    def test_parent_cannot_self_acknowledge_child_delivery(self):
        self.run_scenario('parent-self-ack')

    def test_malformed_endpoint_role_is_not_a_capture_capability(self):
        self.run_scenario('malformed-endpoint')

    def test_source_status_keeps_selected_launch_closed(self):
        self.run_scenario('status')

    def test_process_lifecycle_has_no_raw_pid_signal_fallback(self):
        source = (FINANCIAL / 'registered_parent_role_fork.cpp').read_text()
        self.assertNotIn('::kill(', source)
        self.assertNotIn('SYS_kill', source)
        self.assertIn('SYS_pidfd_open', source)
        self.assertIn('SYS_pidfd_send_signal', source)
        self.assertIn('waitid_pidfd(pidfd, observed, WEXITED | WNOWAIT)',
                      source)
        self.assertIn('action.sa_handler == SIG_DFL', source)
        self.assertIn('(action.sa_flags & SA_NOCLDWAIT) == 0', source)

    def test_production_surface_has_no_argv_env_or_raw_fd_factory(self):
        source = Path(self.temporary.name) / 'production-surface.cpp'
        source.write_text(r'''
#include "registered_parent_role_fork.hpp"
#include <concepts>
using namespace kpi::mpc::financial::registered_driver;
template<class T> concept ArgvFactory = requires(int argc, char** argv) {
    T::admit(argc, argv);
};
template<class T> concept RawFdFactory = requires(
        PublicInheritedCaptureEndpoint value, int fd) {
    T::from_fd(value, fd);
};
static_assert(!std::default_initializable<InheritedCaptureEndpointAuthority>);
static_assert(!std::constructible_from<InheritedCaptureEndpointAuthority,
                                       PublicInheritedCaptureEndpoint, int>);
static_assert(!std::default_initializable<ParentRoleForkPlanAuthority>);
static_assert(!std::copy_constructible<ParentRoleForkPlanAuthority>);
static_assert(!std::default_initializable<
                  ParentAuthenticatedPartyDeliveryAuthority>);
static_assert(!std::copy_constructible<
                  ParentAuthenticatedPartyDeliveryAuthority>);
static_assert(!std::default_initializable<
                  detail::PersistentRoleExitEvidence>);
static_assert(!std::copy_constructible<
                  detail::PersistentRoleExitEvidence>);
static_assert(std::move_constructible<
                  detail::PersistentRoleExitEvidence>);
static_assert(!std::default_initializable<
                  RegisteredTopologyReservationPermit>);
static_assert(!std::copy_constructible<
                  RegisteredTopologyReservationPermit>);
static_assert(std::move_constructible<
                  RegisteredTopologyReservationPermit>);
static_assert(!ArgvFactory<RegisteredParentRoleFork>);
static_assert(!RawFdFactory<InheritedCaptureEndpointAuthority>);
int main() { return 0; }
''', encoding='utf-8')
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-c', str(source), '-I', str(FINANCIAL),
            '-o', str(Path(self.temporary.name) / 'production-surface.o'),
        ], capture_output=True, text=True, check=False)
        self.assertEqual(compiled.returncode, 0,
                         compiled.stdout + compiled.stderr)


if __name__ == '__main__':
    unittest.main()
