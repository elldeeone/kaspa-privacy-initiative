#!/usr/bin/env python3
"""Controls for post-fork, pre-identity capture resource reservation."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent / 'mpc-prover' / 'financial'
MPC = FINANCIAL.parent


class FreshTrialCaptureTopologyReservationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-fresh-trial-topology-reservation-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        compiled = subprocess.run([
            'g++', '-std=c++20', '-O1', '-g0', '-Wall', '-Wextra',
            '-Werror', '-pedantic', '-pthread',
            '-DKPI_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_TEST_SETUP',
            str(HERE /
                'privacy_registered_fresh_trial_capture_topology_reservation_control.cpp'),
            str(HERE /
                'privacy_registered_fresh_trial_capture_topology_reservation.cpp'),
            '-I', str(HERE), '-I', str(FINANCIAL), '-I', str(MPC),
            '-lcrypto',
            '-o', str(cls.binary),
        ], capture_output=True, text=True, check=False, timeout=60)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_scenario(self, scenario):
        result = subprocess.run([str(self.binary), scenario],
                                capture_output=True, text=True,
                                check=False, timeout=20)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def compile_only(self, name, source):
        path = Path(self.temporary.name) / f'{name}.cpp'
        path.write_text(source, encoding='utf-8')
        return subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread', '-c', str(path),
            '-I', str(HERE), '-I', str(FINANCIAL), '-I', str(MPC),
            '-o', str(Path(self.temporary.name) / f'{name}.o'),
        ], capture_output=True, text=True, check=False, timeout=60)

    def test_reservation_pins_ten_streams_and_two_p1_state_archives(self):
        self.run_scenario('reserve')

    def test_reservation_is_move_only_and_one_shot(self):
        self.run_scenario('move')

    def test_closed_stream_or_p1_state_descriptor_refuses(self):
        self.run_scenario('substitute')

    def test_postclaim_quarantine_retains_same_ten_resources(self):
        self.run_scenario('quarantine')

    def test_p1_state_parent_residual_is_move_only_and_exact(self):
        self.run_scenario('p1-state')

    def test_unintegrated_pidfd_binding_and_launch_remain_false(self):
        self.run_scenario('status')

    def test_production_surface_has_no_raw_fd_identity_or_plan_path(self):
        compiled = self.compile_only('surface', r'''
#include "privacy_registered_fresh_trial_capture_topology_reservation.hpp"
#include <concepts>
#include <type_traits>
using namespace kpi::mpc::financial::registered_driver;
template<class T> concept HasReadEnds = requires(T value) {
    value.read_ends();
};
template<class T> concept HasWriterAliases = requires(T value) {
    value.writer_aliases();
};
template<class T> concept HasArchiveFds = requires(T value) {
    value.archive_fds();
};
template<class T> concept HasStateReadFds = requires(T value) {
    value.p1_state_parent_read_fds();
};
template<class T> concept HasStateWriterFds = requires(T value) {
    value.p1_state_child_writer_aliases();
};
template<class T> concept HasBinding = requires(T value) { value.binding(); };
template<class T> concept HasTrial = requires(T value) { value.trial(); };
template<class T> concept HasTestMint = requires { T::test_only_mint(); };
template<class T> concept HasUnboundReserve = requires { T::reserve(); };
template<class T> concept HasDiagnosticReserve = requires {
    T::test_only_reserve_unbound();
};
static_assert(!std::default_initializable<
    FreshTrialCaptureTopologyReservation>);
static_assert(!std::copy_constructible<
    FreshTrialCaptureTopologyReservation>);
static_assert(!std::constructible_from<
    FreshTrialCaptureTopologyReservation, int>);
static_assert(!std::constructible_from<
    FreshTrialCaptureTopologyReservation, std::array<int, 10>>);
static_assert(!HasReadEnds<FreshTrialCaptureTopologyReservation>);
static_assert(!HasWriterAliases<FreshTrialCaptureTopologyReservation>);
static_assert(!HasArchiveFds<FreshTrialCaptureTopologyReservation>);
static_assert(!HasBinding<FreshTrialCaptureTopologyReservation>);
static_assert(!HasTrial<FreshTrialCaptureTopologyReservation>);
static_assert(!HasTestMint<FreshTrialCaptureTopologyReservation>);
static_assert(!HasUnboundReserve<
    FreshTrialCaptureTopologyReservationBridge>);
static_assert(!HasDiagnosticReserve<
    FreshTrialCaptureTopologyReservationBridge>);
static_assert(!HasReadEnds<FreshTrialCaptureTopologyQuarantineResidual>);
static_assert(!HasWriterAliases<
    FreshTrialCaptureTopologyQuarantineResidual>);
static_assert(!HasArchiveFds<
    FreshTrialCaptureTopologyQuarantineResidual>);
static_assert(!HasStateReadFds<
    FreshTrialCaptureTopologyReservation>);
static_assert(!HasStateWriterFds<
    FreshTrialCaptureTopologyReservation>);
static_assert(!HasStateReadFds<
    FreshTrialCaptureTopologyQuarantineResidual>);
static_assert(!HasStateWriterFds<
    FreshTrialCaptureTopologyQuarantineResidual>);
static_assert(!HasStateReadFds<
    FreshTrialP1StateArchiveResidual>);
static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
    .launch_authority_absent);
static_assert(!kFreshTrialCaptureTopologyReservationSourceStatus.configured);
int main() { return 0; }
''')
        self.assertEqual(compiled.returncode, 0,
                         compiled.stdout + compiled.stderr)

    def test_process_permit_stays_live_until_all_resources_validate(self):
        source = (HERE /
            'privacy_registered_fresh_trial_capture_topology_permit.cpp'
            ).read_text(encoding='utf-8')
        first_validate = source.index(
            'permit.validate_for_topology_reservation();')
        opened = source.index('open_unbound_resources(false)',
                              first_validate)
        second_validate = source.index(
            'permit.validate_for_topology_reservation();', opened)
        consumed = source.index(
            'consume_for_topology_reservation()', second_validate)
        bound = source.index('bind_preidentity_epoch', consumed)
        self.assertLess(first_validate, opened)
        self.assertLess(opened, second_validate)
        self.assertLess(second_validate, consumed)
        self.assertLess(consumed, bound)

    def test_complete_contracts_block_exact_name_friend_forgery(self):
        attacks = {
            'reservation': 'FreshTrialCaptureTopologyReservationBridge',
            'closure': 'RegisteredFreshTrialProducerClosureBridge',
            'activation': 'RegisteredPersistentFreshTrialActivationBridge',
            'preidentity-ready': 'RegisteredPreidentityReadyBridge',
            'preidentity-ready-issuance':
                'RegisteredPreidentityReadyIssuanceBridge',
        }
        for name, class_name in attacks.items():
            with self.subTest(name=name):
                compiled = self.compile_only(name, f'''
#include "privacy_registered_fresh_trial_capture_topology_reservation.hpp"
namespace kpi::mpc::financial::registered_driver {{
class {class_name} final {{
public:
    static bool steal(FreshTrialCaptureTopologyReservation& value) {{
        return value.storage_ != nullptr;
    }}
}};
}}
int main() {{ return 0; }}
''')
                self.assertNotEqual(
                    compiled.returncode, 0,
                    f'hostile exact-name {class_name} compiled')
                self.assertIn('redefinition', compiled.stderr)
        compiled = self.compile_only('quarantine-reservation', r'''
#include "privacy_registered_fresh_trial_capture_topology_reservation.hpp"
namespace kpi::mpc::financial::registered_driver {
class FreshTrialCaptureTopologyReservation final {
public:
    static auto steal(FreshTrialCaptureTopologyQuarantineResidual& value) {
        return value.archive_fds_;
    }
};
}
int main() { return 0; }
''')
        self.assertNotEqual(compiled.returncode, 0,
                            'hostile quarantine friend compiled')
        self.assertIn('redefinition', compiled.stderr)

    def test_storage_has_no_trial_identity_and_status_is_truthful(self):
        implementation = (HERE /
            'privacy_registered_fresh_trial_capture_topology_reservation.cpp'
            ).read_text(encoding='utf-8')
        storage = implementation.split(
            'struct FreshTrialCaptureTopologyReservation::Storage {', 1
        )[1].split('Storage() {', 1)[0]
        for forbidden in ('RunBinding', 'trial', 'attempt',
                          'capture_plan', 'process_identity'):
            self.assertNotIn(forbidden, storage)
        self.assertIn(
            'KPB_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_V2',
            implementation)
        self.assertNotIn(
            'KPB_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_V1',
            implementation)
        header = (HERE /
            'privacy_registered_fresh_trial_capture_topology_reservation.hpp'
            ).read_text(encoding='utf-8')
        for expected in (
                '.no_trial_identity_input = true',
                '.postclaim_quarantine_residual = true',
                '.exact_two_p1_state_archives = true',
                '.p1_state_parent_read_descriptions = true',
                '.p1_state_sole_writer_aliases = true',
                '.p1_state_labeled_scm_contract = true',
                '.p1_state_fixed_child_fds_absent = true',
                '.p1_state_scm_activation_integration = false',
                '.p1_state_terminal_disposition_bound = false',
                '.p1_state_parent_rehydration = false',
                '.p1_state_completion_authority = false',
                '.unbound_production_reserve_absent = true',
                '.process_derived_reservation_permit_contract = true',
                '.process_derived_reservation_permit_consumed = true',
                '.hidden_process_epoch_bound = true',
                '.child_postfork_fd_enumeration_control = true',
                '.no_allocation_unavailable_composite = false',
                '.all_three_pidfds_reserved_before_issuance = false',
                '.selected_run_binding_factory = false',
                '.fresh_trial_bind_integration = false',
                '.selected_parent_callsite = false',
                '.configured = false'):
            self.assertIn(expected, header)


if __name__ == '__main__':
    unittest.main()
