#!/usr/bin/env python3
"""Controls for the chronology-correct registered C1 plan/route seam."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
MPC = HERE.parent / 'mpc-prover'
FINANCIAL = MPC / 'financial'


class RegisteredC1PlanRouteBridgeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-registered-c1-plan-route-')
        cls.binary = Path(cls.temporary.name) / 'control'
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
            '-DKPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP',
            '-DKPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP',
            '-DKPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP',
            str(HERE / 'c1_registered_plan_route_bridge_control.cpp'),
            str(HERE / 'c1_registered_plan_route_bridge.cpp'),
            str(HERE / 'c1_contact_value_authority.cpp'),
            str(HERE / 'privacy_capture_producer_runtime.cpp'),
            str(HERE / 'privacy_capture_producer_archive.cpp'),
            str(HERE / 'privacy_measurement_authority.cpp'),
            str(HERE / 'privacy_measurement_child_output_authority.cpp'),
            str(HERE / 'privacy_measurement_output_abi.cpp'),
            '-I', str(HERE), '-I', str(MPC), '-I', str(FINANCIAL),
            '-lcrypto', '-o', str(cls.binary),
        ]
        result = subprocess.run(command, capture_output=True, text=True,
                                check=False)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def compile_syntax(self, source, *extra):
        return subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread', '-I', str(HERE), '-I', str(MPC),
            '-I', str(FINANCIAL), *map(str, extra), '-fsyntax-only',
            str(source),
        ], capture_output=True, text=True, check=False)

    def test_positive_replay_provenance_route_history_and_false_flags(self):
        result = subprocess.run([str(self.binary)], capture_output=True,
                                text=True, check=False, timeout=20)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_registered_prelaunch_split_translation_unit_is_clean(self):
        for source in (
                HERE / 'c1_registered_prelaunch_split.cpp',
                HERE / 'c1_registered_plan_route_bridge.cpp'):
            result = self.compile_syntax(source)
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)

    def test_production_surface_requires_opaque_authorities(self):
        source = Path(self.temporary.name) / 'production-surface.cpp'
        source.write_text(r'''
#include "c1_registered_plan_route_bridge.hpp"
#include <concepts>
#include <type_traits>
using namespace kpb::measurement::c1_capture;
using kpb::measurement::producer_runtime::ParentTenReadEndsAuthority;

template<class Bridge> concept CallerDataPrepare = requires(
        ParentTenReadEndsAuthority& parent,
        PublicRegisteredC1RoundLineage lineage,
        PublicC1AcceptedControllerSelection selection) {
    Bridge::prepare(parent, std::move(lineage), std::move(selection));
};
template<class Bridge> concept CallerTerminalAdmit = requires(
        RegisteredC1PendingTerminalAuthority&& pending,
        PublicC1Fd31QualifiedCompletionAck ack,
        PublicC1AcceptedControllerResult result,
        PublicC1ObservedInvoiceRoute route) {
    Bridge::admit_terminal(std::move(pending), std::move(ack),
                           std::move(result),
                           std::move(route));
};
template<class Bridge> concept MissingAckTerminalAdmit = requires(
        RegisteredC1PendingTerminalAuthority&& pending,
        C1AcceptedControllerResultAuthority&& result,
        C1ObservedInvoiceRouteAuthority&& route) {
    Bridge::admit_terminal(std::move(pending), std::move(result),
                           std::move(route));
};

static_assert(!std::default_initializable<
    RegisteredC1RoundLineageAuthority>);
static_assert(!std::copy_constructible<
    RegisteredC1RoundLineageAuthority>);
static_assert(!std::constructible_from<
    RegisteredC1RoundLineageAuthority,
    PublicRegisteredC1RoundLineage>);
static_assert(!std::constructible_from<
    C1AcceptedControllerSelectionAuthority,
    PublicC1AcceptedControllerSelection>);
static_assert(!std::constructible_from<
    C1Fd31QualifiedCompletionAckAuthority,
    PublicC1Fd31QualifiedCompletionAck>);
static_assert(!std::constructible_from<
    C1AcceptedControllerResultAuthority,
    PublicC1AcceptedControllerResult>);
static_assert(!std::constructible_from<
    C1ObservedInvoiceRouteAuthority,
    PublicC1ObservedInvoiceRoute>);
static_assert(!CallerDataPrepare<RegisteredC1PlanRouteBridge>);
static_assert(!CallerTerminalAdmit<RegisteredC1PlanRouteBridge>);
static_assert(!MissingAckTerminalAdmit<RegisteredC1PlanRouteBridge>);
int main() { return 0; }
''', encoding='utf-8')
        result = self.compile_syntax(source)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)

    def test_test_only_mints_do_not_compile_in_production(self):
        source = Path(self.temporary.name) / 'forbidden-test-mints.cpp'
        source.write_text(r'''
#include "c1_registered_plan_route_bridge.hpp"
using namespace kpb::measurement::c1_capture;
int main() {
    auto lineage = RegisteredC1RoundLineageAuthority::test_only_mint({});
    auto selection =
        C1AcceptedControllerSelectionAuthority::test_only_mint({});
    auto completion =
        C1Fd31QualifiedCompletionAckAuthority::test_only_mint({});
    auto result = C1AcceptedControllerResultAuthority::test_only_mint({});
    auto route = C1ObservedInvoiceRouteAuthority::test_only_mint({});
    (void)lineage; (void)selection; (void)completion;
    (void)result; (void)route;
}
''', encoding='utf-8')
        result = self.compile_syntax(source)
        self.assertNotEqual(result.returncode, 0,
                            'test-only registered C1 minters compiled')
        self.assertIn('test_only_mint', result.stderr)

    def test_complete_bridge_name_cannot_be_hostile_redefined(self):
        source = Path(self.temporary.name) / 'hostile-friend.cpp'
        source.write_text(r'''
#include "c1_registered_plan_route_bridge.hpp"
namespace kpb::measurement::c1_capture {
class RegisteredC1PlanRouteBridge final {};
}
int main() { return 0; }
''', encoding='utf-8')
        result = self.compile_syntax(source)
        self.assertNotEqual(result.returncode, 0,
                            'registered C1 bridge redefinition compiled')
        self.assertIn('redefinition', result.stderr)

    def test_direct_friend_headers_reject_exact_name_redefinition(self):
        for index, header in enumerate((
                'c1_contact_value_authority_bridge_contract.hpp',
                'c1_contact_value_authority.hpp',
                'privacy_capture_producer_runtime.hpp')):
            with self.subTest(header=header):
                source = (Path(self.temporary.name) /
                          f'hostile-direct-friend-{index}.cpp')
                source.write_text(f'''
#include "{header}"
namespace kpb::measurement::c1_capture {{
class RegisteredC1PlanRouteBridge final {{}};
}}
int main() {{ return 0; }}
''', encoding='utf-8')
                result = self.compile_syntax(source)
                self.assertNotEqual(
                    result.returncode, 0,
                    f'hostile friend compiled through {header}')
                self.assertIn('redefinition', result.stderr)

    def test_direct_friend_headers_reject_private_access(self):
        stage_source = (Path(self.temporary.name) /
                        'hostile-stage-private-access.cpp')
        stage_source.write_text(r'''
#include "c1_contact_value_authority.hpp"
#include <utility>
using namespace kpb::measurement::c1_capture;
C1LifecycleStagePlanAuthority attack(PublicC1LifecycleStagePlan value) {
    return C1LifecycleStagePlanAuthority(std::move(value));
}
int main() { return 0; }
''', encoding='utf-8')
        stage_result = self.compile_syntax(stage_source)
        self.assertNotEqual(stage_result.returncode, 0,
                            'private stage-plan constructor compiled')
        self.assertIn('private', stage_result.stderr)

        parent_source = (Path(self.temporary.name) /
                         'hostile-parent-private-access.cpp')
        parent_source.write_text(r'''
#include "privacy_capture_producer_runtime.hpp"
using namespace kpb::measurement::producer_runtime;
bool attack(ParentTenReadEndsAuthority& parent) {
    return parent.live_.load();
}
int main() { return 0; }
''', encoding='utf-8')
        parent_result = self.compile_syntax(parent_source)
        self.assertNotEqual(parent_result.returncode, 0,
                            'private parent authority state compiled')
        self.assertIn('private', parent_result.stderr)

    def test_source_has_no_actual_receipt_or_truth_route(self):
        header = (HERE / 'c1_registered_plan_route_bridge.hpp').read_text(
            encoding='utf-8')
        implementation = (
            HERE / 'c1_registered_plan_route_bridge.cpp').read_text(
                encoding='utf-8')
        self.assertNotIn('OwnerTruth', header)
        self.assertNotIn('TruthAuthority', header)
        self.assertNotIn('ActualReceiptAuthority', header)
        for needle in (
                '.registered_prelaunch_split_core = false',
                '.production_controller_selection_minter = false',
                '.production_fd31_completion_ack_minter = false',
                '.production_controller_terminal_minter = false',
                '.production_observed_route_minter = false',
                '.selected_launcher_consumes_offer = false',
                '.selected_terminal_admission_callsite = false',
                '.owner_truth_input = false',
                '.actual_receipt_emitted = false',
                '.configured = false',
                '.actual_launch = false',
                '.complete = false'):
            self.assertIn(needle, implementation)


if __name__ == '__main__':
    unittest.main()
