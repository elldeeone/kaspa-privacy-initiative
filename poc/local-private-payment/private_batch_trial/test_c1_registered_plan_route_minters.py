#!/usr/bin/env python3
"""Offline controls for opaque-source C1 route evidence minter cores."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
MPC = HERE.parent / 'mpc-prover'
FINANCIAL = MPC / 'financial'


class RegisteredC1PlanRouteMinterControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-registered-c1-route-minters-')
        cls.binary = Path(cls.temporary.name) / 'control'
        cls.sanitized_binary = Path(cls.temporary.name) / 'control-sanitized'
        common = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
            '-DKPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP',
            '-DKPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP',
            '-DKPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP',
            str(HERE / 'c1_registered_plan_route_minters_control.cpp'),
            str(HERE / 'c1_registered_plan_route_minters.cpp'),
            str(HERE / 'c1_registered_plan_route_bridge.cpp'),
            str(HERE / 'c1_contact_value_authority.cpp'),
            str(HERE / 'privacy_capture_producer_runtime.cpp'),
            str(HERE / 'privacy_capture_producer_archive.cpp'),
            str(HERE / 'privacy_measurement_authority.cpp'),
            str(HERE / 'privacy_measurement_child_output_authority.cpp'),
            str(HERE / 'privacy_measurement_output_abi.cpp'),
            '-I', str(HERE), '-I', str(MPC), '-I', str(FINANCIAL),
            '-lcrypto',
        ]
        for binary, flags in (
                (cls.binary, ()),
                (cls.sanitized_binary, (
                    '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer'))):
            result = subprocess.run(
                [*common, *flags, '-o', str(binary)],
                capture_output=True, text=True, check=False)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def compile_syntax(self, source):
        return subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread', '-I', str(HERE), '-I', str(MPC),
            '-I', str(FINANCIAL), '-fsyntax-only', str(source),
        ], capture_output=True, text=True, check=False)

    def test_opaque_source_two_round_and_poison_controls(self):
        result = subprocess.run(
            [str(self.binary)], capture_output=True, text=True,
            check=False, timeout=30)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_opaque_source_controls_under_asan_ubsan(self):
        environment = dict(os.environ)
        environment.update({
            'ASAN_OPTIONS': 'detect_leaks=1:halt_on_error=1',
            'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1',
        })
        result = subprocess.run(
            [str(self.sanitized_binary)], capture_output=True, text=True,
            check=False, timeout=30, env=environment)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_production_surface_has_no_public_aggregate_minter(self):
        source = Path(self.temporary.name) / 'production-surface.cpp'
        source.write_text(r'''
#include "c1_registered_plan_route_minters.hpp"
#include <concepts>
#include <string>
#include <utility>
using namespace kpb::measurement::c1_capture;
using kpb::measurement::producer_runtime::ParentTenReadEndsAuthority;

template<class Bridge> concept PublicLineageBegin = requires(
        PublicRegisteredC1RoundLineage lineage) {
    Bridge::begin_controller_selection(
        std::move(lineage), std::string{});
};
template<class Bridge> concept PublicSelectionPrepare = requires(
        ParentTenReadEndsAuthority& parent,
        PublicC1AcceptedControllerSelection selection) {
    Bridge::prepare_selected(parent, std::move(selection));
};
template<class Callsite> concept AggregateSelectionObservation = requires(
        Callsite& callsite, PublicC1AcceptedControllerSelection selection) {
    callsite.observe_selected_stage(std::move(selection));
};
template<class Callsite> concept AggregateTerminalObservation = requires(
        Callsite& callsite, PublicC1AcceptedControllerResult result) {
    callsite.observe_controller_terminal(std::move(result));
};
template<class Callsite> concept ClaimedDigestRouteObservation = requires(
        Callsite& callsite, kpb::measurement::Digest digest) {
    callsite.observe_route_artifact(digest);
};
template<class Callsite> concept PrimitiveSelectionObservation = requires(
        Callsite& callsite, std::string operation) {
    callsite.observe_selected_stage(
        C1ControllerStage::Invoice, std::move(operation), 4);
};
template<class Callsite> concept SelfAssertedFd31Parse = requires(
        Callsite& callsite) {
    callsite.observe_fd31_offer_parse();
};
template<class Callsite> concept SelfAssertedCompletion = requires(
        Callsite& callsite) {
    callsite.observe_authenticated_completion();
    callsite.observe_writer_close();
    callsite.observe_eof();
    callsite.observe_expected_exit(0);
};

static_assert(!std::default_initializable<
    C1ControllerSelectionSourceAuthority>);
static_assert(!std::default_initializable<
    C1Fd31OfferParseSourceAuthority>);
static_assert(!std::default_initializable<
    C1ControllerTerminalSourceAuthority>);
static_assert(!std::default_initializable<C1ObservedRouteSourceAuthority>);
static_assert(!std::default_initializable<
    C1Fd31CompletionSourceAuthority>);
static_assert(!std::default_initializable<
    RegisteredC1ControllerSelectionCallsite>);
static_assert(!std::default_initializable<RegisteredC1SelectedRound>);
static_assert(!std::default_initializable<
    RegisteredC1SelectedLaunchCallsite>);
static_assert(!std::default_initializable<RegisteredC1TerminalCallsite>);
static_assert(!std::default_initializable<
    RegisteredC1RoundRouteEvidenceAuthority>);
static_assert(!std::default_initializable<
    RegisteredC1TerminalAdmissionSplit>);
static_assert(!std::default_initializable<
    RegisteredC1TwoRoundRouteEvidenceAuthority>);
static_assert(std::default_initializable<
    RegisteredC1TwoRoundRouteEvidenceJoiner>);
static_assert(!PublicLineageBegin<RegisteredC1RuntimeCallsiteBridge>);
static_assert(!PublicSelectionPrepare<RegisteredC1RuntimeCallsiteBridge>);
static_assert(!AggregateSelectionObservation<
    RegisteredC1ControllerSelectionCallsite>);
static_assert(!AggregateTerminalObservation<RegisteredC1TerminalCallsite>);
static_assert(!ClaimedDigestRouteObservation<RegisteredC1TerminalCallsite>);
static_assert(!PrimitiveSelectionObservation<
    RegisteredC1ControllerSelectionCallsite>);
static_assert(!SelfAssertedFd31Parse<RegisteredC1TerminalCallsite>);
static_assert(!SelfAssertedCompletion<RegisteredC1TerminalCallsite>);
int main() { return 0; }
''', encoding='utf-8')
        result = self.compile_syntax(source)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)

    def test_minter_translation_unit_is_clean_without_test_macros(self):
        result = self.compile_syntax(
            HERE / 'c1_registered_plan_route_minters.cpp')
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)

    def test_production_objects_have_no_c1_test_setup_symbols(self):
        forbidden = (
            'RegisteredC1RouteMinterTestFixture',
            'test_only_mint',
        )
        for source_name in (
                'c1_registered_plan_route_minters.cpp',
                'c1_registered_plan_route_bridge.cpp'):
            with self.subTest(source=source_name):
                source = HERE / source_name
                output = (Path(self.temporary.name) /
                          f'{source.stem}-production.o')
                built = subprocess.run([
                    'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                    '-pedantic', '-pthread', '-I', str(HERE),
                    '-I', str(MPC), '-I', str(FINANCIAL), '-c',
                    str(source), '-o', str(output),
                ], capture_output=True, text=True, check=False)
                self.assertEqual(built.returncode, 0,
                                 built.stdout + built.stderr)
                symbols = subprocess.run(
                    ['nm', '-C', str(output)], capture_output=True,
                    text=True, check=False)
                self.assertEqual(symbols.returncode, 0,
                                 symbols.stdout + symbols.stderr)
                for name in forbidden:
                    self.assertNotIn(name, symbols.stdout)

    def test_synthetic_source_factory_is_absent_in_production(self):
        source = Path(self.temporary.name) / 'forbidden-fixture.cpp'
        source.write_text(r'''
#include "c1_registered_plan_route_minters.hpp"
using namespace kpb::measurement::c1_capture;
int main() {
    auto value = RegisteredC1RouteMinterTestFixture::selection_source;
    (void)value;
}
''', encoding='utf-8')
        result = self.compile_syntax(source)
        self.assertNotEqual(result.returncode, 0,
                            'synthetic C1 source factory compiled')
        self.assertIn('RegisteredC1RouteMinterTestFixture', result.stderr)


if __name__ == '__main__':
    unittest.main()
