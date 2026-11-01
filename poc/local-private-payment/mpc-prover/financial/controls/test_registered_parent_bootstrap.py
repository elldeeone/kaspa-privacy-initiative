#!/usr/bin/env python3
"""Compiled controls for the typed retained-channel parent bootstrap."""

from pathlib import Path
import gzip
import hashlib
import json
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
VENDOR = MPC.parents[2] / '.local' / 'mpc-prover-vendor' / 'MP-SPDZ'
PREFIX = VENDOR.parent / 'prefix' / 'usr' / 'include'


class RegisteredParentBootstrapControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-registered-parent-bootstrap-')
        root = Path(cls.temporary.name)
        cls.artifact = root / 'public-query.gz'
        cls.wrong_artifact = root / 'wrong-public-query.gz'
        with gzip.GzipFile(
                filename=str(cls.artifact), mode='wb', mtime=0) as stream:
            stream.write(b'registered-parent-bootstrap-public-query\n')
        with gzip.GzipFile(
                filename=str(cls.wrong_artifact), mode='wb', mtime=0) as stream:
            stream.write(b'wrong-public-query\n')
        cls.binary = root / 'controls'
        zlib_binary = Path('/usr/lib/x86_64-linux-gnu/libz.so.1').resolve()
        zlib_hash = hashlib.sha256(zlib_binary.read_bytes()).hexdigest()
        zlib_headers = [Path('/usr/include/zlib.h'), Path('/usr/include/zconf.h')]
        header_hashes = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in zlib_headers
        }
        header_identity = hashlib.sha256(json.dumps(
            header_hashes, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-Wno-overloaded-virtual', '-Wno-psabi', '-march=native',
            '-DKPI_REGISTERED_PARENT_FORK_TEST_SETUP',
            '-DKPI_REGISTERED_PARENT_BOOTSTRAP_TEST_SETUP',
            '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
            f'-DKPI_TRACE_ZLIB_BINARY_SHA256="{zlib_hash}"',
            f'-DKPI_TRACE_ZLIB_HEADERS_SHA256="{header_identity}"',
            str(HERE / 'registered_parent_bootstrap_test.cpp'),
            str(FINANCIAL / 'registered_parent_bootstrap.cpp'),
            str(FINANCIAL / 'registered_parent_role_fork.cpp'),
            str(FINANCIAL / 'registered_projection_route.cpp'),
            str(FINANCIAL / 'registered_parent_role_delivery_bridge.cpp'),
            str(FINANCIAL / 'registered_driver_bridge.cpp'),
            str(FINANCIAL / 'registered_capture_session.cpp'),
            str(FINANCIAL / 'baseline_public_effects_collector.cpp'),
            str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            str(FINANCIAL / 'docker_monotonic_anchor_client.cpp'),
            str(MPC / 'trace' / 'sealed_trace.cpp'),
            str(MPC.parent / 'private_batch_trial' /
                'privacy_capture_hook.cpp'),
            '-I', str(FINANCIAL), '-I', str(MPC), '-I', str(VENDOR),
            '-I', str(PREFIX), '-I', str(PREFIX / 'x86_64-linux-gnu'),
            str(VENDOR / 'libSPDZ.so'), '-Wl,-rpath,' + str(VENDOR),
            '-lcrypto', '-lz', '-pthread', '-o', str(cls.binary),
        ], capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_scenario(self, scenario):
        result = subprocess.run([
            str(self.binary), scenario, str(self.artifact),
            str(self.wrong_artifact),
        ], capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_exact_three_roles_admit_inherited_artifact_before_capabilities(self):
        self.run_scenario('valid')

    def test_wrong_role_offer_fails_closed(self):
        self.run_scenario('wrong-role')

    def test_capture_plan_trial_must_match_fresh_round(self):
        self.run_scenario('wrong-trial')

    def test_wrong_admitted_query_identity_fails_closed(self):
        self.run_scenario('wrong-model')

    def test_wrong_admission_ack_fails_closed(self):
        self.run_scenario('wrong-ack')

    def test_inherited_artifact_mixup_fails_closed(self):
        self.run_scenario('artifact-mixup')

    def test_role_capability_take_replay_refuses(self):
        self.run_scenario('take-replay')

    def test_source_status_keeps_selected_main_closed(self):
        self.run_scenario('status')

    def test_prepare_burns_fresh_round_and_capture_before_validation(self):
        source = (FINANCIAL / 'registered_parent_bootstrap.cpp').read_text(
            encoding='utf-8')
        self.assertIn(
            'const bool fresh_was_live = fresh.live_.exchange(false);',
            source)
        self.assertIn(
            'const bool capture_was_live = capture.live_.exchange(false);',
            source)
        self.assertIn('need(fresh_was_live && capture_was_live &&', source)
        self.assertNotIn(
            'fresh.live_.exchange(false) &&\n'
            '             capture.live_.exchange(false)', source)

    def test_production_prepare_requires_roster_bound_capture_plan(self):
        contract = (FINANCIAL /
                    'registered_parent_bootstrap_contract.hpp').read_text(
                        encoding='utf-8')
        self.assertIn('class RosterBoundCapturePlan;', contract)
        self.assertIn(
            'static ParentBootstrapPlanAuthority prepare(\n'
            '        fresh_owner_issuance::'
            'ConsumedFreshOwnerRoundBootstrap&&,\n'
            '        RosterBoundCapturePlan&&,', contract)

        orchestrator = (FINANCIAL /
                        'registered_selected_parent_orchestrator.hpp').read_text(
                            encoding='utf-8')
        self.assertIn('RosterBoundCapturePlan&&', orchestrator)

    def test_production_surface_has_no_digest_json_or_friend_forge(self):
        root = Path(self.temporary.name)
        source = root / 'production-surface.cpp'
        source.write_text(r'''
#include "registered_parent_bootstrap.hpp"
#include <concepts>
using namespace kpi::mpc::financial::registered_driver;
template<class T> concept DigestAuthorize = requires(
        T value, const char* model, const char* query) {
    RegisteredParentBootstrapTransport::authorize_admitted_model(
        static_cast<T&&>(value), model, query);
};
static_assert(!std::default_initializable<ParentBootstrapPlanAuthority>);
static_assert(!std::copy_constructible<ParentBootstrapPlanAuthority>);
static_assert(!std::default_initializable<RegisteredChildBootstrapPending>);
static_assert(!std::copy_constructible<RegisteredChildBootstrapPending>);
static_assert(!std::default_initializable<RegisteredAdmittedRoleBootstrap>);
static_assert(!std::copy_constructible<RegisteredAdmittedRoleBootstrap>);
static_assert(!DigestAuthorize<RegisteredChildBootstrapPending>);
int main() { return 0; }
''', encoding='utf-8')
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-c', str(source), '-I', str(FINANCIAL), '-I', str(MPC),
            '-o', str(root / 'production-surface.o'),
        ], capture_output=True, text=True, check=False)
        self.assertEqual(compiled.returncode, 0,
                         compiled.stdout + compiled.stderr)

        forge = root / 'friend-forge.cpp'
        forge.write_text(r'''
#include "registered_driver_bridge.hpp"
namespace kpi::mpc::financial::registered_driver {
class RegisteredParentBootstrapTransport final {
public:
    static CapturePlanAuthority forge(PublicCapturePlan value) {
        return CapturePlanAuthority(std::move(value));
    }
};
}
int main() { return 0; }
''', encoding='utf-8')
        rejected = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-c', str(forge), '-I', str(FINANCIAL), '-I', str(MPC),
            '-o', str(root / 'friend-forge.o'),
        ], capture_output=True, text=True, check=False)
        self.assertNotEqual(rejected.returncode, 0,
                            'bootstrap friend name was forgeable')


if __name__ == '__main__':
    unittest.main()

