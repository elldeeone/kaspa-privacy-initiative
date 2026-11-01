#!/usr/bin/env python3
"""Compiled controls for fresh independent owner-input issuance authority."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
TRIAL = MPC.parent / 'private_batch_trial'
VENDOR = MPC.parents[2] / '.local' / 'mpc-prover-vendor' / 'MP-SPDZ'
PREFIX = VENDOR.parent / 'prefix' / 'usr' / 'include'


class FreshOwnerTrialIssuanceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-fresh-owner-issuance-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-Wno-overloaded-virtual', '-Wno-psabi',
            '-march=native', '-DKPI_FRESH_OWNER_ISSUANCE_TEST_SETUP',
            '-DKPI_FRESH_OWNER_TRANSACTIONAL_ISSUANCE_TEST_SETUP',
            '-DKPB_FRESH_OWNER_TRANSACTIONAL_REPLAY_TEST_SETUP',
            str(HERE / 'fresh_owner_trial_issuance_test.cpp'),
            str(FINANCIAL / 'fresh_owner_trial_issuance.cpp'),
            str(FINANCIAL / 'registered_preidentity_ready.cpp'),
            str(FINANCIAL / 'registered_parent_role_fork.cpp'),
            str(FINANCIAL / 'registered_projection_route.cpp'),
            str(FINANCIAL / 'registered_parent_role_delivery_bridge.cpp'),
            str(FINANCIAL / 'registered_driver_bridge.cpp'),
            str(FINANCIAL / 'registered_capture_session.cpp'),
            str(FINANCIAL / 'baseline_public_effects_collector.cpp'),
            str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
            str(FINANCIAL / 'docker_monotonic_anchor_client.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            str(TRIAL /
                'privacy_registered_fresh_trial_capture_topology_reservation.cpp'),
            str(TRIAL /
                'privacy_registered_fresh_trial_capture_topology_permit.cpp'),
            str(TRIAL / 'privacy_capture_hook.cpp'),
            str(TRIAL /
                'privacy_fresh_owner_transactional_replay_authority.cpp'),
            '-I', str(MPC), '-I', str(TRIAL), '-I', str(VENDOR),
            '-I', str(PREFIX),
            '-I', str(PREFIX / 'x86_64-linux-gnu'),
            str(VENDOR / 'libSPDZ.so'),
            '-Wl,-rpath,' + str(VENDOR), '-lcrypto', '-pthread',
            '-o', str(cls.binary),
        ], capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_scenario(self, scenario):
        ran = subprocess.run([str(self.binary), scenario],
                             capture_output=True, text=True,
                             timeout=20, check=False)
        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        self.assertEqual((ran.stdout, ran.stderr), ('', ''))

    def test_fresh_three_owner_two_round_join(self):
        self.run_scenario('happy')

    def test_hidden_candidate_has_no_baseline_roster_authority(self):
        self.run_scenario('hidden')

    def test_round2_requires_accepted_round1_history_gate(self):
        self.run_scenario('causal')

    def test_permission_separated_registry_refuses_replay(self):
        self.run_scenario('replay')

    def test_transactional_registry_commit_retains_closed_sum(self):
        self.run_scenario('transactional-commit')

    def test_transactional_registry_unavailable_retains_stop_sum(self):
        self.run_scenario('transactional-stop')

    def test_transactional_post_prepare_path_allocates_nothing(self):
        self.run_scenario('transactional-noalloc')

    def test_issuance_split_postclaim_path_allocates_nothing(self):
        self.run_scenario('split-noalloc')

    def test_mixed_controller_tls_and_logical_owner_refuse(self):
        self.run_scenario('mixed')

    def test_a864_consumed_root_and_policy_tombstones_refuse(self):
        self.run_scenario('tombstones')

    def test_wrong_long_lived_owner_proof_poisons_receiver(self):
        self.run_scenario('proof')

    def test_source_status_keeps_production_and_launch_closed(self):
        self.run_scenario('status')

    def test_production_surface_has_no_receipt_path_or_digest_minter(self):
        source = Path(self.temporary.name) / 'production-surface.cpp'
        source.write_text(r'''
#include "fresh_owner_trial_issuance.hpp"
#include <concepts>
using namespace kpi::mpc::financial::fresh_owner_issuance;
template<class T> concept ReceiptFactory = requires(
    PublicOwnerIssuanceReceipt value) { T::from_receipt(value); };
template<class T> concept PathFactory = requires(
    const char* path) { T::from_path(path); };
template<class T> concept PublicStableIdentity = requires(T value) {
    value.logical_owner_identity;
};
template<class T> concept PublicContracts = requires(const T& value) {
    value.contracts();
};
template<class T> concept TestMintVisible = requires(
    PublicOwnerIssuanceReceipt value) { T::test_only_mint(value); };
static_assert(!std::default_initializable<OwnerLocalIssuanceAuthority>);
static_assert(!std::copy_constructible<OwnerLocalIssuanceAuthority>);
static_assert(!std::default_initializable<OwnerIssuanceReplayGuardAuthority>);
static_assert(!ReceiptFactory<OwnerLocalIssuanceAuthority>);
static_assert(!PathFactory<OwnerLocalIssuanceAuthority>);
static_assert(!TestMintVisible<OwnerLocalIssuanceAuthority>);
static_assert(!PublicStableIdentity<PublicOwnerIssuanceReceipt>);
static_assert(!PublicStableIdentity<PublicFreshOwnerTrialIssuanceReceipt>);
static_assert(!PublicContracts<FreshOwnerRoundAuthority>);
int main() { return 0; }
''', encoding='utf-8')
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-Wno-overloaded-virtual', '-Wno-psabi',
            '-march=native', '-c', str(source), '-I', str(FINANCIAL),
            '-I', str(MPC), '-I', str(VENDOR), '-I', str(PREFIX),
            '-I', str(PREFIX / 'x86_64-linux-gnu'),
            '-o', str(Path(self.temporary.name) / 'production-surface.o'),
        ], capture_output=True, text=True, check=False)
        self.assertEqual(compiled.returncode, 0,
                         compiled.stdout + compiled.stderr)

        implementation = (
            (FINANCIAL / 'fresh_owner_trial_issuance.hpp').read_text() +
            (FINANCIAL / 'fresh_owner_trial_issuance.cpp').read_text())
        for forbidden in ('std::filesystem', 'std::ifstream',
                          'body_sha256', 'owner_file_path',
                          'private_file_path'):
            self.assertNotIn(forbidden, implementation)


if __name__ == '__main__':
    unittest.main()
