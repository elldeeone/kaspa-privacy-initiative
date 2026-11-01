#!/usr/bin/env python3
"""Fresh-owner lineage join controls for typed Testnet accepted history."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent / 'mpc-prover' / 'financial'
MPC = FINANCIAL.parent
VENDOR = MPC.parents[2] / '.local' / 'mpc-prover-vendor' / 'MP-SPDZ'
PREFIX = VENDOR.parent / 'prefix' / 'usr' / 'include'


class TestnetAcceptedHistoryFreshOwnerControls(unittest.TestCase):
    def test_staged_chain_authority_injects_only_supervisor_lineages(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-testnet-history-fresh-owner-') as directory:
            binary = Path(directory) / 'control'
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-Wno-overloaded-virtual', '-Wno-psabi',
                '-Wno-unused-function', '-march=native', '-pthread',
                '-DKPI_FRESH_OWNER_ISSUANCE_TEST_SETUP',
                '-DKPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP',
                '-DKPI_FRESH_OWNER_ARM_ISOLATION_TEST_SETUP',
                '-DKPB_MEASUREMENT_AUTHORITY_TEST_SETUP',
                '-DKPB_TESTNET_ACCEPTED_HISTORY_TEST_SETUP',
                str(HERE / 'testnet_accepted_history_fresh_owner_control.cpp'),
                str(FINANCIAL / 'fresh_owner_arm_isolation.cpp'),
                str(FINANCIAL /
                    'candidate_owner_truth_post_barrier_bridge.cpp'),
                str(FINANCIAL / 'fresh_owner_process_adapter.cpp'),
                str(FINANCIAL / 'fresh_owner_trial_issuance.cpp'),
                str(FINANCIAL / 'registered_identity_registry.cpp'),
                str(HERE / 'testnet_accepted_history_authority.cpp'),
                str(HERE /
                    'testnet_accepted_history_fresh_owner_bridge.cpp'),
                str(HERE / 'privacy_measurement_authority.cpp'),
                str(HERE / 'privacy_measurement_child_output_authority.cpp'),
                str(HERE / 'privacy_measurement_output_abi.cpp'),
                '-I', str(MPC), '-I', str(HERE), '-I', str(VENDOR),
                '-I', str(PREFIX), '-I', str(PREFIX / 'x86_64-linux-gnu'),
                str(VENDOR / 'libSPDZ.so'),
                '-Wl,-rpath,' + str(VENDOR), '-lcrypto',
                '-o', str(binary),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, timeout=30, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_public_receipt_digest_or_lineage_array_cannot_enter_supervisor(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-testnet-history-surface-') as directory:
            source = Path(directory) / 'surface.cpp'
            source.write_text(r'''
#include "fresh_owner_process_adapter.hpp"
#include "testnet_accepted_history_authority.hpp"
#include <array>
#include <concepts>
#include <utility>
using namespace kpi::mpc::financial::fresh_owner_issuance;
using namespace kpb::testnet_history;
template<class T> concept ReceiptRound1 = requires(
    FreshOwnerProcessSupervisor& supervisor, T value,
    OwnerIssuanceReplayGuardAuthority replay,
    FreshOwnerArmIsolationResidualAuthority isolation) {
    supervisor.issue_round1(
        std::move(value), std::move(replay), std::move(isolation));
};
template<class T> concept ReceiptRound2 = requires(
    FreshOwnerProcessSupervisor& supervisor,
    FreshOwnerRound1IssuedAuthority round1, T value) {
    supervisor.issue_round2(std::move(round1), std::move(value));
};
static_assert(!ReceiptRound1<PublicAcceptedHistoryStage>);
static_assert(!ReceiptRound2<PublicAcceptedHistoryStage>);
static_assert(!ReceiptRound1<kpb::testnet_activation::Digest>);
static_assert(!ReceiptRound2<kpb::testnet_activation::Digest>);
static_assert(!ReceiptRound1<std::array<
    kpb::testnet_activation::Digest, 3>>);
static_assert(!ReceiptRound2<std::array<
    kpb::testnet_activation::Digest, 3>>);
static_assert(!kpb::testnet_history::kSourceStatus.first_rpc_live_consumer);
static_assert(!kpb::testnet_history::kSourceStatus
    .authenticated_network_child_producer);
static_assert(kpb::testnet_history::kSourceStatus
    .fresh_owner_supervisor_adapter);
static_assert(!kpb::testnet_history::kSourceStatus
    .selected_history_producer_callsite);
static_assert(!kpb::testnet_history::kSourceStatus.configured);
int main() {}
''', encoding='utf-8')
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-Wno-overloaded-virtual', '-Wno-psabi',
                '-march=native', '-fsyntax-only', str(source),
                '-I', str(FINANCIAL), '-I', str(MPC), '-I', str(HERE),
                '-I', str(VENDOR), '-I', str(PREFIX),
                '-I', str(PREFIX / 'x86_64-linux-gnu'),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)


if __name__ == '__main__':
    unittest.main()
