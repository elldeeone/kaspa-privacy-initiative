#!/usr/bin/env python3
"""Hostile controls for the source-unreachable Testnet accepted-history core."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class TestnetAcceptedHistoryAuthorityControls(unittest.TestCase):
    def compile(self, source):
        return subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-fsyntax-only', '-I', str(HERE), str(source),
        ], capture_output=True, text=True, check=False)

    def source(self, directory, name, value):
        path = Path(directory) / name
        path.write_text(value, encoding='utf-8')
        return path

    def test_staged_full20_currentness_reorg_and_replay_controls(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-testnet-accepted-history-') as directory:
            binary = Path(directory) / 'control'
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-pthread',
                '-DKPB_TESTNET_ACCEPTED_HISTORY_TEST_SETUP',
                str(HERE / 'testnet_accepted_history_authority_control.cpp'),
                str(HERE / 'testnet_accepted_history_authority.cpp'),
                '-I', str(HERE), '-lcrypto', '-o', str(binary),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=15)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_authorities_are_move_only_opaque_and_no_receipt_can_mint(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-testnet-accepted-surface-') as directory:
            source = self.source(directory, 'surface.cpp', r'''
#include "testnet_accepted_history_authority.hpp"
#include <concepts>
#include <utility>
using namespace kpb::testnet_history;
template<class T> concept HasReceipt = requires(const T& v) {
    v.public_receipt();
};
template<class T> concept LvalueConsume = requires(T& v) {
    v.consume_for_fresh_owner();
};
static_assert(!std::default_initializable<AcceptedHistoryObservationAuthority>);
static_assert(!std::copy_constructible<AcceptedHistoryObservationAuthority>);
static_assert(std::move_constructible<AcceptedHistoryObservationAuthority>);
static_assert(!std::default_initializable<AcceptedHistoryNetworkSessionAuthority>);
static_assert(!std::copy_constructible<AcceptedHistoryNetworkSessionAuthority>);
static_assert(!std::default_initializable<AcceptedRound1InputChainAuthority>);
static_assert(!std::copy_constructible<AcceptedRound1InputChainAuthority>);
static_assert(std::move_constructible<AcceptedRound1InputChainAuthority>);
static_assert(!std::default_initializable<
    AcceptedRound1SuccessorNetworkContinuationAuthority>);
static_assert(!std::copy_constructible<
    AcceptedRound1SuccessorNetworkContinuationAuthority>);
static_assert(!std::default_initializable<AcceptedRound1SuccessorChainAuthority>);
static_assert(!std::copy_constructible<AcceptedRound1SuccessorChainAuthority>);
static_assert(std::move_constructible<AcceptedRound1SuccessorChainAuthority>);
static_assert(!HasReceipt<AcceptedRound1InputChainAuthority>);
static_assert(!HasReceipt<AcceptedRound1SuccessorChainAuthority>);
static_assert(!LvalueConsume<AcceptedRound1InputChainAuthority>);
static_assert(!LvalueConsume<AcceptedRound1SuccessorChainAuthority>);
static_assert(!kSourceStatus.first_rpc_live_consumer);
static_assert(!kSourceStatus.authenticated_network_child_producer);
static_assert(kSourceStatus.fresh_owner_supervisor_adapter);
static_assert(!kSourceStatus.selected_history_producer_callsite);
static_assert(!kSourceStatus.configured && !kSourceStatus.network_enabled);
static_assert(!kSourceStatus.funding_enabled && !kSourceStatus.broadcast_enabled);
int main() {}
''')
            compiled = self.compile(source)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_direct_construction_and_test_only_mints_are_absent_in_production(self):
        hostile = {
            'direct.cpp': r'''
#include "testnet_accepted_history_authority.hpp"
int main() {
    using namespace kpb::testnet_history;
    AcceptedHistoryNetworkSessionAuthority value(
        kpb::testnet_activation::PublicFirstRpcBoundary{},
        Round1LifecycleBinding{}, kpb::testnet_activation::Digest{});
}
''',
            'observation.cpp': r'''
#include "testnet_accepted_history_authority.hpp"
int main() {
    kpb::testnet_history::AcceptedHistoryObservationAuthority value(
        kpb::testnet_history::AcceptedHistoryObservation{});
}
''',
            'receipt.cpp': r'''
#include "testnet_accepted_history_authority.hpp"
int main() {
    kpb::testnet_history::PublicAcceptedHistoryStage receipt{};
    kpb::testnet_history::AcceptedRound1InputChainAuthority value(receipt);
}
''',
            'test-mint.cpp': r'''
#include "testnet_accepted_history_authority.hpp"
int main() {
    using namespace kpb::testnet_history;
    AcceptedHistoryObservation observation{};
    (void)AcceptedHistoryObservationAuthority::test_only_mint(observation);
}
''',
            'bridge-redefinition.cpp': r'''
namespace kpb::testnet_history {
class AcceptedHistoryConfirmationBridge final {};
}
#include "testnet_accepted_history_authority.hpp"
int main() {}
''',
        }
        with tempfile.TemporaryDirectory(
                prefix='kpb-testnet-accepted-hostile-') as directory:
            for name, value in hostile.items():
                with self.subTest(name=name):
                    compiled = self.compile(self.source(
                        directory, name, value))
                    self.assertNotEqual(
                        compiled.returncode, 0,
                        'hostile source unexpectedly compiled: ' + name)

    def test_core_has_no_network_funding_signing_or_broadcast_call(self):
        source = (HERE / 'testnet_accepted_history_authority.cpp').read_text(
            encoding='utf-8')
        for forbidden in (
                'connectTor(', 'submitTransaction(',
                'getVirtualChainFromBlockV2(', 'getUtxosByAddresses(',
                'signTransaction(', 'broadcastTransaction('):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
