#!/usr/bin/env python3
"""Hostile-TU controls for fresh-owner private authority constructors."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
VENDOR = MPC.parents[2] / '.local' / 'mpc-prover-vendor' / 'MP-SPDZ'
PREFIX = VENDOR.parent / 'prefix' / 'usr' / 'include'


class FreshOwnerFriendSeamControls(unittest.TestCase):
    def compile_hostile(self, source):
        with tempfile.TemporaryDirectory(
                prefix='kpb-fresh-owner-hostile-tu-') as directory:
            path = Path(directory) / 'hostile.cpp'
            path.write_text(source, encoding='utf-8')
            return subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-Wno-overloaded-virtual', '-Wno-psabi',
                '-march=native', '-fsyntax-only', str(path),
                '-I', str(FINANCIAL), '-I', str(MPC),
                '-I', str(VENDOR), '-I', str(PREFIX),
                '-I', str(PREFIX / 'x86_64-linux-gnu'),
            ], capture_output=True, text=True, check=False)

    def test_removed_forward_only_round_bridge_cannot_forge_authority(self):
        result = self.compile_hostile(r'''
#include "fresh_owner_trial_issuance.hpp"
#include <array>
#include <utility>
namespace kpi::mpc::financial::fresh_owner_issuance {
class FreshOwnerRoundBridge final {
public:
    static FreshOwnerRoundAuthority forge(
            PublicFreshOwnerRoundReceipt receipt,
            std::array<OwnerInputContract, 3> contracts) {
        return FreshOwnerRoundAuthority(
            std::move(receipt), std::move(contracts));
    }
};
}
int main() { return 0; }
''')
        self.assertNotEqual(result.returncode, 0,
                            'forward-only friend forged a round authority')
        self.assertIn('FreshOwnerRoundAuthority', result.stderr)
        self.assertIn('private within this context', result.stderr)

    def test_privileged_bridge_names_are_complete_and_cannot_be_redefined(self):
        names = (
            'FreshOwnerProcessMintBridge',
            'FreshOwnerRoundBootstrapBridge',
            'FreshOwnerTrialIssuanceBridge',
            'FreshOwnerTrialSplit',
            'BaselineOwnerRosterBridge',
            'BaselineOwnerRosterReceiverBridge',
            'BaselineOwnerRosterReceiverSplit',
            'BaselineOwnerRosterReceiverSession',
            'BaselineOwnerRosterVerifiedBridge',
            'FreshOwnerArmIsolationBridge',
            'CandidateOwnerTruthPostBarrierBridge',
            'OwnerTruthScoreHandoffBridge',
            'FreshOwnerProcessSupervisor',
            'RegisteredProposalBridge',
            'RegisteredParentBootstrapTransport',
            'V3LifecycleControllerMinter',
        )
        result = self.compile_hostile(r'''
#include "fresh_owner_process_adapter.hpp"
namespace kpi::mpc::financial::fresh_owner_issuance {
class FreshOwnerProcessMintBridge final {};
class FreshOwnerRoundBootstrapBridge final {};
class FreshOwnerTrialIssuanceBridge final {};
class FreshOwnerTrialSplit final {};
class BaselineOwnerRosterBridge final {};
class BaselineOwnerRosterReceiverBridge final {};
class BaselineOwnerRosterReceiverSplit final {};
class BaselineOwnerRosterReceiverSession final {};
class BaselineOwnerRosterVerifiedBridge final {};
class FreshOwnerArmIsolationBridge final {};
class CandidateOwnerTruthPostBarrierBridge final {};
class FreshOwnerProcessSupervisor final {};
}
namespace kpi::mpc::financial::registered_driver::owner_truth_handoff {
class OwnerTruthScoreHandoffBridge final {};
}
namespace kpi::mpc::financial::attempt_supervisor {
class RegisteredProposalBridge final {};
}
namespace kpi::mpc::financial::registered_driver {
class RegisteredParentBootstrapTransport final {};
}
namespace kpb::future_recipient::v3_native {
class V3LifecycleControllerMinter final {};
}
int main() { return 0; }
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('redefinition', result.stderr)
        for name in names:
            with self.subTest(name=name):
                self.assertIn(name, result.stderr)


if __name__ == '__main__':
    unittest.main()
