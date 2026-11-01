#!/usr/bin/env python3
"""Hostile-TU controls for registered-driver authority friend seams."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
ROOT = MPC.parents[2]
VENDOR = ROOT / '.local/mpc-prover-softspoken-vendor'


def compiler_flags():
    compiler = shutil.which('x86_64-linux-gnu-g++-15') or shutil.which('g++')
    if compiler is None:
        raise unittest.SkipTest('C++ compiler unavailable')
    result = [
        compiler, '-std=c++20', '-O1', '-g0', '-march=native', '-pthread',
        '-Wall', '-Wextra', '-Werror', '-Wno-overloaded-virtual',
        '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
        '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK', '-DMCL_FP_BIT=384',
        '-DMCL_FR_BIT=256', '-DMCL_MSM=0', '-fsyntax-only',
    ]
    for include in [
        MPC, VENDOR / 'MP-SPDZ', VENDOR / 'MP-SPDZ/deps',
        VENDOR / 'MP-SPDZ/local/include', VENDOR / 'mcl/include',
        VENDOR / 'prefix/usr/include',
        VENDOR / 'prefix/usr/include/x86_64-linux-gnu',
    ]:
        result.extend(['-I', str(include)])
    return result


INCLUDES = r'''
#include "financial/registered_capture_session.hpp"
#include "financial/registered_capture_plan_roster_bridge.hpp"
#include "financial/registered_parent_role_fork.hpp"
#include "financial/registered_projection_route.hpp"
#include "financial/registered_role_model_admission.hpp"
#include "financial/registered_roster_crypto_player.hpp"
#include "financial/registered_selection.hpp"
#include "financial/streamed_h_map.hpp"
#include "financial/baseline_owner_effects_recipe.hpp"
#include "history/epoch_ticket.hpp"
'''


class RegisteredAuthorityFriendSealingControls(unittest.TestCase):
    def compile(self, source):
        with tempfile.TemporaryDirectory(
                prefix='kpb-registered-friend-sealing-') as directory:
            path = Path(directory) / 'control.cpp'
            path.write_text(INCLUDES + source, encoding='utf-8')
            return subprocess.run(
                [*compiler_flags(), str(path)], capture_output=True,
                text=True, check=False)

    def test_every_source_owned_friend_target_is_complete(self):
        # sizeof is deliberately used here: a forward declaration or a class
        # defined only in a .cpp cannot satisfy this production-header audit.
        source = r'''
using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::registered_driver;
using namespace kpi::mpc::financial::registered_driver::projection_route;
static_assert(sizeof(attempt_supervisor::RegisteredProposalBridge) > 0);
static_assert(sizeof(DriverAttempt) > 0);
static_assert(sizeof(AuthorizedDriverAttempt) > 0);
static_assert(sizeof(CapturePlanAuthorityBridge) > 0);
static_assert(sizeof(RegisteredCapturePlanRosterBridge) > 0);
static_assert(sizeof(RosterBoundCapturePlan) > 0);
static_assert(sizeof(VerifiedEgressAuthorityBridge) > 0);
static_assert(sizeof(RegisteredConstructionAuthorityBridge) > 0);
static_assert(sizeof(RegisteredParentBootstrapTransport) > 0);
static_assert(sizeof(RegisteredSupervisorParentTransport) > 0);
static_assert(sizeof(RegisteredPartyCompletionTransport) > 0);
static_assert(sizeof(ParentRoleForkPlanAuthority) > 0);
static_assert(sizeof(RegisteredParentRoleFork) > 0);
static_assert(sizeof(ParentRoleChildren) > 0);
static_assert(sizeof(RegisteredChildBootstrapPending) > 0);
static_assert(sizeof(
    baseline_disclosure::BaselineOwnerScoringParentTransport) > 0);
static_assert(sizeof(ProjectionRouteEndpoints) > 0);
static_assert(sizeof(RegisteredProjectionRoute) > 0);
static_assert(sizeof(RegisteredProjectionRouteForkBridge) > 0);
static_assert(sizeof(RegisteredProjectionRouteCaptureBridge) > 0);
static_assert(sizeof(RegisteredParentRoundCompletionBridge) > 0);
static_assert(sizeof(kpb::native_terminal::NativeTerminalProjectionIntake) > 0);
static_assert(sizeof(RegisteredRoleModelAdmission) > 0);
static_assert(sizeof(RegisteredRosterCryptoPlayer) > 0);
static_assert(sizeof(RegisteredRosterPlayerRuntime) > 0);
static_assert(sizeof(RegisteredCaptureConstructionBridge) > 0);
static_assert(sizeof(RegisteredCaptureEgressBridge) > 0);
static_assert(sizeof(RegisteredBaselineObserverCaptureBridge) > 0);
static_assert(sizeof(RegisteredSelectionAccess) > 0);
static_assert(sizeof(RegisteredServiceSelectionBridge) > 0);
static_assert(sizeof(RegisteredSelectionConstructionBridge) > 0);
static_assert(sizeof(FinancialHistoryAccess) > 0);
static_assert(sizeof(kpi::mpc::history::FinancialConstructionEpochBridge) > 0);
static_assert(sizeof(kpi::mpc::history::RegisteredOwnerIntakeBridge) > 0);
static_assert(sizeof(PackedValidatedAssignment) > 0);
static_assert(sizeof(FinancialValidatedAssignment) > 0);
static_assert(sizeof(
    baseline_disclosure::AuthenticatedBaselineOwnerReceiver) > 0);
int main() { return 0; }
'''
        result = self.compile(source)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_privileged_friend_names_cannot_be_defined_by_hostile_tu(self):
        attacks = {
            'parent-round': r'''
namespace kpi::mpc::financial::registered_driver {
class RegisteredParentRoundCompletionBridge final {};
}
''',
            'party-completion': r'''
namespace kpi::mpc::financial::registered_driver {
class RegisteredPartyCompletionTransport final {};
}
''',
            'model-admission': r'''
namespace kpi::mpc::financial::registered_driver {
class RegisteredRoleModelAdmission final {};
}
''',
            'roster-runtime': r'''
namespace kpi::mpc::financial {
class RegisteredRosterPlayerRuntime final {};
}
''',
            'capture-plan': r'''
namespace kpi::mpc::financial::registered_driver {
class CapturePlanAuthorityBridge final {};
}
''',
        }
        for name, attack in attacks.items():
            with self.subTest(name=name):
                result = self.compile(attack + '\nint main() { return 0; }\n')
                self.assertNotEqual(
                    result.returncode, 0,
                    name + ' remained externally definable')
                self.assertIn('redefinition', result.stderr)


if __name__ == '__main__':
    unittest.main()
