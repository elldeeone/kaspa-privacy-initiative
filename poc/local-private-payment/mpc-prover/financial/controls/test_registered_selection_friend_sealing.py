#!/usr/bin/env python3
"""Hostile-TU controls for accepted-head and registered-selection friends."""

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


def flags():
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


class RegisteredSelectionFriendSealingControls(unittest.TestCase):
    def compile(self, source):
        with tempfile.TemporaryDirectory(
                prefix='kpb-selection-friend-hostile-') as directory:
            path = Path(directory) / 'hostile.cpp'
            path.write_text(source, encoding='utf-8')
            return subprocess.run(
                [*flags(), str(path)], capture_output=True, text=True,
                check=False)

    def test_forward_friend_names_cannot_mint_or_consume_authority(self):
        attacks = {
            'accepted-head-access': r'''
#include "financial/accepted_head.hpp"
namespace kpi::mpc::financial {
class RegisteredSelectionAccess final {
public:
    static void consume(MascotContext& context, AcceptedFinancialHead& head,
                        const history::Digest& identity) {
        head.consume_for_selection(context, identity, identity);
    }
};
}
''',
            'selection-access': r'''
#include "financial/registered_selection.hpp"
#include <utility>
namespace kpi::mpc::financial {
class RegisteredSelectionAccess final {
public:
    static void consume(RegisteredFinancialSelection& selection,
                        MascotContext& context,
                        AcceptedFinancialHead&& head) {
        selection.consume_for_lock(context, std::move(head));
    }
};
}
''',
            'construction-access': r'''
#include "financial/registered_selection.hpp"
namespace kpi::mpc::financial {
class FinancialConstruction final {
public:
    static const packed::PackedModel& inspect(
            const RegisteredFinancialSelection& selection) {
        return selection.model();
    }
};
}
''',
            'service-copy': r'''
#include "financial/registered_service.hpp"
namespace kpi::mpc::financial {
class RegisteredFinancialSelection final {
public:
    static RegisteredService duplicate(const RegisteredService& service) {
        return service;
    }
};
}
''',
        }
        for name, source in attacks.items():
            with self.subTest(name=name):
                result = self.compile(source + '\nint main() { return 0; }\n')
                self.assertNotEqual(
                    result.returncode, 0,
                    name + ' forged a private selection authority')

    def test_hidden_cohort_bodies_cannot_be_stolen_by_lookalike_construction(
            self):
        result = self.compile(r'''
#include "financial/hidden_cohort_dispatcher.hpp"
namespace kpi::mpc::financial {
class FinancialConstruction final {
public:
    static auto& bodies(hidden_cohort::SealedCohort& cohort) {
        return cohort.by_role_;
    }
};
}
int main() { return 0; }
''')
        self.assertNotEqual(
            result.returncode, 0,
            'lookalike construction read private cohort bodies')

    def test_epoch_ticket_forward_friends_cannot_claim_or_mint(self):
        attacks = {
            'history-access': r'''
#include "history/epoch_ticket.hpp"
#include <utility>
namespace kpi::mpc::financial {
class FinancialHistoryAccess final {
public:
    static history::EpochJournal share(
            const history::PreparedEpochTicket& prepared) {
        return prepared.share_journal();
    }
    static history::EgressRelease release(
            MascotContext& context,
            history::PreparedEpochTicket&& prepared,
            std::span<const unsigned char> core,
            std::span<const unsigned char> proof,
            std::span<const unsigned char> projection) {
        return history::EgressRelease(
            context, std::move(prepared), core, proof, projection, nullptr);
    }
    static history::DurableRecord bind(
            history::EgressRelease& release, MascotContext& context,
            const history::FinalCandidate& candidate) {
        return release.bind_final_candidate(context, candidate);
    }
};
}
''',
            'construction-intake': r'''
#include "history/epoch_ticket.hpp"
namespace kpi::mpc::financial {
class FinancialConstruction final {
public:
    static void claim(history::LockedAttempt& locked,
                      MascotContext& context,
                      const history::AttemptBinding& binding) {
        locked.claim_owner_intake(context, binding);
    }
};
}
''',
            'registered-intake': r'''
#include "history/epoch_ticket.hpp"
#include "financial/registered_attempt_supervisor.hpp"
#include <utility>
namespace kpi::mpc::financial::registered_driver {
class AuthorizedDriverAttempt final {
public:
    static void claim(
            history::LockedAttempt& locked, MascotContext& context,
            const history::AttemptBinding& binding, unsigned role,
            attempt_supervisor::OwnerIntakePermit&& permit) {
        locked.claim_registered_owner_intake(
            context, binding, role, std::move(permit));
    }
};
}
''',
        }
        for name, source in attacks.items():
            with self.subTest(name=name):
                result = self.compile(source + '\nint main() { return 0; }\n')
                self.assertNotEqual(
                    result.returncode, 0,
                    name + ' forged a private epoch authority')

    def test_streamed_map_friend_names_cannot_submit_caller_assignment(self):
        attacks = {
            'financial-validated': r'''
#include "financial/streamed_h_map.hpp"
namespace kpi::mpc::financial {
class FinancialValidatedAssignment final {
public:
    static std::vector<AuthScalar> bypass(
            MascotContext& context, const packed::PackedModel& model,
            std::span<const AuthScalar> caller_assignment) {
        return StreamedWitnessMap::compute(
            context, model, caller_assignment);
    }
};
}
''',
            'packed-validated': r'''
#include "financial/streamed_h_map.hpp"
namespace kpi::mpc::financial {
class PackedValidatedAssignment final {
public:
    static std::vector<AuthScalar> bypass(
            MascotContext& context, const packed::PackedModel& model,
            std::span<const AuthScalar> caller_assignment) {
        return StreamedWitnessMap::compute(
            context, model, caller_assignment);
    }
};
}
''',
        }
        for name, source in attacks.items():
            with self.subTest(name=name):
                result = self.compile(source + '\nint main() { return 0; }\n')
                self.assertNotEqual(
                    result.returncode, 0,
                    name + ' supplied an unvalidated witness map')

    def test_baseline_receiver_friend_name_cannot_steal_owner_mapping(self):
        result = self.compile(r'''
#include "financial/baseline_owner_effects_recipe.hpp"
namespace kpi::mpc::financial::registered_driver::baseline_disclosure {
class AuthenticatedBaselineOwnerReceiver final {
public:
    static PublicOwnerPrivateEffects steal(
            const ConsumedOwnerPrivateEffects& value) {
        return value.value_;
    }
};
}
int main() { return 0; }
''')
        self.assertNotEqual(
            result.returncode, 0,
            'lookalike baseline receiver stole the private owner mapping')


if __name__ == '__main__':
    unittest.main()
