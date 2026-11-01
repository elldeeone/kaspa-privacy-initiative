#!/usr/bin/env python3
"""Ordering and production-surface controls for the registered role child."""

from pathlib import Path
import shutil
import subprocess
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


class RegisteredRoleChildProgramControls(unittest.TestCase):
    def test_production_translation_unit_compiles(self):
        result = subprocess.run(
            [*flags(), str(FINANCIAL / 'registered_role_child_program.cpp')],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_genuine_flow_order_is_closed(self):
        source = (FINANCIAL / 'registered_role_child_program.cpp').read_text()
        ordered = [
            'dispatch_role()',
            'take_p1_state_prelaunch()',
            'begin_role1_prelaunch(',
            'take_root_thread_epoch()',
            'take_entropy_state_adapter(',
            'EntropyIngressCapture::begin(',
            'take_projection_route_writer()',
            'initialize_bn254_field()',
            'RegisteredParentBootstrapTransport::receive(',
            'RegisteredRoleModelAdmission::admit(',
            'authorize_admitted_model(',
            'RegisteredRosterPlayerRuntime::begin_after_fork(',
            'RegisteredP1Context::begin(',
            'RegisteredService::open_selected(',
            'AcceptedFinancialHead::acquire_fresh(',
            'authenticated_party_delivery(',
            'RegisteredProposalBridge::proposal(',
            'RegisteredSupervisorParentTransport::submit_and_wait(',
            'RegisteredFinancialSelection::admit(',
            'RegisteredConstructionAuthorityBridge::admit(',
            'FinancialConstruction::construct_registered(',
            'FinancialValidatedAssignment::validate(',
            'FinancialHistoryAccess::prepare(',
            'prove_and_verify_financial(',
            'release_verified_registered(',
            'baseline_owner_scoring(',
            'await_registered_release_barrier(',
            'route_registered_projection(',
            'complete_registered_egress(',
            'RegisteredPartyCompletionTransport::submit_',
        ]
        positions = [source.index(value) for value in ordered]
        self.assertEqual(positions, sorted(positions))

    def test_role1_state_is_unavailable_and_stops_before_party_success(self):
        source = (FINANCIAL / 'registered_role_child_program.cpp').read_text()
        egress = source.index('complete_registered_egress(')
        role1 = source.index('if (role == 1)', egress)
        unavailable_return = source.index('return true;', role1)
        submit = source.index('RegisteredPartyCompletionTransport::submit_', egress)
        destruction_barrier = source.index('}();', submit)
        unavailable = source.index(
            'finish_unavailable_noexcept()', destruction_barrier)
        self.assertLess(egress, role1)
        self.assertLess(role1, unavailable_return)
        self.assertLess(unavailable_return, submit)
        self.assertLess(submit, destruction_barrier)
        self.assertLess(destruction_barrier, unavailable)
        self.assertIn('refuse();', source[unavailable:])
        self.assertNotIn('finish_success_noexcept', source)

    def test_p0_and_p2_have_no_p1_prelaunch_method(self):
        parent = (FINANCIAL / 'registered_parent_role_fork.hpp').read_text()
        role0 = parent[
            parent.index('class ParentAuthenticatedRole0Delivery final'):
            parent.index('class ParentAuthenticatedRole1Delivery final')]
        role2 = parent[
            parent.index('class ParentAuthenticatedRole2Delivery final'):
            parent.index('using ParentAuthenticatedRoleDispatch')]
        self.assertNotIn('take_p1_state_prelaunch', role0)
        self.assertNotIn('take_p1_state_prelaunch', role2)

    def test_only_role_zero_takes_and_routes_fd30(self):
        source = (FINANCIAL / 'registered_role_child_program.cpp').read_text()
        self.assertIn('if (role == 0)', source)
        self.assertIn('need(!route_writer.has_value())', source)
        self.assertIn('need(route_writer.has_value())', source)
        self.assertNotIn('dup2(', source)
        self.assertNotIn('fixed_fd', source)

    def test_no_test_authority_or_runtime_configuration_substitution(self):
        header = (FINANCIAL / 'registered_role_child_program.hpp').read_text()
        source = (FINANCIAL / 'registered_role_child_program.cpp').read_text()
        for forbidden in ('test_only_', 'argc', 'argv', 'getenv', 'JSON', 'json'):
            self.assertNotIn(forbidden, source)
        self.assertIn('CompiledRoleModelConfigurationAuthority', header)
        self.assertIn('ImmutableRegisteredRosterAuthority', header)
        self.assertIn('InheritedSealedQueryArtifact', header)
        self.assertIn('BaselineOwnerRosterAuthority', header)
        self.assertNotIn('P1CorruptStateCapsulePlanAuthority', header)

    def test_registered_build_closes_the_state_runtime_translation_units(self):
        source = (FINANCIAL / 'build_registered_financial.py').read_text()
        for unit in (
                "financial/registered_p1_state_archive_scm.cpp",
                "financial/registered_p1_private_state_context.cpp",
                "../private_batch_trial/"
                "privacy_p1_corrupt_state_capsule_authority.cpp"):
            self.assertIn(repr(unit), source)

    def test_concrete_persistent_wrapper_is_ordered_and_one_shot(self):
        header = (FINANCIAL / 'registered_role_child_program.hpp').read_text()
        source = (FINANCIAL / 'registered_role_child_program.cpp').read_text()
        self.assertIn(
            'class SelectedRegisteredPersistentRoleChildProgram final',
            header)
        self.assertIn('RegisteredPersistentRoleChildProgram', header)
        self.assertIn('round_program(unsigned round) override', header)
        self.assertIn('round == 1 || round == 2', source)
        self.assertIn('round_claimed_[index].exchange(true)', source)
        self.assertIn('round == 1 || round_claimed_[0].load()', source)
        self.assertNotIn('test_only_', header)

    def test_source_status_remains_unconfigured(self):
        source = (FINANCIAL / 'registered_role_child_program.cpp').read_text()
        self.assertIn('.genuine_registered_construction = true', source)
        self.assertIn('.genuine_verified_release = true', source)
        self.assertIn('.fixed_terminal_composite = true', source)
        self.assertIn('.role1_p1_state_prelaunch_callsite = true', source)
        self.assertIn('.role1_p1_state_completion_qualified = false', source)
        self.assertIn('.production_model_configuration_minter = false', source)
        self.assertIn('.production_roster_authority_minter = false', source)
        self.assertIn('.concrete_persistent_child_program = true', source)
        self.assertIn('.registered_driver_configured = false', source)
        self.assertIn('.launch_authorized = false', source)


if __name__ == '__main__':
    unittest.main()
