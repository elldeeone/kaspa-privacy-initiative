#!/usr/bin/env python3
"""Compile and ordering controls for the source-only registered driver seam."""

from pathlib import Path
import shutil
import subprocess
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
ROOT = MPC.parents[2]
VENDOR = ROOT / '.local/mpc-prover-softspoken-vendor'


class RegisteredDriverIntegrationControls(unittest.TestCase):
    def test_attempt_history_sources_are_in_registered_build_closure(self):
        source = (FINANCIAL / 'build_registered_financial.py').read_text(
            encoding='utf-8')
        for name in (
                "'financial/registered_trial_attempt_history.cpp'",
                "'financial/registered_fresh_trial_history_ledger.cpp'",
                "'financial/registered_full_cohort_release_barrier.cpp'",
                "'financial/registered_producer_route_bridge.cpp'",
                "'financial/registered_persistent_role_exit_history.cpp'",
                "'financial/registered_preidentity_ready.cpp'",
                "'financial/registered_persistent_fresh_trial_activation.cpp'",
                "'financial/registered_selected_producer_run_binding.cpp'",
                "'../private_batch_trial/privacy_capture_producer_archive.cpp'",
                "'../private_batch_trial/privacy_capture_producer_runtime.cpp'",
                "'../private_batch_trial/privacy_fresh_owner_transactional_replay_authority.cpp'",
                "'../private_batch_trial/privacy_all_branch_fresh_trial_owner_authority.cpp'",
                "'../private_batch_trial/privacy_fresh_owner_round1_outcome_consumer_authority.cpp'",
                "'../private_batch_trial/privacy_registered_fresh_trial_capture_topology_reservation.cpp'",
                "'../private_batch_trial/privacy_registered_fresh_trial_capture_topology_permit.cpp'",
                "'../private_batch_trial/privacy_registered_fresh_trial_producer_closure.cpp'"):
            self.assertIn(name, source)

    def test_full_production_translation_unit_closure_compiles(self):
        compiler = shutil.which('x86_64-linux-gnu-g++-15') or shutil.which('g++')
        self.assertIsNotNone(compiler)
        self.assertTrue((VENDOR / 'MP-SPDZ/Machines/maximal.hpp').is_file())
        flags = [
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
            flags.extend(['-I', str(include)])
        sources = [
            FINANCIAL / 'registered_driver_bridge.cpp',
            FINANCIAL / 'registered_capture_plan_roster_bridge.cpp',
            FINANCIAL / 'registered_proposal_bridge.cpp',
            FINANCIAL / 'registered_driver_history_bridge.cpp',
            FINANCIAL / 'registered_parent_role_fork.cpp',
            FINANCIAL / 'registered_preidentity_ready.cpp',
            FINANCIAL / 'registered_persistent_fresh_trial_activation.cpp',
            FINANCIAL / 'registered_projection_route.cpp',
            FINANCIAL / 'registered_projection_route_capture_bridge.cpp',
            FINANCIAL / 'registered_full_cohort_release_barrier.cpp',
            FINANCIAL / 'registered_party_completion_transport.cpp',
            FINANCIAL / 'registered_supervisor_parent_transport.cpp',
            FINANCIAL / 'registered_parent_role_delivery_bridge.cpp',
            FINANCIAL / 'registered_parent_bootstrap.cpp',
            FINANCIAL / 'registered_parent_bootstrap_model.cpp',
            FINANCIAL / 'registered_role_model_admission.cpp',
            FINANCIAL / 'registered_role_child_program.cpp',
            FINANCIAL / 'registered_p1_private_state_context.cpp',
            FINANCIAL / 'registered_p1_state_archive_scm.cpp',
            FINANCIAL / 'registered_parent_round_completion.cpp',
            FINANCIAL / 'registered_producer_route_bridge.cpp',
            FINANCIAL / 'registered_persistent_role_exit_history.cpp',
            FINANCIAL / 'registered_selected_producer_run_binding.cpp',
            FINANCIAL / 'registered_selected_parent_orchestrator.cpp',
            FINANCIAL / 'registered_trial_attempt_history.cpp',
            FINANCIAL / 'registered_fresh_trial_history_ledger.cpp',
            FINANCIAL / 'registered_p1_capture_bridge.cpp',
            FINANCIAL / 'registered_capture_session.cpp',
            FINANCIAL / 'baseline_public_effects_collector.cpp',
            FINANCIAL / 'baseline_public_effects_bridge.cpp',
            FINANCIAL / 'authenticated_baseline_owner_receiver.cpp',
            FINANCIAL / 'authenticated_baseline_owner_receiver_tls.cpp',
            FINANCIAL / 'baseline_owner_scoring_parent_transport.cpp',
            FINANCIAL / 'baseline_owner_truth_capsule_bridge.cpp',
            FINANCIAL / 'fresh_owner_trial_issuance.cpp',
            FINANCIAL / 'fresh_owner_process_adapter.cpp',
            FINANCIAL / 'fresh_owner_arm_isolation.cpp',
            FINANCIAL / 'candidate_owner_truth_post_barrier_bridge.cpp',
            MPC / 'p1_entropy_ingress_capture.cpp',
            MPC / 'p1_mascot_secret_state_hook.cpp',
            MPC.parent / 'private_batch_trial' /
                'privacy_p1_corrupt_state_capsule_authority.cpp',
            MPC.parent / 'private_batch_trial' /
                'privacy_measurement_authority.cpp',
            MPC.parent / 'private_batch_trial' /
                'privacy_capture_producer_archive.cpp',
            MPC.parent / 'private_batch_trial' /
                'privacy_capture_producer_runtime.cpp',
            MPC.parent / 'private_batch_trial' /
                'privacy_fresh_owner_transactional_replay_authority.cpp',
            MPC.parent / 'private_batch_trial' /
                'privacy_all_branch_fresh_trial_owner_authority.cpp',
            MPC.parent / 'private_batch_trial' /
                'privacy_fresh_owner_round1_outcome_consumer_authority.cpp',
            MPC.parent / 'private_batch_trial' /
                'privacy_registered_fresh_trial_capture_topology_reservation.cpp',
            MPC.parent / 'private_batch_trial' /
                'privacy_registered_fresh_trial_capture_topology_permit.cpp',
            MPC.parent / 'private_batch_trial' /
                'privacy_registered_fresh_trial_producer_closure.cpp',
            MPC.parent / 'private_batch_trial' /
                'privacy_measurement_child_output_authority.cpp',
            MPC.parent / 'private_batch_trial' /
                'privacy_measurement_output_abi.cpp',
            MPC.parent / 'private_batch_trial' /
                'privacy_registered_measurement_capture_bridge.cpp',
            FINANCIAL / 'baseline_owner_effects_recipe.cpp',
            FINANCIAL / 'baseline_owner_effects_recipe_bridge.cpp',
            MPC / 'history/epoch_ticket.cpp',
            FINANCIAL / 'registered_selection.cpp',
            FINANCIAL / 'registered_construction.cpp',
            FINANCIAL / 'construction.cpp',
            FINANCIAL / 'financial_release.cpp',
        ]
        for source in sources:
            result = subprocess.run(
                [*flags, str(source)], capture_output=True, text=True,
                check=False)
            self.assertEqual(
                result.returncode, 0,
                f'{source}:\n{result.stdout}{result.stderr}')

    def test_authority_order_is_closed_around_actual_lock_and_intake(self):
        source = (FINANCIAL / 'registered_construction.cpp').read_text(
            encoding='utf-8')
        ordered_needles = [
            'agree_public_bytes("registered-financial-construction-before-lock"',
            'auto before_lock = AcceptedFinancialHead::acquire_fresh',
            'recheck_before_lock(driver_authority,',
            'RegisteredSelectionConstructionBridge::consume_for_lock(',
            'history::lock_attempt(context, journal, binding)',
            'auto after_lock = AcceptedFinancialHead::acquire_fresh',
            'RegisteredProposalBridge::durable_lock(',
            'after_durable_lock(driver_authority,',
            'claim_owner_intake(*authorized, context, *locked, binding)',
            'receiver.receive_cohort(jobs, capture)',
        ]
        positions = [source.index(value) for value in ordered_needles]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn('locked->claim_owner_intake(context, binding)', source)

        header = (FINANCIAL / 'construction.hpp').read_text(encoding='utf-8')
        declaration = header[header.index('construct_registered('):]
        declaration = declaration[:declaration.index(';')]
        self.assertIn('registered_driver::DriverAttempt&&', declaration)
        self.assertNotIn('RegisteredCaptureSession&', declaration)
        self.assertNotIn('owner_port', declaration)

        ticket = (MPC / 'history/epoch_ticket.hpp').read_text(encoding='utf-8')
        locked = ticket[ticket.index('class LockedAttempt {'):]
        locked = locked[:locked.index('\n};')]
        self.assertLess(
            locked.index('void claim_owner_intake('),
            locked.index('\npublic:'))
        self.assertLess(
            locked.index('void claim_registered_owner_intake('),
            locked.index('\npublic:'))

    def test_party_completion_does_not_claim_global_capture_closure(self):
        header = (FINANCIAL / 'registered_driver_bridge.hpp').read_text(
            encoding='utf-8')
        party = header[header.index('struct PublicPartyDriverCompletion {'):]
        party = party[:party.index('\n};')]
        self.assertIn('projection_identity', party)
        self.assertIn('attempt_identity', party)
        self.assertIn('authorization_identity', party)
        self.assertIn('owner_contracts', party)
        self.assertNotIn('producer_identity', party)
        self.assertNotIn('role_closure_identity', party)
        self.assertNotIn('CaptureCompletionAuthority', header)
        self.assertIn('complete_egress(', header)

    def test_proposal_factory_has_no_digest_or_json_authority_route(self):
        # The sole mint bridge is defined beside the supervisor capabilities
        # it may construct.  Keeping the complete class there prevents a
        # hostile translation unit from defining a same-name friend.
        header = (FINANCIAL / 'registered_attempt_supervisor.hpp').read_text(
            encoding='utf-8')
        bridge = header[header.index('class RegisteredProposalBridge final'):]
        bridge = bridge[:bridge.index('\n};')]
        proposal = bridge[bridge.index('static Proposal proposal('):]
        proposal = proposal[:proposal.index(';')]
        for required in [
            'CompiledFreshAttemptAuthority&&',
            'AuthenticatedPartyDeliveryAuthority&&',
            'const registered_driver::CompiledDriverSelection&',
            'const RegisteredService&',
            'const AcceptedFinancialHead&',
            'std::span<const OwnerInputContract>',
        ]:
            self.assertIn(required, proposal)
        self.assertNotIn('Digest', proposal)
        self.assertNotIn('string', proposal)

        source = (FINANCIAL / 'registered_proposal_bridge.cpp').read_text(
            encoding='utf-8')
        for required in [
            'fresh.live_.exchange(false)',
            'delivery.live_.exchange(false)',
            'accepted.service_identity == service.identity()',
            'job.run_nonce == identity_registry::hex(f.attempt)',
            'owner_identities(jobs)',
            'identity_registry::selection_identity(selection)',
        ]:
            self.assertIn(required, source)

    def test_baseline_plan_consumes_live_construction_and_egress(self):
        header = (FINANCIAL / 'baseline_public_effects_collector.hpp').read_text(
            encoding='utf-8')
        self.assertNotIn(
            'friend class ::kpi::mpc::financial::FinancialHistoryAccess',
            header)
        bridge = header[header.index(
            'class BaselineDisclosureAuthorityBridge final'):]
        bridge = bridge[:bridge.index('\n};')]
        production = bridge[bridge.index(
            'from_registered_egress('):]
        production = production[:production.index(';')]
        self.assertIn('const ::kpi::mpc::financial::FinancialConstruction&',
                      production)
        self.assertIn('const ::kpi::mpc::history::EgressRelease&', production)
        self.assertNotIn('PublicBaselineEffectsPlan', production)
        self.assertNotIn('Digest', production)

        source = (FINANCIAL / 'baseline_public_effects_bridge.cpp').read_text(
            encoding='utf-8')
        for required in [
            'claim_baseline_effects(construction)',
            'attempt.durable_lock == release.binding_identity()',
            'history::canonical_history_nullifiers(core)',
            'core.subspan(at, output_bytes)',
            'policy_identity()',
        ]:
            self.assertIn(required, source)

    def test_baseline_owner_recipe_is_post_egress_one_shot_and_source_owned(self):
        header = (FINANCIAL / 'baseline_owner_effects_recipe.hpp').read_text(
            encoding='utf-8')
        bridge = header[header.index(
            'class BaselineOwnerEffectsRecipeBridge final'):]
        bridge = bridge[:bridge.index('\n};')]
        production = bridge[bridge.index(
            'static PreparedBaselineOwnerEffects derive('):]
        production = production[:production.index(';')]
        for required in [
            'MascotContext&',
            'const FinancialConstruction&',
            'const history::EgressRelease&',
            'BaselineEffectsPlanAuthority&&',
            'BaselineOwnerPreDisclosureConsentAuthority&&',
        ]:
            self.assertIn(required, production)
        for forbidden in ['filesystem', 'span<', 'Digest', 'bool']:
            self.assertNotIn(forbidden, production)

        source = (FINANCIAL /
                  'baseline_owner_effects_recipe_bridge.cpp').read_text(
                      encoding='utf-8')
        ordered = [
            'claim_plan(std::move(selected))',
            'release.binding_identity()',
            'open_public_checked(selected_wires)',
            'agree_public_bytes(',
            'derive_claimed(std::move(retained)',
        ]
        positions = [source.index(value) for value in ordered]
        self.assertEqual(positions, sorted(positions))
        for required in [
            'selected_wires.size() == 804',
            'context.check_counter() == before + 2',
            'CaptureClassification::ExplicitOwnerPublicEffectsBaseline',
            'context.poison()',
        ]:
            self.assertIn(required, source)

        selection = (FINANCIAL / 'registered_selection.cpp').read_text(
            encoding='utf-8')
        self.assertIn('KPB_REGISTERED_EXPORT_V2', selection)
        self.assertNotIn('KPB_REGISTERED_EXPORT_V1', selection)
        self.assertIn('BaselineOwnerEffectsRecipe::load(', selection)

        release = (FINANCIAL / 'financial_release.cpp').read_text(
            encoding='utf-8')
        release_order = [
            'from_registered_egress(',
            'from_verified_egress(',
            'AuthenticatedBaselineOwnerReceiver::receive(',
        ]
        positions = [release.index(value) for value in release_order]
        self.assertEqual(positions, sorted(positions))

    def test_baseline_owner_receiver_consumes_tls_ack_before_private_scorer_join(self):
        header = (FINANCIAL /
                  'authenticated_baseline_owner_receiver_contract.hpp').read_text(
                      encoding='utf-8')
        receiver = header[header.index(
            'class AuthenticatedBaselineOwnerReceiver final'):]
        receiver = receiver[:receiver.index('\n};')]
        production = receiver[receiver.index('static '):]
        production = production[:production.index(';')]
        for required in [
            'MascotContext&', 'const FinancialConstruction&',
            'const history::EgressRelease&',
            'BaselineEffectsPlanAuthority&&',
            'BaselineOwnerRosterReceiverAuthority&&',
        ]:
            self.assertIn(required, production)
        for forbidden in ['Digest', 'OwnerInputContract', 'path', 'bool']:
            self.assertNotIn(forbidden, production)

        source = (FINANCIAL /
                  'authenticated_baseline_owner_receiver_tls.cpp').read_text(
                      encoding='utf-8')
        receive_source = source[source.index(
            'AuthenticatedBaselineOwnerReceiver::receive('):]
        ordered = [
            'BaselineOwnerRosterReceiverBridge::consume(',
            'clients.start_listening(',
            'require_authenticated_peer(',
            'BaselineOwnerPreDisclosureProtocol::challenge(',
            'roster_session.verify_owner_proof(',
            'roster_session.finish()',
            'BaselineOwnerPreDisclosureConsentAuthority(',
            'BaselineOwnerEffectsRecipeBridge::derive(',
            'prepared.take_plan()',
            'prepared.take_owner(0)',
            'octetStream(challenges[owner].size()',
            'received.Receive(socket)',
            'exact_frame(received, expected)',
            'PartyBaselineOwnerEffectsAuthority result(std::move(value))',
            'from_acknowledged_registered_egress(',
            'RegisteredBaselineObserverCaptureBridge::',
        ]
        positions = [receive_source.index(value) for value in ordered]
        self.assertEqual(positions, sorted(positions))
        for required in [
            'CaptureClassification::ExplicitOwnerPublicEffectsBaseline',
            'BaselineOwnerRosterVerifiedBridge::consume(',
            'OwnerPrivateEffectsReceiverBridge::consume(',
            'context.poison()',
            'owner_certificate_sha256',
        ]:
            self.assertIn(required, source)
        self.assertNotIn('direct_exports', source)
        self.assertIn('explicit_owner_public_effects(', source)

        storage = (FINANCIAL / 'construction_storage.hpp').read_text(
            encoding='utf-8')
        self.assertIn('baseline_owner_port', storage)
        self.assertIn('baseline_owner_contracts', storage)

        release = (FINANCIAL / 'financial_release.cpp').read_text(
            encoding='utf-8')
        selected = release[release.index(
            'FinancialHistoryAccess::baseline_owner_scoring('):]
        release_order = [
            'BaselineDisclosureAuthorityBridge::from_registered_egress(',
            'BaselineDisclosureAuthorityBridge::from_verified_egress(',
            'AuthenticatedBaselineOwnerReceiver::receive(',
        ]
        release_positions = [selected.index(value) for value in release_order]
        self.assertEqual(release_positions, sorted(release_positions))
        self.assertIn('PartyBaselineOwnerEffectsAuthority', release)
        self.assertNotIn('BaselineOwnerScoringParentTransport::submit(',
                         selected)
        self.assertNotIn('baseline_public_effects(', selected)

        recipe = (FINANCIAL /
                  'baseline_owner_effects_recipe_bridge.cpp').read_text(
                      encoding='utf-8')
        derive = recipe[recipe.index(
            'BaselineOwnerEffectsRecipeBridge::derive('):]
        recipe_order = [
            'supplied_consent.consume_for_recipe()',
            'std::vector<AuthScalar> selected_wires',
            'context.open_public_checked(selected_wires)',
        ]
        recipe_positions = [derive.index(value) for value in recipe_order]
        self.assertEqual(recipe_positions, sorted(recipe_positions))


if __name__ == '__main__':
    unittest.main()
