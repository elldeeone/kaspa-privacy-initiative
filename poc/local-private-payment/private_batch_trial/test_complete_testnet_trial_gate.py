"""Controls for the post-terminal Testnet completion boundary."""
import copy
import hashlib
from pathlib import Path
import unittest

import complete_testnet_trial_gate as gate
import private_worker


def h(label):
    return hashlib.sha256(label.encode()).hexdigest()


class MemoryReader:
    def __init__(self):
        self.rows = {}

    def add(self, name, value):
        raw = private_worker.encoded(value)
        path = str(Path('/public-complete-testnet-controls') / name)
        self.rows[path] = raw
        return {'path': path, 'sha256': hashlib.sha256(raw).hexdigest()}

    def __call__(self, path, expected=None):
        raw = self.rows[str(path)]
        if expected is not None and hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('control-pin')
        return raw


class CompleteTestnetTrialGateControls(unittest.TestCase):
    def setUp(self):
        kinds = ['genesis', 'payment', 'payment'] + ['exit'] * 9
        self.cases = [{'kind': kind, 'path': '/public/case-' + str(index),
                       'sha256': h('case ' + str(index))}
                      for index, kind in enumerate(kinds)]
        self.confirmations = [{
            'schema': gate.CONFIRMATION_SCHEMA,
            'trial_id': '11111111-1111-4111-8111-111111111111',
            'ordinal': index,
            'kind': kind,
            'case_sha256': self.cases[index]['sha256'],
            'transaction_id_hex32': h('transaction ' + str(index)),
            'accepted_whole_case': True,
            'submission_attempts': 1,
            'automatic_resubmission_permitted': False,
            'native_payout_observed': kind == 'exit',
            'terminal_reserve_sompi': 0 if index == 11 else None,
        } for index, kind in enumerate(kinds)]

    def test_exact_genesis_two_payments_and_nine_exits_are_joined(self):
        actual = gate.validate_case_confirmations(
            self.cases, self.confirmations,
            '11111111-1111-4111-8111-111111111111')
        self.assertEqual(actual, self.confirmations)
        self.assertEqual(sum(row['native_payout_observed'] for row in actual),
                         9)

    def test_missing_reordered_or_retransmitted_case_refuses(self):
        mutations = [self.confirmations[:-1]]
        changed = copy.deepcopy(self.confirmations)
        changed[3], changed[4] = changed[4], changed[3]
        mutations.append(changed)
        changed = copy.deepcopy(self.confirmations)
        changed[5]['submission_attempts'] = 2
        mutations.append(changed)
        changed = copy.deepcopy(self.confirmations)
        changed[-1]['native_payout_observed'] = False
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                gate.validate_case_confirmations(
                    self.cases, changed,
                    '11111111-1111-4111-8111-111111111111')

    def test_confirmation_transaction_id_comes_from_exact_case_bytes(self):
        reader = MemoryReader()
        cases, confirmations = [], copy.deepcopy(self.confirmations)
        for index, receipt in enumerate(confirmations):
            reference = reader.add('CASE-' + str(index) + '.json', {
                'transaction': {'id': receipt['transaction_id_hex32']}})
            cases.append({'kind': receipt['kind'], **reference})
            receipt['case_sha256'] = reference['sha256']
        gate.validate_confirmed_case_bytes(cases, confirmations, reader)
        changed = copy.deepcopy(confirmations)
        changed[4]['transaction_id_hex32'] = h('wrong transaction')
        with self.assertRaisesRegex(ValueError,
                                    'exact-case-transaction-identity'):
            gate.validate_confirmed_case_bytes(cases, changed, reader)

    def test_full_public_chain_reaches_but_cannot_bypass_terminal_authority(self):
        reader = MemoryReader()
        trial_id = '11111111-1111-4111-8111-111111111111'
        preflight_receipt_sha = h('preflight receipt')
        profile, tail = h('profile'), h('tail')
        confirmations = copy.deepcopy(self.confirmations)
        cases = []
        for index, receipt in enumerate(confirmations):
            reference = reader.add('CASE-' + str(index) + '.json', {
                'transaction': {'id': receipt['transaction_id_hex32']}})
            cases.append({'kind': receipt['kind'], **reference})
            receipt['case_sha256'] = reference['sha256']
        preflight = reader.add('PREFLIGHT-RESULT.json', {
            'schema': 'kpb-verified-testnet-preflight-audit-evidence/v1',
            'scope': 'UNFUNDED_SUPPLIED_CONTEXT',
            'preflight_receipt_sha256': preflight_receipt_sha,
            'bootstrap_trial_id': trial_id,
            'funding_identity_sha256': h('identity'),
            'component_profile_sha256': profile,
            'tail_sha256': tail,
            'privacy_acceptance_sha256': h('privacy'),
            'registered_driver_result_sha256': [h('driver 1'), h('driver 2')],
            'cases': cases[:3], 'case_count': 3,
            'launch_authorized': False,
            'authority_admitted': False,
            'serialized_receipt_is_authority': False,
            'complete_terminal_lifecycle_observed': False,
            'testnet_trial_readiness_claimed': False,
            'mainnet_or_production_authorized': False,
            'network_funding_or_broadcast_performed': False,
        })
        activation = reader.add('ACTIVATION.json', {
            'schema': 'kpb-research-GEN3-activation-handoff/v1',
            'status': 'EXACT_NEW_GEN3_CONFIRMED_PRIVATE_PAYMENT_LIFECYCLE_PENDING',
            'trial_id': trial_id, 'genesis_case_sha256': cases[0]['sha256'],
            'component_profile_sha256': profile,
            'native_tail_sha256': tail,
            'activation_preflight_sha256': preflight_receipt_sha,
            'R1_R2_nine_exits_and_testnet_terminal_recovery_still_required': True,
            'complete_terminal_lifecycle_observed': False,
            'testnet_trial_readiness_claimed': False,
            'mainnet_or_production_authorized': False,
        })
        manifest = reader.add('MANIFEST.json', {
            'schema': 'kpb-complete-unfunded-native-lifecycle/v2',
            'bootstrap_trial_id': trial_id,
            'component_profile_sha256': profile, 'tail_sha256': tail,
            'cases': cases,
        })
        rehearsal = reader.add('REHEARSAL.json', {
            'schema': 'kpb-executed-complete-native-rehearsal-gate/v1',
            'manifest_sha256': manifest['sha256'],
            'component_profile_sha256': profile, 'tail_sha256': tail,
            'actual_native_CASE_checks': [
                {'kind': row['kind'], 'raw_case_sha256': row['sha256'],
                 'actual_native_Full_all_inputs': True}
                for row in cases],
            'actual_history_payment_and_exit_replay_rejections': 2,
            'actual_public_tree_replay_terminal_reserve_sompi': 0,
            'original_terminal_scan_statuses': 3,
            'testnet_terminal_broadcast_confirmation_or_readiness': False,
            'controller_Original_private_truth_or_wallet_body_read': False,
        })
        confirmations = [reader.add('CONFIRM-' + str(index) + '.json', row)
                         for index, row in enumerate(confirmations)]
        double_spend = reader.add('DOUBLE-SPEND.json', {
            'schema': gate.DOUBLE_SPEND_SCHEMA, 'trial_id': trial_id,
            'after_round2_case_sha256': cases[2]['sha256'],
            'registered_driver_result_sha256': h('driver 2'),
            'current_head_duplicate_nullifier_refused': True,
            'durable_final_candidate_created': False,
            'network_submission_attempted': False,
            'accepted_chain_changed': False,
        })
        service_loss = reader.add('SERVICE-LOSS.json', {
            'schema': 'kpb-unfunded-financial-service-loss/v1',
            'trial_id': trial_id,
            'after_round2_history_sha256': h('round 2 history'),
            'financial_run_ids': [h('run 1'), h('run 2')],
            'process_identities_checked': [101, 102, 103],
            'active_financial_service_processes': 0,
            'active_financial_service_listeners': 0,
            'private_service_state_mounted_to_exit': False,
            'owner_exit_service_dependency': False,
            'controller_read_or_hashed_private_service_state': False,
        })
        terminal = reader.add('TERMINAL-PRIVACY.json', {
            'schema': 'kpb-terminal-exit-source-only-acceptance/v1',
            'privacy_status': 'UNQUALIFIED_SOURCE_ONLY',
            'actual_capture_and_private_score_executed': False,
            'rehearsal_authorized': False,
        })
        source = {'schema': gate.SOURCE_SCHEMA,
            'classification': 'RESEARCH_TESTNET_ONLY',
            'activation_preflight_result': preflight,
            'activation_handoff': activation,
            'lifecycle_manifest': manifest,
            'lifecycle_rehearsal_result': rehearsal,
            'case_confirmations': confirmations,
            'double_spend_refusal': double_spend,
            'service_loss_receipt': service_loss,
            'terminal_privacy_acceptance': terminal}
        source_ref = reader.add('SOURCE.json', source)
        with self.assertRaisesRegex(ValueError,
                'live-parent-activation-completion-not-implemented'):
            gate.rebuild(reader, source_ref)


if __name__ == '__main__':
    unittest.main()
