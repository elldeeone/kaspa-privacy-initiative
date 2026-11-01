"""Projection/witness coupling against retained genuine public Exit CASEs."""
import copy
import hashlib
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest
from unittest import mock

import exit_wire
import private_worker
import rehearsal_gate
import wallet_profile as wallet


class RehearsalEvidenceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
        root = Path(__file__).absolute().parents[3]
        base = root / 'poc/local-private-payment/private-batch-public/native/evidence/2026-10-28-exit-component/native'
        cls.cases = [private_worker.parse(read(base / name / 'CASE.json'))
                     for name in ('continuing-positive', 'terminal-positive')]

    def test_actual_CASE_projection_matches_existing_Exit_codec(self):
        for case in self.cases:
            script = bytes.fromhex(case['transaction']['inputs'][0]['signatureScript'])
            pushes = rehearsal_gate.witness_data(script)
            self.assertEqual([len(data) for data in pushes], [128, 8211])
            redeem = pushes[-1]
            self.assertEqual(redeem[:2], b'\x4c\x70')
            expected = exit_wire.projection(bytes.fromhex(case['transaction']['payload']), redeem[114:])
            self.assertEqual(rehearsal_gate.case_projection(case, 'exit'), expected)

    def test_actual_effect_mutation_cannot_keep_old_projection(self):
        original = self.cases[0]
        changed = copy.deepcopy(original); changed['transaction']['outputs'][-1]['value'] += 1
        self.assertNotEqual(rehearsal_gate.case_projection(original, 'exit'),
                            rehearsal_gate.case_projection(changed, 'exit'))

    def test_no_nested_proof_search_and_malformed_push_refusal(self):
        embedded = b'x' * 128
        redeem = b'z' + embedded + b'z'
        script = b'\x4c' + bytes([len(redeem)]) + redeem
        self.assertEqual(rehearsal_gate.witness_data(script), [redeem])
        self.assertEqual([data for data in rehearsal_gate.witness_data(script) if len(data) == 128], [])
        for raw in (b'\x4c', b'\x4d\x01', b'\x4c\x80' + bytes(127), b'\xa9'):
            with self.subTest(raw=raw[:3]), self.assertRaises(wallet.Invalid): rehearsal_gate.witness_data(raw)

    def test_activation_trial_must_equal_manifest_trial_path_hash_and_uuid(self):
        path = Path('/public-rehearsal-controls/TRIAL.json')
        trial = {'trial_id': '11111111-1111-4111-8111-111111111111'}
        raw = private_worker.encoded(trial); pin = hashlib.sha256(raw).hexdigest()
        args = SimpleNamespace(trial=str(path), trial_sha256=pin)
        value = {'bootstrap_trial': {'path': str(path), 'sha256': pin},
                 'bootstrap_trial_id': trial['trial_id']}
        read = lambda actual, expected: raw if (Path(actual) == path and expected == pin) else None
        self.assertEqual(rehearsal_gate.require_activation_trial(value, args, read), trial)
        changed = copy.deepcopy(value)
        changed['bootstrap_trial_id'] = '22222222-2222-4222-8222-222222222222'
        with self.assertRaises(wallet.Invalid):
            rehearsal_gate.require_activation_trial(changed, args, read)

    def test_replay_control_rejects_at_transition_with_exact_categories(self):
        history = {'transitions': [
            {'projection_hex': '00'}, {'projection_hex': '00'},
            {'projection_hex': '00'}]}
        state = SimpleNamespace(head='successor-head', state='successor-state')
        selected = SimpleNamespace(tail=b'tail', initial_cv=b'cv', identity=(),
            verifier=SimpleNamespace(profile='profile', verify=lambda _: True))
        with mock.patch.object(rehearsal_gate, 'history_prefix', side_effect=lambda value, count: count), \
             mock.patch.object(rehearsal_gate.wallet_history, 'load_supplied', return_value=state), \
             mock.patch.object(rehearsal_gate.wallet_history, 'payment',
                side_effect=wallet.Invalid('wallet-payment-exact-current-context')), \
             mock.patch.object(rehearsal_gate.exit_wire, 'require_current_head',
                side_effect=ValueError('new-exit-exact-selected-head')):
            self.assertEqual(rehearsal_gate.require_actual_replay_refusals(history, selected), 2)
        with mock.patch.object(rehearsal_gate, 'history_prefix', side_effect=lambda value, count: count), \
             mock.patch.object(rehearsal_gate.wallet_history, 'load_supplied', return_value=state), \
             mock.patch.object(rehearsal_gate.wallet_history, 'payment',
                side_effect=wallet.Invalid('wallet-history-exact-final-head')):
            with self.assertRaises(wallet.Invalid):
                rehearsal_gate.require_actual_replay_refusals(history, selected)


if __name__ == '__main__':
    unittest.main()
