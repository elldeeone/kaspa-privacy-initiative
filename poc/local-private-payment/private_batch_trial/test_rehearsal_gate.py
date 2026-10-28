"""Projection/witness coupling against retained genuine public Exit CASEs."""
import copy
from pathlib import Path
import runpy
import unittest

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


if __name__ == '__main__':
    unittest.main()
