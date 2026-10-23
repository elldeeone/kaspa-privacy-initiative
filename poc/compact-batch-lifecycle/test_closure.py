"""Public arithmetic/record-projection controls only; no native/G16 invocation."""
import copy
import unittest
from closure import accounting, recorded_metrics


class ClosureControls(unittest.TestCase):
    def values(self):
        return (42_623_726_600, 10_000_000_000, 258_500,
            [19_701_700] + [18_867_700] * 31 + [18_718_200],
            [1_000_000_000] * 31 + [1_000_149_500], 1_000_000_000)

    def test_exact_all_fees_denominator_and_refund(self):
        result = accounting(*self.values())
        self.assertEqual(result['all_entry_and_private_fees_sompi'], 623_577_100)
        self.assertEqual(result['useful_payment_total_sompi'], 32_000_000_000)
        self.assertEqual(result['native_payout_total_sompi'], 32_000_149_500)
        self.assertEqual(result['terminal_credit_refund_sompi'], 149_500)
        self.assertEqual(result['fee_percent_decimal'], '1.9486784375')
        self.assertFalse(result['refund_gross_note_credit_and_ordinary_change_counted_as_useful'])

    def test_terminal_credit_donation_hidden_tail_and_missing_exit_reject(self):
        for fault in ('donation', 'tail', 'missing', 'extra'):
            source, change, entry, fees, payouts, useful = self.values()
            if fault == 'donation':
                payouts[-1] -= 149_500
                fees[-1] += 149_500
            elif fault == 'tail':
                source += 1
            elif fault == 'missing':
                fees.pop()
                payouts.pop()
            else:
                fees.append(1000)
                payouts.append(1000)
            with self.assertRaises(ValueError):
                accounting(source, change, entry, fees, payouts, useful)

    def test_gross_credit_or_refund_cannot_enlarge_useful_denominator(self):
        values = self.values()
        for false_useful in (1_018_867_700, 1_000_149_500, 0, True):
            with self.assertRaises(ValueError):
                accounting(*values[:-1], false_useful)

    def test_source_and_refund_reclassification_reject(self):
        # Reducing the measured source or relabeling the terminal credit as
        # ordinary change must not turn an incomplete ledger into a closure.
        for fault in ('source', 'change', 'refund-as-change', 'refund-removed'):
            source, change, entry, fees, payouts, useful = self.values()
            if fault == 'source':
                source -= 1
            elif fault == 'change':
                change += 1
            elif fault == 'refund-as-change':
                change += 149_500
                payouts[-1] -= 149_500
            else:
                source -= 149_500
                payouts[-1] -= 149_500
            with self.assertRaises(ValueError):
                accounting(source, change, entry, fees, payouts, useful)

    def selected_mock(self):
        # Recorded data are deliberately mock; this test verifies only projection
        # gates and claims no real native/proof acceptance.
        body = {'version': 1, 'id': '11' * 32,
            'inputs': [{'sequence': (1 << 64) - 1}],
            'outputs': [{'value': 999_000, 'covenant': None}],
            'lockTime': 0, 'gas': 0, 'subnetworkId': '00' * 20, 'mass': 5}
        entry = {'amount': 1_000_000, 'scriptPublicKey': '000020' + '22' * 32 + 'ac',
            'blockDaaScore': 0, 'isCoinbase': False, 'covenantId': None}
        report = {'isolation': 'PASS', 'Full': {'accepted': True, 'fee_sompi': 1000},
            'all_input_engines_accepted': True, 'per_input_ScriptEngine': [{'accepted': True}]}
        metrics = {'mining_mass': 10, 'actual_fee_sompi': 1000, 'storage_mass': 5}
        return {'transaction': body, 'entries': [entry]}, report, metrics

    def test_exact_recorded_metrics_and_Full_projection(self):
        case, report, metrics = self.selected_mock()
        _, fee = recorded_metrics(case, report, metrics, 100)
        self.assertEqual(fee, 1000)
        for fault in ('rate', 'mass', 'full', 'engine', 'coinbase', 'DAA', 'fee'):
            c, r, m = copy.deepcopy((case, report, metrics))
            rate = 100
            if fault == 'rate': rate = 101
            elif fault == 'mass': c['transaction']['mass'] += 1
            elif fault == 'full': r['Full']['accepted'] = False
            elif fault == 'engine': r['per_input_ScriptEngine'][0]['accepted'] = False
            elif fault == 'coinbase': c['entries'][0]['isCoinbase'] = True
            elif fault == 'DAA': c['entries'][0]['blockDaaScore'] = 1
            else: m['actual_fee_sompi'] += 1
            with self.assertRaises(ValueError):
                recorded_metrics(c, r, m, rate)


if __name__ == '__main__':
    unittest.main()
