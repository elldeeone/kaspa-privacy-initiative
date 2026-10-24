"""Public wire/accounting controls; dummy tail/ciphertexts prove no W validity."""
import copy
import unittest

from gn3 import (EntrySelection, decode_payload, encode_payload, p2sh, record,
                 validate_accepted_genesis, validate_genesis)
from gn3_common import MAX, NOTE_FLOOR, encoded, parse

TRIAL = '2bf79d53-a37a-4780-b6b2-1264edf15b87'
SELECTED = EntrySelection('11' * 32, bytes.fromhex(
    'be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480'), b'\x51')
SCRIPTS = ['000020' + '31' * 32 + 'ac', '000020' + '32' * 32 + 'ac', '000020' + '33' * 32 + 'ac']


def note(value, distinct):
    return (bytes([distinct]) * 32 + bytes([distinct + 1]) * 32 + value.to_bytes(8, 'little')
        + bytes([distinct + 2]) * 32 + bytes([distinct + 3]) * 32 + bytes([distinct + 4]) * 32)


def fixture(fee=100_000, changes=(500_000, 600_000, 700_000), values=(NOTE_FLOOR, NOTE_FLOOR, NOTE_FLOOR)):
    rows = [record(note(v, i + 1), bytes([i + 1]) * 264, SELECTED.domain) for i, v in enumerate(values)]
    raw = encode_payload(SELECTED, TRIAL, rows)
    _, snapshot, reserve = decode_payload(raw, SELECTED, TRIAL)
    outputs = [{'value': reserve, 'scriptPublicKey': p2sh(b'\x4c\x70' + SELECTED.state_magic + snapshot.state(SELECTED.domain)[8:]
        + SELECTED.tail), 'covenant': None}]
    outputs += [{'value': v, 'scriptPublicKey': SCRIPTS[i], 'covenant': None}
                for i, v in enumerate(changes) if v]
    fees = [fee // 3, fee // 3, fee - 2 * (fee // 3)]
    return {'transaction': {'version': 1, 'id': '55' * 32, 'inputs': [
        {'previousOutpoint': {'transactionId': (str(i + 6) * 2) * 32, 'index': i},
         'signatureScript': '41' + '00' * 64 + '01', 'sequence': (1 << 64) - 1, 'computeBudget': 10}
        for i in range(3)], 'outputs': outputs, 'lockTime': 0, 'subnetworkId': '00' * 20,
        'gas': 0, 'payload': raw.hex(), 'mass': 1},
        'entries': [{'amount': values[i] + changes[i] + fees[i], 'scriptPublicKey': SCRIPTS[i],
            'blockDaaScore': i, 'isCoinbase': False, 'covenantId': None} for i in range(3)]}


class GN3Controls(unittest.TestCase):
    def test_history_budget_is_native_owned_but_financial_guards_stay(self):
        baseline = fixture()
        expected = validate_accepted_genesis(baseline, SELECTED, TRIAL)
        for budget in (0, 11, 1600, 65535):
            row = copy.deepcopy(baseline); row['transaction']['inputs'][0]['computeBudget'] = budget
            self.assertEqual(validate_accepted_genesis(row, SELECTED, TRIAL), expected)
            with self.assertRaises(ValueError):
                validate_genesis(row, SELECTED, TRIAL)
        for budget in (True, -1, 65536, 11.0, '11'):
            row = copy.deepcopy(baseline); row['transaction']['inputs'][0]['computeBudget'] = budget
            with self.assertRaises(ValueError):
                validate_accepted_genesis(row, SELECTED, TRIAL)
        row = copy.deepcopy(baseline); row['transaction']['inputs'][0]['computeBudget'] = 11
        row['transaction']['outputs'][1]['value'] -= 1
        row['transaction']['outputs'][2]['value'] += 1
        with self.assertRaises(ValueError):
            validate_accepted_genesis(row, SELECTED, TRIAL)

    def test_all_change_shapes_and_odd_exact_allocation(self):
        for fee in (1, 2, 99, 100_000, MAX):
            for changes in ((0, 0, 0), (0, 0, 700_000), (0, 600_000, 0), (0, 600_000, 700_000),
                            (500_000, 0, 0), (500_000, 0, 700_000), (500_000, 600_000, 0),
                            (500_000, 600_000, 700_000)):
                with self.subTest(fee=fee, changes=changes):
                    result = validate_genesis(fixture(fee, changes), SELECTED, TRIAL, required_fee=fee)
                    self.assertEqual(result['snapshot']['cm_cursor'], 3)
                    self.assertEqual(len(result['snapshot']['nullifiers']), 1)
                    self.assertEqual([r['entry_fee_sompi'] for r in result['contributions']],
                                     [fee // 3, fee // 3, fee - 2 * (fee // 3)])

    def test_range_boundaries(self):
        for value in (0, NOTE_FLOOR - 1, MAX + 1):
            with self.assertRaises(ValueError):
                record(note(value, 1), bytes(264), SELECTED.domain)
        with self.assertRaises(ValueError):
            fixture(values=(MAX, NOTE_FLOOR, NOTE_FLOOR))
        self.assertEqual(record(note(MAX, 1), bytes(264), SELECTED.domain)[64:72], MAX.to_bytes(8, 'little'))

    def test_profile_domain_trial_and_exact_lengths(self):
        baseline = fixture()
        raw = bytes.fromhex(baseline['transaction']['payload'])
        for candidate in (raw[:-1], raw + b'\0', b'WRONGMAG' + raw[8:],
                          raw[:8] + bytes(32) + raw[40:], raw[:40] + bytes(32) + raw[72:],
                          raw[:72] + bytes(16) + raw[88:]):
            row = copy.deepcopy(baseline); row['transaction']['payload'] = candidate.hex()
            with self.assertRaises(ValueError):
                validate_genesis(row, SELECTED, TRIAL)
        with self.assertRaises(ValueError):
            validate_genesis(baseline, SELECTED, '2bf79d53-a37a-4780-b6b2-1264edf15b88')

    def test_CM_CF_roots_and_output_binding(self):
        baseline = fixture()
        for offset in (88, 88 + 168, 88 + 200, 88 + 464, 584 + 64):
            row = copy.deepcopy(baseline)
            raw = bytearray.fromhex(row['transaction']['payload']); raw[offset] ^= 1
            row['transaction']['payload'] = raw.hex()
            with self.assertRaises(ValueError):
                validate_genesis(row, SELECTED, TRIAL)
        for field, value in [('value', 120_000_001), ('scriptPublicKey', '000020' + '42' * 32 + 'ac'),
                             ('covenant', {})]:
            row = copy.deepcopy(baseline); row['transaction']['outputs'][0][field] = value
            with self.assertRaises(ValueError):
                validate_genesis(row, SELECTED, TRIAL)

    def test_no_redistribution_foreign_change_or_duplicates(self):
        cases = []
        row = fixture(); row['transaction']['outputs'][1]['value'] -= 1
        row['transaction']['outputs'][2]['value'] += 1; cases.append(row)
        row = fixture(); row['transaction']['outputs'][1:]=list(reversed(row['transaction']['outputs'][1:])); cases.append(row)
        row = fixture(); row['transaction']['outputs'][1]['scriptPublicKey'] = '000020' + '42' * 32 + 'ac'; cases.append(row)
        row = fixture(); row['entries'][1]['scriptPublicKey'] = SCRIPTS[0]; cases.append(row)
        row = fixture(); row['transaction']['inputs'][1]['previousOutpoint'] = copy.deepcopy(row['transaction']['inputs'][0]['previousOutpoint']); cases.append(row)
        for row in cases:
            with self.assertRaises(ValueError):
                validate_genesis(row, SELECTED, TRIAL)
        with self.assertRaises(ValueError):
            validate_genesis(fixture(), SELECTED, TRIAL, required_fee=100_001)

    def test_headers_types_contexts_and_canonical_JSON(self):
        baseline = fixture()
        for field, value in [('version', True), ('version', 1.0), ('lockTime', 1),
                             ('gas', 1), ('subnetworkId', '01' * 20), ('mass', True)]:
            row = copy.deepcopy(baseline); row['transaction'][field] = value
            with self.assertRaises(ValueError):
                validate_genesis(row, SELECTED, TRIAL)
        for field, value in [('computeBudget', 11), ('sequence', 0),
                             ('signatureScript', '41'), ('signatureScript', '')]:
            row = copy.deepcopy(baseline); row['transaction']['inputs'][0][field] = value
            with self.assertRaises(ValueError):
                validate_genesis(row, SELECTED, TRIAL)
        for field, value in [('amount', True), ('blockDaaScore', -1), ('isCoinbase', True), ('covenantId', {})]:
            row = copy.deepcopy(baseline); row['entries'][0][field] = value
            with self.assertRaises(ValueError):
                validate_genesis(row, SELECTED, TRIAL)
        raw = encoded(baseline)
        with self.assertRaises(ValueError):
            parse(b'{"entries":null,' + raw[1:])


if __name__ == '__main__':
    unittest.main()
