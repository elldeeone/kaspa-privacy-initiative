"""Live-current-entry joins: UTXO context never comes from a default or flag."""
from copy import deepcopy
import unittest

from public import current_entry_context, load_wire
from test_history import fixture


def entry():
    history, _ = fixture()
    head = history['head']
    point = bytes.fromhex(head['outpoint_hex36'])
    value = {'outpoint': {'transactionId': point[:32].hex(), 'index': int.from_bytes(point[32:], 'little')},
        'entry': {'amount': head['reserve_sompi'],
            'scriptPublicKey': load_wire().state_spk(bytes.fromhex(head['state_hex112']), b'\x75').hex(),
            'blockDaaScore': 600_000_000, 'isCoinbase': False, 'covenantId': None}}
    return history, value


class LiveContextTests(unittest.TestCase):
    def test_current_context_requires_exact_point_reserve_and_selected_policy(self):
        history, value = entry()
        self.assertEqual(current_entry_context(history, '75', value), 600_000_000)
        for field, bad in (('amount', history['head']['reserve_sompi'] + 1),
                           ('scriptPublicKey', '00' * 37), ('isCoinbase', True), ('covenantId', '00' * 32)):
            changed = deepcopy(value)
            changed['entry'][field] = bad
            with self.assertRaises(ValueError):
                current_entry_context(history, '75', changed)
        changed = deepcopy(value)
        changed['outpoint']['index'] = 1
        with self.assertRaises(ValueError):
            current_entry_context(history, '75', changed)

    def test_DAA_boundary_and_no_strings_floats_or_booleans(self):
        history, value = entry()
        for daa in (0, (1 << 64) - 1):
            value['entry']['blockDaaScore'] = daa
            self.assertEqual(current_entry_context(history, '75', value), daa)
        for daa in (-1, 1 << 64, True, '600000000', 6.0):
            value['entry']['blockDaaScore'] = daa
            with self.assertRaises(ValueError):
                current_entry_context(history, '75', value)


if __name__ == '__main__':
    unittest.main()
