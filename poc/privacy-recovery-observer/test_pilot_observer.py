"""Synthetic byte/amount controls only; zero proof or native acceptance claim."""
import copy
import hashlib
import hmac
import unittest

from pilot_observer import Invalid, analyze, cm, necessary_slot_bounds

D = b'\x02' * 32
SCRIPT = '000020' + '03' * 32 + 'ac'


def state(n, m):
    return b'KPX2ST01' + D + bytes(32) + n.to_bytes(4, 'little') + bytes(32) + m.to_bytes(4, 'little')


def note(value, tag):
    key = hashlib.sha256(b'SYNTHETIC_NOT_NATIVE_ACCEPTED' + bytes([tag])).digest()
    fields = bytes([tag]) * 64 + value.to_bytes(8, 'little') + bytes([tag + 1]) * 32
    opening = fields + hashlib.sha256(b'KPX1KEY\0' + D + key).digest() + bytes([tag + 2]) * 32
    return opening, key


def fixture():
    # All Merkle/Groth16/signature bytes are placeholders; the caller tests
    # disclosure parsing and public arithmetic only, never native validity.
    g, _ = note(60_000_000, 10)
    a, _ = note(158_751_400, 20)
    notes = [note(100_000_000, 30), note(100_000_000, 40)]
    genesis = b'KPX2GN01' + D + g + cm(D, g) + bytes(264) + hashlib.sha256(bytes(264)).digest()
    admit = bytearray(1344)
    admit[:8], admit[8:40], admit[40:208] = b'KPX2AD01', D, a
    admit[208:240] = cm(D, a)
    admit[504:536] = hashlib.sha256(admit[240:504]).digest()
    admit[1048:1160] = state(2, 1)
    private = bytearray(4356)
    private[:8], private[8:40], private[76:188] = b'KPX2AU01', D, state(2, 1)
    private[196:204] = (18_751_400).to_bytes(8, 'little')
    for slot, (opening, _) in enumerate(notes):
        private[268 + slot * 32:300 + slot * 32] = cm(D, opening)
    private[332:364] = hashlib.sha256(private[484:1012]).digest()
    payloads = [b'', genesis, bytes(admit), bytes(private)]
    payouts = []
    for slot, (opening, key) in enumerate(notes):
        value, fee = 100_000_000, (4_973_800 if slot == 0 else 4_963_200)
        p = bytearray(2029)
        p[:9], p[9:113], p[113:145] = b'KPX2RV01\x01', opening[:104], key
        p[145:177], p[177:181], p[181:213] = opening[136:168], (2 + slot).to_bytes(4, 'little'), opening[104:136]
        p[213:245] = cm(D, opening)
        p[1917:1949] = hmac.digest(key, b'KPX1NF\0\0' + D + cm(D, opening) + p[177:181], 'sha256')
        p[2013:2021], p[2021:2029] = fee.to_bytes(8, 'little'), (value - fee).to_bytes(8, 'little')
        payloads.append(bytes(p))
        payouts.append({'value': str(value - fee), 'scriptPublicKey': '000020' + opening[136:168].hex() + 'ac', 'covenant': None})
    outputs = [[{'value': str(v), 'scriptPublicKey': SCRIPT, 'covenant': None}
                for v in (60_217_300, 163_601_800, 79_848_700)],
               [{'value': '60000000', 'scriptPublicKey': SCRIPT, 'covenant': None}],
               [{'value': '218751400', 'scriptPublicKey': SCRIPT, 'covenant': None}],
               [{'value': '200000000', 'scriptPublicKey': SCRIPT, 'covenant': None}],
               [{'value': '100000000', 'scriptPublicKey': SCRIPT, 'covenant': None}, payouts[0]],
               [payouts[1]]]
    parents = [[('ff' * 32, 0, 306_866_100)], [(f'{1:064x}', 0, 60_217_300)],
               [(f'{2:064x}', 0, 60_000_000), (f'{1:064x}', 1, 163_601_800)],
               [(f'{3:064x}', 0, 218_751_400)], [(f'{4:064x}', 0, 200_000_000)],
               [(f'{5:064x}', 0, 100_000_000)]]
    rows = []
    for ordinal, payload in enumerate(payloads):
        inputs, contexts = [], []
        for txid, index, value in parents[ordinal]:
            point = {'transactionId': txid, 'index': index}
            inputs.append({'previousOutpoint': point, 'signatureScript': '', 'sequence': str(2**64 - 1), 'computeBudget': 1})
            contexts.append({'outpoint': point, 'amount_sompi': str(value), 'script_public_key': SCRIPT,
                             'block_daa_score': '0', 'is_coinbase': False, 'covenant_id': None})
        rows.append({'ordinal': ordinal, 'body': {'version': 1, 'id': f'{ordinal + 1:064x}',
            'inputs': inputs, 'outputs': outputs[ordinal], 'lockTime': '0', 'subnetworkId': '00' * 20,
            'gas': '0', 'payload': payload.hex(), 'storageMass': '0'},
            'accepted_input_contexts': contexts, 'accepting_header': {'synthetic': True}})
    return {'schema': 'kpx2-public-chain-observer/v1', 'observer': 'C',
            'classification': 'SYNTHETIC_SHAPE_ONLY_NOT_NATIVE_ACCEPTED', 'transactions': rows}


class DisclosureTests(unittest.TestCase):
    def test_synthetic_control_links_and_bounds(self):
        result = analyze(fixture())
        self.assertEqual(result['classification'], 'SYNTHETIC_SHAPE_CONTROL_NOT_NATIVE_ACCEPTED')
        self.assertEqual(result['after_complete_cashout']['forced_note_to_payout_links'], 2)
        self.assertEqual(result['payment_horizon']['necessary_slot_value_intervals_sompi'],
                         [[0, 0], [60_000_000, 140_000_000], [200_000_000, 200_000_000]])
        self.assertFalse(result['human_identities_inferred'])

    def test_corrupt_fields_reject(self):
        for row_index, byte_index in [(1, 8), (1, 208), (1, 504), (2, 208), (2, 504), (3, 332), (4, 113),
                                       (4, 177), (4, 213), (4, 1917), (4, 73), (5, 2021)]:
            with self.subTest(row=row_index, byte=byte_index):
                data = fixture()
                raw = bytearray.fromhex(data['transactions'][row_index]['body']['payload'])
                raw[byte_index] ^= 1
                data['transactions'][row_index]['body']['payload'] = raw.hex()
                with self.assertRaises(Invalid):
                    analyze(data)

    def test_payout_substitution_rejects(self):
        data = fixture()
        data['transactions'][4]['body']['outputs'][1]['value'] = '95026201'
        with self.assertRaises(Invalid):
            analyze(data)

    def test_researcher_metadata_rejects(self):
        for level in ('dataset', 'row', 'body'):
            data = fixture()
            target = data if level == 'dataset' else data['transactions'][0] if level == 'row' else data['transactions'][0]['body']
            target['actor'] = 'HIDDEN_RESEARCHER_LABEL'
            with self.assertRaises(Invalid):
                analyze(data)

    def test_bad_arity_and_public_order_rejects(self):
        data = fixture()
        data['transactions'].pop()
        with self.assertRaises(Invalid):
            analyze(data)
        data = fixture()
        data['transactions'][1]['ordinal'] = 5
        with self.assertRaises(Invalid):
            analyze(data)


if __name__ == '__main__':
    unittest.main()
