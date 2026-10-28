"""New GEN3 public CASE predicates over explicit unfunded model rows.

Actual independent known-value CV and real Output verification have their own
retained execution receipt. These tests do not execute NativeFull or a node.
"""
import copy
import hashlib
import unittest

import exit_wire
import genesis
import wallet_history
import wallet_profile as wallet

TRIAL = '00000000-0000-4000-8000-000000000001'
CV = bytes([73]) * 64
TAIL = b'UNFUNDED MODEL GEN3 TAIL; NO NATIVE ACCEPTANCE'


def model_row(index):
    cf = bytes([index + 3]) * 264
    return hashlib.sha256(b'public GEN3 model CM' + bytes([index])).digest() + CV + cf + hashlib.sha256(cf).digest() + bytes([index + 31]) * 128


ROWS = tuple(model_row(i) for i in range(3))


class ModelVerifier:
    def verify(self, row):
        return row in ROWS


def selection():
    return genesis.Selection(hashlib.sha256(b'model component profile').digest(),
        genesis.EXPECTED_IDENTITY, TAIL, ModelVerifier(), CV)


def case():
    selected = selection()
    payload = genesis.encode_payload(selected, TRIAL, ROWS)
    _, state = genesis.records(payload, selected, TRIAL)
    scripts = [(b'\0\0\x20' + hashlib.sha256(b'model source key' + bytes([i])).digest() + b'\xac').hex() for i in range(3)]
    return {'transaction': {'version': 1, 'id': hashlib.sha256(b'model GEN3 transaction ID').hexdigest(),
        'inputs': [{'previousOutpoint': {'transactionId': hashlib.sha256(b'model funding' + bytes([i])).hexdigest(), 'index': i},
            'signatureScript': '41' + '00' * 64 + '01', 'sequence': (1 << 64) - 1, 'computeBudget': 10} for i in range(3)],
        'outputs': [{'value': 6_000_000_000,
            'scriptPublicKey': exit_wire.state_spk(wallet_history.state_bytes(state, selected.identity[3]), TAIL).hex(), 'covenant': None}]
            + [{'value': 999_000_000, 'scriptPublicKey': script, 'covenant': None} for script in scripts],
        'lockTime': 0, 'subnetworkId': '00' * 20, 'gas': 0, 'payload': payload.hex(), 'mass': 0},
        'entries': [{'amount': 3_000_000_000, 'scriptPublicKey': script, 'blockDaaScore': 123,
            'isCoinbase': False, 'covenantId': None} for script in scripts]}


class GenesisControls(unittest.TestCase):
    def test_exact_public_funding_and_liability_equations(self):
        actual = genesis.validate_case(case(), selection(), TRIAL, quoted_fee_sompi=3_000_000)
        self.assertEqual(actual['reserve_sompi'], 6_000_000_000)
        self.assertEqual(actual['owner_fee_shares_sompi'], [1_000_000] * 3)
        self.assertEqual(actual['owner_changes_sompi'], [999_000_000] * 3)
        self.assertFalse(actual['native_Full_SDK_id_and_accepted_chain_verified'])

    def test_old_tag_and_other_profile_trial_are_not_relabelled(self):
        for at in (0, 8, 40, 72):
            value = case(); raw = bytearray.fromhex(value['transaction']['payload']); raw[at] ^= 1
            value['transaction']['payload'] = raw.hex()
            with self.subTest(at=at), self.assertRaises(wallet.Invalid): genesis.validate_case(value, selection(), TRIAL)

    def test_CV_proof_duplicate_CM_and_CF_changes_reject(self):
        for at in (88 + 32, 88 + 96, 88 + 392):
            value = case(); raw = bytearray.fromhex(value['transaction']['payload']); raw[at] ^= 1
            value['transaction']['payload'] = raw.hex()
            with self.subTest(at=at), self.assertRaises(wallet.Invalid): genesis.validate_case(value, selection(), TRIAL)
        value = case(); raw = bytearray.fromhex(value['transaction']['payload']); raw[608:1128] = raw[88:608]
        value['transaction']['payload'] = raw.hex()
        with self.assertRaises(wallet.Invalid): genesis.validate_case(value, selection(), TRIAL)

    def test_contribution_subsidy_and_inflated_reserve_reject(self):
        value = case(); value['transaction']['outputs'][1]['value'] += 1; value['transaction']['outputs'][2]['value'] -= 1
        with self.assertRaises(wallet.Invalid): genesis.validate_case(value, selection(), TRIAL)
        value = case(); value['transaction']['outputs'][0]['value'] += 1
        with self.assertRaises(wallet.Invalid): genesis.validate_case(value, selection(), TRIAL)

    def test_foreign_duplicate_reordered_change_and_funding_reject(self):
        for mode in ('foreign', 'duplicate-change', 'reordered-change', 'duplicate-point', 'duplicate-key'):
            value = case()
            if mode == 'foreign': value['transaction']['outputs'][1]['scriptPublicKey'] = '000020' + '00' * 32 + 'ac'
            if mode == 'duplicate-change': value['transaction']['outputs'][2]['scriptPublicKey'] = value['transaction']['outputs'][1]['scriptPublicKey']
            if mode == 'reordered-change': value['transaction']['outputs'][1], value['transaction']['outputs'][2] = value['transaction']['outputs'][2], value['transaction']['outputs'][1]
            if mode == 'duplicate-point': value['transaction']['inputs'][1]['previousOutpoint'] = copy.deepcopy(value['transaction']['inputs'][0]['previousOutpoint'])
            if mode == 'duplicate-key': value['entries'][1]['scriptPublicKey'] = value['entries'][0]['scriptPublicKey']
            with self.subTest(mode=mode), self.assertRaises(wallet.Invalid): genesis.validate_case(value, selection(), TRIAL)

    def test_boolean_decimal_and_unsigned_budget_aliases_reject(self):
        for field, value in (('amount', True), ('amount', '3000000000'), ('blockDaaScore', True)):
            changed = case(); changed['entries'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(wallet.Invalid): genesis.validate_case(changed, selection(), TRIAL)
        changed = case(); changed['transaction']['inputs'][0]['computeBudget'] = 11
        with self.assertRaises(wallet.Invalid): genesis.validate_case(changed, selection(), TRIAL)
        # History permits actual u16 budgets only when actual native execution
        # is still required; this flag does not verify a signature or a CASE.
        result = genesis.validate_case(changed, selection(), TRIAL, signed=True)
        self.assertFalse(result['native_Full_SDK_id_and_accepted_chain_verified'])

    def test_non_ALL_and_wrong_quote_reject(self):
        changed = case(); changed['transaction']['inputs'][0]['signatureScript'] = '41' + '00' * 64 + '02'
        with self.assertRaises(wallet.Invalid): genesis.validate_case(changed, selection(), TRIAL, signed=True)
        with self.assertRaises(wallet.Invalid): genesis.validate_case(case(), selection(), TRIAL, quoted_fee_sompi=3_000_001)

    def test_wrong_native_state_policy_reject(self):
        changed = case(); script = bytearray.fromhex(changed['transaction']['outputs'][0]['scriptPublicKey']); script[5] ^= 1
        changed['transaction']['outputs'][0]['scriptPublicKey'] = script.hex()
        with self.assertRaises(wallet.Invalid): genesis.validate_case(changed, selection(), TRIAL)


if __name__ == '__main__':
    unittest.main()
