"""Actual native Full tests using only public DO_NOT_FUND historical inputs."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]
BINARY = Path(os.environ['KPI_RECOVERY_NATIVE_TEST_BINARY'])
BASE = ROOT / 'research/next-session/private-integration/lifecycle/execution-01'
CONSENT = 'I_ACCEPT_PUBLIC_NOTE_VALUE_COMMITMENT_NULLIFIER_KEY_AND_PAYOUT_KEY_DISCLOSURE'


def fixture(owner):
    vector = json.loads((BASE / f'{owner}-reveal.vector.json').read_bytes())
    body = json.loads((BASE / f'{owner}-reveal/transaction.json').read_bytes())
    context = json.loads((BASE / f'{owner}-reveal/supplied-context.json').read_bytes())[0]
    redeem = bytes.fromhex(body['inputs'][0]['signatureScript'])[199:]
    return {'mode': 'quote', 'domain_hex32': redeem[10:42].hex(),
            'current_redeem_hex': redeem.hex(),
            'immutable_tail_sha256': hashlib.sha256(redeem[114:]).hexdigest(),
            'current_script_public_key_hex': context['script_public_key'],
            'previous_outpoint': body['inputs'][0]['previousOutpoint'],
            'reserve_sompi': str(context['amount_sompi']),
            'payload_hex2029': body['payload'], 'block_daa_score': str(context['block_daa_score'])}, vector, body


def invoke(request):
    result = subprocess.run([str(BINARY)], input=json.dumps(request), text=True, capture_output=True)
    return result, json.loads(result.stdout) if result.stdout else None


class NativeHelperTests(unittest.TestCase):
    def test_new_private_balance_profile_authorized_sign_reaches_full(self):
        base = ROOT / 'research/next-session/privacy-recovery/native/new-profile-fallback-01'
        request = json.loads((base / 'quote-request.json').read_bytes())
        public_key = json.loads((base / 'PUBLIC-DO-NOT-FUND-NATIVE-KEY.json').read_bytes())
        self.assertTrue(public_key['never_a_live_trial_key'])
        result, quote = invoke(request)
        self.assertEqual(result.returncode, 0, result.stderr)
        signed = dict(request, mode='sign', consent=CONSENT,
                      expected_unsigned_txid_raw_hex=quote['transaction_id'],
                      native_secret_hex32=public_key['public_native_secret_hex32'])
        result, signed = invoke(signed)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(signed['native_validation']['Full']['accepted'])
        self.assertTrue(signed['native_validation']['all_input_engines_accepted'])
        self.assertEqual(signed['approved_policy_program'], 'SOURCE_DERIVED_KPX3_UNIFIED_PRIVATE_BALANCE_UNION')
        self.assertEqual(signed['transaction_id'], quote['transaction_id'])
        self.assertIsNone(signed['successor_state_hex112'])
        self.assertNotIn(public_key['public_native_secret_hex32'], result.stdout + result.stderr)

    def test_new_private_balance_profile_still_quotes_without_prover_or_pk(self):
        path = ROOT / 'research/next-session/privacy-recovery/native/new-profile-fallback-01/quote-request.json'
        request = json.loads(path.read_bytes())
        self.assertNotIn('native_secret_hex32', request)
        result, quote = invoke(request)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(quote['approved_policy_program'], 'SOURCE_DERIVED_KPX3_UNIFIED_PRIVATE_BALANCE_UNION')
        self.assertTrue(quote['public_checks_reached_owner_signature'])
        self.assertFalse(quote['transaction_or_revealing_payload_returned'])
        self.assertNotIn('transaction', quote)

    def test_actual_fresh_domain_historical_quote_without_any_fresh_key(self):
        root = ROOT / 'research/next-session/testnet-rehearsal/accepted-01/local-native/bob-reveal'
        body = json.loads((root / 'transaction.json').read_bytes())
        entry = json.loads((root / 'supplied-context.json').read_bytes())[0]
        redeem = bytes.fromhex(body['inputs'][0]['signatureScript'])[199:]
        request = {'mode': 'quote', 'domain_hex32': redeem[10:42].hex(),
                   'current_redeem_hex': redeem.hex(),
                   'immutable_tail_sha256': hashlib.sha256(redeem[114:]).hexdigest(),
                   'current_script_public_key_hex': entry['script_public_key'],
                   'previous_outpoint': body['inputs'][0]['previousOutpoint'],
                   'reserve_sompi': str(entry['amount_sompi']), 'payload_hex2029': body['payload'],
                   'block_daa_score': str(entry['block_daa_score'])}
        self.assertEqual(request['domain_hex32'], '42fab9c9042a1fbf0e0ef7755cb04df8a79ce32b6715bdd600a3deb100bfe827')
        result, quote = invoke(request)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(quote['transaction_id'], body['id'])
        self.assertTrue(quote['public_checks_reached_owner_signature'])
        self.assertNotIn('transaction', quote)

    def test_current_redeem_continuing_and_terminal_quote_and_authorized_sign(self):
        for owner in ('bob', 'charlie'):
            with self.subTest(owner=owner):
                request, vector, original = fixture(owner)
                result, quote = invoke(request)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(quote['public_checks_reached_owner_signature'])
                self.assertFalse(quote['transaction_or_revealing_payload_returned'])
                self.assertNotIn('transaction', quote)
                self.assertNotIn('payload_hex2029', quote)
                self.assertEqual(quote['transaction_id'], original['id'])
                signed = dict(request, mode='sign', consent=CONSENT,
                              expected_unsigned_txid_raw_hex=quote['transaction_id'],
                              native_secret_hex32=vector['native_secret_hex'])
                result, body = invoke(signed)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(body['native_validation']['Full']['accepted'])
                self.assertTrue(body['native_validation']['all_input_engines_accepted'])
                self.assertEqual(body['transaction_id'], original['id'])
                self.assertEqual(body['metrics'], quote['metrics'])
                self.assertEqual(body['transaction']['outputs'], original['outputs'])
                self.assertEqual(body['transaction']['inputs'][0]['signatureScript'][398:],
                                 original['inputs'][0]['signatureScript'][398:])
                self.assertNotIn(vector['native_secret_hex'], result.stdout + result.stderr)
                self.assertEqual(body['successor_state_hex112'] is None, owner == 'charlie')

    def reject(self, mutate, category):
        request, _, _ = fixture('bob')
        mutate(request)
        result, value = invoke(request)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(value)
        self.assertIn(category, result.stderr)

    def test_explicit_disclosure_consent_before_signing(self):
        self.reject(lambda r: r.update(mode='sign'), 'EXPLICIT_REVEAL_PRIVACY_CONSENT_REQUIRED')
        self.reject(lambda r: r.update(mode='sign', consent='automatic'), 'EXPLICIT_REVEAL_PRIVACY_CONSENT_REQUIRED')

    def test_quote_refuses_any_signing_key(self):
        self.reject(lambda r: r.update(native_secret_hex32='11' * 32), 'QUOTE_MUST_NOT_RECEIVE')

    def test_domain_policy_and_current_spk_are_bound(self):
        self.reject(lambda r: r.update(domain_hex32='11' * 32), 'DOMAIN_MISMATCH')
        self.reject(lambda r: r.update(immutable_tail_sha256='11' * 32), 'IMMUTABLE_POLICY_MISMATCH')
        self.reject(lambda r: r.update(current_script_public_key_hex='000020' + '11' * 32 + 'ac'),
                    'CURRENT_RESERVE_SPK_MISMATCH')

    def test_integer_hex_and_note_fee_ranges(self):
        self.reject(lambda r: r.update(reserve_sompi='02000000000'), 'UNSIGNED_DECIMAL_REQUIRED')
        self.reject(lambda r: r.update(reserve_sompi='2870000000000000001'), 'AMOUNT_RANGE')
        self.reject(lambda r: r.update(current_redeem_hex=r['current_redeem_hex'].upper()), 'CANONICAL_HEX_REQUIRED')
        def wrong_fee(r):
            payload = bytearray.fromhex(r['payload_hex2029'])
            payload[2013:2021] = (1).to_bytes(8, 'little')
            r['payload_hex2029'] = payload.hex()
        self.reject(wrong_fee, 'REVEAL_VALUE_FEE_RANGE')

    def test_stale_current_nf_path_is_rejected_before_signature(self):
        def wrong_root(r):
            redeem = bytearray.fromhex(r['current_redeem_hex'])
            redeem[2 + 76] ^= 1
            r['current_redeem_hex'] = redeem.hex()
            # The supplied SPK must follow the altered exact current bytecode;
            # an unrelated old SPK would reject before reaching state checks.
            digest = hashlib.blake2b(redeem, digest_size=32).hexdigest()
            r['current_script_public_key_hex'] = '0000aa20' + digest + '87'
        self.reject(wrong_root, 'PUBLIC_REVEAL_CHECKS_DID_NOT_REACH_OWNER_SIGNATURE')

    def test_quoted_body_and_owner_key_binding(self):
        request, vector, _ = fixture('bob')
        result, quote = invoke(request)
        self.assertEqual(result.returncode, 0)
        signed = dict(request, mode='sign', consent=CONSENT,
                      expected_unsigned_txid_raw_hex='11' * 32,
                      native_secret_hex32=vector['native_secret_hex'])
        result, _ = invoke(signed)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('QUOTED_TRANSACTION_CHANGED', result.stderr)
        signed['expected_unsigned_txid_raw_hex'] = quote['transaction_id']
        signed['native_secret_hex32'] = '11' * 32
        result, _ = invoke(signed)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('OWNER_KEY_DOES_NOT_MATCH', result.stderr)

    def test_unknown_options_and_unilateral_sighash_override_rejected(self):
        self.reject(lambda r: r.update(sighash_type=2), 'INVALID_HELPER_REQUEST')

    def test_self_hashed_modified_program_is_not_approved(self):
        def arbitrary_program(r):
            redeem = bytearray.fromhex(r['current_redeem_hex'])
            redeem[-1] ^= 1
            r['current_redeem_hex'] = redeem.hex()
            r['immutable_tail_sha256'] = hashlib.sha256(redeem[114:]).hexdigest()
            r['current_script_public_key_hex'] = '0000aa20' + hashlib.blake2b(redeem, digest_size=32).hexdigest() + '87'
        self.reject(arbitrary_program, 'APPROVED_POLICY_TEMPLATE_MISMATCH')


if __name__ == '__main__':
    unittest.main()
