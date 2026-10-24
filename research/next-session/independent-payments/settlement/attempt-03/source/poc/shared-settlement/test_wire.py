"""Public wire/official-ID controls; no ScriptEngine, proof, PK or private data.

ID and selected storage tests execute only the independently selected upstream
normalizer's control-normalize-freeze operation. No acceptance report is used
as a substitute for these fresh byte-derived results.
"""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

from wire import Invalid, MAX, ROOT, hexbytes, p2sh, storage_mass, transaction_id, uint, validate_case

LIFECYCLE = ROOT / 'research/next-session/compact-batch/lifecycle'
FIXTURES = {
    'wide': ('public-native-canaries-01/wide32/validation-case.json',
        '308e841e4b212bfc67aad79bcab0a61698c0ce294fdbded7d3697137809b3f23',
        'aaabacff2784e834ee5c1ec7040d1b24cfbe2d270f2cebcaf3366926454efe64'),
    'compact': ('competition-01/native-01/compact2-positive/validation-case.json',
        'ae757a390a0a630e1b0678335536580cf9f82a5f10bdfe790503b0216252fc06',
        'dcedc25f71b4c5cc9ce54e873182c56f27565a2de1a5786b3e169fe633633e1b'),
    'alternative': ('competition-01/native-01/wide32-positive/validation-case.json',
        'c96a4eb95480839ae5446993b683ffd596f1d91954ae1b55f90169435dcdf2ed',
        '70c75323bd00cc758b21a83960f23331dcceff9b44c29b1ccd24751e251d88e7'),
    'occupied': ('competition-01/finish-01/genuine-current-compact-after-REVEAL-NF-duplicate/validation-case.json',
        'ab39c204efb45952d17896882fc07d197edc2893eb91807197ec0ccabaa321a6',
        '7ca826ff75a09a10b42cddd4d6c1a3e616692f906fafbf317683eb495b67d21c'),
    'stale-compact': ('competition-01/native-01/old-compact2-proof-rebased-after-wide32-STALE-AUTH/validation-case.json',
        '153c7005769793b7562a5506f48e22a4cfd677431924c46065dbda6539d3e270',
        '21e351665adceeca3a9cec09b4412d0b625c1ad9555bff1bbdeb11433e98973d'),
    'stale-wide': ('competition-01/native-01/old-wide32-proof-rebased-after-compact2-STALE-AUTH/validation-case.json',
        '59533c72b61c51e10f2c2f912b1810c20a51db9ffe038b990c02649fd9b63916',
        '16fad33c1fd8341778075fc2827f51ed7e11572d964f299dfb806fbda04bd8c6'),
}


def fixture(name='wide'):
    path, expected, _ = FIXTURES[name]
    raw = (LIFECYCLE / path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise RuntimeError('selected-public-fixture-changed')
    return json.loads(raw)


class WireControls(unittest.TestCase):
    def test_actual_v1_ids_match_all_selected_public_bodies(self):
        for name, (_, _, expected) in FIXTURES.items():
            with self.subTest(name=name):
                body, entry = validate_case(fixture(name))
                self.assertEqual(transaction_id(body, entry), expected)

    def test_v1_excludes_signature_mass_budget_and_cached_id(self):
        original, entry = validate_case(fixture())
        expected = FIXTURES['wide'][2]
        for field in ('signature', 'mass', 'budget', 'cached-id'):
            body = copy.deepcopy(original)
            if field == 'signature':
                body['inputs'][0]['signatureScript'] = ''
            elif field == 'mass':
                body['mass'] = (1 << 64) - 1
            elif field == 'budget':
                body['inputs'][0]['computeBudget'] = 65535
            else:
                body['id'] = '11' * 32
            with self.subTest(field=field):
                self.assertEqual(transaction_id(body, entry), expected)

    def test_v1_includes_payload_outpoint_sequence_and_outputs(self):
        original, entry = validate_case(fixture())
        expected = FIXTURES['wide'][2]
        for field in ('payload', 'previous-id', 'previous-index', 'sequence', 'output-value', 'output-SPK'):
            body = copy.deepcopy(original)
            if field == 'payload':
                raw = bytearray.fromhex(body['payload'])
                raw[0] ^= 1
                body['payload'] = raw.hex()
            elif field == 'previous-id':
                body['inputs'][0]['previousOutpoint']['transactionId'] = '22' * 32
            elif field == 'previous-index':
                body['inputs'][0]['previousOutpoint']['index'] = 1
            elif field == 'sequence':
                body['inputs'][0]['sequence'] -= 1
            elif field == 'output-value':
                body['outputs'][0]['value'] -= 1
            else:
                raw = bytearray.fromhex(body['outputs'][0]['scriptPublicKey'])
                raw[-2] ^= 1
                body['outputs'][0]['scriptPublicKey'] = raw.hex()
            with self.subTest(field=field):
                self.assertNotEqual(transaction_id(body, entry), expected)

    def test_p2sh_matches_current_and_successor_public_outputs(self):
        for name in ('wide', 'compact', 'alternative'):
            body, entry = validate_case(fixture(name))
            redeem = hexbytes(body['inputs'][0]['signatureScript'])[199:]
            auth = hexbytes(body['payload'])[:528]
            self.assertEqual(p2sh(redeem), entry['scriptPublicKey'])
            successor = redeem[:2] + auth[364:476] + redeem[114:]
            self.assertEqual(p2sh(successor), body['outputs'][0]['scriptPublicKey'])

    def test_canonical_types_hex_fields_and_context_reject(self):
        for field in ('bool-version', 'bool-mass', 'float-locktime', 'amount-string',
                      'coinbase', 'covenant', 'context-extra', 'body-extra',
                      'uppercase', 'oddhex', 'negative-index', 'index-overflow',
                      'zero-output', 'too-large-output'):
            case = fixture()
            body, entry = case['transaction'], case['entries'][0]
            if field == 'bool-version': body['version'] = True
            elif field == 'bool-mass': body['mass'] = False
            elif field == 'float-locktime': body['lockTime'] = 0.0
            elif field == 'amount-string': entry['amount'] = str(entry['amount'])
            elif field == 'coinbase': entry['isCoinbase'] = True
            elif field == 'covenant': entry['covenantId'] = '00' * 32
            elif field == 'context-extra': entry['extra'] = 0
            elif field == 'body-extra': body['extra'] = 0
            elif field == 'uppercase': body['payload'] = body['payload'].upper()
            elif field == 'oddhex': body['payload'] += '0'
            elif field == 'negative-index': body['inputs'][0]['previousOutpoint']['index'] = -1
            elif field == 'index-overflow': body['inputs'][0]['previousOutpoint']['index'] = 1 << 32
            elif field == 'zero-output': body['outputs'][0]['value'] = 0
            else: body['outputs'][0]['value'] = MAX + 1
            with self.subTest(field=field), self.assertRaises(Invalid):
                validate_case(case)
        for value in (True, -1, 256, 1.0):
            with self.assertRaises(Invalid):
                uint(value, 8)
        for value in ('AB', '0', 'gg', b'00'):
            with self.assertRaises(Invalid):
                hexbytes(value)

    def test_parser_does_not_confuse_profile_with_semantics(self):
        for budget in (0, 1600, 65535):
            case = fixture()
            case['transaction']['inputs'][0]['computeBudget'] = budget
            case['transaction']['inputs'][0]['signatureScript'] = '00'
            case['entries'][0]['blockDaaScore'] = 1
            validate_case(case)

    def test_storage_matches_selected_normalized_bodies_and_integer_floor(self):
        for name in FIXTURES:
            body, entry = validate_case(fixture(name))
            self.assertEqual(storage_mass(body, entry), body['mass'])
        case = fixture()
        body, entry = validate_case(case)
        script = body['outputs'][0]['scriptPublicKey']
        body['outputs'] = [{'value': value, 'scriptPublicKey': script, 'covenant': None}
                           for value in (60_000_000, 100_000_000)]
        entry['amount'] = 1_000_000_000
        self.assertEqual(storage_mass(body, entry), 25_666)
        # This second shape has nonzero floor-sensitive storage; compare with
        # the real upstream normalizer, which does not execute ScriptEngine.
        adapter = ROOT / 'poc/shared-settlement-verifier'
        if str(adapter) not in sys.path:
            sys.path.insert(0, str(adapter))
        import public_native
        result = public_native.normalize(case)
        self.assertIs(result['native_VM_executed'], False)
        self.assertEqual(result['transaction']['mass'], 25_666)
        self.assertEqual(result['metrics']['storage_mass'], 25_666)

    def test_storage_saturates_and_refuses_larger_plurality(self):
        body, entry = validate_case(fixture())
        entry['amount'] = 1
        self.assertEqual(storage_mass(body, entry), 0)
        entry['amount'] = MAX
        body['outputs'][0]['value'] = 1
        self.assertEqual(storage_mass(body, entry), 1_000_000_000_000)
        for where in ('input', 'output'):
            b, e = copy.deepcopy((body, entry))
            target = e if where == 'input' else b['outputs'][0]
            target['scriptPublicKey'] = '0000' + '00' * 38
            with self.subTest(where=where), self.assertRaises(Invalid) as caught:
                storage_mass(b, e)
            self.assertEqual(caught.exception.code, 'unsupported-storage-plurality')


if __name__ == '__main__':
    unittest.main()
