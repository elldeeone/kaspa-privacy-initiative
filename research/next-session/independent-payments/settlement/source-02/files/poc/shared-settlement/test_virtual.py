"""ADR59 codec tests; synthetic emitter is NOT a financial/native policy."""
import copy
import sys
import unittest

from fixtures import ROOT, given_head, install
from policy import public_material
from virtual import (InstalledProfile, check_outer, decode_journal, decode_payload, encode_journal,
                     encode_payload, financial_projection, outer_case)
from wire import Invalid, h, transaction_id


class VirtualCodecControls(unittest.TestCase):
    def setUp(self):
        child, self.cases = install()
        # Public byte codec only: this dummy script is not represented as a
        # spendable/reviewed wrapper and no VM executes it.
        self.profile = InstalledProfile(b'w' * 32, child,
            lambda state: b'\x4c\x70' + state + b'\x75' + b'PUBLIC-CODEC-ONLY' * 20)
        base = self.cases['compact']
        auth, proof = public_material(base)
        self.records = (bytes.fromhex(base['transaction']['payload']) + proof,) * 2
        self.head = given_head(base)
        self.case = outer_case(self.profile, self.head, self.records)
        self.final_state = auth[364:476]
        self.final_reserve = int.from_bytes(auth[476:484], 'little')

    def journal(self, case=None):
        return encode_journal(self.profile.wrapper_domain, self.profile.child.domain, self.head.point(),
            self.head.state, self.head.reserve, self.final_state, self.final_reserve,
            self.head.reserve - self.final_reserve, self.records, financial_projection(case or self.case))

    def test_exact_payload_and_journal_layout(self):
        payload = encode_payload(self.records)
        self.assertEqual(len(payload), 8108)
        self.assertEqual(decode_payload(payload), self.records)
        journal = self.journal()
        decoded = decode_journal(journal)
        self.assertEqual(len(journal), 424)
        self.assertEqual(decoded['point'], self.head.point())
        self.assertEqual(decoded['reserve'], self.head.reserve)
        self.assertEqual(decoded['next_state'], self.final_state)
        self.assertEqual(decoded['records_sha256'], h(b''.join(self.records)))
        self.assertEqual(decoded['financial_projection_sha256'], h(financial_projection(self.case)))

    def test_no_journal_or_outer_proof_self_reference(self):
        original_id = self.case['transaction']['id']
        changed = copy.deepcopy(self.case)
        frame = bytearray.fromhex(changed['transaction']['inputs'][0]['signatureScript'])
        frame[68:196] = h(self.journal()) + bytes(96)
        changed['transaction']['inputs'][0]['signatureScript'] = frame.hex()
        self.assertEqual(self.journal(changed), self.journal())
        self.assertEqual(transaction_id(changed['transaction'], changed['entries'][0]), original_id)
        self.assertNotIn(self.journal(), bytes.fromhex(changed['transaction']['payload']))

    def test_inner_proof_bytes_are_payload_and_ID_bound(self):
        changed = copy.deepcopy(self.case)
        payload = bytearray.fromhex(changed['transaction']['payload'])
        payload[12 + 3920] ^= 1
        changed['transaction']['payload'] = payload.hex()
        self.assertNotEqual(financial_projection(changed), financial_projection(self.case))
        self.assertNotEqual(transaction_id(changed['transaction'], changed['entries'][0]),
                            self.case['transaction']['id'])

    def test_budget_mass_and_ID_exclusions_are_explicit(self):
        for key in ('id', 'mass', 'computeBudget'):
            changed = copy.deepcopy(self.case)
            if key == 'computeBudget': changed['transaction']['inputs'][0][key] += 1
            elif key == 'id': changed['transaction'][key] = '11' * 32
            else: changed['transaction'][key] += 1
            self.assertEqual(financial_projection(changed), financial_projection(self.case))
        # Profile/effect checker, not this byte projection, owns those fields.

    def test_financial_body_fields_are_bound(self):
        for field in ('amount', 'point', 'sequence', 'output', 'inputSPK', 'outputSPK', 'lockTime', 'gas', 'subnet'):
            changed = copy.deepcopy(self.case)
            body, entry = changed['transaction'], changed['entries'][0]
            if field == 'amount': entry['amount'] += 1
            elif field == 'point': body['inputs'][0]['previousOutpoint']['index'] += 1
            elif field == 'sequence': body['inputs'][0]['sequence'] -= 1
            elif field == 'output': body['outputs'][0]['value'] -= 1
            elif field == 'inputSPK': entry['scriptPublicKey'] = '0000aa20' + '11' * 32 + '87'
            elif field == 'outputSPK': body['outputs'][0]['scriptPublicKey'] = '0000aa20' + '11' * 32 + '87'
            elif field == 'subnet': body['subnetworkId'] = '01' * 20
            else: body[field] += 1
            self.assertNotEqual(financial_projection(changed), financial_projection(self.case), field)

    def test_malformed_or_nonconserving_codec_refused(self):
        raw = encode_payload(self.records)
        for bad in (raw[:-1], raw + b'\0', b'INVALID!' + raw[8:], raw[:10] + b'\x03\0' + raw[12:]):
            with self.assertRaises(Invalid): decode_payload(bad)
        with self.assertRaises(Invalid): encode_payload(self.records[:1])
        journal = bytearray(self.journal()); journal[352] ^= 1
        with self.assertRaises(Invalid): decode_journal(bytes(journal))

    def test_two_repeated_genuine_actions_do_not_become_a_settlement(self):
        sys.path.insert(0, str(ROOT / 'poc/shared-settlement-verifier'))
        from public_g16 import verify
        with self.assertRaisesRegex(Invalid, 'child_1_proof_public_or_profile_invalid'):
            check_outer(self.profile, self.case, self.head, verify)


if __name__ == '__main__':
    unittest.main()
