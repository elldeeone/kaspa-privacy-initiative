"""Public synthetic policy controls; no runtime, SDK, network or backup access."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import types
import unittest

import ordinary_common as c


class Policy(unittest.TestCase):
    def setUp(self):
        self.chosen = {'trial_id': '11111111-1111-4111-8111-111111111111',
            'identity_sha256': 'aa' * 32, 'wallets': {
                role: {'script_public_key': '000020' + key * 32 + 'ac'}
                for role, key in [('A', '11'), ('C', '22')]}}
        self.obs = {'schema': 'kpx6-ordinary-mined-funding-observation/v1', 'network_id': c.NET,
            'genesis_hash_hex': c.GENESIS, 'financial_profile_sha256': c.PROFILE_SHA,
            'funding_identity_sha256': 'aa' * 32, 'trial_id': self.chosen['trial_id'],
            'virtual_daa_score': '2000', 'sources': [
                {'outpoint': {'transactionId': f'{i:064x}', 'index': 0}, 'entry': {
                    'amount_sompi': '1500000000', 'script_public_key': self.chosen['wallets']['A']['script_public_key'],
                    'block_daa_score': '1000', 'is_coinbase': True, 'covenant_id': None}}
                for i in (1, 2, 3)]}
        self.points, self.entries, self.daa = c.observation(self.obs, self.chosen)
        self.case = c.draft(self.points, self.entries, self.chosen, 100000)

    def refuses(self, change):
        value = copy.deepcopy(self.case); change(value)
        with self.assertRaises(ValueError):
            c.validate_case(value, self.chosen, self.daa, 1000)

    def test_exact_targets_refund_fee_and_lossless_boundary(self):
        self.assertEqual(c.validate_case(self.case, self.chosen, self.daa, 1000), 100000)
        self.assertEqual([r['value'] for r in self.case['transaction']['outputs']],
                         [2100000000, 2100000000, 299900000])
        body, contexts = c.sdk_body(self.case)
        self.assertEqual(body['inputs'][0]['sequence'], str(c.U64))
        self.assertIs(contexts[0]['is_coinbase'], True)

    def test_no_arbitrary_destination_or_refund(self):
        for index in range(3):
            self.refuses(lambda v, i=index: v['transaction']['outputs'][i].update(scriptPublicKey='000020' + '33' * 32 + 'ac'))
        self.refuses(lambda v: v['transaction']['outputs'][0].update(value=c.TARGET - 1))

    def test_no_fee_or_value_creation(self):
        self.refuses(lambda v: v['transaction']['outputs'][2].update(value=300000001))
        self.refuses(lambda v: v['transaction']['outputs'][2].update(value=299900001))
        self.refuses(lambda v: v['entries'][0].update(amount=True))

    def test_real_maturity_boundary(self):
        value = copy.deepcopy(self.obs); value['virtual_daa_score'] = '1999'
        with self.assertRaises(ValueError): c.observation(value, self.chosen)
        self.assertEqual(c.observation(self.obs, self.chosen)[2], 2000)

    def test_only_exact_owned_coinbases_without_covenants(self):
        for key, value in [('is_coinbase', False), ('covenant_id', '00' * 32),
                           ('script_public_key', '000020' + '22' * 32 + 'ac')]:
            bad = copy.deepcopy(self.obs); bad['sources'][0]['entry'][key] = value
            with self.assertRaises(ValueError): c.observation(bad, self.chosen)

    def test_duplicates_wrong_identity_and_order_refuse(self):
        for mutate in [lambda v: v['sources'].append(copy.deepcopy(v['sources'][0])),
                       lambda v: v.update(funding_identity_sha256='bb' * 32),
                       lambda v: v['sources'].reverse()]:
            bad = copy.deepcopy(self.obs); mutate(bad)
            with self.assertRaises(ValueError): c.observation(bad, self.chosen)

    def test_fixed_header_budget_and_final_signature_shape(self):
        self.refuses(lambda v: v['transaction'].update(payload='00'))
        self.refuses(lambda v: v['transaction'].update(version=0))
        self.refuses(lambda v: v['transaction']['inputs'][0].update(computeBudget=11))
        with self.assertRaises(ValueError):
            c.validate_case(self.case, self.chosen, self.daa, 1000, signed=True)

    def test_single_immutable_intent(self):
        spec = importlib.util.spec_from_file_location('_ordinary_host_test', Path(__file__).with_name('ordinary_funding.py'))
        host = importlib.util.module_from_spec(spec); spec.loader.exec_module(host)
        def write(path, raw, mode):
            import os
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
            with os.fdopen(fd, 'wb') as output:
                output.write(raw); output.flush(); os.fsync(output.fileno())
        base = types.SimpleNamespace(write_new=write, encoded=c.encoded)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); first = {'case': '11' * 32, 'never_resubmit': True}
            host.reserve(base, root, first)
            before = (root / 'ordinary-funding-intent.json').read_bytes()
            with self.assertRaises(FileExistsError): host.reserve(base, root, {'case': '22' * 32})
            self.assertEqual((root / 'ordinary-funding-intent.json').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
