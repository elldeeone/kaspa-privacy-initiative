"""New-profile public mining-observation boundaries; no keys or network."""
import copy
import unittest

import funding_worker
import genesis
import wallet_profile as wallet

TRIAL = '00000000-0000-4000-8000-000000000002'
SCRIPT = '000020' + '12' * 32 + 'ac'


def observation():
    chain, pool, profile, domain, service = (part.hex() for part in genesis.EXPECTED_IDENTITY)
    return {'schema': 'kpb-own-mature-coinbase-observation/v1', 'network_id': 'testnet-10',
        'genesis_hash_hex': chain, 'domain_hex32': domain, 'profile_id_hex32': profile,
        'pool_lineage_hex32': pool, 'service_policy_hex32': service, 'trial_id': TRIAL,
        'owner_component': 0, 'funding_script_public_key': SCRIPT, 'virtual_daa_score': '2000',
        'sources': [{'outpoint': {'transactionId': '34' * 32, 'index': 0},
            'entry': {'amount': '3100000000', 'scriptPublicKey': SCRIPT, 'blockDaaScore': '1000',
                      'isCoinbase': True, 'covenantId': None}}]}


def convert(value):
    return funding_worker.mature_sources(value, genesis.EXPECTED_IDENTITY, TRIAL, 0, SCRIPT)


class FundingBoundaryControls(unittest.TestCase):
    def test_exact_maturity_boundary_and_one_integer_conversion(self):
        rows, total = convert(observation())
        self.assertEqual(total, 3_100_000_000)
        self.assertIs(type(rows[0]['entry']['amount']), int)
        self.assertIs(type(rows[0]['entry']['blockDaaScore']), int)
        self.assertIs(type(observation()['sources'][0]['entry']['amount']), str)

    def test_immature_and_legacy_profile_refuse(self):
        value = observation(); value['virtual_daa_score'] = '1999'
        with self.assertRaises(wallet.Invalid): convert(value)
        for key, item in (('schema', 'kpxa-own-mature-coinbase-observation/v1'),
                          ('domain_hex32', 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'),
                          ('network_id', 'mainnet'), ('pool_lineage_hex32', '00' * 32),
                          ('profile_id_hex32', '00' * 32), ('service_policy_hex32', '00' * 32),
                          ('owner_component', True)):
            changed = observation(); changed[key] = item
            with self.subTest(key=key), self.assertRaises(wallet.Invalid): convert(changed)

    def test_RPC_amount_aliases_reject_at_boundary(self):
        for value in (3_100_000_000, True, '03100000000', '+3100000000', '3.1e9', '-1'):
            changed = observation(); changed['sources'][0]['entry']['amount'] = value
            with self.subTest(value=value), self.assertRaises(wallet.Invalid): convert(changed)

    def test_foreign_script_duplicate_source_and_ordinary_flags_refuse(self):
        for mode in ('foreign', 'duplicate', 'not-coinbase', 'covenant', 'extra-field'):
            changed = observation()
            if mode == 'foreign': changed['sources'][0]['entry']['scriptPublicKey'] = '000020' + '99' * 32 + 'ac'
            if mode == 'duplicate': changed['sources'].append(copy.deepcopy(changed['sources'][0]))
            if mode == 'not-coinbase': changed['sources'][0]['entry']['isCoinbase'] = False
            if mode == 'covenant': changed['sources'][0]['entry']['covenantId'] = '00' * 32
            if mode == 'extra-field': changed['accepted'] = True
            with self.subTest(mode=mode), self.assertRaises(wallet.Invalid): convert(changed)


if __name__ == '__main__':
    unittest.main()
