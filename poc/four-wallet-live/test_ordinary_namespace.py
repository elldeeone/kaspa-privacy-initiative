"""Synthetic identity/intent namespace regression; no backup or network IO."""
import copy
import unittest
from ordinary_funding import check_namespace


class Namespace(unittest.TestCase):
    def test_other_original_trial_cannot_reserve_same_selected_identity(self):
        profile = {'financial_profile_id': '11111111-1111-4111-8111-111111111111',
            'child_domain_hex32': '11' * 32, 'network_id': 'testnet-10',
            'genesis_hash_hex': '22' * 32}
        receipt = {'trial_id': '33333333-3333-4333-8333-333333333333',
            'financial_profile_id': profile['financial_profile_id'], 'domain_hex32': '11' * 32,
            'constructor_source_sha256': '44' * 32, 'profile_identity_sha256': '55' * 32}
        trial = {'schema': 'kpx6-four-wallet-trial/v1', 'trial_id': receipt['trial_id'],
            'financial_profile_id': profile['financial_profile_id'], 'domain_hex32': '11' * 32,
            'network_id': 'testnet-10', 'genesis_hash_hex': '22' * 32,
            'constructor_source_sha256': '44' * 32, 'profile_identity_sha256': '55' * 32}
        check_namespace(trial, profile, receipt)
        for key, replacement in [('trial_id', '66666666-6666-4666-8666-666666666666'),
                ('financial_profile_id', '77777777-7777-4777-8777-777777777777'),
                ('domain_hex32', '88' * 32), ('network_id', 'mainnet'),
                ('constructor_source_sha256', '99' * 32), ('profile_identity_sha256', 'aa' * 32)]:
            wrong = copy.deepcopy(trial); wrong[key] = replacement
            with self.assertRaises(ValueError):
                check_namespace(wrong, profile, receipt)


if __name__ == '__main__':
    unittest.main()
