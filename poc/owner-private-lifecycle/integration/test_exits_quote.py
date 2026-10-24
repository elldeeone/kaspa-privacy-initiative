"""New empty-result and exact final-fee boundary controls."""
from copy import deepcopy
import unittest
from construction.codec import canonical_json
from exits import ready_export, read_context
from public import DOMAIN
from quote import exact_final
from test_history import fixture


class ExitBoundaryTests(unittest.TestCase):
    def test_only_authenticated_empty_result_is_empty(self):
        value = {'schema': 'kpx8-owner-no-unspent-claim/v1', 'participant_id_hex32': '11' * 32,
                 'history_sha256': '22' * 32, 'empty': True}
        self.assertTrue(ready_export(canonical_json(value), 'exit-ready', '11' * 32, '22' * 32)['empty'])
        for changed in (dict(value, empty=False), dict(value, empty=1),
                        dict(value, history_sha256='33' * 32), dict(value, nf_hex32='44' * 32)):
            with self.assertRaises(ValueError):
                ready_export(canonical_json(changed), 'exit-ready', '11' * 32, '22' * 32)

    def test_exit_ready_rejects_private_CM_position_and_noninteger_gross(self):
        value = {'schema': 'kpx8-owner-exit-ready/v1', 'domain_hex32': DOMAIN.hex(),
                 'participant_id_hex32': '11' * 32, 'history_sha256': '22' * 32,
                 'nf_hex32': '33' * 32, 'gross_claim_sompi': 100_000_000,
                 'payout_spk_hex36': '000020' + '44' * 32 + 'ac', 'financial_authorization': False}
        ready_export(canonical_json(value), 'exit-ready', '11' * 32, '22' * 32)
        for changed in (dict(value, input_cm_hex32='55' * 32), dict(value, position=4),
                        dict(value, gross_claim_sompi=True), dict(value, gross_claim_sompi=-1)):
            with self.assertRaises(ValueError):
                ready_export(canonical_json(changed), 'exit-ready', '11' * 32, '22' * 32)

    def test_exact_final_quote_refuses_wrong_fee_mass_and_boolean(self):
        exact_final({'metrics': {'actual_fee_sompi': 100_000, 'mining_mass': 1000}}, 100_000)
        for metrics in ({'actual_fee_sompi': 100_001, 'mining_mass': 1000},
                        {'actual_fee_sompi': 100_000, 'mining_mass': 1001},
                        {'actual_fee_sompi': 100, 'mining_mass': True}):
            with self.assertRaises(ValueError):
                exact_final({'metrics': metrics}, metrics['actual_fee_sompi'])


if __name__ == '__main__':
    unittest.main()
