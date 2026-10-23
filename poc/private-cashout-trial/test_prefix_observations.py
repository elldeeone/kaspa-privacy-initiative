"""Public acceptance/context substitution controls; never execute native or RPC."""
import copy
import json
import unittest

import prefix_observations as packet


class PrefixObservationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.exporter = packet.funding.base_exporter()
        cls.values = []
        for index, (name, txid, body_sha, daa, fee) in enumerate(packet.STAGES):
            raw = cls.exporter.safe_file(packet.SOURCE, name + '-confirmed-observation.json').read_bytes()
            body = json.loads(cls.exporter.safe_file(packet.CLOSED, f'case-{index:04d}/transaction.json').read_bytes())
            context = json.loads(cls.exporter.safe_file(packet.CLOSED, f'case-{index:04d}/supplied-context.json').read_bytes())[0]
            cls.values.append((json.loads(raw), body, context, daa, txid))

    def check(self, value):
        return packet.checked(value, *self.values[1][1:], self.exporter)

    def test_both_actual_public_prefixes(self):
        for value in self.values:
            plain = packet.checked(*value, self.exporter)
            self.assertNotIn('post_query_related_spend_check', plain)

    def test_stale_post_query_rejected(self):
        changed = copy.deepcopy(self.values[1][0])
        changed['post_query_related_spend_check'] = False
        with self.assertRaisesRegex(ValueError, 'post-query-related-spend-required'):
            self.check(changed)

    def test_wrong_actual_daa_rejected(self):
        changed = copy.deepcopy(self.values[1][0])
        changed['accepted_input_contexts'][0]['block_daa_score'] = '1'
        with self.assertRaisesRegex(ValueError, 'actual-prefix-input-context'):
            self.check(changed)

    def test_wrong_output_query_rejected(self):
        changed = copy.deepcopy(self.values[1][0])
        changed['current_outputs'][0]['utxo']['amount_sompi'] = '1'
        with self.assertRaisesRegex(ValueError, 'prefix-output-unspent-at-its-observation'):
            self.check(changed)


if __name__ == '__main__':
    unittest.main()
