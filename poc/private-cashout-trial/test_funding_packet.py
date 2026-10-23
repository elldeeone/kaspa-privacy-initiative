"""Read-only public observation substitution controls; no network/native/proofs."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('funding_packet', Path(__file__).with_name('funding_packet.py'))
packet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packet)


class PublicFundingControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.exporter = packet.base_exporter()
        cls.body = json.loads(cls.exporter.safe_file(packet.SOURCE, 'transaction.json').read_bytes())
        cls.contexts = json.loads(cls.exporter.safe_file(packet.SOURCE, 'local-check.json').read_bytes())['inputs']
        cls.raw = cls.exporter.safe_file(packet.SOURCE, 'confirmed-observation-01.json').read_bytes()
        cls.observation = json.loads(cls.raw)

    def check(self, observation):
        return packet.checked_observation(observation, self.body, self.contexts,
            hashlib.sha256(self.raw).hexdigest(), len(self.raw), self.exporter)

    def test_exact_public_observation(self):
        selected = self.check(self.observation)
        self.assertNotIn('pages', selected)
        records = selected['public_extraction']['selected_acceptance_records']
        self.assertTrue(records)
        self.assertTrue(all(self.exporter.canonical_full_record(tx) == selected['accepted_body']
            for group in records for tx in group['acceptedTransactions']))

    def test_same_id_wrong_body(self):
        changed = copy.deepcopy(self.observation)
        changed['accepted_body']['outputs'][0]['value'] = '1'
        with self.assertRaisesRegex(ValueError, 'exact-observed-body'):
            self.check(changed)

    def test_wrong_accepted_context(self):
        changed = copy.deepcopy(self.observation)
        changed['accepted_input_contexts'][0]['amount_sompi'] = '1'
        with self.assertRaisesRegex(ValueError, 'accepted-input-context-binding'):
            self.check(changed)

    def test_wrong_spent_query_script(self):
        changed = copy.deepcopy(self.observation)
        changed['spent_inputs'][0]['script_public_key'] = packet.DESTINATION
        with self.assertRaisesRegex(ValueError, 'spent-query-script-binding'):
            self.check(changed)

    def test_acceptance_record_wrong_body(self):
        changed = copy.deepcopy(self.observation)
        for page in changed['pages']:
            for group in page['response']['chainBlockAcceptedTransactions']:
                for tx in group['acceptedTransactions']:
                    if tx.get('verboseData', {}).get('transactionId', tx.get('id')) == packet.TXID:
                        tx['outputs'][0]['value'] = '1'
        with self.assertRaisesRegex(ValueError, 'selected-acceptance-body'):
            self.check(changed)

    def test_paired_header_identity(self):
        changed = copy.deepcopy(self.observation)
        changed['pages'][0]['response']['addedChainBlockHashes'][0] = '00' * 32
        with self.assertRaisesRegex(ValueError, 'page-header-identity'):
            self.check(changed)


if __name__ == '__main__':
    unittest.main()
