"""Public descriptor and new-funder guards; no private profile or RPC access."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import live

PUBLIC = live.ROOT / 'research/next-session/testnet-rehearsal/accepted-01'


class LiveTests(unittest.TestCase):
    def setUp(self):
        self.identity = live.load(PUBLIC / 'public/identity.json')
        self.founding = live.load(PUBLIC / 'chain-public/bodies/founding.json')
        self.admit = live.load(PUBLIC / 'chain-public/bodies/admit.json')
        self.vk = (PUBLIC / 'setup/verification-key.bin').read_bytes()
        self.birth = live.load(PUBLIC / 'chain/founding.submission-intent.json')['start_hash']
        self.source = {'source_key': 'TRIAL_FUNDING_KEY', 'oracle_stage': 'LOCAL_SUPPLIED_CONTEXT',
            'transaction_id': 'ab' * 32, 'index': 0, 'amount_sompi': 174_600_300,
            'spk_version': 0, 'spk_hex': self.identity['identities']['funding']['spk_hex']}

    def descriptor(self):
        return live.build_descriptor(self.identity, self.founding, self.admit, self.vk, self.birth)

    def test_public_actual_body_produces_exact_minimal_descriptor(self):
        result = self.descriptor()
        self.assertEqual(set(result), live.replay.DESCRIPTOR_FIELDS)
        self.assertEqual(len(result), 9)
        self.assertEqual(result['founding_outpoint']['transactionId'], self.founding['id'])
        self.assertEqual(live.replay.descriptor_check(result)[0].hex(), self.identity['domain_hex32'])

    def test_wrong_founding_outpoint_is_rejected(self):
        self.founding['id'] = 'ab' * 32
        with self.assertRaises(ValueError):
            self.descriptor()

    def test_wrong_founding_script_is_rejected(self):
        self.founding['outputs'][0]['scriptPublicKey'] = '000020' + 'ab' * 32 + 'ac'
        with self.assertRaises(ValueError):
            self.descriptor()

    def test_non_genesis_state_with_matching_script_is_rejected(self):
        sig = bytearray.fromhex(self.admit['inputs'][0]['signatureScript'])
        sig[199 + 74:199 + 78] = (2).to_bytes(4, 'little')
        self.admit['inputs'][0]['signatureScript'] = sig.hex()
        self.founding['outputs'][0]['scriptPublicKey'] = live.replay.p2sh(bytes(sig[199:]))
        with self.assertRaisesRegex(ValueError, 'descriptor-founding-genesis-state'):
            self.descriptor()

    def test_wrong_genesis_reserve_is_rejected(self):
        self.founding['outputs'][0]['value'] = 60_000_001
        with self.assertRaisesRegex(ValueError, 'descriptor-founding-reserve'):
            self.descriptor()

    def test_wrong_policy_and_vk_are_rejected(self):
        self.vk = bytes(328)
        with self.assertRaises(ValueError):
            self.descriptor()

    def test_wrong_domain_is_rejected(self):
        self.identity['domain_hex32'] = 'ab' * 32
        with self.assertRaises(ValueError):
            self.descriptor()

    def test_old_or_external_key_path_rejected_before_read(self):
        self.source['source_key'] = '/must/not/read/old-secret'
        with self.assertRaisesRegex(ValueError, 'new-trial-funding-key-required'):
            live.checked_source(self.identity, self.source)

    def test_new_identity_funding_destination_required(self):
        self.source['spk_hex'] = '20' + 'ab' * 32 + 'ac'
        with self.assertRaisesRegex(ValueError, 'source-fresh-funding-destination'):
            live.checked_source(self.identity, self.source)

    def test_integer_sompi_not_string_bool_or_float(self):
        for value in ('174600300', True, 174600300.0, -1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                live.checked_source(self.identity, dict(self.source, amount_sompi=value))
        self.assertIs(live.checked_source(self.identity, self.source), self.source)

    def test_used_identity_rejected_before_context_or_source_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'prover-session.json').write_text('{}')
            with patch.object(live.orchestrate, 'Context') as context:
                with self.assertRaisesRegex(ValueError, 'fresh-session-required'):
                    live.rehearse(directory, '/must/not/read/source', 1)
                context.assert_not_called()

    def test_missing_node_rejected_before_context_or_source_reads(self):
        with patch.object(live.shutil, 'which', return_value=None):
            with patch.object(live.orchestrate, 'Context') as context:
                with self.assertRaisesRegex(ValueError, 'node-missing-from-service-path'):
                    live.rehearse('/must/not/read/profile', '/must/not/read/source', 1)
                context.assert_not_called()


if __name__ == '__main__':
    unittest.main()
