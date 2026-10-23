"""Public extraction controls; synthetic RPC rows and retained public bodies."""
import json
from pathlib import Path
import tempfile
import unittest

import export_public as publication


def observation():
    txid = 'ab' * 32
    own = {'version': 1, 'verboseData': {'transactionId': txid},
        'inputs': [{'previousOutpoint': {'transactionId': '56' * 32, 'index': 0},
                    'signatureScript': '', 'sequence': '0', 'computeBudget': 10}],
        'outputs': [{'value': '100000000', 'scriptPublicKey': {'version': 0,
                    'script': '20' + '11' * 32 + 'ac'}}],
        'lockTime': '0', 'subnetworkId': '00' * 20, 'gas': '0', 'payload': '4142', 'mass': '0'}
    other = {'verboseData': {'transactionId': 'cd' * 32}, 'payload': 'UNRELATED_PAYLOAD_MUST_NOT_LEAK'}
    value = {key: None for key in publication.OBSERVATION_FIELDS}
    value.update({'transaction_id': txid, 'accepted_body': publication.canonical_full_record(own),
        'accepting_block_header': {'hash': '34' * 32},
        'network': 'testnet-10', 'confirmation_policy': {'passes': True,
        'actual_blue_score_distance': '21', 'min_confirmation_count': 20},
        'chain_delta_removed': [], 'spent_inputs': [{'queried': True, 'unspent': False}],
        'pages': [{'start_hash': '12' * 32, 'response': {'removedChainBlockHashes': [],
            'addedChainBlockHashes': ['34' * 32], 'chainBlockAcceptedTransactions': [{
                'chainBlockHeader': {'hash': '34' * 32, 'parentsByLevel': {}},
                'acceptedTransactions': [own, other]}]}}]})
    return value


class PublicExportTests(unittest.TestCase):
    def test_only_selected_accepted_records_are_published(self):
        value = observation()
        result = publication.sanitize_observation(value, 'ef' * 32, 12345)
        encoded = json.dumps(result)
        self.assertNotIn('UNRELATED_PAYLOAD_MUST_NOT_LEAK', encoded)
        self.assertNotIn('pages', result)
        metadata = result['public_extraction']
        self.assertEqual(metadata['original_file_sha256'], 'ef' * 32)
        self.assertEqual(len(metadata['selected_acceptance_records'][0]['acceptedTransactions']), 1)
        self.assertEqual(metadata['original_page_summaries'][0]['accepted_transaction_records'], 2)
        self.assertFalse(metadata['headers_independently_rehashed_by_this_extractor'])

    def test_missing_selected_record_and_removed_prefix_rejected(self):
        for mutate in ('missing', 'removed'):
            value = observation()
            response = value['pages'][0]['response']
            if mutate == 'missing':
                response['chainBlockAcceptedTransactions'][0]['acceptedTransactions'] = []
            else:
                response['removedChainBlockHashes'] = ['56' * 32]
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                publication.sanitize_observation(value, 'ef' * 32, 12345)

    def test_insufficient_depth_rejected(self):
        value = observation()
        value['confirmation_policy']['actual_blue_score_distance'] = '20'
        with self.assertRaisesRegex(ValueError, 'confirmation-depth'):
            publication.sanitize_observation(value, 'ef' * 32, 12345)

    def test_same_id_wrong_selected_body_rejected(self):
        value = observation()
        selected = value['pages'][0]['response']['chainBlockAcceptedTransactions'][0]['acceptedTransactions'][0]
        selected['outputs'][0]['value'] = '100000001'
        with self.assertRaisesRegex(ValueError, 'selected-acceptance-body'):
            publication.sanitize_observation(value, 'ef' * 32, 12345)

    def test_paired_added_block_hash_mismatch_rejected(self):
        value = observation()
        value['pages'][0]['response']['addedChainBlockHashes'][0] = '99' * 32
        with self.assertRaisesRegex(ValueError, 'page-header-identity'):
            publication.sanitize_observation(value, 'ef' * 32, 12345)

    def test_private_fields_and_unexpected_observation_fields_rejected(self):
        with self.assertRaisesRegex(ValueError, 'private-key-field-rejected'):
            publication.public_json({'nested': [{'seed_hex32': 'PUBLIC_SYNTHETIC_MARKER'}]})
        value = observation()
        value['unexpected'] = 'not allowlisted'
        with self.assertRaisesRegex(ValueError, 'observation-fields'):
            publication.sanitize_observation(value, 'ef' * 32, 12345)

    def test_private_path_escape_symlink_and_output_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'public.json').write_text('{}')
            (root / 'linked.json').symlink_to(root / 'public.json')
            with self.assertRaisesRegex(ValueError, 'relative-public-path'):
                publication.safe_file(root, '../backups/bob.json')
            with self.assertRaisesRegex(ValueError, 'symlink-rejected'):
                publication.safe_file(root, 'linked.json')
            with self.assertRaisesRegex(ValueError, 'public-output-must-not-be-in-private-trial'):
                publication.Packet(root, root / 'public-export')

    def test_established_native_conversion_matches_public_sdk_roundtrip(self):
        public = publication.ROOT / 'research/next-session/privacy-recovery/live/readiness-02/prefix/fundingprep'
        native = json.loads((public / 'transaction.json').read_bytes())
        expected = json.loads((public / 'sdk-roundtrip.json').read_bytes())['transaction']
        self.assertEqual(publication.canonical_body(native), expected)


if __name__ == '__main__':
    unittest.main()
