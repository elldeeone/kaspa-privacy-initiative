"""Retained no-funds control for the selected sealed-box byte layout."""

import json
import unittest

import selected_crypto_box_layout_control as control


class SelectedCryptoBoxLayoutControl(unittest.TestCase):
    def test_selected_binary_uses_prefix_poly1305_tag(self):
        receipt = control.run_control()
        self.assertEqual(set(receipt), {
            'schema',
            'selected_binary_sha256',
            'libsodium_version',
            'fixed_test_secret_sha256',
            'fixed_test_plaintext_sha256',
            'fixed_test_recipient_public_hex',
            'retained_vector_bytes',
            'retained_vector_sha256',
            'retained_vector_prefix_tag_opened',
            'retained_vector_reordered_tag_refused',
            'fresh_vector_bytes',
            'fresh_vector_sha256',
            'fresh_vector_prefix_tag_opened',
            'fresh_vector_reordered_tag_refused',
            'production_secret_material_used',
            'privacy_claim',
        })
        self.assertEqual(
            receipt['schema'], 'kpb-selected-crypto-box-layout-control/v1')
        self.assertEqual(
            receipt['selected_binary_sha256'],
            '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff')
        self.assertEqual(receipt['libsodium_version'], '1.0.18')
        self.assertEqual(
            receipt['fixed_test_secret_sha256'],
            'ae216c2ef5247a3782c135efa279a3e4cdc61094270f5d2be58c6204b7a612c9')
        self.assertEqual(
            receipt['fixed_test_plaintext_sha256'],
            '4b6bdc1d08475896bbb71750e2f7849c2305eef637adaa2772960692555578ad')
        self.assertEqual(
            receipt['fixed_test_recipient_public_hex'],
            '07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c')
        self.assertEqual(receipt['retained_vector_bytes'], 264)
        self.assertEqual(
            receipt['retained_vector_sha256'],
            '49bdb288a0d09f8e1ab044f486c8209fa7f2f9f70885256323af7303e13059c6')
        self.assertTrue(receipt['retained_vector_prefix_tag_opened'])
        self.assertTrue(receipt['retained_vector_reordered_tag_refused'])
        self.assertEqual(receipt['fresh_vector_bytes'], 264)
        self.assertRegex(receipt['fresh_vector_sha256'], r'^[0-9a-f]{64}$')
        self.assertTrue(receipt['fresh_vector_prefix_tag_opened'])
        self.assertTrue(receipt['fresh_vector_reordered_tag_refused'])
        self.assertFalse(receipt['production_secret_material_used'])
        self.assertFalse(receipt['privacy_claim'])

        # The command interface is canonical JSON so its evidence can be
        # retained without exposing the synthetic secret or plaintext.
        encoded = control.encode_receipt(receipt)
        self.assertEqual(json.loads(encoded), receipt)
        self.assertEqual(encoded, json.dumps(
            receipt, sort_keys=True, separators=(',', ':')) + '\n')


if __name__ == '__main__':
    unittest.main()
