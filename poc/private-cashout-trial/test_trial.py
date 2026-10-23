"""Public source/guard controls. Never create a trial identity or execute crypto."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import trial


class ConstructorGuards(unittest.TestCase):
    def test_frozen_authorities_match(self):
        self.assertEqual(trial.selected_adr(), trial.SELECTED_ADR_SHA256)

    def test_unselected_adr_precedes_entropy(self):
        with patch.object(trial, 'SELECTED_ADR_SHA256', None), \
             patch.object(trial.secrets, 'token_bytes', side_effect=AssertionError('entropy')):
            with self.assertRaisesRegex(ValueError, 'before-entropy'):
                trial.new(Path('/never-created-private-cashout-test'))

    def test_used_directory_precedes_entropy(self):
        with tempfile.TemporaryDirectory(prefix='kpx3-public-guard-') as directory, \
             patch.object(trial.secrets, 'token_bytes', side_effect=AssertionError('entropy')):
            with self.assertRaisesRegex(ValueError, 'fresh-private-destination'):
                trial.new(Path(directory))

    def test_git_parent_alias_and_lexical_symlink_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'inside-git'):
            trial.outside_git(trial.ROOT / '..' / trial.ROOT.name / 'uncreated')
        with tempfile.TemporaryDirectory(prefix='kpx3-public-path-') as directory:
            directory = Path(directory)
            (directory / 'link').symlink_to(directory, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                trial.outside_git(directory / 'link' / '..' / 'uncreated')

    def test_domain_recipe_is_exact_public_known_answer(self):
        nonce = bytes([0x11]) * 32  # PUBLIC_SYNTHETIC_DO_NOT_FUND, no identity.
        expected = hashlib.sha256(b'KPX3/TN10/PRIVATE-RECOVERY/v1\0'
            + bytes.fromhex(trial.GENESIS) + nonce).hexdigest()
        self.assertEqual(trial.domain(nonce), expected)
        self.assertNotIn(expected, (trial.AA_DOMAIN, trial.OLD_DOMAIN))
        with self.assertRaises(ValueError):
            trial.domain(bytes(31))

    def test_duplicate_json_and_unselected_template_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate-json'):
            trial.parse_json('{"a":1,"a":2}')
        with patch.object(trial, 'SELECTED_TEMPLATE_FREEZE_SHA256', None):
            with self.assertRaisesRegex(ValueError, 'source-selection-required'):
                trial.source_provenance()

    def test_domain_substitution_is_one_exact_array_only(self):
        raw = ('prefix\npub const DOMAIN: [u8; 32] = [\n    '
               + ', '.join('0x'+trial.AA_DOMAIN[i:i+2] for i in range(0,64,2))
               + ',\n];\nsuffix\n').encode()
        generated = trial.replace_domain(raw, bytes([0x42])*32)
        self.assertTrue(generated.startswith(b'prefix\n'))
        self.assertTrue(generated.endswith(b'\nsuffix\n'))
        self.assertEqual(generated.count(b'0x42'), 32)
        for malformed in (raw+raw, raw.replace(b'0xaa', b'0xab', 1)):
            with self.assertRaises(ValueError):
                trial.replace_domain(malformed, bytes([0x42])*32)


if __name__ == '__main__':
    unittest.main()
