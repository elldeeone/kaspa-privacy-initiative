#!/usr/bin/env python3
"""Adversarial controls for the one-command registered trial bootstrap."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


FINANCIAL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FINANCIAL))
import bootstrap_registered_trial as bootstrap  # noqa: E402


class RegisteredTrialBootstrapControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-registered-trial-controls-')
        cls.parent = Path(cls.temporary.name)
        cls.first = cls.parent / 'trial-first'
        cls.second = cls.parent / 'trial-second'
        cls.first_result = bootstrap.bootstrap(cls.first)
        cls.second_result = bootstrap.bootstrap(cls.second)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @staticmethod
    def rewrite(path, raw):
        path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(0o400)

    def selection(self, root=None):
        root = root or self.first
        return json.loads((root / 'public/SELECTION-CANDIDATE.json').read_text())

    def test_one_command_creates_distinct_fresh_unfunded_identities(self):
        first = bootstrap.verify_trial(self.first)
        second = bootstrap.verify_trial(self.second)
        self.assertEqual(first, self.first_result)
        self.assertEqual(second, self.second_result)
        self.assertNotEqual(first['trial_id'], second['trial_id'])
        self.assertNotEqual(first['registration_sha256'],
                            second['registration_sha256'])
        first_selection, second_selection = self.selection(), self.selection(self.second)
        self.assertNotEqual(
            [row['certificate_der_sha256']
             for row in first_selection['certificates']],
            [row['certificate_der_sha256']
             for row in second_selection['certificates']])
        self.assertFalse(first_selection['registered_driver_configured'])
        self.assertFalse(first_selection['network_node_contacted'])
        self.assertFalse(first_selection['owner_input_or_mpc_executed'])

    def test_existing_or_partial_target_is_never_reused(self):
        with self.assertRaises(ValueError):
            bootstrap.bootstrap(self.first)
        partial = self.parent / 'partial-target'
        partial.mkdir(mode=0o700)
        (partial / 'partial').write_text('retained\n')
        with self.assertRaises(ValueError):
            bootstrap.bootstrap(partial)
        self.assertEqual((partial / 'partial').read_text(), 'retained\n')

    def test_atomic_publication_cannot_replace_a_raced_target(self):
        source = self.parent / 'publish-source'
        target = self.parent / 'publish-target'
        source.mkdir(mode=0o700); target.mkdir(mode=0o700)
        (source / 'source').write_text('source\n')
        (target / 'target').write_text('target\n')
        with self.assertRaises(ValueError):
            bootstrap.publish_new(source, target)
        self.assertEqual((source / 'source').read_text(), 'source\n')
        self.assertEqual((target / 'target').read_text(), 'target\n')

    def test_symlink_certificate_and_hardlink_private_key_refuse(self):
        certificate = self.first / 'public/certificates/P0.pem'
        backup = certificate.with_name('P0.saved.pem')
        certificate.rename(backup)
        certificate.symlink_to(backup.name)
        try:
            with self.assertRaises(ValueError):
                bootstrap.verify_trial(self.first)
        finally:
            certificate.unlink(); backup.rename(certificate)

        key = self.first / 'private/party-0/tls/P0.key'
        alias = key.with_name('P0-hardlink.key')
        os.link(key, alias)
        try:
            with self.assertRaises(ValueError):
                bootstrap.verify_trial(self.first)
        finally:
            alias.unlink()
        self.assertEqual(bootstrap.verify_trial(self.first), self.first_result)

    def test_wrong_public_certificate_or_registration_refuses(self):
        certificate = self.first / 'public/certificates/P0.pem'
        other = self.first / 'public/certificates/P1.pem'
        original = certificate.read_bytes()
        try:
            self.rewrite(certificate, other.read_bytes())
            with self.assertRaises(ValueError):
                bootstrap.verify_trial(self.first)
        finally:
            self.rewrite(certificate, original)

        registration = self.first / 'public/registration/REGISTRATION.json'
        original = registration.read_bytes()
        changed = json.loads(original)
        changed['registration']['registration_nonce_hex32'] = 'ff' * 32
        try:
            self.rewrite(registration, bootstrap.encoded(changed))
            with self.assertRaises(ValueError):
                bootstrap.verify_trial(self.first)
        finally:
            self.rewrite(registration, original)
        self.assertEqual(bootstrap.verify_trial(self.first), self.first_result)

    def test_initializer_directly_rejects_wrong_registration(self):
        selected = self.selection()
        binary = self.first / 'public/build/registered-trial-init'
        pins = [row['certificate_der_sha256']
                for row in selected['certificates']]
        result = subprocess.run([str(binary), 'verify', str(self.first),
            'ff' * 32, *pins], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                 'LC_ALL': 'C.UTF-8'})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr,
                         b'registered unfunded trial state refused\n')

    def test_public_receipts_contain_no_private_body_hash_authority(self):
        selected = self.selection()
        receipt = json.loads((self.first / 'public/BOOTSTRAP.json').read_text())
        self.assertFalse(receipt[
            'private_key_bodies_exported_or_hashed_in_public_receipts'])
        self.assertFalse(selected['registered_driver_configured'])
        for certificate in selected['certificates']:
            self.assertFalse(certificate[
                'private_key_body_exported_or_hashed_in_public_receipts'])
            self.assertNotIn('private_key_sha256', certificate)
        public = json.dumps({'selection': selected, 'receipt': receipt},
                            sort_keys=True)
        self.assertNotIn('BEGIN PRIVATE KEY', public)
        self.assertNotIn('PRIVATE KEY-----', public)


if __name__ == '__main__':
    unittest.main()
