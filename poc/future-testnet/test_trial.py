"""Finite offline identity controls; every generated secret stays outside Git."""
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

import trial


class TrialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='kpx2-tn10-identity-')
        cls.base = Path(cls.temp.name)
        cls.a = cls.base / 'alice'
        cls.b = cls.base / 'bob'
        cls.ra = trial.new(cls.a)
        cls.rb = trial.new(cls.b)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_01_fresh_os_random_identity_and_private_backups(self):
        a, b = trial.load_profile(self.a), trial.load_profile(self.b)
        self.assertNotEqual(a['trial_id'], b['trial_id'])
        self.assertNotEqual(a['domain_hex32'], b['domain_hex32'])
        self.assertNotEqual(a['secrets'], b['secrets'])
        self.assertEqual(a['domain_hex32'], trial.domain(bytes.fromhex(a['domain_nonce_hex32'])))
        self.assertIsNone(a['selected_vk'])
        self.assertIsNone(a['funding_utxo'])
        self.assertEqual(a['status'], 'unfunded')
        for owner in ('alice', 'bob', 'charlie'):
            backup = json.loads((self.a / 'backups' / (owner + '.json')).read_bytes())
            self.assertEqual(backup['seed_hex32'], a['secrets'][owner + '_seed_hex32'])
            self.assertEqual(backup['domain_hex32'], a['domain_hex32'])

    def test_02_all_private_permissions(self):
        for p in (self.a, *self.a.rglob('*')):
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o700 if p.is_dir() else 0o600)

    def test_03_public_manifest_and_stdout_do_not_contain_secrets(self):
        p = trial.load_profile(self.a)
        public = (self.a / 'public/identity.json').read_text() + json.dumps(self.ra)
        for secret in p['secrets'].values():
            self.assertNotIn(secret, public)
        self.assertNotIn('secrets', json.loads((self.a / 'public/identity.json').read_text()))

    def test_04_addresses_are_exact_tn10_p2pk(self):
        p = trial.load_profile(self.a)
        for identity in p['identities'].values():
            self.assertTrue(identity['address'].startswith('kaspatest:'))
            self.assertEqual(identity['spk_version'], 0)
            self.assertEqual(identity['spk_hex'], '20' + identity['xonly_hex32'] + 'ac')

    def test_05_existing_destination_refused_without_changes(self):
        before = (self.a / 'profile.json').read_bytes()
        with self.assertRaisesRegex(trial.Invalid, 'destination already exists'):
            trial.new(self.a)
        self.assertEqual(before, (self.a / 'profile.json').read_bytes())

    def test_06_git_destination_refused(self):
        with self.assertRaisesRegex(trial.Invalid, 'outside every Git'):
            trial.new(trial.ROOT / 'must-never-create-private-trial')
        self.assertFalse((trial.ROOT / 'must-never-create-private-trial').exists())

    def test_07_symlink_destination_refused(self):
        link = self.base / 'linked'
        link.symlink_to(self.a, target_is_directory=True)
        with self.assertRaisesRegex(trial.Invalid, 'symlink'):
            trial.new(link / 'child')

    def test_08_mainnet_has_no_cli_option(self):
        p = subprocess.run(['python3', '-B', str(trial.HERE / 'trial.py'),
                            'new', '--network', 'mainnet', str(self.base / 'mainnet')],
                           capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse((self.base / 'mainnet').exists())

    def test_09_wrong_genesis_domain_and_profile_permissions_rejected(self):
        target = self.base / 'mutant'
        trial.new(target)
        profile_path = target / 'profile.json'
        original = profile_path.read_bytes()
        for key, value in (('genesis_hash_hex', '00' * 32), ('network_id', 'mainnet'),
                           ('domain_hex32', trial.OLD_DOMAIN), ('classification', 'PUBLIC_SYNTHETIC_DO_NOT_FUND')):
            p = json.loads(original)
            p[key] = value
            profile_path.write_bytes(trial.encoded(p))
            with self.assertRaisesRegex(trial.Invalid, 'wrong private TN10'):
                trial.load_profile(target)
        profile_path.write_bytes(original)
        profile_path.chmod(0o644)
        with self.assertRaisesRegex(trial.Invalid, '0600'):
            trial.load_profile(target)

    def test_10_materialization_changes_only_exact_two_domain_arrays(self):
        before = {str(p): p.read_bytes() for p in trial.source_files()}
        p = trial.load_profile(self.a)
        result = trial.materialize(self.a)
        out = Path(result['source_workspace'])
        manifest = json.loads((out / 'domain-source-manifest.json').read_bytes())
        self.assertEqual(sum(r['domain_replaced'] for r in manifest['files']), 2)
        self.assertFalse(manifest['old_pk_or_vk_copied'])
        for record in manifest['files']:
            raw = (out / record['path']).read_bytes()
            original = (trial.ROOT / record['path']).read_bytes()
            self.assertEqual(trial.digest(raw), record['generated_sha256'])
            self.assertEqual(trial.digest(original), record['base_sha256'])
            expected = trial.replace_domain(original, bytes.fromhex(p['domain_hex32'])) if record['domain_replaced'] else original
            self.assertEqual(raw, expected)
        for path, raw in before.items():
            self.assertEqual(Path(path).read_bytes(), raw)
        with self.assertRaisesRegex(trial.Invalid, 'already exists'):
            trial.materialize(self.a)

    def test_11_ignored_git_directory_also_refused(self):
        repo = self.base / 'another-repo'
        repo.mkdir()
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        (repo / '.gitignore').write_text('ignored/\n')
        (repo / 'ignored').mkdir()
        with self.assertRaisesRegex(trial.Invalid, 'outside every Git'):
            trial.new(repo / 'ignored/secret-trial')

    def test_12_wrong_sdk_pin_rejected_before_creating_identity(self):
        fake = self.base / 'fake-sdk'
        fake.mkdir()
        for name in trial.SDK_PINS:
            (fake / name).write_bytes(b'not-the-official-sdk')
        with self.assertRaisesRegex(trial.Invalid, 'SDK 2.1.0 identity mismatch'):
            trial.new(self.base / 'bad-sdk-trial', sdk=fake / 'kaspa.js')
        self.assertFalse((self.base / 'bad-sdk-trial').exists())

    def test_13_alternate_sdk_file_beside_genuine_pins_rejected(self):
        fake = self.base / 'alternate-sdk'
        fake.mkdir()
        for name in trial.SDK_PINS:
            (fake / name).symlink_to(trial.DEFAULT_SDK.parent / name)
        (fake / 'other.js').write_bytes(b'throw new Error("not the pinned module");')
        with self.assertRaisesRegex(trial.Invalid, 'SDK 2.1.0 identity mismatch'):
            trial.new(self.base / 'alternate-sdk-trial', sdk=fake / 'other.js')
        self.assertFalse((self.base / 'alternate-sdk-trial').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
