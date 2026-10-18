"""R01–R04 at the documented backup/reconstruction boundary; model only."""
import unittest
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from model import MAX, Note, ProofOracle, Wallet
from recovery import model_checkpoint, reconstruct_public, restore_wallet
from recovery_format import RecoveryError, make_backup, wallet_from_backup
from recovery_format import read_json, write_private_json
from nacl.public import PublicKey, SealedBox


class BackupTests(unittest.TestCase):
    def test_backup_restores_authority_without_original_wallet_name(self):
        alice = Wallet('recovery-test-Alice')
        note = alice.note(600_000_000, 'change')
        backup = make_backup(alice, [note.commitment])
        restored = wallet_from_backup(backup)
        self.assertEqual(restored.owner, alice.owner)
        self.assertEqual(restored.address.incoming, alice.address.incoming)
        self.assertEqual(restored.nullifier(note), alice.nullifier(note))
        self.assertEqual(restored.discover([note.public(alice.address)]), [note])
        self.assertNotIn('recovery-test-Alice', str(backup))

    def test_backup_rejects_wrong_keys_missing_fields_and_noncanonical_identities(self):
        good = make_backup(Wallet('backup-boundary'))
        for field, value in [('spending_seed', '00' * 32), ('incoming_secret', '11' * 32),
                             ('owner', good['owner'].upper()), ('scope', 'PRODUCTION'),
                             ('expected_receipts', [True])]:
            with self.subTest(field=field):
                bad = copy.deepcopy(good); bad[field] = value
                with self.assertRaises(RecoveryError):
                    wallet_from_backup(bad)
        del good['incoming_secret']
        with self.assertRaises(RecoveryError) as missing:
            wallet_from_backup(good)
        self.assertEqual(missing.exception.status, 'incomplete_data')


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        from recovery_fixture import build_fixture
        self.fixture = build_fixture()

    def assert_restore_fails(self, fixture, backup=None, code=None):
        before = copy.deepcopy(fixture)
        with self.assertRaises(RecoveryError) as caught:
            restore_wallet(fixture['archive'], fixture['checkpoint'], backup or fixture['backups']['Bob'])
        if code:
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(before, fixture)
        return caught.exception

    def test_r01_fresh_process_restores_worked_bob_ledger_without_producer_state(self):
        from recovery_fixture import build_fixture
        fixture = build_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in [('archive', fixture['archive']), ('checkpoint', fixture['checkpoint']),
                                ('backup', fixture['backups']['Bob'])]:
                write_private_json(root / (name + '.json'), value)
            command = [sys.executable, str(Path(__file__).with_name('recovery.py')),
                       '--archive', str(root / 'archive.json'), '--checkpoint', str(root / 'checkpoint.json'),
                       '--backup', str(root / 'backup.json'), '--output', str(root / 'wallet.json')]
            run = subprocess.run(command, cwd=root, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            report = read_json(root / 'wallet.json')
            self.assertEqual(report['status'], 'complete_at_model_checkpoint')
            self.assertEqual(report['spendable_sompi'], 899_999_000)
            self.assertEqual(report['unpaid_exit_sompi'], 200_000_000)
            self.assertEqual(len(report['spendable_notes']), 2)
            self.assertEqual(report['accepted_note_count'], 3)
            self.assertEqual(report['spent_note_count'], 1)
            self.assertEqual((root / 'wallet.json').stat().st_mode & 0o777, 0o600)
            for secret in ('899999000', fixture['backups']['Bob']['owner'],
                           fixture['backups']['Bob']['spending_seed'], 'randomness'):
                self.assertNotIn(secret, run.stdout + run.stderr)
            self.assertFalse(json.loads(run.stdout)['chain_or_zk_verified'])

    def test_r01_all_users_and_independent_literal_accounting(self):
        f = self.fixture
        state = reconstruct_public(f['archive'], f['checkpoint'])
        self.assertEqual((state['reserve_sompi'], state['private_liability_sompi'],
                          state['rent_reserved_sompi']), (2_000_000_000, 1_499_999_000, 50_000_000))
        self.assertEqual(sum(e['amount'] for e in state['deposits'].values() if e['state'] == 'pending'), 300_000_000)
        self.assertEqual(sum(e['amount'] for e in state['claims'].values()), 200_000_000)
        self.assertEqual(sum(e['amount'] for e in state['fees'].values()), 1_000)
        for name, expected in [('Alice', (600_000_000, 0, 0)),
                               ('Bob', (899_999_000, 0, 200_000_000)), ('Carol', (0, 300_000_000, 0))]:
            with self.subTest(user=name):
                report = restore_wallet(f['archive'], f['checkpoint'], f['backups'][name])
                self.assertEqual((report['spendable_sompi'], report['pending_deposit_sompi'],
                                  report['unpaid_exit_sompi']), expected)
        # Recovered Bob can satisfy the existing ideal predicate with a NEW
        # local oracle; no producer proof registry or private database is reused.
        backup = f['backups']['Bob']
        wallet = wallet_from_backup(backup)
        report = restore_wallet(f['archive'], f['checkpoint'], backup)
        notes = [Note(**item['note']) for item in report['spendable_notes']]
        proof = ProofOracle().spend(wallet, notes, [(wallet.note(899_999_000, 'restored-spend'), wallet.address)],
                                    state['commitments'])
        self.assertEqual(len(proof.public['nullifiers']), 2)
        self.assertNotIn('token', json.dumps(f['archive']))

    def test_r02_omitted_middle_record_and_suffix_never_become_zero_balance(self):
        for position in (0, 3, -1):
            f = copy.deepcopy(self.fixture)
            del f['archive']['records'][position]
            error = self.assert_restore_fails(f, code='record_range_missing')
            self.assertEqual(error.status, 'incomplete_data')
        f = copy.deepcopy(self.fixture)
        f['archive']['records'] = []
        self.assert_restore_fails(f, code='record_range_missing')

    def test_r02_missing_delivery_is_explicitly_incomplete(self):
        for action in ('remove', 'empty'):
            f = copy.deepcopy(self.fixture)
            output = f['archive']['records'][3]['public']['outputs'][0]
            if action == 'remove':
                del output['ciphertext']
            else:
                output['ciphertext'] = ''
            self.assertEqual(self.assert_restore_fails(f).status, 'incomplete_data')

    def test_r03_substitution_rehashing_and_stale_horizon_fail_against_retained_checkpoint(self):
        for mutation in ('ciphertext', 'manifest', 'stale'):
            f = copy.deepcopy(self.fixture)
            if mutation == 'ciphertext':
                f['archive']['records'][3]['public']['outputs'][0]['ciphertext'] = '00'
            elif mutation == 'manifest':
                f['archive']['records'][-1]['public']['withdrawal']['amount'] += 1
                f['archive']['manifest_hash'] = model_checkpoint(f['archive'])['archive_hash']
            else:
                f['archive']['records'] = f['archive']['records'][:-1]
                stale = model_checkpoint(f['archive'])
                # Archive-provided checkpoint cannot replace caller's horizon.
                f['archive']['checkpoint'] = stale
            self.assert_restore_fails(f)

    def test_r03_foreign_domain_reordering_and_duplicate_records_fail(self):
        for mutate in ('network', 'pool', 'lane', 'genesis', 'version', 'reorder', 'duplicate'):
            f = copy.deepcopy(self.fixture)
            if mutate == 'version':
                f['archive']['descriptor']['statement_version'] = True
            elif mutate in ('network', 'pool', 'lane', 'genesis'):
                f['archive']['descriptor'][mutate] = 'other'
            elif mutate == 'reorder':
                f['archive']['records'][3:5] = list(reversed(f['archive']['records'][3:5]))
            else:
                f['archive']['records'][-1] = copy.deepcopy(f['archive']['records'][3])
            self.assert_restore_fails(f)

    def test_r04_bad_original_delivery_is_rejected_even_without_receipt_expectations(self):
        f = copy.deepcopy(self.fixture)
        wallet = wallet_from_backup(f['backups']['Bob'])
        wrong = wallet.note(123, 'sender-wrong-plaintext').public(wallet.address)
        f['archive']['records'][4]['public']['outputs'][0]['ciphertext'] = wrong['ciphertext']
        # Model a malicious sender's originally accepted ciphertext, rather than
        # post-checkpoint corruption. This fixture authority is explicit, not ZK.
        f['checkpoint'] = model_checkpoint(f['archive'])
        backup = copy.deepcopy(f['backups']['Bob']); backup['expected_receipts'] = []
        self.assert_restore_fails(f, backup, code='invalid_recipient_delivery')

    def test_r04_wrong_recipient_key_is_detected_for_known_receipt_and_limit_is_visible(self):
        f = copy.deepcopy(self.fixture)
        mallory = Wallet('wrong-recipient-fixture')
        f['archive']['records'][4]['public']['outputs'][0]['ciphertext'] = mallory.note(
            700_000_000, 'not-bob').public(mallory.address)['ciphertext']
        f['checkpoint'] = model_checkpoint(f['archive'])
        error = self.assert_restore_fails(f, code='expected_receipt_not_recoverable')
        self.assertEqual(error.status, 'incomplete_wallet_data')
        unknown = copy.deepcopy(f['backups']['Bob']); unknown['expected_receipts'] = []
        report = restore_wallet(f['archive'], f['checkpoint'], unknown)
        self.assertFalse(report['unknown_sender_delivery_guaranteed'])
        self.assertFalse(report['chain_or_zk_verified'])

    def test_r04_unaccepted_duplicate_and_spent_notes_add_no_balance(self):
        f = self.fixture
        backup = copy.deepcopy(f['backups']['Bob'])
        wallet = wallet_from_backup(backup)
        backup['expected_receipts'].append(wallet.note(999, 'never-funded').commitment)
        self.assert_restore_fails(f, backup, code='expected_receipt_not_recoverable')
        for record_index in (3, 4):
            bad = copy.deepcopy(f)
            bad['archive']['records'][-1] = copy.deepcopy(bad['archive']['records'][record_index])
            bad['archive']['records'][-1]['seq'] = len(bad['archive']['records']) - 1
            bad['checkpoint'] = model_checkpoint(bad['archive'])
            self.assert_restore_fails(bad, code='operation_replay')
        report = restore_wallet(f['archive'], f['checkpoint'], f['backups']['Bob'])
        spent = f['archive']['records'][4]['public']['outputs'][0]['commitment']
        self.assertNotIn(spent, [n['commitment'] for n in report['spendable_notes']])
        self.assertEqual(report['spendable_sompi'], 899_999_000)

    def test_r03_malformed_committed_reference_fails_with_controlled_error(self):
        f = copy.deepcopy(self.fixture)
        f['archive']['records'][3]['public']['deposit'] = []
        f['checkpoint'] = model_checkpoint(f['archive'])
        self.assert_restore_fails(f, code='canonical_hex32_required')

    def test_r03_strict_json_and_numeric_boundaries(self):
        for raw in ('{"x":1,"x":2}', '{"amount":1.0}', '{"amount":NaN}', '{"amount":Infinity}'):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'invalid.json'; path.write_text(raw)
                with self.assertRaises(RecoveryError):
                    read_json(path)
        for value in (-1, MAX + 1, True, '700000000', 700_000_000.0):
            f = copy.deepcopy(self.fixture)
            f['archive']['records'][1]['event']['amount'] = value
            f['checkpoint'] = model_checkpoint(f['archive'])
            self.assert_restore_fails(f, code='integer_sompi_range')

    def test_r03_u64_maximum_pending_deposit_and_aggregate_overflow(self):
        f = copy.deepcopy(self.fixture)
        f['archive']['records'] = [copy.deepcopy(f['archive']['records'][0])]
        f['archive']['records'][0]['event']['amount'] = MAX
        f['checkpoint'] = model_checkpoint(f['archive'])
        backup = copy.deepcopy(f['backups']['Alice']); backup['expected_receipts'] = []
        self.assertEqual(restore_wallet(f['archive'], f['checkpoint'], backup)['pending_deposit_sompi'], MAX)
        extra = copy.deepcopy(self.fixture['archive']['records'][1]); extra['seq'] = 1
        extra['event']['amount'] = 1
        f['archive']['records'].append(extra); f['checkpoint'] = model_checkpoint(f['archive'])
        self.assert_restore_fails(f, backup, code='integer_sompi_overflow')

    def test_r04_malformed_decrypted_note_is_controlled_failure(self):
        for raw in (b'not json', b'{"value":true}', b'[' * 20000 + b']' * 20000):
            f = copy.deepcopy(self.fixture)
            key = PublicKey(bytes.fromhex(f['backups']['Bob']['incoming']))
            f['archive']['records'][4]['public']['outputs'][0]['ciphertext'] = bytes(SealedBox(key).encrypt(raw)).hex()
            f['checkpoint'] = model_checkpoint(f['archive'])
            self.assert_restore_fails(f, code='invalid_recipient_delivery')

    def test_cli_failure_has_no_wallet_output_or_private_diagnostics(self):
        f = copy.deepcopy(self.fixture); del f['archive']['records'][-1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in [('archive', f['archive']), ('checkpoint', f['checkpoint']),
                                ('backup', f['backups']['Bob'])]:
                write_private_json(root / (name + '.json'), value)
            run = subprocess.run([sys.executable, str(Path(__file__).with_name('recovery.py')),
                                  '--archive', str(root / 'archive.json'), '--checkpoint', str(root / 'checkpoint.json'),
                                  '--backup', str(root / 'backup.json'), '--output', str(root / 'wallet.json')],
                                 cwd=root, capture_output=True, text=True)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(json.loads(run.stdout)['status'], 'incomplete_data')
            self.assertEqual(run.stderr, '')
            self.assertFalse((root / 'wallet.json').exists())
            self.assertNotIn('spendable', run.stdout)
            self.assertNotIn(f['backups']['Bob']['owner'], run.stdout)

    def test_private_file_writer_refuses_overwrite_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / 'backup.json'
            write_private_json(path, self.fixture['backups']['Bob'])
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                write_private_json(path, {'accidental': 'overwrite'})
            link = root / 'link.json'; link.symlink_to(path)
            with self.assertRaises(FileExistsError):
                write_private_json(link, {'accidental': 'overwrite'})
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_r01_fixture_generation_under_optimized_python_preserves_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'fixture'
            run = subprocess.run([sys.executable, '-O', str(Path(__file__).with_name('recovery_fixture.py')), str(root)],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            report = restore_wallet(read_json(root / 'archive.json'), read_json(root / 'checkpoint.json'),
                                    read_json(root / 'bob-backup.json'))
            self.assertEqual(report['spendable_sompi'], 899_999_000)



if __name__ == '__main__':
    unittest.main()
