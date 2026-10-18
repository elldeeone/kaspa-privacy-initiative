"""Offline R08–R16 behavior; model results never close proof/native gates."""
import copy
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

from recovery import model_checkpoint, reconstruct_public, restore_wallet
from recovery_fixture import build_fixture
from recovery_format import RecoveryError, write_private_json
from recovery_format import read_json, wallet_from_backup
from model import Note, hash_id
from recovery_session import RecoverySession


def state(session):
    saved = session.export()
    result = reconstruct_public(saved['archive'], saved['checkpoint'])
    result.pop('checkpoint_hash')
    return result


class RecoveryFailureTests(unittest.TestCase):
    def setUp(self):
        self.f = build_fixture()

    def test_r08_orphan_payment_restores_unpaid_claim_and_invalid_fork_is_atomic(self):
        f = self.f
        session = RecoverySession(f['archive'], f['checkpoint'])
        identity, claim = next(iter(state(session)['claims'].items()))
        self.assertTrue(session.payout(identity, claim['recipient'], 200_000_000, 50_000_000, 1_800_000_000)['accepted'])
        session.reorganize(f['archive'], f['checkpoint'], common_records=9)
        current = state(session)
        self.assertFalse(current['claims'][identity]['paid'])
        self.assertEqual((current['reserve_sompi'], current['rent_paid_sompi']), (2_000_000_000, 0))
        self.assertEqual(restore_wallet(**session.export(), backup=f['backups']['Bob'])['unpaid_exit_sompi'], 200_000_000)
        self.assertTrue(session.payout(identity, claim['recipient'], 200_000_000, 50_000_000, 1_800_000_000)['accepted'])
        before = session.export()
        broken = copy.deepcopy(f['archive']); broken['records'].pop(0)
        with self.assertRaises(RecoveryError):
            session.reorganize(broken, model_checkpoint(broken), common_records=0)
        self.assertEqual(session.export(), before)

    def test_r09_killed_writers_publish_old_or_new_coherent_generation(self):
        from recovery_store import RecoveryStore
        f = self.f
        next_session = RecoverySession(f['archive'], f['checkpoint'])
        identity, claim = next(iter(state(next_session)['claims'].items()))
        next_session.payout(identity, claim['recipient'], 200_000_000, 50_000_000, 1_800_000_000)
        new = next_session.export()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_private_json(root / 'inputs.json', {'export': new, 'backups': f['backups']})
            for phase in ('file_synced', 'before_replace', 'replaced', 'directory_synced'):
                store_path = root / phase
                store = RecoveryStore(store_path)
                self.assertEqual(store.commit({key: f[key] for key in ('archive', 'checkpoint')}, f['backups'], 0), 1)
                code = '''import os, signal, sys
from recovery_store import RecoveryStore
from recovery_format import read_json
data = read_json(sys.argv[2])
def interrupt(phase):
    if phase == sys.argv[3]: os.kill(os.getpid(), signal.SIGKILL)
RecoveryStore(sys.argv[1], phase_hook=interrupt).commit(data['export'], data['backups'], 1)
'''
                env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(Path(__file__).parent))
                run = subprocess.run([sys.executable, '-c', code, str(store_path), str(root / 'inputs.json'), phase],
                                     env=env, capture_output=True, text=True)
                self.assertEqual(run.returncode, -signal.SIGKILL, run.stderr)
                loaded = RecoveryStore(store_path).load(f['backups'])
                expected = 1 if phase in ('file_synced', 'before_replace') else 2
                self.assertEqual(loaded['revision'], expected)
                self.assertEqual(loaded['wallets']['Bob']['unpaid_exit_sompi'], 200_000_000 if expected == 1 else 0)
                with self.assertRaises(RecoveryError):
                    store.commit(new, f['backups'], 0)

    def test_r09_unknown_submission_requires_inspection_until_payment_observed(self):
        from recovery_store import RecoveryStore
        f = self.f
        session = RecoverySession(f['archive'], f['checkpoint'])
        identity, claim = next(iter(state(session)['claims'].items()))
        request = {'kind': 'payout', 'claim': identity, 'recipient': claim['recipient'],
                   'principal': 200_000_000, 'rent': 50_000_000, 'remaining_reserve': 1_800_000_000}
        with tempfile.TemporaryDirectory() as directory:
            store = RecoveryStore(Path(directory) / 'store')
            store.commit(session.export(), f['backups'], 0, pending_submission=request)
            loaded = store.load(f['backups'])
            self.assertEqual(loaded['next_action'], 'inspect_history_do_not_resubmit')
            self.assertEqual(loaded['pending_submission'], request)
            store.commit(session.export(), f['backups'], 1)
            self.assertEqual(store.load(f['backups'])['next_action'], 'inspect_history_do_not_resubmit')
            self.assertEqual(state(session)['reserve_sompi'], 2_000_000_000)
            self.assertTrue(session.payout(identity, claim['recipient'], 200_000_000, 50_000_000, 1_800_000_000)['accepted'])
            store.commit(session.export(), f['backups'], 2)
            loaded = store.load(f['backups'])
            self.assertIsNone(loaded['pending_submission'])
            self.assertEqual(loaded['next_action'], 'continue_at_model_horizon')

    def test_r10_replacement_archive_and_no_copy_failure(self):
        from recovery_inputs import load_retained_archive
        f = self.f
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            partial = copy.deepcopy(f['archive']); partial['records'].pop()
            write_private_json(root / 'partial.json', partial)
            write_private_json(root / 'replica.json', f['archive'])
            recovered = load_retained_archive([root / 'gone.json', root / 'partial.json', root / 'replica.json'], f['checkpoint'])
            self.assertEqual(recovered['archive'], f['archive'])
            for backup in f['backups'].values():
                self.assertEqual(restore_wallet(**recovered, backup=backup)['status'], 'complete_at_model_checkpoint')
            with self.assertRaises(RecoveryError) as missing:
                load_retained_archive([root / 'gone.json', root / 'partial.json'], f['checkpoint'])
            self.assertEqual(missing.exception.status, 'incomplete_data')

    def test_r11_view_only_backup_cannot_claim_spendability_or_authorize_spending(self):
        from recovery_view import make_view_backup, inspect_view
        from recovery_format import wallet_from_backup
        f = self.f
        view = make_view_backup(f['backups']['Alice'])
        self.assertNotIn('spending_seed', view)
        result = inspect_view(f['archive'], f['checkpoint'], view)
        self.assertEqual(result['accepted_received_sompi'], 1_600_000_000)  # Includes the spent original note.
        self.assertEqual(result['status'], 'view_only_spentness_unknown')
        self.assertFalse(result['can_spend'])
        self.assertNotIn('spendable_sompi', result)
        with self.assertRaises(RecoveryError):
            wallet_from_backup(view)
        for field in ('incoming_secret', 'owner', 'address_signature'):
            bad = copy.deepcopy(view); bad[field] = '00' * (64 if field == 'address_signature' else 32)
            with self.assertRaises(RecoveryError):
                inspect_view(f['archive'], f['checkpoint'], bad)

    def test_r11_missing_or_substituted_prover_artifact_is_not_invalid_proof(self):
        from recovery_inputs import require_prover_artifact
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'program'
            with self.assertRaises(RecoveryError) as missing:
                require_prover_artifact(path, 'ab' * 32)
            self.assertEqual(missing.exception.status, 'proof_unavailable')
            path.write_bytes(b'wrong-program')
            with self.assertRaises(RecoveryError):
                require_prover_artifact(path, 'ab' * 32)

    def test_r12_replacement_rent_funding_preserves_principal_and_permission_terms(self):
        f = self.f
        session = RecoverySession(f['archive'], f['checkpoint'])
        alice = wallet_from_backup(f['backups']['Alice'])
        restored = restore_wallet(**session.export(), backup=f['backups']['Alice'])
        note = Note(**restored['spendable_notes'][0]['note'])
        proof = session.proof_oracle.spend(alice, [note], [], state(session)['commitments'],
                  withdrawal={'recipient': 'model-native:' + alice.owner, 'amount': 600_000_000})
        before = state(session)
        self.assertFalse(session.process(proof)['accepted'])
        self.assertEqual(state(session), before)
        # The normal sponsor has no key or privileged role in this model API.
        session.fund_rent(50_000_000)
        self.assertTrue(session.process(proof)['accepted'])
        current = state(session)
        self.assertEqual((current['reserve_sompi'], current['rent_funded_sompi']), (2_000_000_000, 100_000_000))
        before = state(session)
        self.assertFalse(session.payout(hash_id(proof.public),
                         'attacker', 600_000_000, 50_000_000, 1_400_000_000)['accepted'])
        self.assertEqual(state(session), before)

    def test_r13_valid_invalid_wrong_root_valid_order_survives_restart(self):
        from recovery_trials import note_with_value
        f = self.f
        session = RecoverySession(f['archive'], f['checkpoint'])
        alice = wallet_from_backup(f['backups']['Alice']); bob = wallet_from_backup(f['backups']['Bob'])
        note = note_with_value(alice, state(session), 600_000_000)
        first = session.proof_oracle.spend(alice, [note], [(alice.note(600_000_000, 'r13-first'), alice.address)], state(session)['commitments'])
        self.assertTrue(session.process(first)['accepted'])
        exported = session.export(); session = RecoverySession(**exported)
        source = note_with_value(bob, state(session), 400_000_000)
        wrong_root = session.proof_oracle.spend(bob, [source], [(bob.note(400_000_000, 'r13-root'), bob.address)], [source.commitment])
        session.proof_oracle.verify(wrong_root)  # Individually valid under an unaccepted root.
        invalid = copy.deepcopy(wrong_root); invalid.token = 'bad-inner-model-proof'
        before = state(session)
        self.assertFalse(session.process(invalid)['accepted'])
        self.assertIn('anchor', session.process(wrong_root)['reason'])
        self.assertFalse(session.process(None)['accepted'])
        self.assertEqual(state(session), before)
        later = session.proof_oracle.spend(bob, [source], [(bob.note(400_000_000, 'r13-last'), bob.address)], state(session)['commitments'])
        self.assertTrue(session.process(later)['accepted'])
        current = state(session)
        self.assertEqual(current['reserve_sompi'], 2_000_000_000)
        self.assertEqual(current['private_liability_sompi'], 1_499_999_000)

    def test_r15_rejects_foreign_domains_versions_and_migration_fields(self):
        from recovery_format import wallet_from_backup
        f = self.f
        for field, value in [('network', 'mainnet'), ('pool', 'other'), ('lane', 'other'),
                             ('statement_version', 2), ('statement_version', True),
                             ('genesis', 'wrong'), ('verifier_image', 'ab' * 32)]:
            bad = copy.deepcopy(f['archive']); bad['descriptor'][field] = value
            with self.subTest(field=field), self.assertRaises(RecoveryError):
                RecoverySession(bad, model_checkpoint(bad))
        for schema in ('kpi-model-backup/v0', 'kpi-model-backup/v3', 'migration-enabled'):
            bad = copy.deepcopy(f['backups']['Alice']); bad['schema'] = schema
            with self.assertRaises(RecoveryError):
                wallet_from_backup(bad)

    def test_r16_three_user_shutdown_rehearsal_uses_only_each_users_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = Path(__file__).parent
            producer = root / 'producer'
            subprocess.run([sys.executable, str(package / 'recovery_fixture.py'), str(producer)],
                           check=True, capture_output=True, text=True)
            retained = root / 'retained'; retained.mkdir(mode=0o700)
            for name in ('archive.json', 'checkpoint.json'):
                (retained / name).write_bytes((producer / name).read_bytes())
            users = {}
            for user in ('alice', 'bob', 'carol'):
                users[user] = root / user; users[user].mkdir(mode=0o700)
                write_private_json(users[user] / 'backup.json', read_json(producer / (user + '-backup.json')))
            producer.rename(root / 'unavailable-original')  # Original declared path is gone; its producer exited.
            prior = retained
            for user, workspace in users.items():
                output = workspace / 'exit'
                run = subprocess.run([sys.executable, '-O', str(package / 'recovery_shutdown.py'), 'exit-user',
                    '--archive', str(prior / 'archive.json'), '--checkpoint', str(prior / 'checkpoint.json'),
                    '--backup', str(workspace / 'backup.json'), '--output', str(output)],
                    cwd=workspace, capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
                self.assertEqual(list(workspace.glob('*backup*')), [workspace / 'backup.json'])
                prior = output
            final = root / 'final'
            run = subprocess.run([sys.executable, '-O', str(package / 'recovery_shutdown.py'), 'pay-all',
                    '--archive', str(prior / 'archive.json'), '--checkpoint', str(prior / 'checkpoint.json'),
                    '--output', str(final)], cwd=root, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            result = read_json(final / 'result.json')
            self.assertEqual((result['reserve_sompi'], result['paid_user_principal_sompi'], result['paid_fee_sompi']),
                             (0, 1_999_999_000, 1_000))
            self.assertEqual(result['rent_paid_sompi'], 200_000_000)
            self.assertFalse(result['native_shutdown_gate_passed'])
            for user, workspace in users.items():
                output = workspace / 'audit'
                run = subprocess.run([sys.executable, '-O', str(package / 'recovery_shutdown.py'), 'audit-user',
                    '--archive', str(final / 'archive.json'), '--checkpoint', str(final / 'checkpoint.json'),
                    '--backup', str(workspace / 'backup.json'), '--output', str(output)],
                    cwd=workspace, capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
                report = read_json(output / 'wallet.json')
                self.assertTrue(all(report[key] == 0 for key in ('spendable_sompi', 'pending_deposit_sompi', 'unpaid_exit_sompi', 'unpaid_refund_sompi')))

    def test_r14_cli_and_public_history_have_no_secret_canaries_or_network_attempts(self):
        import json
        package = Path(__file__).parent
        f = self.f
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('archive', 'checkpoint'):
                write_private_json(root / (name + '.json'), f[name])
            write_private_json(root / 'backup.json', f['backups']['Bob'])
            command = [sys.executable, str(package / 'offline_probe.py'), str(root / 'trace.json'),
                str(package / 'recovery.py'), '--archive', str(root / 'archive.json'),
                '--checkpoint', str(root / 'checkpoint.json'), '--backup', str(root / 'backup.json'),
                '--output', str(root / 'wallet.json')]
            run = subprocess.run(command, cwd=root, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            self.assertEqual(read_json(root / 'trace.json')['network_attempts'], [])
            public = run.stdout + run.stderr + json.dumps(f['archive'])
            canaries = [backup[key] for backup in f['backups'].values() for key in ('spending_seed', 'incoming_secret')]
            report = read_json(root / 'wallet.json')
            canaries += [entry['note']['randomness'] for entry in report['spendable_notes']]
            self.assertTrue(all(secret not in public for secret in canaries))
            self.assertEqual((root / 'wallet.json').stat().st_mode & 0o777, 0o600)
            attack = root / 'network-control.py'; attack.write_text('import socket\nsocket.socket()\n')
            control = subprocess.run([sys.executable, str(package / 'offline_probe.py'), str(root / 'blocked.json'), str(attack)],
                                     cwd=root, capture_output=True, text=True)
            self.assertNotEqual(control.returncode, 0)
            self.assertIn('socket.__new__', read_json(root / 'blocked.json')['network_attempts'])

    def test_r08_deep_fork_removes_orphan_notes_nullifiers_and_claims(self):
        from recovery_format import make_backup
        from recovery_trials import note_with_value
        f = self.f
        session = RecoverySession(f['archive'], f['checkpoint'])
        prefix = copy.deepcopy(f['archive']); prefix['records'] = prefix['records'][:6]
        replacement = RecoverySession(prefix, model_checkpoint(prefix))
        alice, carol = (wallet_from_backup(f['backups'][name]) for name in ('Alice', 'Carol'))
        original = note_with_value(alice, state(replacement), 1_000_000_000)
        proof = replacement.proof_oracle.spend(alice, [original],
            [(alice.note(750_000_000, 'fork-change'), alice.address), (carol.note(250_000_000, 'fork-receipt'), carol.address)],
            state(replacement)['commitments'])
        self.assertTrue(replacement.process(proof)['accepted'])
        changed = replacement.export()
        before = session.export()
        for count in (7, True, -1):
            with self.assertRaises(RecoveryError):
                session.reorganize(**changed, common_records=count)
            self.assertEqual(before, session.export())
        session.reorganize(**changed, common_records=6)
        current = state(session)
        self.assertEqual((len(current['nullifiers']), len(current['claims']), len(current['fees'])), (1, 0, 0))
        self.assertEqual((current['reserve_sompi'], current['private_liability_sompi'], current['rent_funded_sompi']),
                         (2_000_000_000, 1_700_000_000, 0))
        self.assertEqual(restore_wallet(**session.export(), backup=make_backup(alice))['spendable_sompi'], 750_000_000)
        self.assertEqual(restore_wallet(**session.export(), backup=make_backup(carol))['spendable_sompi'], 250_000_000)
        # An orphan expected receipt must not silently appear as spendable value.
        with self.assertRaises(RecoveryError) as orphan:
            restore_wallet(**session.export(), backup=f['backups']['Alice'])
        self.assertEqual(orphan.exception.status, 'incomplete_wallet_data')
        session.reorganize(**{key: f[key] for key in ('archive', 'checkpoint')}, common_records=0)
        self.assertEqual(state(session)['private_liability_sompi'], 1_499_999_000)

    def test_r09_concurrent_writers_stale_revision_and_corrupt_private_scan(self):
        from recovery_store import RecoveryStore
        f = self.f
        export = {key: f[key] for key in ('archive', 'checkpoint')}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); store = RecoveryStore(root / 'store')
            store.commit(export, f['backups'], 0)
            write_private_json(root / 'inputs.json', {'export': export, 'backups': f['backups']})
            code = '''import sys
from recovery_store import RecoveryStore
from recovery_format import RecoveryError, read_json
data = read_json(sys.argv[2])
try: RecoveryStore(sys.argv[1]).commit(data['export'], data['backups'], 1)
except RecoveryError: sys.exit(2)
'''
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(Path(__file__).parent))
            workers = [subprocess.Popen([sys.executable, '-c', code, str(root / 'store'), str(root / 'inputs.json')],
                       env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
            codes = []
            for worker in workers:
                _, errors = worker.communicate(timeout=30)
                self.assertEqual(errors, '')
                codes.append(worker.returncode)
            self.assertEqual(sorted(codes), [0, 2])
            self.assertEqual(store.load(f['backups'])['revision'], 2)
            path = root / 'store' / 'recovery.json'
            data = read_json(path); data['wallets']['Alice']['spendable_sompi'] = 0
            import json
            path.write_text(json.dumps(data))
            with self.assertRaises(RecoveryError):
                store.load(f['backups'])

    def test_r09_malformed_revisions_and_invalid_export_preserve_saved_generation(self):
        from recovery_store import RecoveryStore
        f = self.f
        export = {key: f[key] for key in ('archive', 'checkpoint')}
        with tempfile.TemporaryDirectory() as directory:
            store = RecoveryStore(Path(directory) / 'store')
            store.commit(export, f['backups'], 0)
            for revision in (True, -1, 1.0, 2 ** 64):
                with self.assertRaises(RecoveryError):
                    store.commit(export, f['backups'], revision)
                self.assertEqual(store.load(f['backups'])['revision'], 1)
            bad = copy.deepcopy(export); bad['archive']['records'].pop()
            with self.assertRaises(RecoveryError):
                store.commit(bad, f['backups'], 1)
            self.assertEqual(store.load(f['backups'])['revision'], 1)


if __name__ == '__main__':
    unittest.main()
