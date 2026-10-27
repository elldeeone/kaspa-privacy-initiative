"""Public controls for private scheduling, metadata-only backup and once-submit."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import campaign


class RecordingRNG:
    def __init__(self):
        self.shuffles = []

    def choice(self, values):
        return values[-1]

    def shuffle(self, values):
        self.shuffles.append(tuple(values))
        values.reverse()


class Controls(unittest.TestCase):
    def test_submission_journal_matches_frozen_controller_contract_before_proof(self):
        private = campaign.PRIVATE / 'known-public-fixture-caller'
        journal = campaign.submission_journal(private)
        self.assertEqual(journal, private / 'controller/submission-journal')
        self.assertIn('controller', journal.parts)
        with self.assertRaisesRegex(ValueError, 'declared-private-submit-controller'):
            campaign.submission_journal(Path('/outside-authorized-private-prefix'))

    def test_actual_reserve_birth_DAA_and_all_context_fields_are_preserved(self):
        point = 'aa' * 32 + '00000000'
        script = '0000aa20' + 'bb' * 32 + '87'
        checkpoint = {'state_hex112': 'cc' * 112, 'reserve_sompi': 6_000_000_000, 'outpoint_hex36': point}
        entry = {'outpoint': {'transactionId': 'aa' * 32, 'index': 0}, 'amount_sompi': '6000000000',
            'script_public_key': script, 'block_daa_score': '606339508', 'is_coinbase': False, 'covenant_id': None}
        actual = campaign.canonical_reserve_entry(entry, checkpoint, script)
        self.assertEqual(actual, {'amount': 6_000_000_000, 'scriptPublicKey': script,
            'blockDaaScore': 606339508, 'isCoinbase': False, 'covenantId': None})
        for changed in ('point', 'amount', 'script', 'coinbase', 'covenant'):
            bad = copy.deepcopy(entry)
            if changed == 'point':
                bad['outpoint']['transactionId'] = 'dd' * 32
            elif changed == 'amount':
                bad['amount_sompi'] = '6000000001'
            elif changed == 'script':
                bad['script_public_key'] = '0000aa20' + 'ee' * 32 + '87'
            elif changed == 'coinbase':
                bad['is_coinbase'] = True
            else:
                bad['covenant_id'] = 'ff' * 32
            with self.assertRaisesRegex(ValueError, 'current-entry-must-match'):
                campaign.canonical_reserve_entry(bad, checkpoint, script)
        for bad_daa in (True, 606339508.0, '0606339508', '-1', str(1 << 64)):
            bad = dict(entry, block_daa_score=bad_daa)
            with self.assertRaises(ValueError):
                campaign.canonical_reserve_entry(bad, checkpoint, script)

    def test_each_round_and_all_nine_exits_use_private_shuffle(self):
        rng = RecordingRNG()
        plan = campaign.make_plan(['/known-public-fixture/one', '/known-public-fixture/two',
                                   '/known-public-fixture/three'], rng=rng)
        self.assertEqual([len(values) for values in rng.shuffles], [3, 3, 9])
        payments, exits = plan['actions'][:6], plan['actions'][6:]
        self.assertEqual(sum(row['payment_sompi'] for row in payments), 2_100_000_000)
        self.assertEqual([row['payment_sompi'] for row in payments], [500_000_000] * 3 + [200_000_000] * 3)
        self.assertTrue(all(row['owner'] != row['recipient'] for row in payments))
        self.assertEqual(sorted(row['owner'] for row in exits), [0, 0, 0, 1, 1, 1, 2, 2, 2])
        self.assertEqual({row['owner']: row['selection_kind'] for row in payments[3:]},
                         {0: 'received-preferred', 1: 'change', 2: 'received-preferred'})

    def test_backup_interface_never_opens_or_hashes_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'PUBLIC-DUMMY-NOT-A-SEED'
            path.write_bytes(b'KNOWN PUBLIC DUMMY; NO ACTUAL BACKUP')
            path.chmod(0o600)
            with patch.object(campaign, 'PRIVATE', root), patch('builtins.open', side_effect=AssertionError('content-read')):
                actual, identity = campaign.backup_metadata(path)
            self.assertEqual(actual, path)
            self.assertEqual(identity, (path.stat().st_dev, path.stat().st_ino))

    def test_unknown_submit_is_durably_consumed_and_resume_only_confirms(self):
        caller = campaign.Campaign.__new__(campaign.Campaign)
        selected = lambda name: {'path': '/known-public/' + name, 'sha256': '11' * 32}
        caller.selection = {'trial_id': 'KNOWN-PUBLIC-TRIAL', 'scripts': {
            'submit': selected('submit'), 'confirm': selected('confirm')}, 'node': selected('node')}
        caller.activation = {name: selected(name) for name in ('selection', 'descriptor', 'assets', 'parameters', 'codec')}
        caller.private = campaign.PRIVATE / 'known-public-fixture-private-caller'
        case = selected('CASE.json')
        case_value = {'transaction': {'id': '22' * 32}}
        caller.row = lambda row: campaign.encoded(case_value) if row == case else b'KNOWN PUBLIC SELECTED SOURCE'
        handoff = {'accepted_whole_CASE_equals_expected': True, 'expected_transaction_id': '22' * 32}
        caller.public_read = lambda path: campaign.encoded(handoff)
        calls, saved = [], []

        def invoke(argv, *, label):
            calls.append(list(map(str, argv)))
            if '/known-public/submit' in calls[-1]:
                self.assertTrue(saved[-1]['submission_consumed'])
                raise ValueError('PUBLIC-UNKNOWN-RPC-RESPONSE')

        caller.call = invoke
        state = {'head': {'fetch.json': selected('fetch.json')}, 'submission_consumed': False}
        with patch.object(campaign, 'private_save', lambda path, value: saved.append(copy.deepcopy(value))):
            caller.settle(Path('/known-public/action-0001'), 'action-0001', case, state)
            caller.settle(Path('/known-public/action-0001'), 'action-0001', case, state)
        self.assertEqual(sum('/known-public/submit' in argv for argv in calls), 1)
        self.assertEqual(sum('/known-public/confirm' in argv for argv in calls), 2)

    def test_native_cold_mounts_reject_extra_PK(self):
        caller = campaign.Campaign.__new__(campaign.Campaign)
        targets = {name: '/public/' + name for name in ('validator', 'engine', 'codec', 'component', 'selection')}
        names = list(targets.values()) + ['/public/verification/native_case.py', '/public/verification/wire.py',
                                          '/public/parameters.pk']
        caller.selection = {'cold': {'download_receipt': {}, 'native_targets': targets,
            'native_files': [{'target': target, 'path': '/known-public/' + str(i),
                             'sha256': '11' * 32, 'executable': False} for i, target in enumerate(names)]}}
        caller.row = lambda row: b'KNOWN PUBLIC DOWNLOADED RECEIPT'
        caller.downloaded_files = lambda: {(row['path'], row['sha256']) for row in caller.selection['cold']['native_files']}
        with self.assertRaisesRegex(ValueError, 'no-PK-or-prover'):
            caller.cold_entries(native_only=True)

    def test_private_payment_plan_rejects_changed_demand_and_role_policy(self):
        plan = campaign.make_plan(['/known-public/one', '/known-public/two', '/known-public/three'], rng=RecordingRNG())
        self.assertIs(campaign.validate_plan(plan), plan)
        changed = copy.deepcopy(plan)
        changed['actions'][0]['payment_sompi'] = True
        with self.assertRaisesRegex(ValueError, 'exact-approved-private-payment'):
            campaign.validate_plan(changed)
        changed = copy.deepcopy(plan)
        changed['actions'][3]['selection_kind'] = 'any'
        with self.assertRaisesRegex(ValueError, 'original-seed-private-selection-policy'):
            campaign.validate_plan(changed)

    def test_download_receipt_binds_exact_unpacked_files_and_selected_exit_parameters(self):
        caller = campaign.Campaign.__new__(campaign.Campaign)
        archive = b'KNOWN PUBLIC SYNTHETIC ARCHIVE'
        pk = b'KNOWN PUBLIC SYNTHETIC EXIT PARAMETERS'
        inventory = {'schema': 'kpxa-recovery-software-inventory/v1', 'domain_hex32': campaign.DOMAIN.hex(),
            'PKs_included': False, 'files': [{'path': 'wallet/worker.py', 'sha256': '33' * 32, 'bytes': 10}]}
        inventory_raw = campaign.encoded(inventory)
        inventory_row = {'path': '/public-download-fixture/unpacked/INVENTORY.json',
                         'sha256': campaign.digest(inventory_raw)}
        receipt = {'schema': 'kpxa-downloaded-recovery-receipt/v1',
            'classification': 'ACTUAL_TOR_TLS_DOWNLOAD_AND_INVENTORY_VERIFIED', 'transport': 'TOR_SOCKS5H_TLS',
            'inventory': inventory_row, 'artifacts': [
                {'path': '/public-download-fixture/software.tar', 'sha256': campaign.digest(archive),
                 'bytes': len(archive), 'origin_url': 'https://known-public.invalid/software.tar'},
                {'path': '/public-download-fixture/parameters.pk', 'sha256': campaign.digest(pk),
                 'bytes': len(pk), 'origin_url': 'https://known-public.invalid/parameters.pk'}], 'files': [
                {**inventory_row, 'bytes': len(inventory_raw)},
                {'path': '/public-download-fixture/unpacked/wallet/worker.py', 'sha256': '33' * 32, 'bytes': 10},
                {'path': '/public-download-fixture/parameters.pk', 'sha256': campaign.digest(pk), 'bytes': len(pk)}]}
        caller.assets = {'exit': {'manifest': '/known-public/manifest', 'manifest_sha256': '44' * 32}}
        caller.selection = {'cold': {'download_receipt': {'path': '/known-public/receipt', 'sha256': '55' * 32}}}
        values = {'/known-public/receipt': campaign.encoded(receipt), inventory_row['path']: inventory_raw,
                  '/public-download-fixture/software.tar': archive, '/public-download-fixture/parameters.pk': pk}
        caller.row = lambda row: values[row['path']]
        caller.public_read = lambda path, pin: campaign.encoded({'pk_sha256': campaign.digest(pk), 'pk_bytes': len(pk)})
        self.assertEqual(len(caller.downloaded_files()), 3)
        del caller._downloaded_files
        receipt['files'][1]['path'] = '/original-service/wallet/worker.py'
        values['/known-public/receipt'] = campaign.encoded(receipt)
        with self.assertRaisesRegex(ValueError, 'exact-unpacked-inventory'):
            caller.downloaded_files()


if __name__ == '__main__':
    unittest.main()
