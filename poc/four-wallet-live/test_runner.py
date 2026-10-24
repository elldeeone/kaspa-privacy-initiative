"""PUBLIC SYNTHETIC orchestration controls; no SDK/Native/chain execution.

Only public sentinels are placed at backup-shaped fixture paths. The selected
software authentication, accepted-history replay and native validation APIs are
mocked. These controls establish refusal/correspondence ordering in the runner,
not the truth of a financial proof or an actual testnet transaction.
"""
from copy import deepcopy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from journal import Journal
from owner_journal import OwnerJournal
import public
import runner
from test_journal import EVIDENCE, P2SH, SOURCE, TRIAL, route


class PublicFixture:
    def __init__(self, root, *, owner=False):
        self.root = root
        for role in public.ROLES:
            path = root / 'owners' / role / 'backup.json'
            path.parent.mkdir(parents=True)
            path.write_bytes(b'PUBLIC_SYNTHETIC_SENTINEL_' + role.encode())
        self.cases = [case for _, case in route()[:3 if owner else 1]]
        profile = b'PUBLIC_SYNTHETIC_FINANCIAL_NOT_REAL'
        profile_sha = public.digest(profile)
        descriptor = public.encoded({'trial_id': TRIAL, 'financial_profile_sha256': profile_sha})
        descriptor_sha = public.digest(descriptor)
        self.page = root / 'pages' / '0000.json.gz'
        self.page.parent.mkdir()
        page = b'PUBLIC_SYNTHETIC_FULL_PAGE_NOT_REAL'
        self.page.write_bytes(page)
        self.bundle = {'pages': [{'path': 'pages/0000.json.gz',
            'gzip_sha256': public.digest(page), 'gzip_bytes': len(page)}],
            'current_view': {'post_query_delta': {'pages': []}},
            'transactions': [{'case': case} for case in self.cases]}
        for name, raw in (('profile.json', profile), ('descriptor.json', descriptor),
                          ('inventory.json', b'{}')):
            (root / name).write_bytes(raw)
        self.args = SimpleNamespace(trial_directory=root, trial_id=TRIAL,
            financial_profile=root / 'profile.json', financial_sha256=profile_sha,
            descriptor=root / 'descriptor.json', descriptor_sha256=descriptor_sha,
            fetch=root / 'fetch.json', fetch_sha256=None,
            inventory=root / 'inventory.json', inventory_sha256=public.digest(b'{}'),
            bundle_directory=root, software_root=root / 'software',
            output=root / 'output', stage='owner-exit' if owner else 'funding',
            journal=None if owner else root / 'journal',
            owner_attempt=root / 'owner-attempt' if owner else None)
        self.save_bundle()
        self.events = []
        self.reject_replay = False
        if owner:
            head = self.cases[-1]['transaction']['inputs'][0]['previousOutpoint']
            self.tracker = OwnerJournal(self.args.owner_attempt, TRIAL, profile_sha,
                descriptor_sha, trial_directory=root, previous_head=head,
                prior_evidence_sha256=EVIDENCE)
            self.tracker.reserve(self.cases[-1], SOURCE)
        else:
            self.tracker = Journal(self.args.journal, TRIAL, profile_sha,
                                   descriptor_sha, trial_directory=root)
            self.tracker.reserve('funding', self.cases[0], previous_head=None,
                prior_evidence_sha256=None, submit_source_sha256=SOURCE)

    def save_bundle(self):
        raw = public.encoded(self.bundle)
        self.args.fetch.write_bytes(raw)
        self.args.fetch_sha256 = public.digest(raw)

    @staticmethod
    def native_case(row):
        value = deepcopy(row['case'])
        contexts = [{'amount_sompi': str(entry['amount']),
            'script_public_key': entry['scriptPublicKey'],
            'block_daa_score': str(entry['blockDaaScore']),
            'is_coinbase': False, 'covenant_id': None} for entry in value['entries']]
        return value, contexts

    @staticmethod
    def metrics(body, contexts):
        return {'actual_fee_sompi': sum(int(row['amount_sompi']) for row in contexts)
                - sum(row['value'] for row in body['outputs'])}

    def normalize(self, body, contexts, output):
        self.events.append('MOCK_NATIVE_NORMALIZE')
        return body, self.metrics(body, contexts)

    def sdk(self, body, contexts):
        self.events.append('MOCK_SDK')

    def validate(self, body, contexts, output):
        self.events.append('MOCK_NATIVE_FULL')
        return {'all_input_engines_accepted': True}, self.metrics(body, contexts)

    def replay_bundle(self, *args, **kwargs):
        self.events.append('MOCK_COMPLETE_ACCEPTED_REPLAY')
        if self.reject_replay:
            raise ValueError('PUBLIC_SYNTHETIC_REPLAY_REFUSAL')
        body = self.cases[-1]['transaction']
        remaining = body['outputs'][0]['value'] if body['outputs'][0]['scriptPublicKey'] == P2SH else 0
        return {'trial_id': TRIAL, 'accepted_chain_backing_verified': True,
            'currentness_verified': True,
            'entry': {'founding_outpoint': {'transactionId': self.cases[0]['transaction']['id'], 'index': 0},
                      'reserve_sompi': 2000, 'snapshot': {}},
            'reserve': remaining, 'payouts': [], 'observation_checkpoint': {},
            'currentness_scope': 'PUBLIC_SYNTHETIC_NOT_CHAIN'}

    def run(self):
        chain = SimpleNamespace(bundle_public_files=lambda *args: (self.page,),
            native_case=self.native_case, replay_bundle=self.replay_bundle)
        with patch.object(runner, 'authenticate_tree', return_value=(
                self.root / 'selected-source', self.root / 'runtime', {})), \
             patch.object(runner, 'public_runtime', return_value=(object(), self, chain)):
            with patch.object(runner, 'stage_sdk', return_value=self.root / 'MOCK_SELECTED_SDK'):
                return runner.reconcile(self.args)


class SyntheticPublicRunnerControls(unittest.TestCase):
    def fixture(self, *, owner=False):
        temporary = tempfile.TemporaryDirectory(prefix='four-wallet-public-runner-controls-')
        self.addCleanup(temporary.cleanup)
        return PublicFixture(Path(temporary.name), owner=owner)

    def test_mock_variant_records_only_after_replay_and_native_with_immutable_intent(self):
        f = self.fixture()
        intent = (f.tracker.intents / 'funding.json').read_bytes()
        body = f.bundle['transactions'][0]['case']['transaction']
        body['inputs'][0]['computeBudget'] = 11
        body['inputs'][0]['signatureScript'] = 'aa'
        f.save_bundle()
        result = f.run()
        self.assertEqual(result['byte_correspondence'], 'INTENT_VS_ACCEPTED_BYTES_DIFFER')
        self.assertEqual((f.tracker.intents / 'funding.json').read_bytes(), intent)
        self.assertEqual(f.events, ['MOCK_COMPLETE_ACCEPTED_REPLAY', 'MOCK_NATIVE_NORMALIZE',
                                    'MOCK_SDK', 'MOCK_NATIVE_FULL'])
        self.assertFalse(result['workflow_readiness_or_privacy_qualification'])

    def test_mock_complete_replay_refusal_cannot_create_accepted_receipt(self):
        f = self.fixture()
        f.reject_replay = True
        with self.assertRaises(ValueError):
            f.run()
        self.assertEqual(list(f.tracker.receipts.iterdir()), [])
        self.assertEqual(f.events, ['MOCK_COMPLETE_ACCEPTED_REPLAY'])

    def test_mock_accepted_changed_financial_effects_cannot_create_receipt(self):
        f = self.fixture()
        f.bundle['transactions'][0]['case']['transaction']['outputs'][1]['value'] -= 1
        f.save_bundle()
        with self.assertRaises(ValueError):
            f.run()
        self.assertEqual(list(f.tracker.receipts.iterdir()), [])
        self.assertEqual(f.events, ['MOCK_COMPLETE_ACCEPTED_REPLAY'])

    def test_standalone_owner_attempt_needs_no_campaign_journal(self):
        f = self.fixture(owner=True)
        result = f.run()
        self.assertEqual(result['status'], 'ACTUAL_ACCEPTED_PREFIX_RECONCILED')
        self.assertTrue((f.args.owner_attempt / 'ACCEPTED.json').is_file())
        self.assertFalse((f.root / 'journal').exists())

    def test_retained_page_alias_to_fourth_public_backup_sentinel_refuses_before_replay(self):
        f = self.fixture()
        f.page.unlink()
        f.page.hardlink_to(f.root / 'owners' / 'D' / 'backup.json')
        with self.assertRaises(ValueError):
            f.run()
        self.assertEqual(list(f.tracker.receipts.iterdir()), [])
        self.assertEqual(f.events, [])


if __name__ == '__main__':
    unittest.main()
