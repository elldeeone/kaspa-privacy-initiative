"""PUBLIC structural controls; mocked IDs/proofs are never Native/chain evidence."""
from copy import deepcopy
import multiprocessing
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import public
import live_contracts
from journal import Journal, NORMAL
from ledger import complete
from owner_journal import OwnerJournal
from journal_cli import run as record_cli

TRIAL = '75183e58-4fb2-44d9-b09c-172d566bb25c'
PROFILE, DESCRIPTOR, EVIDENCE, SOURCE = ('11' * 32, '22' * 32, '33' * 32, '44' * 32)
P2PK, P2SH = '000020' + '55' * 32 + 'ac', '0000aa20' + '66' * 32 + '87'


def identifier(number):
    return public.digest(('PUBLIC_SYNTHETIC_NOT_SDK_ID_' + str(number)).encode())


def case(number, previous, incoming, outputs, payload):
    inputs = [{'previousOutpoint': point, 'signatureScript': '41' + '00' * 64 + '01',
               'sequence': (1 << 64) - 1, 'computeBudget': 10 if number == 0 else 1500}
              for point in previous]
    return {'transaction': {'version': 1, 'id': identifier(number), 'inputs': inputs,
        'outputs': [{'value': value, 'scriptPublicKey': script, 'covenant': None}
                    for value, script in outputs], 'lockTime': 0, 'subnetworkId': '00' * 20,
        'gas': 0, 'payload': payload.hex(), 'mass': 1},
        'entries': [{'amount': value, 'scriptPublicKey': P2PK if number == 0 else P2SH,
                     'blockDaaScore': 42, 'isCoinbase': False, 'covenantId': None}
                    for value in incoming]}


def route():
    funding = case(0, [{'transactionId': identifier(100 + n), 'index': 0} for n in range(2)],
        [1100, 1100], [(2000, P2SH), (180, P2PK)], b'KPX5GN02' + bytes(1072))
    rows = [('funding', funding)]
    reserve = 2000
    for number, remaining in enumerate((1980, 1480, 980, 480, 0), 1):
        previous = {'transactionId': rows[-1][1]['transaction']['id'], 'index': 0}
        if number == 1:
            outputs, payload = [(remaining, P2SH)], b'KPX5VP01' + bytes(8100)
        else:
            payout = reserve - remaining - 20
            outputs = ([(remaining, P2SH)] if remaining else []) + [(payout, P2PK)]
            payload = b'KPX4AU01' + bytes(2840)
        rows.append((NORMAL[number], case(number, [previous], [reserve], outputs, payload)))
        reserve = remaining
    return rows


def concurrent_reserve(root, queue):
    try:
        journal = Journal(Path(root) / 'journal', TRIAL, PROFILE, DESCRIPTOR,
                          trial_directory=root)
        journal.reserve('funding', route()[0][1], previous_head=None,
                        prior_evidence_sha256=None, submit_source_sha256=SOURCE)
        queue.put('RESERVED')
    except ValueError:
        queue.put('REFUSED')


class PublicJournalControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='four-wallet-live-public-controls-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for role in public.ROLES:
            folder = self.root / 'owners' / role; folder.mkdir(parents=True)
            (folder / 'backup.json').write_bytes(b'PUBLIC_TEST_SENTINEL_NOT_A_KEY_' + role.encode())
        self.journal = Journal(self.root / 'journal', TRIAL, PROFILE, DESCRIPTOR,
                               trial_directory=self.root)

    def reserve(self, stage, value, previous):
        return self.journal.reserve(stage, value, previous_head=previous,
            prior_evidence_sha256=EVIDENCE if previous else None, submit_source_sha256=SOURCE)

    def accept(self, stage, value):
        body = value['transaction']
        remaining = body['outputs'][0]['value'] if body['outputs'][0]['scriptPublicKey'] == P2SH else 0
        return self.journal.record_accepted(stage, value, evidence_sha256=EVIDENCE,
            new_head={'transactionId': body['id'], 'index': 0} if remaining else None,
            remaining_reserve_sompi=remaining,
            native_metrics={'actual_fee_sompi': public.case_summary(value)['fee_sompi']})

    def test_mocked_full_route_closes_all_fees_and_four_payouts(self):
        point = None
        for stage, value in route():
            self.reserve(stage, value, point)
            receipt = self.accept(stage, value); point = receipt['new_head']
        result = complete(self.journal.accepted_cases())
        self.assertEqual(result['source_sompi'], 2200)
        self.assertEqual(result['ordinary_change_sompi'], 180)
        self.assertEqual(result['native_payouts_sompi'], 1900)
        self.assertEqual(result['total_fee_sompi'], 120)
        self.assertEqual(result['payout_count'], 4)
        self.assertFalse(result['accepted_consensus_backup_ownership_or_privacy_verified_by_this_function'])

    def test_unknown_response_cannot_resubmit_or_modify_intent(self):
        value = route()[0][1]; self.reserve('funding', value, None)
        before = (self.journal.intents / 'funding.json').read_bytes()
        result = self.journal.submission_result('funding', value['transaction']['id'], acknowledged=False)
        self.assertEqual(result['status'], 'RECONCILE_READ_ONLY')
        self.assertFalse(result['accepted_or_confirmed'])
        with self.assertRaises(ValueError): self.reserve('funding', value, None)
        self.assertEqual((self.journal.intents / 'funding.json').read_bytes(), before)

    def test_SDK_candidate_exact_unsigned_fields_and_context_join_before_intent(self):
        value = route()[0][1]
        case_raw = public.encoded(value)
        case_path = self.root / 'public-case.json'; case_path.write_bytes(case_raw)
        body = deepcopy(value['transaction'])
        for item in body['inputs']: item['sequence'] = str(item['sequence'])
        for item in body['outputs']: item['value'] = str(item['value'])
        for name in ('lockTime', 'gas'): body[name] = str(body[name])
        body['storageMass'] = str(body.pop('mass'))
        summary = public.case_summary(value)
        candidate = {'schema': 'kpx6-four-wallet-public-SDK-candidate/v1',
            'trial_id': TRIAL, 'stage': 'funding', 'financial_profile_sha256': PROFILE,
            'descriptor_sha256': DESCRIPTOR, 'case_file_sha256': public.digest(case_raw),
            'canonical_case_sha256': summary['case_sha256'],
            'financial_projection_sha256': summary['financial_projection_sha256'],
            'transaction': body, 'contexts': [{'amount_sompi': str(row['amount']),
                'script_public_key': row['scriptPublicKey'], 'block_daa_score': str(row['blockDaaScore']),
                'is_coinbase': False, 'covenant_id': None} for row in value['entries']],
            'previous_head': None, 'prior_evidence_sha256': None}
        candidate_path = self.root / 'public-sdk-candidate.json'
        source = public.read_stable_public(public.ROOT / 'poc/four-wallet-live/submit.mjs', self.root)
        args = SimpleNamespace(trial_directory=self.root, case=case_path,
            case_sha256=public.digest(case_raw), sdk_candidate=candidate_path,
            trial_id=TRIAL, stage='funding', financial_sha256=PROFILE,
            descriptor_sha256=DESCRIPTOR, journal=self.journal.directory, owner_attempt=None,
            operation='reserve', submit_source_sha256=public.digest(source))
        mutations = [lambda v: v['transaction']['inputs'][0].update(computeBudget=11),
            lambda v: v['transaction']['inputs'][0].update(signatureScript='00'),
            lambda v: v['contexts'][0].update(block_daa_score='43'),
            lambda v: v['transaction']['inputs'][0].update(sequence=18446744073709551615)]
        for mutate in mutations:
            changed = deepcopy(candidate); mutate(changed)
            raw = public.encoded(changed); candidate_path.write_bytes(raw)
            args.sdk_candidate_sha256 = public.digest(raw)
            with self.assertRaises(ValueError): record_cli(args)
            self.assertFalse((self.journal.intents / 'funding.json').exists())
        raw = public.encoded(candidate); candidate_path.write_bytes(raw)
        args.sdk_candidate_sha256 = public.digest(raw)
        self.assertEqual(record_cli(args)['status'], 'RESERVED_NEVER_RESUBMIT')

    def test_public_SDK_staging_excludes_fourth_backup_before_any_member_read(self):
        sdk = self.root / 'software' / 'runtime-sdk'; sdk.mkdir(parents=True)
        members = {'kaspa.js': b'PUBLIC_FAKE_SDK_JS', 'kaspa_bg.wasm': b'PUBLIC_FAKE_WASM',
                   'package.json': b'{}'}
        pins = {name: public.digest(raw) for name, raw in members.items()}
        for name, raw in members.items(): (sdk / name).write_bytes(raw)
        (sdk / 'kaspa_bg.wasm').unlink()
        (sdk / 'kaspa_bg.wasm').hardlink_to(self.root / 'owners' / 'D' / 'backup.json')
        with patch.object(live_contracts, 'SDK_PINS', pins), \
             patch.object(live_contracts, 'read_public', side_effect=AssertionError('no member read')):
            with self.assertRaises(ValueError):
                live_contracts.stage_sdk(self.root / 'software', self.root / 'staged-SDK', self.root)
        self.assertFalse((self.root / 'staged-SDK').exists())

    def test_concurrent_processes_reserve_only_one_network_attempt(self):
        context = multiprocessing.get_context('fork'); queue = context.Queue()
        children = [context.Process(target=concurrent_reserve, args=(str(self.root), queue)) for _ in range(2)]
        for child in children: child.start()
        for child in children: child.join(10); self.assertEqual(child.exitcode, 0)
        self.assertEqual(sorted(queue.get(timeout=1) for _ in children), ['REFUSED', 'RESERVED'])

    def test_same_transaction_id_cannot_be_sent_under_another_stage(self):
        rows = route(); self.reserve('funding', rows[0][1], None); self.accept('funding', rows[0][1])
        changed = deepcopy(rows[1][1]); changed['transaction']['id'] = rows[0][1]['transaction']['id']
        with self.assertRaises(ValueError):
            self.reserve('settlement', changed, rows[1][1]['transaction']['inputs'][0]['previousOutpoint'])

    def test_corrupt_intent_blocks_all_further_attempts(self):
        (self.journal.intents / 'funding.json').write_bytes(b'{')
        with self.assertRaises(ValueError): self.reserve('funding', route()[0][1], None)
        self.assertEqual((self.journal.intents / 'funding.json').read_bytes(), b'{')

    def test_wrong_trial_or_financial_identity_refused(self):
        for identity in ('aa' * 32, 'bb' * 32):
            with self.assertRaises(ValueError):
                Journal(self.journal.directory, TRIAL, identity, DESCRIPTOR, trial_directory=self.root)

    def test_structural_variant_correspondence_preserves_intent_pending_native_precondition(self):
        value = route()[0][1]; self.reserve('funding', value, None)
        before = (self.journal.intents / 'funding.json').read_bytes()
        changed = deepcopy(value)
        changed['transaction']['inputs'][0]['computeBudget'] = 11
        changed['transaction']['inputs'][0]['signatureScript'] = '41' + '12' * 64 + '01'
        # This reducer test does NOT claim the mock signature is Native-valid.
        receipt = self.accept('funding', changed)
        self.assertEqual(receipt['byte_correspondence'], 'INTENT_VS_ACCEPTED_BYTES_DIFFER')
        self.assertNotEqual(receipt['intent_case_sha256'], receipt['accepted_case_sha256'])
        self.assertEqual((self.journal.intents / 'funding.json').read_bytes(), before)

    def test_changed_financial_effects_never_reconcile(self):
        value = route()[0][1]; self.reserve('funding', value, None)
        mutations = [lambda v: v['transaction']['outputs'][1].update(value=179),
            lambda v: v['entries'][0].update(amount=1101),
            lambda v: v['transaction'].update(gas=1),
            lambda v: v['entries'][0].update(blockDaaScore=43)]
        for mutate in mutations:
            changed = deepcopy(value); mutate(changed)
            with self.assertRaises(ValueError): self.accept('funding', changed)

    def test_stale_head_and_unaccepted_predecessor_refused(self):
        rows = route(); self.reserve('funding', rows[0][1], None)
        with self.assertRaises(ValueError):
            self.reserve('settlement', rows[1][1], rows[1][1]['transaction']['inputs'][0]['previousOutpoint'])
        self.accept('funding', rows[0][1])
        with self.assertRaises(ValueError):
            self.reserve('settlement', rows[1][1], {'transactionId': identifier(999), 'index': 0})

    def test_incomplete_or_extra_route_is_not_fee_closure(self):
        for rows in (route()[:-1], route() + [route()[-1]]):
            with self.assertRaises(ValueError): complete(rows)

    def test_all_four_backup_aliases_rejected_before_read(self):
        for role in public.ROLES:
            source = self.root / ('alias-' + role); os.link(self.root / 'owners' / role / 'backup.json', source)
            with patch.object(public.os, 'fdopen') as read:
                with self.assertRaises(ValueError): public.read_public(source, '00' * 32, self.root)
                read.assert_not_called()

    def test_hardlink_swap_between_metadata_and_open_reads_zero_backup_bytes(self):
        source = self.root / 'public.json'; source.write_bytes(b'PUBLIC_SELECTED')
        original_open, original_fdopen = os.open, os.fdopen
        def swap(path, flags, *args, **kwargs):
            if Path(path) == source:
                source.unlink(); os.link(self.root / 'owners' / 'D' / 'backup.json', source)
            return original_open(path, flags, *args, **kwargs)
        with patch.object(public.os, 'open', side_effect=swap), \
             patch.object(public.os, 'fdopen', wraps=original_fdopen) as read:
            with self.assertRaises(ValueError): public.read_public(source, public.digest(b'PUBLIC_SELECTED'), self.root)
            read.assert_not_called()

    def test_independent_owner_attempt_needs_no_coordinator_journal(self):
        value = route()[2][1]; previous = value['transaction']['inputs'][0]['previousOutpoint']
        owner = OwnerJournal(self.root / 'standalone-owner-attempt', TRIAL, PROFILE, DESCRIPTOR,
            trial_directory=self.root, previous_head=previous, prior_evidence_sha256=EVIDENCE)
        intent = owner.reserve(value, SOURCE)
        self.assertFalse(intent['operator_journal_or_other_owner_data_required'])
        result = owner.submission_result(value['transaction']['id'], False)
        self.assertEqual(result['status'], 'RECONCILE_READ_ONLY')
        with self.assertRaises(ValueError): owner.reserve(value, SOURCE)


if __name__ == '__main__':
    unittest.main()
