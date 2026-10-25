"""Synthetic adapter joins, never an execution or chain-acceptance claim."""
from copy import deepcopy
from types import SimpleNamespace
import unittest

import campaign
from codec import canonical_json, parse_json, sha
import public
from test_history import fixture, batch_projection


class MemoryIngress:
    def __init__(self):
        self.files = {}

    def put(self, name, value):
        raw = value if type(value) is bytes else canonical_json(value)
        self.files[name] = raw
        return [name, sha(raw)]

    def read(self, path, expected):
        raw = self.files[path]
        public.need(sha(raw) == expected, 'test-external-hash')
        return raw


def selected_fixture():
    ingress = MemoryIngress()
    previous, roster = fixture()
    transition = batch_projection(previous, 0, roster)
    history = public.extend(previous, transition)
    txid = history['head']['outpoint_hex36'][:64]
    point = {'transactionId': txid, 'index': 0}
    entry = {'amount': history['head']['reserve_sompi'], 'blockDaaScore': 600000000,
             'scriptPublicKey': public.load_wire().state_spk(bytes.fromhex(history['head']['state_hex112']), b'\x75').hex(),
             'isCoinbase': False, 'covenantId': None}
    observed = {'outpoint': point, 'amount_sompi': str(entry['amount']),
                'script_public_key': entry['scriptPublicKey'], 'block_daa_score': '600000000',
                'is_coinbase': False, 'covenant_id': None}
    page = b'public synthetic compressed-page stand-in; no real chain proof'
    ingress.put('/prefix/page.gz', page)
    fetch = {'transactions': [{'transaction': {'id': previous['head']['outpoint_hex36'][:64], 'inputs': []}},
                              {'transaction': {'id': txid, 'inputs': []}}],
             'pages': [{'path': 'page.gz', 'gzip_sha256': sha(page), 'gzip_bytes': len(page)}],
             'current_view': {'queries': [{'outpoint': point, 'queried': True, 'entry': observed}],
                              'post_query_delta': {'pages': []}}}
    values = {'HISTORY.json': history, 'CHECKPOINT.json': history['head'],
              'fetch.json': fetch, 'CURRENT-ENTRY.json': {'outpoint': point, 'entry': entry},
              'selection': {'financial_profile_sha256': campaign.PROFILE, 'native_tail_hex': '75'},
              'descriptor': {'trial_id': 'synthetic-trial'}, 'parameters': {},
              'sessions': [transition['session']], 'source_pins': {}}
    selectors = {name: dict(zip(('path', 'sha256'), ingress.put('/prefix/' + name, value)))
                 for name, value in values.items()}
    report = {'schema': 'kpx8-accepted-native-replay/v1', 'status': campaign.STATUS,
              'financial_profile_sha256': campaign.PROFILE,
              'genesis_rederived_from_public_notes_and_native_backing': True,
              'all_native_Full_and_input_engines_executed': True,
              'current_checkpoint': history['head'], 'history_sha256': selectors['HISTORY.json']['sha256'],
              'fetch_sha256': selectors['fetch.json']['sha256'],
              'descriptor_sha256': selectors['descriptor']['sha256'],
              'selection_file_sha256': selectors['selection']['sha256'],
              'transactions': [{'transaction_id': row['transaction']['id'],
                                'native_full_and_all_input_engines_passed': True}
                               for row in fetch['transactions']],
              'payouts': [], 'observed_total_fee_sompi': 30000000}
    selectors['RESULTS.json'] = dict(zip(('path', 'sha256'), ingress.put('/prefix/RESULTS.json', report)))
    handoff = {'schema': 'kpx8-confirmed-transition-handoff/v1', 'status': campaign.STATUS,
               'financial_profile_sha256': campaign.PROFILE, 'trial_id': 'synthetic-trial',
               'expected_transaction_id': txid, 'accepted_transactions': 2,
               'checkpoint': history['head'], 'terminal': False, 'native_payouts_observed': [],
               'automatic_resubmission_permitted': False, 'submission_performed': False,
               'independent_consensus_or_continuous_currentness': False,
               'selectors': selectors, 'full_prefix_pages': [{'path': '/prefix/page.gz',
                   'sha256': sha(page), 'bytes': len(page)}], 'observed_total_fee_sompi': 30000000}
    kwargs = {'trial_id': 'synthetic-trial', 'expected_txid': txid, 'transition_count': 1,
              'tail_hex': '75', 'previous_history': ingress.put('/previous', previous),
              'prepared_projection': ingress.put('/prepared', bytes.fromhex(transition['projection_hex']))}
    return SimpleNamespace(ingress=ingress), handoff, kwargs


class CampaignTests(unittest.TestCase):
    def invoke(self, runner, handoff, kwargs):
        return campaign.confirmed(runner, runner.ingress.put('/handoff', handoff), **kwargs)

    def test_all_selected_links_and_actual_entry_agree(self):
        runner, handoff, kwargs = selected_fixture()
        result = self.invoke(runner, handoff, kwargs)
        self.assertEqual(result['current_entry']['entry']['blockDaaScore'], 600000000)

    def test_identity_count_terminal_or_retry_flags_cannot_be_forged(self):
        for key, bad in [('trial_id', 'other'), ('expected_transaction_id', '00' * 32),
                         ('accepted_transactions', 3), ('terminal', True),
                         ('automatic_resubmission_permitted', True), ('submission_performed', True)]:
            with self.subTest(key=key):
                runner, handoff, kwargs = selected_fixture()
                handoff[key] = bad
                with self.assertRaises(ValueError): self.invoke(runner, handoff, kwargs)

    def test_every_input_hash_and_full_page_is_required(self):
        for name in campaign.SELECTORS:
            with self.subTest(name=name):
                runner, handoff, kwargs = selected_fixture()
                runner.ingress.files[handoff['selectors'][name]['path']] += b' '
                with self.assertRaises(ValueError): self.invoke(runner, handoff, kwargs)
        for operation in ('remove', 'corrupt', 'wrong-length'):
            runner, handoff, kwargs = selected_fixture()
            if operation == 'remove': handoff['full_prefix_pages'] = []
            elif operation == 'corrupt': runner.ingress.files['/prefix/page.gz'] += b'x'
            else: handoff['full_prefix_pages'][0]['bytes'] += 1
            with self.assertRaises(ValueError): self.invoke(runner, handoff, kwargs)

    def test_candidate_and_predecessor_must_be_exact(self):
        runner, handoff, kwargs = selected_fixture()
        kwargs['prepared_projection'] = runner.ingress.put('/other', b'wrong candidate')
        with self.assertRaises(ValueError): self.invoke(runner, handoff, kwargs)
        runner, handoff, kwargs = selected_fixture()
        previous = parse_json(runner.ingress.read(*kwargs['previous_history']))
        previous['genesis']['reserve_sompi'] += 1
        kwargs['previous_history'] = runner.ingress.put('/other', previous)
        with self.assertRaises(ValueError): self.invoke(runner, handoff, kwargs)

    def test_selected_entry_must_equal_fresh_fetch_birth_DAA(self):
        runner, handoff, kwargs = selected_fixture()
        entry = parse_json(runner.ingress.files['/prefix/CURRENT-ENTRY.json'])
        entry['entry']['blockDaaScore'] += 1
        handoff['selectors']['CURRENT-ENTRY.json'] = dict(zip(('path', 'sha256'),
            runner.ingress.put('/prefix/CURRENT-ENTRY.json', entry)))
        with self.assertRaises(ValueError): self.invoke(runner, handoff, kwargs)


if __name__ == '__main__': unittest.main()
