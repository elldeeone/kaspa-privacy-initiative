"""Accepted-prefix gates and fresh owner orchestration for the live rehearsal.

This controller never submits. A candidate cannot advance its input history:
only a byte-selected result of the reviewed fresh fetch/replay adapter can.
UNKNOWN submissions therefore use that adapter again, never a submit retry.
"""
from pathlib import Path
import argparse
import os

from exits import ready_export
from backend import write
from codec import canonical_json, parse_json, sha
from public import DOMAIN, current_entry_context, fields, hx, need, reconstruct
from rounds import run as mixed_round, selected

PROFILE = '69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f'
STATUS = 'RECORDED_VALIDATING_NODE_PREFIX_FINANCIAL_AND_NATIVE_PASS'
SELECTORS = {'HISTORY.json', 'CHECKPOINT.json', 'RESULTS.json', 'fetch.json',
             'CURRENT-ENTRY.json', 'selection', 'descriptor', 'parameters', 'sessions', 'source_pins'}


def confirmed(runner, handoff_selector, *, trial_id, expected_txid, transition_count,
              tail_hex, previous_history=None, prepared_projection=None):
    """Join one actual replay, its complete acquisition and the exact candidate.

    The external caller selects the handoff from the reviewed confirmation
    adapter. Status booleans alone are insufficient: every referenced public
    input/output/page is authenticated and the candidate/predecessor join is
    checked before any owner operation is allowed.
    """
    handoff = parse_json(runner.ingress.read(*handoff_selector))
    need(handoff['schema'] == 'kpx8-confirmed-transition-handoff/v1'
         and handoff['status'] == STATUS and handoff['financial_profile_sha256'] == PROFILE
         and handoff['trial_id'] == trial_id and handoff['expected_transaction_id'] == expected_txid,
         'selected-actual-confirmation-identity')
    hx(expected_txid, 32)
    need(type(transition_count) is int and 1 <= transition_count <= 11
         and type(handoff['accepted_transactions']) is int
         and handoff['accepted_transactions'] == transition_count + 1,
         'exact-accepted-transition-count')
    need(handoff['automatic_resubmission_permitted'] is False
         and handoff['submission_performed'] is False
         and handoff['independent_consensus_or_continuous_currentness'] is False,
         'read-only-node-observation-boundary')
    need(set(handoff['selectors']) == SELECTORS, 'complete-confirmation-selectors')
    raw, values = {}, {}
    for name, selector in handoff['selectors'].items():
        fields(selector, ('path', 'sha256'), 'exact-confirmation-selector')
        raw[name] = runner.ingress.read(selector['path'], selector['sha256'])
        values[name] = parse_json(raw[name])
    history, checkpoint, report, fetch = (values[name] for name in
        ('HISTORY.json', 'CHECKPOINT.json', 'RESULTS.json', 'fetch.json'))
    reconstruct(history)
    need(history['head'] == checkpoint == handoff['checkpoint'] == report['current_checkpoint'],
         'actual-replay-history-and-checkpoint-join')
    need(len(history['transitions']) == transition_count
         and report['schema'] == 'kpx8-accepted-native-replay/v1' and report['status'] == STATUS
         and report['financial_profile_sha256'] == PROFILE
         and report['genesis_rederived_from_public_notes_and_native_backing'] is True
         and report['all_native_Full_and_input_engines_executed'] is True
         and report['history_sha256'] == sha(raw['HISTORY.json'])
         and report['fetch_sha256'] == sha(raw['fetch.json'])
         and report['descriptor_sha256'] == sha(raw['descriptor'])
         and report['selection_file_sha256'] == sha(raw['selection']),
         'fixed-full-native-financial-replay-and-input-identities')
    need(values['descriptor']['trial_id'] == trial_id
         and values['selection']['financial_profile_sha256'] == PROFILE
         and values['selection']['native_tail_hex'] == tail_hex,
         'actual-founding-descriptor-and-financial-selection')
    transactions = report['transactions']
    need(len(transactions) == len(fetch['transactions']) == transition_count + 1
         and all(row['native_full_and_all_input_engines_passed'] is True for row in transactions)
         and [row['transaction_id'] for row in transactions]
             == [row['transaction']['id'] for row in fetch['transactions']]
         and transactions[-1]['transaction_id'] == expected_txid,
         'all-actual-accepted-transactions-native-checked')
    sessions = values['sessions']
    need(type(sessions) is list, 'complete-selected-public-session-list')
    session_hashes = [sha(canonical_json(value)) for value in sessions]
    need(len(session_hashes) == len(set(session_hashes))
         and all(sha(canonical_json(row['session'])) in session_hashes
                 for row in history['transitions'] if row['kind'] == 'batch'),
         'every-accepted-batch-public-session-selected')
    expected_pages = [*fetch['pages'], *fetch['current_view']['post_query_delta']['pages']]
    pages = handoff['full_prefix_pages']
    need(len(pages) == len(expected_pages) and len(pages) > 0, 'complete-full-prefix-page-set')
    fetch_directory = Path(handoff['selectors']['fetch.json']['path']).parent
    for page, expected in zip(pages, expected_pages):
        fields(page, ('path', 'sha256', 'bytes'), 'exact-full-prefix-page-selector')
        need(Path(page['path']) == fetch_directory / expected['path']
             and page['sha256'] == expected['gzip_sha256'] and type(page['bytes']) is int
             and page['bytes'] == expected['gzip_bytes'], 'full-prefix-page-fetch-join')
        need(len(runner.ingress.read(page['path'], page['sha256'])) == page['bytes'],
             'authenticated-complete-full-prefix-page')
    if previous_history is not None:
        previous = parse_json(runner.ingress.read(*previous_history))
        need(history['genesis'] == previous['genesis']
             and history['transitions'][:-1] == previous['transitions']
             and len(previous['transitions']) + 1 == transition_count,
             'accepted-prefix-exactly-extends-selected-predecessor')
    if prepared_projection is not None:
        projection = runner.ingress.read(*prepared_projection)
        need(history['transitions'][-1]['projection_hex'] == projection.hex(),
             'exact-prepared-projection-in-actual-accepted-prefix')
    current = values['CURRENT-ENTRY.json']
    queries = {}
    for row in fetch['current_view']['queries']:
        point = row['outpoint']
        hx(point['transactionId'], 32)
        need(type(point['index']) is int and 0 <= point['index'] < 1 << 32
             and row['queried'] is True, 'actual-exact-outpoint-query')
        key = point['transactionId'] + point['index'].to_bytes(4, 'little').hex()
        need(key not in queries, 'distinct-actual-currentness-query')
        queries[key] = row
    for row in fetch['transactions']:
        for item in row['transaction']['inputs']:
            point = item['previousOutpoint']
            key = point['transactionId'] + point['index'].to_bytes(4, 'little').hex()
            need(key in queries and queries[key]['entry'] is None, 'accepted-predecessor-input-spent')
    terminal = checkpoint['outpoint_hex36'] is None
    need(handoff['terminal'] is terminal, 'explicit-terminal-observation')
    if terminal:
        need(current is None and checkpoint['reserve_sompi'] == 0, 'actual-terminal-zero-reserve')
    else:
        current_entry_context(history, tail_hex, current)
        need(current['outpoint']['transactionId'] == expected_txid,
             'newly-accepted-head-current-entry')
        observed = queries.get(checkpoint['outpoint_hex36'])
        need(observed is not None and observed['entry'] is not None,
             'newly-accepted-head-actually-queried')
        observed = observed['entry']
        need(observed['outpoint'] == current['outpoint']
             and str(current['entry']['amount']) == observed['amount_sompi']
             and str(current['entry']['blockDaaScore']) == observed['block_daa_score']
             and current['entry']['scriptPublicKey'] == observed['script_public_key']
             and observed['is_coinbase'] is False and observed['covenant_id'] is None,
             'selected-current-entry-exact-fresh-node-query')
    payouts = report['payouts']
    need(len(payouts) == len(handoff['native_payouts_observed']), 'all-payouts-observed')
    for payout, actual in zip(payouts, handoff['native_payouts_observed']):
        point = {'transactionId': payout['transaction_id'], 'index': payout['output_index']}
        key = point['transactionId'] + point['index'].to_bytes(4, 'little').hex()
        queried = queries.get(key)
        need(queried is not None and queried['entry'] is not None
             and actual['outpoint'] == point
             and actual['entry']['amount'] == payout['payout_sompi']
             and actual['entry']['scriptPublicKey'] == payout['script_public_key']
             and queried['entry']['amount_sompi'] == str(payout['payout_sompi'])
             and queried['entry']['script_public_key'] == payout['script_public_key'],
             'every-confirmed-native-payout-exact-query')
    need(handoff['observed_total_fee_sompi'] == report['observed_total_fee_sompi'],
         'accepted-fee-ledger-join')
    return {'handoff': handoff, 'history': history, 'history_selector':
            [handoff['selectors']['HISTORY.json']['path'], sha(raw['HISTORY.json'])],
            'checkpoint': checkpoint, 'current_entry': current,
            'current_entry_selector': [handoff['selectors']['CURRENT-ENTRY.json']['path'],
                                       sha(raw['CURRENT-ENTRY.json'])]}


def restore_public(raw, kind, participant):
    value = parse_json(raw)
    fields(value, ('schema', 'domain_hex32', 'participant_id_hex32', 'seed_only', 'private_maps_imported'),
           'exact-fresh-seed-restore-result')
    need(value['schema'] == 'kpx8-owner-restored/v1' and value['domain_hex32'] == DOMAIN.hex()
         and value['participant_id_hex32'] == participant and value['seed_only'] is True
         and value['private_maps_imported'] is False, 'one-original-seed-only-fresh-restore')
    return value


def cold_round2(runner, accepted, assets_selector, native_selection, owners, original_private, engine_root):
    """Three fresh clients are restored only after actual accepted R1 replay."""
    need(len(accepted['history']['transitions']) == 1
         and accepted['current_entry'] is not None, 'actual-confirmed-round1-required-before-restores')
    runner.initialize_directories()
    outputs = [runner.public / ('restore-%d' % index) for index in range(3)]
    for output in outputs:
        runner.ingress.register(output, 'restore')
    commands = [runner.wallet_command('restore', index, outputs[index],
        runner.private / 'controller' / ('restore-%d' % index), ['--backup',
            str(Path(original_private) / ('party-%d' % index) / 'owner/BACKUP.json')]) for index in range(3)]
    runner.stage('accepted-r1-seed-restores', commands)
    receipts = []
    for index, output in enumerate(outputs):
        _, selector = runner.ingress.promote(output, runner.public / ('RESTORE-%d.json' % index),
            lambda raw, kind, index=index: restore_public(raw, kind, owners[index]['participant_id_hex32']))
        receipts.append(selector)
    write(runner.public / 'COLD-RESTORES.json', canonical_json({
        'schema': 'kpx8-accepted-round1-fresh-restores/v1', 'restores': receipts,
        'accepted_history': accepted['history_selector'], 'seed_only': True,
        'original_seed_bytes_read_or_hashed_by_supervisor': 0}))
    return mixed_round(runner, 'round-02', accepted['history_selector'], assets_selector,
        native_selection, owners, engine_root, 200_000_000,
        ['received-or-change', 'change', 'received-or-change'], current_entry=accepted['current_entry'])


class ExitSequence:
    """One candidate at a time; no virtual histories, network writes or retry."""
    def __init__(self, accepted_round2):
        state, head = reconstruct(accepted_round2['history'])
        need(len(accepted_round2['history']['transitions']) == 2
             and (len(state.cms), len(state.entries)) == (15, 7)
             and head['reserve_sompi'] > 0, 'actual-accepted-round2-nine-unspent-notes')
        self.accepted = accepted_round2
        self.next_owner = 0
        self.pending = None
        self.completed = []
        self.empty = set()

    def owner_ready(self, raw, participant, owner_index):
        need(self.pending is None and type(owner_index) is int and 0 <= owner_index < 3,
             'one-candidate-only-at-current-accepted-head')
        value = ready_export(raw, 'exit-ready', participant, self.accepted['history_selector'][1])
        if value['schema'] == 'kpx8-owner-no-unspent-claim/v1':
            need(owner_index not in self.empty, 'distinct-empty-probe-at-this-head')
            self.empty.add(owner_index)
            need(len(self.empty) < 3 or len(self.completed) == 9, 'nonterminal-claims-cannot-disappear')
            return False
        self.pending = {'owner': owner_index, 'ready': value}
        return True

    def candidate(self, transaction_id, projection_selector):
        need(self.pending is not None and 'transaction_id' not in self.pending,
             'one-fresh-genuine-exit-candidate')
        hx(transaction_id, 32)
        self.pending.update(transaction_id=transaction_id, projection=projection_selector)

    def advance(self, actual):
        need(self.pending is not None and 'transaction_id' in self.pending,
             'candidate-must-be-prepared-before-confirmation')
        pending = self.pending
        need(actual['handoff']['expected_transaction_id'] == pending['transaction_id']
             and actual['history']['transitions'][:-1] == self.accepted['history']['transitions']
             and actual['history']['genesis'] == self.accepted['history']['genesis']
             and actual['history']['transitions'][-1]['kind'] == 'exit',
             'next-exit-only-after-exact-accepted-predecessor-replay')
        # confirmed() must have joined the candidate's exact projection selector.
        need(sha(bytes.fromhex(actual['history']['transitions'][-1]['projection_hex']))
             == pending['projection'][1], 'accepted-exit-exact-candidate-projection')
        self.completed.append(pending['transaction_id'])
        self.next_owner = (pending['owner'] + 1) % 3
        self.accepted, self.pending, self.empty = actual, None, set()
        if len(self.completed) == 9:
            state, head = reconstruct(actual['history'])
            need(head['reserve_sompi'] == 0 and head['outpoint_hex36'] is None
                 and (len(state.cms), len(state.entries)) == (15, 16), 'nine-accepted-exits-terminal-drain')


def main():
    from runner import StageRunner
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('gate', 'round2'))
    for name in ('handoff', 'previous-history', 'prepared-projection', 'assets',
                 'native-selection', 'owners', 'source-manifest'):
        p.add_argument('--' + name, nargs=2, required=True, metavar=('FILE', 'SHA256'))
    for name in ('private-base', 'public-base', 'original-private', 'engine-root'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('trial-id', 'expected-transaction-id'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--exclude-old-trial', action='append', required=True)
    p.add_argument('--exclude-private-directory', action='append', required=True)
    a = p.parse_args()
    runner = StageRunner(a.private_base, a.public_base, a.exclude_old_trial,
                         a.exclude_private_directory, a.source_manifest)
    runner.authenticate()
    native = parse_json(runner.ingress.read(*a.native_selection))
    owners = parse_json(runner.ingress.read(*a.owners))['owners']
    assets = parse_json(runner.ingress.read(*a.assets))
    need(assets['domain_hex32'] == DOMAIN.hex() and len(owners) == 3,
         'selected-native-domain-and-three-owners')
    accepted = confirmed(runner, a.handoff, trial_id=a.trial_id,
        expected_txid=a.expected_transaction_id, transition_count=1,
        tail_hex=native['immutable_tail_hex'], previous_history=a.previous_history,
        prepared_projection=a.prepared_projection)
    if a.operation == 'gate':
        print(canonical_json({'status': 'EXACT_ACTUAL_ACCEPTED_ROUND1_HANDOFF_JOIN_PASS',
            'owner_operations_performed': 0, 'history': accepted['history_selector']}).decode().strip())
    else:
        result = cold_round2(runner, accepted, a.assets, native, owners, a.original_private, a.engine_root)
        print(canonical_json(result).decode().strip())


if __name__ == '__main__':
    os.umask(0o077)
    main()
