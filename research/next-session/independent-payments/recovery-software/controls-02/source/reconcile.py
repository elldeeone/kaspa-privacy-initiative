"""Strict accepted-state JOIN contract, not a node/consensus/spend implementation.

Only a selected installed RPC adapter may supply observation bytes in a future
live integration. A capsule must never supply this authority. The current
compact adapter does not exist, so actual restored canaries remain synthetic.
"""
from __future__ import annotations

import hashlib
import re

from software_bundle import Invalid, encoded, need

HEX = re.compile('[0-9a-f]{64}')


def hx(value):
    need(type(value) is str and HEX.fullmatch(value), 'currentness-hex')


def point(value):
    need(type(value) is dict and set(value) == {'transactionId', 'index'}
         and type(value['index']) is int and 0 <= value['index'] < 1 << 32,
         'currentness-outpoint')
    hx(value['transactionId'])
    return value['transactionId'], value['index']


def utxo(value):
    need(type(value) is dict and set(value) == {'amount_sompi', 'script_public_key',
         'block_daa_score', 'is_coinbase', 'covenant_id'}, 'currentness-utxo-fields')
    need(type(value['amount_sompi']) is int and 0 < value['amount_sompi'] <= 2_870_000_000_000_000_000
         and type(value['block_daa_score']) is int and 0 <= value['block_daa_score'] < 1 << 64
         and value['is_coinbase'] is False and value['covenant_id'] is None,
         'currentness-utxo-values')
    need(type(value['script_public_key']) is str and len(value['script_public_key']) >= 4
         and len(value['script_public_key']) % 2 == 0
         and all(c in '0123456789abcdef' for c in value['script_public_key']), 'currentness-utxo-script')


def reconcile(replayed, observation, session, *, fixture_contract_only=False):
    """Check facts, never promote synthetic evidence into spend authorization.

`replayed` must come from full local SDK/native/sparse replay of the complete
record list. `session` is local acquisition state, NEVER capsule data. This
function cannot verify who supplied either object; installed caller isolation
and authenticated selected-node transport are explicit external assumptions.
"""
    need(type(fixture_contract_only) is bool, 'currentness-context')
    need(type(session) is dict and set(session) == {'request_nonce_hex32', 'provider_id',
         'network_id', 'genesis_hash_hex', 'domain_hex32', 'descriptor_sha256',
         'birth_start_hash', 'founding_outpoint'}, 'session-fields')
    for key in ('request_nonce_hex32', 'genesis_hash_hex', 'domain_hex32', 'descriptor_sha256', 'birth_start_hash'):
        hx(session[key])
    founding = point(session['founding_outpoint'])
    need(type(session['provider_id']) is str and session['provider_id']
         and session['network_id'] == 'testnet-10', 'session-selected-provider')
    need(type(replayed) is dict and set(replayed) == {'descriptor_sha256', 'classification',
         'ordered_transaction_ids', 'head_outpoint', 'head_utxo', 'terminal',
         'reserve_outpoints', 'public_replay_complete', 'native_Full_all_engines'}, 'replayed-facts-fields')
    need(replayed['descriptor_sha256'] == session['descriptor_sha256']
         and replayed['public_replay_complete'] is True and replayed['native_Full_all_engines'] is True,
         'locally-validated-complete-history-required')
    need(type(replayed['ordered_transaction_ids']) is list and replayed['ordered_transaction_ids'],
         'ordered-history-required')
    for value in replayed['ordered_transaction_ids']:
        hx(value)
    need(len(set(replayed['ordered_transaction_ids'])) == len(replayed['ordered_transaction_ids']),
         'duplicate-history-body')
    need(type(replayed['terminal']) is bool and type(replayed['reserve_outpoints']) is list
         and replayed['reserve_outpoints'], 'replayed-terminal-reserves')
    reserves = [point(value) for value in replayed['reserve_outpoints']]
    need(len(set(reserves)) == len(reserves), 'duplicate-reserve-point')
    need(reserves[0] == founding and founding[0] == replayed['ordered_transaction_ids'][0],
         'pinned-founding-outpoint-and-history-required')
    if replayed['terminal']:
        need(replayed['head_outpoint'] is None and replayed['head_utxo'] is None, 'terminal-head-must-be-absent')
        head = None
    else:
        head = point(replayed['head_outpoint'])
        utxo(replayed['head_utxo'])
        need(head in reserves and head[0] == replayed['ordered_transaction_ids'][-1], 'replayed-head-link')
    need(type(observation) is dict and set(observation) == {'schema', 'source_kind',
         *session.keys(), 'frontier', 'acceptance', 'queries', 'postquery'}, 'observation-fields')
    need(observation['schema'] == 'kpx4-selected-node-reconciliation/v1'
         and observation['source_kind'] == ('PUBLIC_CONTRACT_FIXTURE_NOT_A_NODE' if fixture_contract_only
                                           else 'SELECTED_VALIDATING_NODE_RPC'), 'selected-node-observation-required')
    for key, value in session.items():
        need(observation[key] == value, 'observation-session-or-instance-mismatch')
    # Actual compact histories are synthetic: they can NEVER reach a real-current result.
    expected = 'PUBLIC_CONTRACT_FIXTURE_NOT_ACCEPTED' if fixture_contract_only else 'LOCALLY_REPLAYED_ACCEPTED_NODE_RECORDS'
    need(replayed['classification'] == expected, 'synthetic-history-cannot-authorize-spend')
    frontier = observation['frontier']
    need(type(frontier) is dict and set(frontier) == {'start_hash', 'end_hash', 'reached_end',
         'missing', 'pruned', 'removed_block_hashes'}, 'frontier-fields')
    hx(frontier['start_hash']); hx(frontier['end_hash'])
    need(frontier['start_hash'] == session['birth_start_hash'], 'pinned-birth-frontier-start-required')
    need(frontier['reached_end'] is True and frontier['missing'] == [] and frontier['pruned'] is False
         and frontier['removed_block_hashes'] == [], 'incomplete-or-reorganized-frontier')
    acceptance = observation['acceptance']
    need(type(acceptance) is list and len(acceptance) == len(replayed['ordered_transaction_ids']),
         'accepted-history-suffix-or-prefix-missing')
    for txid, row in zip(replayed['ordered_transaction_ids'], acceptance):
        need(type(row) is dict and set(row) == {'transaction_id', 'accepting_block_hash',
             'block_daa_score'} and row['transaction_id'] == txid
             and type(row['block_daa_score']) is int and 0 <= row['block_daa_score'] < 1 << 64,
             'exact-ordered-accepted-prefix-required')
        hx(row['accepting_block_hash'])
    queries = observation['queries']
    need(type(queries) is list and len(queries) == len(reserves), 'every-reserve-point-query-required')
    queried = {}
    for row in queries:
        need(type(row) is dict and set(row) == {'outpoint', 'queried', 'utxo'}
             and row['queried'] is True, 'explicit-current-query-required')
        selected = point(row['outpoint'])
        need(selected in reserves and selected not in queried, 'unexpected-or-duplicate-current-query')
        if row['utxo'] is not None:
            utxo(row['utxo'])
        queried[selected] = row['utxo']
    for selected in reserves:
        need(queried[selected] == (replayed['head_utxo'] if selected == head else None),
             'current-head-spent-replaced-or-context-mismatch')
    post = observation['postquery']
    need(type(post) is dict and set(post) == {'start_hash', 'end_hash', 'reached_end', 'missing',
         'pruned', 'removed_block_hashes', 'related_transaction_ids', 'watched_outpoints'},
         'postquery-fields')
    hx(post['end_hash'])
    need(post['start_hash'] == frontier['end_hash'] and post['reached_end'] is True
         and post['missing'] == [] and post['pruned'] is False and post['removed_block_hashes'] == []
         and post['related_transaction_ids'] == [], 'postquery-gap-spend-or-reorg')
    need(type(post['watched_outpoints']) is list
         and sorted(point(value) for value in post['watched_outpoints']) == ([] if head is None else [head]),
         'postquery-must-watch-exact-current-head')
    return {'schema': 'kpx4-accepted-state-join-result/v1',
            'classification': ('PUBLIC_CONTRACT_FIXTURE_NOT_ACCEPTED_CURRENT' if fixture_contract_only
                               else 'SELECTED_NODE_JOIN_REQUIRES_TRUSTED_INSTALLED_ADAPTER'),
            'ordered_bodies_reconciled': len(acceptance), 'reserve_queries_reconciled': len(queries),
            'terminal': replayed['terminal'], 'join_contract_satisfied': True,
            'currentness_verified': False, 'accepted_chain_backing_verified': False,
            'selected_node_join_at_observation': not fixture_contract_only,
            'spend_authorized': False,
            'broadcaster_fresh_recheck_required': True,
            'independent_consensus_or_finality_verified': False,
            'observation_sha256': hashlib.sha256(encoded(observation)).hexdigest()}
