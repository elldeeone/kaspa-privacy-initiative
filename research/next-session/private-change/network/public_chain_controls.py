#!/usr/bin/env python3
"""UNPROVED public-predicate controls; never a chain/private-payment fixture.

Opaque CMs/ciphers/NFs, invented transaction IDs/header assertions and invalid
placeholder proofs intentionally prevent any acceptance/ownership claim. No
seed, PK, RPC, SDK/native executable or prover is used. Hidden positive change
cannot be established by a public parser and remains a later genuine-proof gate.
"""
import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'poc/private-network-recovery'))
import network_replay as network
from pinned_dependencies import old, adapter
from approved_template import approved_policy

DOMAIN = hashlib.sha256(b'KPX3/private-change/PUBLIC-CONTROLS/DO-NOT-FUND/v1').digest()
ZERO = bytes(32)
FEE = 20_000_000
START = 1_000_000_000


def h(text):
    return hashlib.sha256(text.encode()).digest()


def cipher(label):
    return (h(label) * 9)[:264]


def nf_witness(state, value):
    order = int.from_bytes(value, 'little')
    index, entry = max(((i, row) for i, row in enumerate(state.entries)
                        if int.from_bytes(row['value'], 'little') < order),
                       key=lambda pair: int.from_bytes(pair[1]['value'], 'little'))
    witness = old.u32(index) + entry['value'] + entry['next_value'] + old.u32(entry['next_index']) + state.nf.path(index)
    temporary = copy.deepcopy(state.nf)
    temporary.set(index, old.nf_leaf({'value': entry['value'], 'next_value': value, 'next_index': len(state.entries)}))
    return witness + temporary.path(len(state.entries))


def base():
    # Only this public2500-byte configuration is read. Its actual PK is neither
    # located nor opened; modifying D makes this a deliberately unselected mock.
    manifest = json.loads((ROOT / 'research/next-session/private-service-loss/prover/parameters-01/public-parameters.json').read_bytes())
    manifest = copy.deepcopy(manifest)
    manifest.update(trial_id='PUBLIC_SYNTHETIC_PRIVATE_CHANGE_DO_NOT_FUND', domain_hex32=DOMAIN.hex())
    manifest['compiled_build_identity_sha256'] = h('not-an-actual-compiled-control-build').hex()
    vk = bytes.fromhex(manifest['vk_hex328'])
    note = h('opaque-public-APK0') + h('opaque-public-APK1') + START.to_bytes(8, 'little') + h('public-rho') + h('public-native0') + h('public-native1')
    assert len(note) == 168
    sealed = cipher('opaque-public-genesis-cipher')
    state = old.State(DOMAIN, note, sealed)
    initial = b'\x4c\x70' + state.encoded() + approved_policy(DOMAIN, vk)
    genesis = {'transactionId': h('public-founding-tx').hex(), 'index': 0}
    descriptor = {'schema': 'kpx3-private-network-descriptor/v1', 'network_id': 'testnet-10',
                  'genesis_hash_hex': old.GENESIS, 'domain_hex32': DOMAIN.hex(), 'founding_outpoint': genesis,
                  'birth_start_hash': h('invented-public-anchor').hex(), 'initial_redeem_hex': initial.hex(),
                  'vk_hex328': vk.hex(), 'immutable_policy_sha256': old.h(initial[114:]).hex(),
                  'public_params_manifest_sha256': old.digest(manifest)}
    funding = {'transactionId': h('invented-funding-input').hex(), 'index': 0}
    funding_spk = old.p2pk(h('opaque-public-funding-key'))
    entry = {'outpoint': funding, 'amount_sompi': str(START + FEE + 10_000_000), 'script_public_key': funding_spk,
             'block_daa_score': '0', 'is_coinbase': False, 'covenant_id': None}
    payload = b'KPX2GN01' + DOMAIN + note + h_from_note(note) + sealed + old.h(sealed)
    tx = transaction(genesis['transactionId'], funding, (b'\x41' + bytes([1]) * 64 + b'\x01').hex(),
                     [{'value': str(START), 'scriptPublicKey': old.p2sh(initial), 'covenant': None},
                      {'value': '10000000', 'scriptPublicKey': funding_spk, 'covenant': None}], payload)
    return descriptor, manifest, state, initial, genesis, START, [(tx, [entry])]


def h_from_note(note):
    return old.h(b'KPX1NOT\0', DOMAIN, note)


def transaction(txid, previous, signature, outputs, payload):
    return {'version': 1, 'id': txid, 'inputs': [{'previousOutpoint': previous, 'signatureScript': signature,
            'sequence': str((1 << 64) - 1), 'computeBudget': 1600}], 'outputs': outputs,
            'lockTime': '0', 'subnetworkId': '00' * 20, 'gas': '0', 'payload': payload.hex(), 'storageMass': '0'}


def append_action(state, current, reserve, redeem, number, payout, rows):
    before = state.encoded()
    work = copy.deepcopy(state)
    remaining = reserve - FEE - payout
    assert remaining == 0 or remaining >= old.NOTE_FLOOR
    nfs, public_witness = [], b''
    for slot in range(2):
        nf = h(f'opaque-public-NF/{number}/{slot}')
        witness = nf_witness(work, nf)
        work.insert(nf, witness); public_witness += witness; nfs.append(nf)
    commitments, ciphers = [], []
    if remaining:
        for slot in range(2):
            cm, sealed = h(f'opaque-public-CM/{number}/{slot}'), cipher(f'opaque-public-cipher/{number}/{slot}')
            path = work.cm.path(len(work.deliveries))
            work.append(cm, sealed, path)
            commitments.append(cm); ciphers.append(sealed); public_witness += path
        ciphertexts = b''.join(ciphers)
    else:
        commitments, ciphertexts = [ZERO, ZERO], bytes(528)
        public_witness += bytes(1024)
    destination = old.p2pk(h(f'opaque-public-payout/{number}')) if payout else bytes(36).hex()
    auth = (b'KPX3AU01' + DOMAIN + bytes.fromhex(current['transactionId']) + old.u32(current['index']) + before
            + reserve.to_bytes(8, 'little') + FEE.to_bytes(8, 'little') + b''.join(nfs) + b''.join(commitments)
            + old.h(ciphertexts) + work.encoded() + remaining.to_bytes(8, 'little') + payout.to_bytes(8, 'little')
            + bytes.fromhex(destination))
    assert len(auth) == 528 and len(public_witness) == 3344
    successor = b'\x4c\x70' + work.encoded() + redeem[114:] if remaining else None
    outputs = []
    if remaining: outputs.append({'value': str(remaining), 'scriptPublicKey': old.p2sh(successor), 'covenant': None})
    if payout: outputs.append({'value': str(payout), 'scriptPublicKey': destination, 'covenant': None})
    # Deliberately invalid cryptographic placeholder, never run in a validator.
    frame = b'\x41' + bytes(65) + b'\x4c\x80' + bytes([1]) * 128 + b'\x4d' + len(redeem).to_bytes(2, 'little') + redeem
    txid = h(f'invented-public-action-id/{number}').hex()
    tx = transaction(txid, current, frame.hex(), outputs, auth + ciphertexts + public_witness)
    entry = {'outpoint': current, 'amount_sompi': str(reserve), 'script_public_key': old.p2sh(redeem),
             'block_daa_score': '0', 'is_coinbase': False, 'covenant_id': None}
    rows.append((tx, [entry]))
    return work, {'transactionId': txid, 'index': 0} if remaining else None, remaining, successor


def network_claims(descriptor, manifest, rows):
    transactions, points, consumed = [], {}, set()
    for index, (tx, entries) in enumerate(rows):
        transactions.append({'transaction': tx, 'accepted_input_contexts': entries,
            'accepting_block_header': {'hash': h(f'invented-acceptance/{index}').hex(), 'blueScore': str(index + 10)},
            'confirmation_policy': {'min_confirmation_count': 20, 'accepting_blue_score': str(index + 10),
                'sink_blue_score': '200', 'actual_blue_score_distance': str(190 - index), 'passes': True},
            'network_id': 'testnet-10', 'genesis_hash_hex': old.GENESIS, 'sdk_transaction_id_recomputed': False})
        for entry in entries:
            points[old.point(entry['outpoint'])] = {key: entry[key] for key in ('outpoint', 'amount_sompi', 'script_public_key')}
            consumed.add(old.point(entry['outpoint']))
        for number, output in enumerate(tx['outputs']):
            point = old.outpoint(tx, number)
            points[old.point(point)] = {'outpoint': point, 'amount_sompi': output['value'], 'script_public_key': output['scriptPublicKey']}
    queries = []
    for at, point in points.items():
        entry = None if at in consumed else dict(point, block_daa_score='0', is_coinbase=False, covenant_id=None)
        queries.append(dict(point, queried=True, entry=entry))
    frontier = {'hash': h('invented-finite-frontier').hex(), 'blueScore': '100'}
    return {'schema': 'kpx3-private-network-fetch/v1', 'network_id': 'testnet-10', 'genesis_hash_hex': old.GENESIS,
        'descriptor': descriptor, 'descriptor_sha256': old.digest(descriptor), 'transactions': transactions,
        'public_params_manifest': manifest, 'public_params_manifest_sha256': old.digest(manifest), 'public_parameter_blob_read': False,
        'coverage': {'start_hash': descriptor['birth_start_hash'], 'anchor_header': {'hash': descriptor['birth_start_hash'], 'blueScore': '1'},
            'frontier': frontier, 'initial_sink': {'hash': h('invented-initial-sink').hex(), 'blueScore': '200'},
            'end_cursor': frontier['hash'], 'complete': True, 'frontier_seen': True, 'removed_chain_block_hashes': [],
            'missing': [], 'pruned': False, 'min_confirmation_count': 20},
        'current_view': {'checkpoint': {'network': 'testnet-10', 'expected_genesis': old.GENESIS, 'observed_at': '2026-10-23T00:00:00Z'},
            'observed_at': '2026-10-23T00:00:01Z', 'queries': queries,
            'post_query_delta': {'removed_chain_block_hashes': [], 'related_transactions': [], 'start_hash': frontier['hash'],
                'completed': True, 'frontier': {'hash': h('invented-post-frontier').hex(), 'blueScore': '101'},
                'checked_at': '2026-10-23T00:00:02Z', 'watched_outpoints': [q['outpoint'] for q in queries if q['entry'] is not None]}}}


def make(actions):
    descriptor, manifest, state, redeem, current, reserve, rows = base()
    states = []
    for number, paid in enumerate(actions):
        if paid == 'terminal': paid = reserve - FEE
        state, current, reserve, redeem = append_action(state, current, reserve, redeem, number, paid, rows)
        states.append({'cm_count': len(state.deliveries), 'nf_count': len(state.entries), 'reserve_sompi': reserve})
    return descriptor, network_claims(descriptor, manifest, rows), manifest, states


def checked(descriptor, bundle, manifest):
    inner, head, payouts, _, _ = network._public_state(descriptor, bundle, manifest)
    assert inner['completeness']['complete'] is False and inner['completeness']['accepted_chain_backing'] is False
    return inner, head, payouts


def main():
    results = []
    for name, actions in [('repeated_P0_open', [0, 0]), ('continuing_payout_and_opaque_change', [0, 0, 100_000_000]),
                          ('longer_terminal_trace', [0, 0, 100_000_000, 0, 200_000_000, 'terminal'])]:
        d, b, m, states = make(actions); inner, head, payouts = checked(d, b, m)
        results.append({'case': name, 'passed': True, 'operations': len(inner['operations']), 'states': states,
                        'public_payouts': len(payouts), 'reserve_sompi': head['reserve_sompi'], 'inner_complete': False})
    d, b, m, states = make([0, 0, 100_000_000, 0, 200_000_000, 'terminal'])
    before = checked(d, b, m)[0]
    shuffled = copy.deepcopy(b); shuffled['transactions'].reverse()
    assert checked(d, shuffled, m)[0]['operations'] == before['operations']
    results.append({'case': 'unordered_longer_graph', 'passed': True})
    assert states[-1]['cm_count'] == states[-2]['cm_count'] and states[-1]['nf_count'] == states[-2]['nf_count'] + 2
    results.append({'case': 'terminal_preserves_CM_and_adds_both_NFs', 'passed': True})
    cases = []
    broken = copy.deepcopy(b); broken['transactions'].append(copy.deepcopy(broken['transactions'][2])); cases.append(('duplicate_spend', broken))
    broken = copy.deepcopy(b); broken['current_view']['queries'].pop(); cases.append(('missing_payout_query', broken))
    broken = copy.deepcopy(b); broken['current_view']['post_query_delta']['watched_outpoints'].pop(); cases.append(('missing_live_point_watch', broken))
    broken = copy.deepcopy(b); payload = bytearray.fromhex(broken['transactions'][-1]['transaction']['payload']); payload[268] = 1
    broken['transactions'][-1]['transaction']['payload'] = payload.hex(); cases.append(('terminal_CM_nonzero', broken))
    broken = copy.deepcopy(b); payload = bytearray.fromhex(broken['transactions'][3]['transaction']['payload']); payload[1056] ^= 1
    broken['transactions'][3]['transaction']['payload'] = payload.hex(); cases.append(('stale_or_wrong_NF_path', broken))
    for name, broken in cases:
        try: checked(d, broken, m)
        except old.Invalid as error: results.append({'case': name, 'passed': True, 'rejected_with': str(error)})
        else: raise AssertionError(name + '-accepted')
    print(json.dumps({'classification': 'UNPROVED_PUBLIC_PREDICATES_ONLY_DO_NOT_FUND', 'cases': results,
        'passed': len(results), 'rpc_sdk_native_prover_PK_seed_execution': False,
        'production_complete_network_replay_called': False,
        'invented_IDs_and_incomplete_headers_would_fail_production_SDK_checks': True,
        'hidden_positive_change_or_private_conservation_or_ownership_proved': False}, sort_keys=True, indent=2))


if __name__ == '__main__': main()
