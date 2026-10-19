#!/usr/bin/env python3
"""Decode H11 native public bytes; no private plan/truth/descriptor input.

Framing/accounting check only. The separate pinned Rust validator verifies the
proofs and covenant. Supplied synthetic UTXOs do not prove chain acceptance.
"""
import hashlib
import json
import sys
from pathlib import Path
from privacy_study_observer import analyze, decode, need


def p2sh(redeem):
    return (b'\0\0\xaa\x20'+hashlib.blake2b(redeem, digest_size=32).digest()+b'\x87').hex()


def project(raw):
    need(set(raw) == {'schema', 'transactions', 'contexts', 'minutes'} and
         raw['schema'] == 'kpi-h11-native-chain-v1', 'native trace schema')
    txs, contexts, minutes = raw['transactions'], raw['contexts'], raw['minutes']
    need(len(txs) == len(contexts) == len(minutes) and len(txs) > 1, 'native trace dimensions')
    initial = {'id': txs[0]['id'], 'value': int(txs[0]['outputs'][0]['value']),
               'minute': minutes[0], 'funding_group': contexts[0][0]['txid']}
    need(txs[0]['payload'] == '' and len(contexts[0]) == 1, 'ordinary genesis')
    events, roots, nullifiers = [], {}, set()
    previous = txs[0]
    last_state = suffix = domain = None
    count, spent = 1, 0
    for step, (tx, ctx, minute) in enumerate(zip(txs[1:], contexts[1:], minutes[1:], strict=True)):
        payload = bytes.fromhex(tx['payload'])
        need(len(payload) == 3892 and payload[:8] in (b'KPICD01\0', b'KPICR01\0'), 'native payload')
        deposit = payload[:8] == b'KPICD01\0'
        need(len(tx['inputs']) == len(ctx) == (2 if deposit else 1), 'native input count')
        for inp, u in zip(tx['inputs'], ctx, strict=True):
            need(inp['previousOutpoint'] == {'transactionId': u['txid'], 'index': u['index']}, 'prevout/context')
        need(tx['inputs'][0]['previousOutpoint'] == {'transactionId': previous['id'], 'index': 0}, 'reserve ancestry')
        need(int(ctx[0]['amount']) == int(previous['outputs'][0]['value']) and ctx[0]['spk'] == previous['outputs'][0]['scriptPublicKey'], 'reserve context')
        sig = bytes.fromhex(tx['inputs'][0]['signatureScript'])
        need(len(sig) == 14469 and sig[:2] == b'\x4c\x80' and sig[130:133] == b'\x4d\x00\x38', 'v5 witness framing')
        redeem = sig[133:]; old = redeem[36:141]
        need(p2sh(redeem) == previous['outputs'][0]['scriptPublicKey'], 'redeem commitment')
        if last_state is None:
            domain, suffix = redeem[1:33], redeem[141:]
            roots[1] = old[9:41]
        else:
            need(old == last_state and redeem[1:33] == domain and redeem[141:] == suffix, 'covenant continuity')
        need(old[0] == 5 and int.from_bytes(old[1:5], 'little') == count and int.from_bytes(old[5:9], 'little') == spent, 'old counts')
        a, cipher, state = payload[8:273], payload[273:643], payload[643:748]
        need(a[:8] == b'KPICU01\0' and a[8:40] == domain and hashlib.sha256(cipher).digest() == a[233:265], 'native auth/cipher')
        mode, anchor = a[172], int.from_bytes(a[40:44], 'little')
        need(mode in (1, 2), 'native mode')
        if not deposit:
            need(anchor in roots and a[44:76] == roots[anchor], 'native historical anchor')
            need(any(a[76:108]) and a[76:108] not in nullifiers, 'native duplicate nullifier')
            nullifiers.add(a[76:108]); spent += 1
        else:
            need(mode == 1 and anchor == 1 and payload[748:2356] == bytes(1608), 'native admission shape')
        fee, payout = int.from_bytes(a[181:189], 'little'), int.from_bytes(a[173:181], 'little')
        added = int(ctx[1]['amount']) if deposit else 0
        need(int.from_bytes(a[225:233], 'little') == (added if deposit else initial['value'] if step == 0 else 0), 'native bootstrap value')
        kind = 'deposit' if deposit else 'exit' if mode == 2 else 'bootstrap' if step == 0 else 'transfer'
        new = [count, count+1] if mode == 1 else []
        before = count; count += len(new)
        need(state[0] == 5 and int.from_bytes(state[1:5], 'little') == count and
             int.from_bytes(state[5:9], 'little') == spent, 'new counts')
        if mode == 1:
            need(a[108:140] != a[140:172] and any(a[108:140]) and any(a[140:172]), 'output commitments')
            roots[count] = state[9:41]
        else:
            need(a[108:172] == bytes(64) and cipher == bytes(370) and state[9:41] == old[9:41], 'full exit')
        terminal = count == spent
        need(len(tx['outputs']) == (1 if terminal or mode == 1 else 2), 'native output count')
        reserve = 0 if terminal else int(tx['outputs'][0]['value'])
        if not terminal:
            need(tx['outputs'][0]['scriptPublicKey'] == p2sh(redeem[:36]+state+suffix), 'successor script')
        if mode == 2:
            need(int(tx['outputs'][-1]['value']) == payout and tx['outputs'][-1]['scriptPublicKey'] == a[189:225].hex(), 'payout binding')
        need(sum(int(u['amount']) for u in ctx)-sum(int(o['value']) for o in tx['outputs']) == fee, 'native fees')
        events.append({'id': tx['id'], 'minute': minute, 'kind': kind, 'anchor_count': anchor,
            'count_before': before, 'fee': fee, 'payout': payout, 'deposit': added, 'new': new,
            'reserve_out': reserve, 'destination': a[189:225].hex() if mode == 2 else None,
            'funding_group': ctx[1]['txid'] if deposit else None})
        last_state, previous = state, tx
    result = {'schema': 'kpi-privacy-projection-v1', 'initial': initial, 'events': events}
    decode(result)
    return result


def normalized(chain):
    # Relabel only opaque public identifiers for exact model/native comparison.
    ids = [chain['initial']['id']]+[e['id'] for e in chain['events']]
    groups = [chain['initial']['funding_group']]+[e['funding_group'] for e in chain['events'] if e['kind'] == 'deposit']
    destinations = [e['destination'] for e in chain['events'] if e['kind'] == 'exit']
    need(len(destinations) == len(set(destinations)), 'unexpected reused destination')
    result = json.loads(json.dumps(chain))
    result['initial']['id'] = 0; result['initial']['funding_group'] = 0
    for e in result['events']:
        e['id'] = ids.index(e['id'])
        if e['funding_group'] is not None: e['funding_group'] = groups.index(e['funding_group'])
        if e['destination'] is not None: e['destination'] = destinations.index(e['destination'])
    return result


if __name__ == '__main__':
    raw = Path(sys.argv[1]).read_bytes()
    projection = project(json.loads(raw))
    result = {'projection': projection, 'observer': analyze(projection),
              'native_input_sha256': hashlib.sha256(raw).hexdigest()}
    with Path(sys.argv[2]).open('x') as f:
        json.dump(result, f, separators=(',', ':'))
