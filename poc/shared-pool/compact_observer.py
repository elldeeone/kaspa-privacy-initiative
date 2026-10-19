#!/usr/bin/env python3
"""Public-only compact-pool audit. Feasibility is not an anonymity probability.

Assume the recorded transitions were accepted under the published relation.
This checks framing/ancestry/accounting, not Groth16 or Kaspa consensus. It has
no wallet, descriptor, experiment manifest or ground-truth input.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

FLOOR = 60_000_000
MAX_SOMPI = 2_900_000_000_000_000_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).digest()


def p2sh(redeem):
    return (b'\0\0\xaa\x20' + hashlib.blake2b(redeem, digest_size=32).digest() + b'\x87').hex()


def compact_state(data):
    require(len(data) == 105 and data[0] == 4, 'compact state framing')
    cm, nf = int.from_bytes(data[1:5], 'little'), int.from_bytes(data[5:9], 'little')
    require(0 < cm <= 65535 and cm % 2 == 1 and 0 <= nf <= cm, 'state counts')
    return cm, nf, data[9:41]


def decode(chain):
    require(set(chain) == {'schema', 'network', 'records'}, 'observer input fields')
    require(chain['schema'] == 'kpi-compact-chain-observer-v1' and
            chain['network'] == 'testnet-10', 'observer schema/network')
    require(len(chain['records']) >= 2, 'missing funding/first spend')
    for row in chain['records']:
        require(set(row) == {'transaction', 'header'}, 'non-chain metadata')
        tx = row['transaction']
        require(set(tx) == {'version', 'id', 'inputs', 'outputs', 'lockTime',
                           'subnetworkId', 'gas', 'payload', 'storageMass'}, 'transaction fields')
        for inp in tx['inputs']:
            require(set(inp) == {'previousOutpoint', 'signatureScript', 'sequence',
                                 'computeBudget', 'sigOpCount'}, 'input fields')
        for out in tx['outputs']:
            require(set(out) == {'value', 'scriptPublicKey', 'covenant'} and out['covenant'] is None,
                    'output fields')
            require(0 < int(out['value']) <= MAX_SOMPI, 'native output amount')
    # The funding transaction has an empty payload. Follow reserve ancestry,
    # never experiment filenames, owner labels or local arrival order.
    transactions = {r['transaction']['id']: r['transaction'] for r in chain['records']}
    require(len(transactions) == len(chain['records']), 'duplicate transaction ID')
    funding = [t for t in transactions.values() if t['payload'] == '']
    require(len(funding) == 1, 'one initial funding transaction required')
    previous = funding[0]
    funding_id = previous['id']
    initial_value = int(previous['outputs'][0]['value'])
    require(FLOOR <= initial_value <= MAX_SOMPI, 'initial reserve value')
    remaining = {i: t for i, t in transactions.items() if i != funding_id}
    notes = [{'position': 0, 'source': funding_id, 'born': 0, 'commitment': None}]
    events, roots, nullifiers = [], {}, set()
    last_state = domain = suffix = None
    while remaining:
        children = [t for t in remaining.values() if t['inputs'] and
                    t['inputs'][0]['previousOutpoint'] == {'transactionId': previous['id'], 'index': 0}]
        require(len(children) == 1, 'incomplete or branching reserve ancestry')
        tx = children[0]
        del remaining[tx['id']]
        require(len(tx['inputs']) == 1, 'compact requires one reserve input')
        sig = bytes.fromhex(tx['inputs'][0]['signatureScript'])
        require(len(sig) == 12421 and sig[:2] == b'\x4c\x80' and
                sig[130:133] == b'\x4d\x00\x30', 'proof/redeem framing')
        redeem = sig[133:]
        require(p2sh(redeem) == previous['outputs'][0]['scriptPublicKey'], 'reserve script')
        old = redeem[36:141]
        cm, nf, cm_root = compact_state(old)
        if last_state is None:
            require(cm == 1 and nf == 0, 'not initial compact state')
            roots[1] = cm_root
            domain, suffix = redeem[1:33], redeem[141:]
        else:
            require(old == last_state and redeem[1:33] == domain and redeem[141:] == suffix,
                    'state/domain/covenant continuity')
        require(cm == len(notes) and nf == len(events), 'public count/history mismatch')
        payload = bytes.fromhex(tx['payload'])
        require(len(payload) == 3892 and payload[:8] == b'KPICR01\0', 'payload framing')
        auth, cipher, new = payload[8:273], payload[273:643], payload[643:748]
        require(auth[:8] == b'KPICU01\0' and auth[8:40] == domain, 'authorization framing/domain')
        count = int.from_bytes(auth[40:44], 'little')
        require(count in roots and count <= cm and auth[44:76] == roots[count], 'historical anchor')
        nullifier = auth[76:108]
        require(any(nullifier) and nullifier not in nullifiers, 'duplicate/zero nullifier')
        nullifiers.add(nullifier)
        mode = auth[172]
        require(mode in (1, 2), 'unsupported compact operation')
        require(sha(cipher) == auth[233:265], 'ciphertext hash')
        payout, fee = int.from_bytes(auth[173:181], 'little'), int.from_bytes(auth[181:189], 'little')
        require(0 < fee <= MAX_SOMPI and 0 <= payout <= MAX_SOMPI, 'amount ranges')
        reserve = int(previous['outputs'][0]['value'])
        require(int.from_bytes(auth[225:233], 'little') == (reserve if not events else 0), 'bootstrap binding')
        nc, nn, root = compact_state(new)
        require(nc == cm + (2 if mode == 1 else 0) and nn == nf + 1, 'successor counts')
        created = []
        if mode == 1:
            require(payout == 0 and not any(auth[189:225]), 'transfer public payout')
            commitments = [auth[108:140], auth[140:172]]
            require(all(any(c) for c in commitments) and commitments[0] != commitments[1], 'transfer commitments')
            for c in commitments:
                created.append(len(notes))
                notes.append({'position': len(notes), 'source': tx['id'],
                              'born': len(events)+1, 'commitment': c.hex()})
            roots[nc] = root
        else:
            require(payout >= 10_000_000 and not any(auth[108:172]) and
                    not any(cipher) and not any(payload[748+1608:]), 'full exit encoding')
            require(root == cm_root, 'exit commitment root')
        terminal = nn == nc
        require(len(tx['outputs']) == (1 if terminal or mode == 1 else 2), 'native output count')
        require(reserve - sum(int(o['value']) for o in tx['outputs']) == fee, 'native fee')
        reserve_out = 0 if terminal else int(tx['outputs'][0]['value'])
        if not terminal:
            require(tx['outputs'][0]['scriptPublicKey'] == p2sh(redeem[:36]+new+suffix), 'successor script')
        if mode == 2:
            out = tx['outputs'][-1]
            require(int(out['value']) == payout and out['scriptPublicKey'] == auth[189:225].hex(), 'payout binding')
        require(reserve == reserve_out + payout + fee, 'native conservation')
        require(not terminal or not remaining, 'transactions after terminal exit')
        events.append({'step': len(events)+1, 'txid': tx['id'], 'mode': mode,
                       'anchor_count': count, 'current_count': cm, 'fee': fee,
                       'payout': payout, 'reserve_out': reserve_out, 'new': created})
        last_state, previous = new, tx
    return {'funding_txid': funding_id, 'initial_value': initial_value,
            'notes': notes, 'events': events}


def matching_candidates(events, target):
    """Exact matching for nested eligible sets [0, historical_count).

    Remove the target spend and reserve candidate i for it. Sorted remaining
    bounds b[k] admit a matching iff b[k] - (i < b[k]) >= k (one-based k).
    This is the prefix Hall condition, not independent per-spend reasoning.
    """
    bounds = sorted(e['anchor_count'] for e in events if e['step'] != target['step'])
    require(all(b >= k for k, b in enumerate(bounds, 1)), 'inconsistent spend history')
    lower = max((b for k, b in enumerate(bounds, 1) if b == k), default=0)
    candidates = list(range(lower, target['anchor_count']))
    require(candidates, 'no jointly feasible input positions')
    return candidates


class ValueModel:
    """Small-trace integer model. Owner identities and note openings are absent."""
    def __init__(self, decoded, events):
        import z3
        self.z3 = z3
        self.events = events
        self.s = z3.Solver()
        self.values = [z3.Int(f'value_{i}') for i in range(1 + sum(len(e['new']) for e in events))]
        self.choices = {}
        for value in self.values:
            self.s.add(value >= FLOOR, value <= MAX_SOMPI)
        self.s.add(self.values[0] == decoded['initial_value'])
        for e in events:
            choice = z3.Int(f'input_{e["step"]}')
            self.choices[e['step']] = choice
            eligible = matching_candidates(events, e)
            self.s.add(z3.Or([choice == i for i in eligible]))
            cost = sum((self.values[i] for i in e['new']), z3.IntVal(e['fee']+e['payout']))
            for i in eligible:
                self.s.add(z3.Implies(choice == i, self.values[i] == cost))
        self.s.add(z3.Distinct(list(self.choices.values())))
        # Conservation + single spend imply the remaining native reserve.
        final_choices = list(self.choices.values())
        self.s.add(z3.Sum([z3.If(z3.And([c != i for c in final_choices]), v, 0)
                           for i, v in enumerate(self.values)]) == events[-1]['reserve_out'])
        require(self.s.check() == z3.sat, 'inconsistent or unknown value model')

    def candidates(self, event):
        z3 = self.z3
        result = []
        for i in matching_candidates(self.events, event):
            self.s.push()
            self.s.add(self.choices[event['step']] == i)
            answer = self.s.check()
            require(answer != z3.unknown, 'solver unknown is not ambiguity')
            if answer == z3.sat:
                result.append(i)
            self.s.pop()
        require(result, 'no value-compatible input')
        return result

def describe(decoded, event, positions):
    notes = decoded['notes']
    sources = sorted({notes[i]['source'] for i in positions})
    latest = max(notes[i]['born'] for i in positions)
    recent = sorted({notes[i]['source'] for i in positions if notes[i]['born'] == latest})
    return {'step': event['step'], 'withdrawal_txid': event['txid'],
            'anchor_count': event['anchor_count'], 'current_count': event['current_count'],
            'consumed_position_candidates': positions, 'creation_transaction_candidates': sources,
            'source_candidate_count': len(sources), 'position_candidate_count': len(positions),
            'singleton_source_prediction': sources[0] if len(sources) == 1 else None,
            'recency_source_ties': recent,
            'uniform_candidate_prior_top1': {'numerator': 1, 'denominator': len(sources)},
            'exact_input_value_sompi': event['payout']+event['fee'],
            'deposit_ancestor_candidates': [decoded['funding_txid']]}


def audit(chain, joint_values=False):
    decoded = decode(chain)
    events = decoded['events']
    exits = [e for e in events if e['mode'] == 2]
    rows = []
    full_model = ValueModel(decoded, events) if joint_values else None
    for event in exits:
        prefix = events[:event['step']]
        own_model = ValueModel(decoded, prefix) if joint_values else None
        row = {'withdrawal_txid': event['txid'], 'step': event['step']}
        for name, observed, model in [('at_withdrawal', prefix, own_model), ('complete_trace', events, full_model)]:
            item = {'anchor_single_spend': describe(decoded, event, matching_candidates(observed, event))}
            if model:
                item['joint_values'] = describe(decoded, event, model.candidates(event))
            row[name] = item
        rows.append(row)
    coverage = {}
    for horizon in ['at_withdrawal', 'complete_trace']:
        covered = sum(r[horizon]['anchor_single_spend']['source_candidate_count'] == 1 for r in rows)
        coverage[horizon] = {'singleton_source_predictions': covered, 'withdrawals': len(exits),
                             'abstentions': len(exits)-covered}
    result = {'schema': 'kpi-compact-privacy-audit-v1', 'rows': rows, 'coverage': coverage,
            'transaction_count': len(events)+1, 'pool_fees_sompi': sum(e['fee'] for e in events),
            'all_claims_drained': events[-1]['reserve_out'] == 0,
            'initial_reserve_sompi': decoded['initial_value'],
            'joint_value_model': joint_values,
            'scope': 'Selected synthetic traces; logical candidates, not people, posteriors or real-world anonymity'}
    if joint_values and exits:
        # Structural control only: no replacement transaction is proved or valid.
        changed = copy.deepcopy(events)
        target = changed[exits[0]['step']-1]
        old_count = target['anchor_count']
        target['anchor_count'] = target['current_count']
        model = ValueModel(decoded, changed)
        result['fresh_anchor_sensitivity'] = {
            'modeled_only': True, 'old_count': old_count, 'new_count': target['anchor_count'],
            'complete_trace': describe(decoded, target, model.candidates(target)),
            'warning': 'Requires new private authorization/proof; no signed transaction or policy effectiveness measurement'}
    # Store identical candidate lists once; keep every exit/horizon in the report.
    # This only compacts evidence and does not change the model or queries.
    sets, identifiers = {}, {}
    descriptions = [item for row in rows for horizon in ['at_withdrawal', 'complete_trace']
                    for item in row[horizon].values()]
    if 'fresh_anchor_sensitivity' in result:
        descriptions.append(result['fresh_anchor_sensitivity']['complete_trace'])
    for item in descriptions:
        positions = item.pop('consumed_position_candidates')
        sources = item.pop('creation_transaction_candidates')
        key = (tuple(positions), tuple(sources))
        if key not in identifiers:
            identifier = f'set-{len(sets)+1}'
            identifiers[key] = identifier
            sets[identifier] = {'consumed_position_candidates': positions,
                                'creation_transaction_candidates': sources}
        item['candidate_set'] = identifiers[key]
    result['candidate_sets'] = sets
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('chain', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--joint-values', action='store_true')
    args = parser.parse_args()
    raw = args.chain.read_bytes()
    result = audit(json.loads(raw), args.joint_values)
    result['input_sha256'] = hashlib.sha256(raw).hexdigest()
    with args.output.open('x') as out:
        json.dump(result, out, indent=2)
        out.write('\n')
    print(json.dumps({k: result[k] for k in ['coverage', 'transaction_count', 'pool_fees_sompi']}))


if __name__ == '__main__':
    main()
