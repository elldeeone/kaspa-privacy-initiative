#!/usr/bin/env python3
"""Observe one exclusive offline transaction world. No labels or other arm."""
import argparse
import hashlib
import json
from pathlib import Path
from compact_observer import audit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('chain', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    raw = args.chain.read_bytes()
    chain = json.loads(raw)
    result = audit(chain, joint_values=True)
    # H9 compares actual generated proof/transaction alternatives. Do not report
    # H8's abstract eligibility edit as another native execution result.
    result.pop('fresh_anchor_sensitivity', None)
    times = {r['transaction']['id']: int(r['header']['timestamp']) for r in chain['records']}
    used = set()
    for row in result['rows']:
        for horizon in ['at_withdrawal', 'complete_trace']:
            for attack in row[horizon].values():
                used.add(attack['candidate_set'])
                sources = result['candidate_sets'][attack['candidate_set']]['creation_transaction_candidates']
                if any(times[s] >= times[row['withdrawal_txid']] for s in sources):
                    raise ValueError('candidate source must precede withdrawal in the declared synthetic clock')
                latest = max(times[s] for s in sources)
                attack['nearest_time_source_ties'] = sorted(s for s in sources if times[s] == latest)
    result['candidate_sets'] = {k: v for k, v in result['candidate_sets'].items() if k in used}
    result['schema'] = 'kpi-fresh-proof-observer-v1'
    result['input_sha256'] = hashlib.sha256(raw).hexdigest()
    result['clock_scope'] = 'Declared synthetic schedule, not accepted block timestamps or RPC arrival times'
    with args.output.open('x') as out:
        json.dump(result, out, indent=2)
        out.write('\n')
    print(json.dumps({'transactions': result['transaction_count'], 'withdrawals': len(result['rows']),
                      'pool_fees_sompi': result['pool_fees_sompi']}))


if __name__ == '__main__':
    main()
