"""Arithmetic/lineage over cases already verified by accepted-prefix replay."""
import re

from journal import NORMAL
from public import amount, case_summary, need

P2SH = re.compile('0000aa20[0-9a-f]{64}87\\Z')
P2PK = re.compile('000020[0-9a-f]{64}ac\\Z')


def complete(cases):
    need(type(cases) is list and [stage for stage, _ in cases] == list(NORMAL),
         'complete-funding-settlement-four-exit-route')
    rows = [(stage, case, case_summary(case)) for stage, case in cases]
    funding, first = rows[0][1]['transaction'], rows[0][2]
    need(len(funding['inputs']) == 2 and P2SH.fullmatch(funding['outputs'][0]['scriptPublicKey']),
         'two-source-funding-and-initial-W')
    initial = amount(funding['outputs'][0]['value'], positive=True)
    ordinary_change = amount(sum(o['value'] for o in funding['outputs'][1:]))
    need(all(P2PK.fullmatch(o['scriptPublicKey']) for o in funding['outputs'][1:]),
         'ordinary-change-only')
    point = {'transactionId': funding['id'], 'index': 0}
    reserve = initial
    payouts, fees = [], []
    for ordinal, (stage, case, summary) in enumerate(rows[1:], 1):
        body = case['transaction']
        need(summary['input_outpoints'] == [point] and summary['source_sompi'] == reserve,
             'ordered-physical-reserve-chain')
        fees.append(summary['fee_sompi'])
        if stage == 'settlement':
            need(len(body['outputs']) == 1 and P2SH.fullmatch(body['outputs'][0]['scriptPublicKey'])
                 and body['payload'].startswith(b'KPX5VP01'.hex()), 'two-child-settlement-body')
            reserve = amount(body['outputs'][0]['value'], positive=True)
        else:
            need(len(bytes.fromhex(body['payload'])) == 2848
                 and body['payload'].startswith(b'KPX4AU01'.hex()), 'full-noappend-private-exit')
            terminal = ordinal == len(rows) - 1
            need(len(body['outputs']) == (1 if terminal else 2), 'exit-continuation-count')
            payout = body['outputs'][-1]
            need(P2PK.fullmatch(payout['scriptPublicKey']), 'native-payout-P2PK')
            payouts.append({'transaction_id': body['id'], 'index': len(body['outputs']) - 1,
                'amount_sompi': payout['value']})
            reserve = 0 if terminal else amount(body['outputs'][0]['value'], positive=True)
            if not terminal:
                need(P2SH.fullmatch(body['outputs'][0]['scriptPublicKey']), 'W-continuation-shape')
        point = {'transactionId': body['id'], 'index': 0} if reserve else None
    payout_sum = amount(sum(r['amount_sompi'] for r in payouts))
    total_fee = amount(first['fee_sompi'] + sum(fees))
    need(len(payouts) == 4 and reserve == 0
         and len({(r['transaction_id'], r['index']) for r in payouts}) == 4,
         'four-distinct-terminal-payouts')
    need(first['source_sompi'] == ordinary_change + payout_sum + total_fee,
         'all-sources-change-fees-payouts-conserve')
    return {'schema': 'kpx6-four-wallet-complete-arithmetic/v1',
        'source_sompi': first['source_sompi'], 'initial_reserve_sompi': initial,
        'ordinary_change_sompi': ordinary_change, 'entry_fee_sompi': first['fee_sompi'],
        'settlement_fee_sompi': fees[0], 'private_exit_fees_sompi': fees[1:],
        'total_fee_sompi': total_fee, 'native_payouts_sompi': payout_sum,
        'payout_count': 4, 'terminal_reserve_sompi': 0,
        'arithmetic_and_physical_lineage_only': True,
        'accepted_consensus_backup_ownership_or_privacy_verified_by_this_function': False}
