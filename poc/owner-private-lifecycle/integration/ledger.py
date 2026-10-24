"""Integer accounting over a separately verified native lifecycle.

This checks arithmetic and physical outpoint lineage. It verifies neither
proofs nor inclusion/currentness and must never promote a case to accepted.
"""
import re

from trees import need

MAX = 2_870_000_000_000_000_000
P2SH = re.compile(r'0000aa20[0-9a-f]{64}87\Z')
P2PK = re.compile(r'000020[0-9a-f]{64}ac\Z')


def amount(value, *, positive=False):
    need(type(value) is int and (0 < value if positive else 0 <= value) and value <= MAX,
         'integer-sompi-range')
    return value


def txid(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'canonical-transaction-id')
    return value


def point(value):
    need(type(value) is dict and set(value) == {'transactionId', 'index'}, 'canonical-outpoint')
    need(type(value['index']) is int and 0 <= value['index'] < 1 << 32, 'outpoint-index')
    return txid(value['transactionId']), value['index']


def summary(case):
    need(type(case) is dict and type(case.get('transaction')) is dict
         and type(case.get('entries')) is list, 'public-native-case-shape')
    body = case['transaction']
    txid(body.get('id'))
    need(type(body.get('inputs')) is list and type(body.get('outputs')) is list
         and len(body['inputs']) == len(case['entries']) > 0
         and len(body['outputs']) > 0, 'native-input-output-counts')
    points = [point(row['previousOutpoint']) for row in body['inputs']]
    need(len(set(points)) == len(points), 'distinct-physical-inputs')
    source = amount(sum(amount(row['amount'], positive=True) for row in case['entries']), positive=True)
    outputs = amount(sum(amount(row['value'], positive=True) for row in body['outputs']), positive=True)
    fee = amount(source - outputs)
    return {'id': body['id'], 'points': points, 'source': source, 'outputs': outputs, 'fee': fee}


def complete(stages, *, expected_rounds, expected_exits, acquisition_cases=(),
             useful_payment_sompi=None):
    """Reconcile the exact supplied cases; chain authority remains external."""
    need(type(expected_rounds) is int and expected_rounds >= 2
         and type(expected_exits) is int and expected_exits == 3 + 3 * expected_rounds,
         'declared-repeated-rounds-and-all-note-exits')
    need(type(stages) is list and len(stages) == 1 + expected_rounds + expected_exits
         and [row[0] for row in stages] == ['funding'] + ['batch'] * expected_rounds
             + ['exit'] * expected_exits, 'complete-ordered-lifecycle')
    need(type(acquisition_cases) in (list, tuple), 'finite-acquisition-cases')
    pool = [(kind, case, summary(case)) for kind, case in stages]
    acquisition = [('acquisition', case, summary(case)) for case in acquisition_cases]
    rows = acquisition + pool
    need(len({row[2]['id'] for row in rows}) == len(rows), 'distinct-trial-transactions')

    # One complete finite DAG. Any included prior output must match its actual
    # next input context; reusing an external input also fails the arithmetic join.
    created, spent, external_sources = {}, set(), 0
    seen_transactions = set()
    all_ids = {row[2]['id'] for row in rows}
    for _, case, check in rows:
        for key, entry in zip(check['points'], case['entries']):
            need(key not in spent, 'physical-input-spent-once')
            spent.add(key)
            if key in created:
                previous = created[key]
                need(entry['amount'] == previous['value']
                     and entry['scriptPublicKey'] == previous['scriptPublicKey'],
                     'input-context-matches-exact-prior-output')
            else:
                need(key[0] not in all_ids, 'no-forward-or-missing-internal-outpoint')
                external_sources = amount(external_sources + entry['amount'])
        for index, output in enumerate(case['transaction']['outputs']):
            created[(check['id'], index)] = output
        seen_transactions.add(check['id'])

    first_case, first = pool[0][1:]
    body = first_case['transaction']
    need(len(body['inputs']) == 3 and P2SH.fullmatch(body['outputs'][0]['scriptPublicKey'])
         and all(P2PK.fullmatch(row['scriptPublicKey']) for row in body['outputs'][1:]),
         'GN3-three-sources-one-reserve-and-ordinary-change')
    initial_reserve = amount(body['outputs'][0]['value'], positive=True)
    reserve, head = initial_reserve, (body['id'], 0)
    payouts, batch_fees, exit_fees = [], [], []
    for ordinal, (kind, case, check) in enumerate(pool[1:], 1):
        body = case['transaction']
        need(check['points'] == [head] and check['source'] == reserve,
             'one-current-physical-reserve-input')
        if kind == 'batch':
            need(len(body['outputs']) == 1 and P2SH.fullmatch(body['outputs'][0]['scriptPublicKey']),
                 'batch-one-continuing-reserve')
            reserve = amount(body['outputs'][0]['value'], positive=True)
            batch_fees.append(check['fee'])
        else:
            terminal = ordinal == len(pool) - 1
            need(len(body['outputs']) == (1 if terminal else 2), 'exact-independent-exit-output-count')
            payout = body['outputs'][-1]
            need(P2PK.fullmatch(payout['scriptPublicKey']), 'exit-native-P2PK-recipient')
            if not terminal:
                need(P2SH.fullmatch(body['outputs'][0]['scriptPublicKey']), 'exit-continuing-reserve')
            reserve = 0 if terminal else amount(body['outputs'][0]['value'], positive=True)
            payouts.append({'transaction_id': check['id'], 'index': len(body['outputs']) - 1,
                            'amount_sompi': payout['value']})
            exit_fees.append(check['fee'])
        head = (body['id'], 0) if reserve else None
    need(reserve == 0 and len(payouts) == expected_exits, 'all-notes-paid-and-terminal-reserve-zero')
    total_fees = amount(sum(check['fee'] for _, _, check in rows))
    leaves = [(key, row) for key, row in created.items() if key not in spent]
    final_outputs = amount(sum(row['value'] for _, row in leaves))
    need(external_sources == final_outputs + total_fees, 'all-trial-sources-outputs-fees-conserve')
    payout_sum = amount(sum(row['amount_sompi'] for row in payouts))
    pool_change = amount(sum(row['value'] for row in first_case['transaction']['outputs'][1:]))
    pool_fees = amount(first['fee'] + sum(batch_fees) + sum(exit_fees))
    need(first['source'] == pool_change + payout_sum + pool_fees,
         'GN3-sources-change-payouts-pool-fees-conserve')
    result = {'schema': 'kpx8-complete-lifecycle-arithmetic/v1',
        'transaction_count': len(rows), 'payment_round_count': expected_rounds,
        'payout_count': len(payouts), 'external_source_sompi': external_sources,
        'final_native_outputs_sompi': final_outputs, 'initial_reserve_sompi': initial_reserve,
        'ordinary_GN3_change_sompi': pool_change, 'GN3_fee_sompi': first['fee'],
        'batch_fees_sompi': batch_fees, 'private_exit_fees_sompi': exit_fees,
        'acquisition_fees_sompi': amount(sum(check['fee'] for _, _, check in acquisition)),
        'total_fee_sompi': total_fees, 'pool_fee_sompi': pool_fees,
        'native_payouts_sompi': payout_sum, 'terminal_reserve_sompi': 0,
        'arithmetic_and_physical_lineage_checked': True,
        'proofs_native_VM_chain_currentness_wallet_ownership_or_privacy_verified': False}
    if useful_payment_sompi is not None:
        useful = amount(useful_payment_sompi, positive=True)
        result.update({'declared_useful_payment_sompi': useful,
            'denominator_derived_from_private_payments_by_this_function': False,
            'complete_fee_target_numerator': 2, 'complete_fee_target_denominator': 100,
            'complete_2_percent_fee_target_met': total_fees * 100 <= useful * 2})
    return result
