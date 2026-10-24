"""Complete four-wallet campaign accounting after independent public replay.

This is an evidence join, not a consensus validator or proof of owner identity.
Requested payment amounts come from the selected workload, not total payouts.
"""
from decimal import Decimal, localcontext
from fractions import Fraction

from compat import core


def close(replayed, exit_summaries, final_scans, recipient_exit_summaries, requested_nets):
    p = core().primitives
    p.need(replayed['provided_public_prefix_validated'] is True
           and replayed['reserve'] == 0 and replayed['point'] is None,
           'complete-public-replay-and-zero-reserve')
    p.need(type(requested_nets) in (list, tuple) and len(requested_nets) == 2
           and all(type(value) is int and value == 1_000_000_000 for value in requested_nets),
           'exact-two-selected-net-10KAS-payments')
    operations = replayed['operations']
    p.need(type(operations) is list and len(operations) == 5
           and operations[0]['kind'] == 'ACTUAL_W_TWO_VIRTUAL_CHILDREN'
           and all(row['kind'] == 'ACTUAL_W_PRIVATE_DIRECT' for row in operations[1:])
           and all(row['fresh_native_Full_all_engines'] is True for row in operations),
           'one-settlement-four-owner-exits')
    p.need((replayed['snapshot'].cm_cursor, len(replayed['snapshot'].nullifiers)) == (6, 13),
           'exact-four-wallet-final-public-counts')
    p.need(type(exit_summaries) in (list, tuple) and len(exit_summaries) == 4
           and len({row['transaction_id'] for row in exit_summaries}) == 4
           and {row['transaction_id'] for row in exit_summaries}
               == {row['transaction_id'] for row in operations[1:]}, 'four-distinct-selected-exit-receipts')
    public_payouts = {row['transaction_id']: row['amount_sompi'] for row in replayed['payouts']}
    public_operations = {row['transaction_id']: row for row in operations}
    p.need(len(public_payouts) == 4, 'four-actual-native-payouts')
    for row in exit_summaries:
        p.need(row['op'] == 'prepare-full-cashout'
               and row['consumed_same_backup_claim_count'] == 1
               and row['recognized_unspent_claim_count_after'] == 0
               and row['whole_PK_VK_READY_before_original_backup'] is True
               and row['native_Full_all_input_engines'] is True
               and public_payouts[row['transaction_id']] == row['native_payout_sompi']
               and public_operations[row['transaction_id']]['fee_sompi'] == row['fee_sompi'],
               'isolated-one-real-owner-exit-and-payout-evidence')
        p.amount(row['native_payout_sompi']); p.amount(row['fee_sompi'])
    p.need(type(recipient_exit_summaries) in (list, tuple) and len(recipient_exit_summaries) == 2
           and len({row['transaction_id'] for row in recipient_exit_summaries}) == 2,
           'two-separately-selected-recipient-exits')
    selected_exits = {row['transaction_id']: row for row in exit_summaries}
    for row, net in zip(recipient_exit_summaries, requested_nets):
        p.need(row == selected_exits.get(row['transaction_id'])
               and row['minimum_payout_sompi'] == net and row['native_payout_sompi'] >= net,
               'recipient-requested-net-survives-all-actual-fees')
    p.need(type(final_scans) in (list, tuple) and len(final_scans) == 4
           and sorted(row['recognized_historical_receipt_count'] for row in final_scans) == [1, 1, 2, 2],
           'four-original-backup-final-scan-workload')
    for row in final_scans:
        p.need(row['op'] == 'recover' and row['recognized_unspent_claim_count_before'] == 0
               and row['recognized_spent_receipt_count'] == row['recognized_historical_receipt_count']
               and row['historical_native_payout_key_control_match_count'] == 1
               and row['unresolved_owned_NF_payout_records'] == 0,
               'all-original-backups-recognize-spent-claims-and-owned-payout')
    entry = replayed['entry']
    sources = sum(row['source_amount_sompi'] for row in entry['contributions'])
    ordinary_change = sum(row['ordinary_change_sompi'] for row in entry['contributions'])
    entry_fee = p.amount(entry['fee_sompi'])
    outer_fee = p.amount(operations[0]['fee_sompi'])
    exit_fees = sum(p.amount(row['fee_sompi']) for row in operations[1:])
    payouts = sum(p.amount(value) for value in public_payouts.values())
    p.uint(sources, 64); p.uint(ordinary_change, 64); p.uint(exit_fees, 64); p.uint(payouts, 64)
    p.need(sources == ordinary_change + entry_fee + outer_fee + exit_fees + payouts,
           'all-sources-ordinary-change-entry-settlement-four-exits-and-payouts-close')
    total_fee = entry_fee + outer_fee + exit_fees
    useful = sum(requested_nets)
    ratio = Fraction(100 * total_fee, useful)
    with localcontext() as context:
        context.prec = 80
        display = format(Decimal(ratio.numerator) / Decimal(ratio.denominator), 'f')
    return {'schema': 'kpx6-four-wallet-complete-fee-ledger/v1',
        'source_sompi': sources, 'ordinary_returned_change_sompi': ordinary_change,
        'entry_fee_sompi': entry_fee, 'settlement_fee_sompi': outer_fee,
        'all_four_private_exit_fees_sompi': exit_fees, 'native_payouts_sompi': payouts,
        'remaining_reserve_sompi': 0, 'total_fee_sompi': total_fee,
        'selected_useful_requested_net_sompi': useful,
        'fee_percent_fraction': {'numerator': ratio.numerator, 'denominator': ratio.denominator},
        'fee_percent_display': display,
        'two_percent_fee_target_passes_this_complete_workload': total_fee * 100 <= 2 * useful,
        'change_refunds_principal_or_payouts_counted_as_extra_useful_payments': False,
        'public_network_evidence_consistency_validated':
            replayed.get('network_evidence_consistency_validated', False),
        'financial_privacy_or_cryptographic_soundness_qualification': False}
