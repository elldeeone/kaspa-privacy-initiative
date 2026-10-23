"""Integer accounting for the root-selected six-body change-spend workload.

Pure source/component model: no identity, entropy, keys, SDK, VM or network.
This is an internal planning value model, not a public report schema. A future
controller must project only permitted counts and already-public effects.
"""
MAX_SOMPI = 2_870_000_000_000_000_000
NOTE_FLOOR = 60_000_000
PAYOUT_FLOOR = 10_000_000
PRINCIPAL = 1_000_000_000
PARTIAL_PAYOUT = 400_000_000
FOLLOW_ON_PAYMENT = 300_000_000
FEE_NAMES = ('initial-payment', 'partial-cashout', 'change-payment',
             'owner-full', 'recipient-terminal')


def require(condition, category):
    if not condition:
        raise ValueError(category)


def amount(value, category, minimum=0):
    require(type(value) is int and minimum <= value <= MAX_SOMPI, category)
    return value


def derive(private_fees):
    require(type(private_fees) is dict and set(private_fees) == set(FEE_NAMES),
            'exact-five-private-fees')
    fees = [amount(private_fees[name], 'positive-bounded-private-fee', 1) for name in FEE_NAMES]
    first_change = PRINCIPAL - PARTIAL_PAYOUT - fees[1]
    second_change = first_change - FOLLOW_ON_PAYMENT - fees[2]
    owner_payout = second_change - fees[3]
    recipient_payout = FOLLOW_ON_PAYMENT - fees[4]
    amount(first_change, 'partial-positive-change-floor', NOTE_FLOOR)
    amount(second_change, 'payment-positive-change-floor', NOTE_FLOOR)
    amount(owner_payout, 'owner-final-payout-floor', PAYOUT_FLOOR)
    amount(recipient_payout, 'recipient-final-payout-floor', PAYOUT_FLOOR)
    reserve = amount(PRINCIPAL + fees[0], 'whole-founding-reserve', NOTE_FLOOR)
    outputs = ((PRINCIPAL, 0), (first_change, 0),
               (second_change, FOLLOW_ON_PAYMENT), (0, 0), ())
    consumed = (reserve, PRINCIPAL, first_change, second_change, FOLLOW_ON_PAYMENT)
    payouts = (0, PARTIAL_PAYOUT, 0, owner_payout, recipient_payout)
    counts = ((3, 3), (5, 5), (7, 7), (9, 9), (9, 11))
    rows = []
    for name, fee, incoming, outgoing, payout, (cm, nf) in zip(
            FEE_NAMES, fees, consumed, outputs, payouts, counts):
        require(incoming == sum(outgoing) + payout + fee, 'private-action-conservation')
        after = amount(reserve - payout - fee, 'bounded-successor-reserve')
        require(after == 0 or after >= NOTE_FLOOR, 'successor-reserve-floor')
        require(incoming <= reserve and sum(outgoing) <= after, 'liability-backing')
        require(after != 0 or not outgoing, 'terminal-no-private-output')
        rows.append({'action': name, 'fee_sompi': fee, 'input_note_sompi': incoming,
            'output_notes_sompi': list(outgoing), 'payout_sompi': payout,
            'reserve_before_sompi': reserve, 'reserve_after_sompi': after,
            'CM_count': cm, 'NF_count': nf})
        reserve = after
    require(reserve == 0 and counts[-1] == (9, 11), 'terminal-zero-counts')
    require(sum(payouts) + sum(fees) == PRINCIPAL + fees[0], 'whole-private-reserve-conservation')
    return {'founding_reserve_sompi': consumed[0], 'actions': rows,
        'private_fees_sompi': sum(fees), 'native_payouts_sompi': sum(payouts),
        'positive_native_payouts': 3, 'private_actions': 5, 'native_bodies': 6,
        'terminal_reserve_sompi': 0, 'final_CM_count': 9, 'final_NF_count': 11}


def reconcile(private_fees, *, funding_input_sompi, funding_output_sompi,
              funding_fee_sompi, funding_change_sompi, founding_fee_sompi,
              founding_change_sompi):
    flow = derive(private_fees)
    values = {name: amount(value, name) for name, value in {
        'funding-input': funding_input_sompi, 'funding-output': funding_output_sompi,
        'funding-fee': funding_fee_sompi, 'funding-change': funding_change_sompi,
        'founding-fee': founding_fee_sompi, 'founding-change': founding_change_sompi}.items()}
    require(values['funding-input'] > 0 and values['funding-output'] > 0
        and values['founding-fee'] > 0, 'positive-source-and-founding-fee')
    require(values['funding-input'] == values['funding-output']
        + values['funding-fee'] + values['funding-change'], 'ordinary-funding-conservation')
    require(values['funding-output'] == flow['founding_reserve_sompi']
        + values['founding-fee'] + values['founding-change'], 'ordinary-founding-conservation')
    total_fees = values['funding-fee'] + values['founding-fee'] + flow['private_fees_sompi']
    all_change = values['funding-change'] + values['founding-change']
    require(values['funding-input'] == all_change + total_fees + flow['native_payouts_sompi'],
            'whole-original-source-reconciliation')
    return {'funding_input_sompi': funding_input_sompi,
        'all_ordinary_change_sompi': all_change, 'all_fees_sompi': total_fees,
        'all_native_payouts_sompi': flow['native_payouts_sompi'],
        'terminal_reserve_sompi': 0, 'modeled_terminal_private_liabilities_sompi': 0}
