"""Public fixed-width sizing before owner preparation; never a legal proof.

These deliberately invalid record skeletons have no private witness, G16/R0
receipt or settlement authority. Every genuine child and final aggregate body
must be independently normalized/reconciled before use.
"""
from pathlib import Path

from compat import core, public
from paths import outside


def _case(runtime, state, point, reserve, payload, outputs, budget, daa):
    c = core(); p = c.primitives
    p.uint(daa, 64)
    redeem = runtime.emit(state)
    frame = c.native_runtime.push(bytes(65)) + c.native_runtime.push(bytes(128)) + c.native_runtime.push(redeem)
    body = c.native_runtime.tx(point, outputs, payload, frame, budget)
    return c.native_runtime.public_case(body, [c.native_runtime.context(reserve, redeem, daa=daa)])


def _fixed_fee(runtime, build, rate, output):
    p = core().primitives
    fee, seen, steps = 2, set(), []
    while True:
        p.need(fee not in seen, 'public-mass-fixed-point-incomplete')
        seen.add(fee)
        case = build(fee)
        normalized, _, metrics = runtime.normalize_case(case, output / ('normalize-' + str(len(steps))))
        required = p.amount(rate * metrics['mining_mass'])
        steps.append({'fee_sompi': fee, 'required_sompi': required,
                      'storage_mass': metrics['storage_mass']})
        if fee == required:
            p.need(metrics['actual_fee_sompi'] == fee, 'exact-public-sizing-fee')
            return normalized, metrics, steps
        fee = required


def evaluate(runtime, snapshot, point, reserve, daa, output, *, net_principal_sompi, rate):
    c = core(); p = c.primitives; pub = public(); selected = runtime.profile
    p.need(type(rate) is int and 0 < rate < 1 << 64, 'reference-rate')
    net = p.amount(net_principal_sompi)
    p.need(net >= p.PAYOUT_FLOOR, 'useful-payment-net-floor')
    state = snapshot.state(selected.domain)
    fields = pub.policy.state(state, selected.domain)
    c.actions.point_bytes(point); p.amount(reserve)
    output = outside(output)
    p.need(not output.exists(), 'fresh-public-sizing-output')
    output.mkdir(parents=True, mode=0o700)
    final = bytearray(state)
    final[40:72] = final[76:108] = bytes(32)
    final[72:76] = (((fields['n'] + 1) // 2 * 2) + 4).to_bytes(4, 'little')
    final[108:112] = (fields['m'] + 4).to_bytes(4, 'little')
    final = bytes(final)
    pub.policy.state(final, selected.domain)
    next_spk = c.native_runtime.p2sh(runtime.emit(final))
    payload = pub.virtual.encode_payload((bytes(4048), bytes(4048)))
    outer, metrics, steps = _fixed_fee(runtime, lambda fee:
        _case(runtime, state, point, reserve, payload, [(reserve-fee, next_spk)],
              selected.aggregate_budget, daa), rate, output / 'outer')
    total = metrics['actual_fee_sompi']
    allocated = [total // 2, total - total // 2]
    p.need(all(fee > 0 for fee in allocated), 'positive-exact-child-allocation')
    remaining = reserve - total
    p.need(remaining > net + p.NOTE_FLOOR, 'public-sizing-positive-other-reserve')
    payout_spk = '000020' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' + 'ac'
    direct_payload = b'KPX4AU01' + selected.domain + bytes(2848-40)
    continuing, direct_metrics, direct_steps = _fixed_fee(runtime, lambda fee:
        _case(runtime, final, point, remaining, direct_payload,
              [(remaining-net-fee, next_spk), (net, payout_spk)],
              selected.private_budget, daa), rate, output / 'continuing')
    credit = direct_metrics['actual_fee_sompi']
    gross = p.amount(net + credit)
    terminal, terminal_metrics, terminal_steps = _fixed_fee(runtime, lambda fee:
        _case(runtime, final, point, gross, direct_payload, [(gross-fee, payout_spk)],
              selected.private_budget, daa), rate, output / 'terminal')
    p.need(credit >= terminal_metrics['actual_fee_sompi'], 'recipient-terminal-credit-coverage')
    for name, case in (('outer', outer), ('continuing', continuing), ('terminal', terminal)):
        c.native_runtime.save(output / (name + '-INVALID-SIZING-ONLY.json'), case)
    result = {'schema': 'kpx6-four-wallet-public-sizing/v1',
        'classification': 'INVALID_PUBLIC_RECORD_SIZING_NOT_QUOTE_OR_SETTLEMENT_AUTHORITY',
        'financial_profile_sha256': selected.profile_sha256,
        'reference_rate': rate, 'net_principal_sompi': net, 'recipient_exit_credit_sompi': credit,
        'recipient_gross_sompi': gross, 'outer_fee_sompi': total,
        'allocated_child_fees_sompi': allocated,
        'private_budget': selected.private_budget, 'aggregate_budget': selected.aggregate_budget,
        'official_outer_metrics': metrics, 'official_continuing_metrics': direct_metrics,
        'official_terminal_metrics': terminal_metrics,
        'outer_fixed_point': steps, 'continuing_fixed_point': direct_steps,
        'terminal_fixed_point': terminal_steps,
        'genuine_body_requote_and_exact_fee_reconciliation_required': True,
        'private_witness_PK_proof_native_Full_chain_acceptance_or_fee_qualification': False}
    c.native_runtime.save(output / 'RESULTS.json', result)
    return result
