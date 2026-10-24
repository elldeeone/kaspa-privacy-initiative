"""Public shape sizing followed by exact native re-quotation.

Batch sizing uses explicitly invalid public proof/CV records of the exact fixed
shape. It authorizes no money or owner witness. The genuinely authorized final
case must independently reproduce the exact fee before native validation.
"""
from public import Q, body_core, exit_body, reconstruct, sha
from trees import need


def batch_scaffold(history, roster, fee):
    state, head = reconstruct(history)
    point = bytes.fromhex(head['outpoint_hex36'])
    used = set(state.nfs)
    nfs = []
    counter = 0
    while len(nfs) != 3:
        nf = sha(b'KPX8 PUBLIC INVALID SIZING NF\0', point, counter.to_bytes(8, 'little'))
        counter += 1
        if nf != bytes(32) and nf not in used:
            used.add(nf)
            nfs.append(nf)
    rows = []
    for index in range(6):
        cf = bytes([index + 1]) * 264
        cm = sha(b'KPX8 PUBLIC INVALID SIZING CM\0', point, bytes([index]))
        rows.append(cm + bytes(64) + cf + sha(cf) + bytes(128))
    return body_core(history, [(nf, bytes(64)) for nf in nfs], rows, bytes(32),
                     sha(b'KPX8 PUBLIC INVALID SIZING SESSION\0', point).hex(), roster, fee)


def fixed_point(build, native_module, codec, selected, *, budget=1800, rate=100):
    need(type(budget) is int and budget == 1800 and type(rate) is int and rate == 100,
         'selected-B1800-rate100-quote')
    fee = 1_000_000
    seen, attempts = set(), []
    for _ in range(1024):
        need(fee not in seen, 'no-exact-integer-fee-fixed-point')
        seen.add(fee)
        body = build(fee)
        case, projection, journal, report = native_module.make_case(codec, body, *selected, budget)
        metrics = report['metrics']
        mass = metrics['mining_mass']
        need(type(mass) is int and mass > 0 and type(metrics['actual_fee_sompi']) is int
             and metrics['actual_fee_sompi'] == fee, 'canonical-native-mass-and-actual-fee')
        needed = mass * rate
        attempts.append({'proposed_fee_sompi': fee, 'mining_mass': mass, 'quoted_fee_sompi': needed})
        if needed == fee:
            return body, case, projection, journal, report, {
                'schema': 'kpx8-exact-native-shape-quote/v1', 'fee_sompi': fee,
                'mining_mass': mass, 'compute_budget': budget, 'reference_rate': rate,
                'iterations': attempts, 'exact_integer_fixed_point': True,
                'genuine_final_candidate_requote_required': True,
                'financial_authorization_proofs_native_Full_chain_or_privacy_verified': False}
        fee = needed
    raise ValueError('operational-quote-incomplete-no-authorization')


def batch(history, roster, native_module, codec, selected):
    result = fixed_point(lambda fee: batch_scaffold(history, roster, fee), native_module, codec, selected)
    result[-1]['classification'] = 'INVALID_PUBLIC_RECORD_SIZING_NOT_FINANCIAL_AUTHORIZATION'
    return result


def exit(history, nf, payout_spk, gross, session_sha256, native_module, codec, selected):
    result = fixed_point(lambda fee: exit_body(history, nf, payout_spk, gross, fee, session_sha256),
                         native_module, codec, selected)
    result[-1]['classification'] = 'UNPROVED_OWN_EXACT_EXIT_SHAPE_NOT_FINANCIAL_AUTHORIZATION'
    return result


def exact_final(report, approved_fee, *, rate=100):
    """Call on the genuine final case before Full/submission; never revise it."""
    metrics = report['metrics']
    need(type(approved_fee) is int and type(rate) is int and rate == 100
         and type(metrics['actual_fee_sompi']) is int
         and type(metrics['mining_mass']) is int and metrics['mining_mass'] > 0
         and metrics['actual_fee_sompi'] == approved_fee
         and metrics['mining_mass'] * rate == approved_fee,
         'genuine-final-case-must-match-approved-exact-fee')
