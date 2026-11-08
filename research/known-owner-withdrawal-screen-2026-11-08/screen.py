#!/usr/bin/env python3
"""Exact integer balance screen for the already accepted TN10 bundle trial.

The prediction reads public amounts and the declared auxiliary owner/contact
model. The actual private payment amounts enter only the separate score step.
"""
import argparse
import hashlib
import json
from pathlib import Path


def read(path):
    return json.loads(path.read_text())


def write_new(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def amounts(root, stage):
    receipt = read(root / 'accepted' / f'{stage}.json')
    assert receipt['confirmed'] >= 10
    assert receipt['transactionId'] == receipt['transaction']['verboseData']['transactionId']
    return receipt['transactionId'], [output['value'] for output in receipt['transaction']['outputs']], receipt


def feasible(principal, group, terminal, edges):
    a, b, c, d = principal, 0, 0, 0
    x, y, z, w = edges
    if not all(isinstance(v, int) and v > 0 for v in edges):
        return False
    a -= x; b += x
    if a < 0: return False
    b -= y; c += y
    if b < 0: return False
    a -= z; d += z
    if a < 0: return False
    a -= group[0]; b -= group[1]; c -= group[2]
    if min(a, b, c, d) < 0: return False
    d -= w; a += w
    return (a, b, c, d) == (terminal[0], 0, 0, terminal[1])


def predict(root):
    complete = read(root / 'COMPLETE.json')
    assert complete['freshTN10RehearsalComplete'] is True
    assert complete['terminalBankValueSompi'] == 0
    principal = complete['principalSompi']
    assert principal == 120_000_000
    fund_id, fund, _ = amounts(root, 'fund')
    withdrawal_id, withdrawal, withdrawal_receipt = amounts(root, 'withdrawal')
    terminal_id, terminal, terminal_receipt = amounts(root, 'terminal')
    assert fund[0] == 200_000_000 and len(withdrawal) == 4 and len(terminal) == 3
    assert withdrawal[1:] == [30_000_000] * 3
    assert terminal[:2] == [6_000_000, 24_000_000]
    assert terminal_receipt['transaction']['inputs'][0]['previousOutpoint'] == {
        'transactionId': withdrawal_id, 'index': 0}
    # The accepted public outputs are given their *auxiliary* known-owner map:
    # group A/B/C each 0.3 KAS; terminal A 0.06 and D 0.24 KAS.
    group = withdrawal[1:]
    final = terminal[:2]
    # C has no other contact or terminal balance: B->C is exactly C's exit.
    y = group[2]
    # B receives only A->B and sends only B->C: A->B is B's exit plus B->C.
    x = group[1] + y
    # D receives A->D and later sends D->A: z-w equals D's terminal exit.
    d = final[1]
    z_min, z_max = d + 1, principal - x - group[0]
    assert z_min <= z_max
    # A's terminal balance must agree independently with the other equations.
    assert principal - x - group[0] - d == final[0]
    lower = (x, y, z_min, z_min - d)
    upper = (x, y, z_max, z_max - d)
    assert feasible(principal, group, final, lower)
    assert feasible(principal, group, final, upper)
    # Every intermediate integer z is feasible: w=z-d, so B/C/D terminal
    # balances stay fixed; A's post-group balance is nonnegative until z_max.
    labels = ('A_to_B', 'B_to_C', 'A_to_D', 'D_to_A')
    intervals = {label: {'min': lo, 'max': hi} for label, lo, hi in zip(labels, lower, upper)}
    return {
        'scope': 'known-owner, known-contact, positive-integer-sompi full-drainage control',
        'inputTransactionIds': {'fund': fund_id, 'withdrawal': withdrawal_id, 'terminal': terminal_id},
        'principalSompi': principal, 'groupPayoutsSompi': group,
        'terminalPayoutsSompi': final,
        'rangesSompi': intervals,
        'compatibleAmountTuples': z_max - z_min + 1,
        'exactPaymentAmounts': sum(lo == hi for lo, hi in zip(lower, upper)),
        'bundleBytesOrServiceLogRead': False,
        'ownerMapIsAuxiliary': True,
        'actualPaymentAmountsRead': False,
    }


def score(prediction, truth):
    labels = ('A_to_B', 'B_to_C', 'A_to_D', 'D_to_A')
    expected = tuple(truth[label] for label in labels)
    p = prediction['principalSompi']
    g = prediction['groupPayoutsSompi']
    t = prediction['terminalPayoutsSompi']
    assert feasible(p, g, t, expected), 'execution truth excluded by observer model'
    assert all(prediction['rangesSompi'][label]['min'] <= value <= prediction['rangesSompi'][label]['max']
               for label, value in zip(labels, expected))
    exact = [label for label, value in zip(labels, expected)
             if prediction['rangesSompi'][label]['min'] == prediction['rangesSompi'][label]['max'] == value]
    return {'truthRetained': True, 'exactActualPaymentAmounts': exact,
            'stopRuleTriggered': bool(exact),
            'decision': 'no independent-wallet or cost escalation for complete payment privacy' if exact else 'next privacy gate may proceed',
            'relationshipDiscoveryMeasured': False,
            'matchedUpstreamExecutionCompared': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('predict', 'score'))
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--truth', type=Path)
    args = parser.parse_args()
    if args.mode == 'predict':
        assert args.truth is None
        prediction = predict(args.input)
        write_new(args.output, prediction)
        print('prediction_sha256=' + hashlib.sha256(args.output.read_bytes()).hexdigest())
    else:
        assert args.truth is not None
        prediction = read(args.input)
        result = score(prediction, read(args.truth))
        result['predictionSha256'] = hashlib.sha256(args.input.read_bytes()).hexdigest()
        write_new(args.output, result)
        print('exact_amounts=' + str(len(result['exactActualPaymentAmounts'])) +
              ' stop=' + str(result['stopRuleTriggered']).lower())


if __name__ == '__main__':
    main()
