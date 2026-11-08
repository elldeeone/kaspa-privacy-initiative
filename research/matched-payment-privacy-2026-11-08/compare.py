#!/usr/bin/env python3
"""Offline, pinned 47-KAS ordinary-reply versus public-board privacy screen.

Predict reads public evidence and declared owner/contact auxiliaries only.
Score is a separate step which reads the actual private transfer amounts.
"""
import argparse
import hashlib
import itertools
import json
import math
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'research/cached-approval-verification-2026-11-07/run'
HOST = ROOT / '.local/ci-target/release/kpi-separated-withdrawal'
UNIT = 100_000_000
LABELS = ('A_to_B', 'B_to_C', 'A_to_D', 'D_to_A_before_group',
          'D_to_B_after_group', 'D_to_C_after_group', 'D_to_A_after_group')
PINS = {
    'combined/MAIN.json': '07c0e4fedf81d3776d66f2042c986ca1baf471b3fb6e0fbafb2bba798be45f69',
    'combined/APPROVALS.json': '1f221b5be0ea2b0f83f9115bd0dd6c1bcdb0f12dc9b4e32f219f9926c4e69ebd',
    'registration/operator.jsonl': 'aae893908071bd6e5b9ce30976bdd6ddb691bf598f31245419e30fcf0f508255',
    'registration/config.json': 'af6f63274e01eb995e5b01c3d5c05a45d8902e6b1f1f7a61538f71f267f8e5cb',
    'registration/PUBLIC-REPLAY.json': 'eac5b0fc001fd07d388e117923f79772528496e6b249bcb7ba26aef68e5feed3',
    'registration/PRIVACY-VIEWS.json': 'a1ffa0ab0bcec5b0124085c92a994584df8550a47f43146cce7cd33558362914',
}


def read(path):
    return json.loads(path.read_text())


def write_new(path, value):
    with path.open('x') as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write('\n')


def write_compact_new(path, value):
    with path.open('x') as out:
        json.dump(value, out, separators=(',', ':'), sort_keys=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def model(values, principal, group, final):
    """Replays all seven positive integer-sompi payments in their actual order."""
    if len(values) != 7 or any(type(n) is not int or n <= 0 for n in values):
        return False
    a, b, c, d = principal, 0, 0, 0
    x, y, z, w, u, v, t = values
    a -= x; b += x
    if min(a, b, c, d) < 0: return False
    b -= y; c += y
    if min(a, b, c, d) < 0: return False
    a -= z; d += z
    if min(a, b, c, d) < 0: return False
    d -= w; a += w
    if min(a, b, c, d) < 0: return False
    a -= group[0]; b -= group[1]; c -= group[2]
    if min(a, b, c, d) < 0: return False
    d -= u; b += u
    if min(a, b, c, d) < 0: return False
    d -= v; c += v
    if min(a, b, c, d) < 0: return False
    d -= t; a += t
    return (a, b, c, d) == tuple(final)


def tuple_from_parameters(y, q, s, w, group, final):
    # y=B->C, q=x-y, s=x+z-w. The final balances solve the later transfers.
    ga, gb, gc = group
    fa, fb, fc, _ = final
    x = y + q
    return (x, y, s - x + w, w,
            fb + gb - q, fc + gc - y, fa + ga - (40 * UNIT - s))


def amounts(principal, group, final):
    assert principal == 40 * UNIT
    assert group == [10 * UNIT] * 3
    assert final == [3 * UNIT, UNIT, 3 * UNIT, 3 * UNIT]
    # Strictly positive after-group transfers and nonnegative intervening
    # balances give y in [10,13), q in [10,11), s in (27,30].
    y_bounds = (10 * UNIT, 13 * UNIT - 1)
    q_bounds = (10 * UNIT, 11 * UNIT - 1)
    s_bounds = (27 * UNIT + 1, 30 * UNIT)
    vertices = []
    for y, q, s in itertools.product(y_bounds, q_bounds, s_bounds):
        for w in (1, principal - s):
            values = tuple_from_parameters(y, q, s, w, group, final)
            assert model(values, principal, group, final)
            vertices.append(values)
    # Each value is affine in y,q,s,w and w's upper bound is affine in s.
    # Thus these corner witnesses attain every per-value minimum and maximum.
    ranges = {label: {'min': min(v[i] for v in vertices),
                      'max': max(v[i] for v in vertices)}
              for i, label in enumerate(LABELS)}
    grid = []
    for y in range(y_bounds[0], y_bounds[1] + 1, UNIT):
        for q in range(q_bounds[0], q_bounds[1] + 1, UNIT):
            for s in range(28 * UNIT, 31 * UNIT, UNIT):
                for w in range(UNIT, principal - s + 1, UNIT):
                    values = tuple_from_parameters(y, q, s, w, group, final)
                    assert model(values, principal, group, final)
                    grid.append(values)
    assert len(grid) == 99
    grid_ranges = {label: {'min': min(v[i] for v in grid),
                           'max': max(v[i] for v in grid)}
                   for i, label in enumerate(LABELS)}
    return ranges, grid_ranges, len(grid)


def predict(outdir):
    assert all(digest(SOURCE / rel) == sha for rel, sha in PINS.items())
    main = read(SOURCE / 'combined/MAIN.json')
    approvals = read(SOURCE / 'combined/APPROVALS.json')
    replay = read(SOURCE / 'registration/PUBLIC-REPLAY.json')
    privacy = read(SOURCE / 'registration/PRIVACY-VIEWS.json')
    config = read(SOURCE / 'registration/config.json')
    events = [json.loads(line) for line in
              (SOURCE / 'registration/operator.jsonl').read_text().splitlines()]
    assert len(events) >= 6
    issues, redeems = events[:3], events[3:6]
    assert all(e['request']['kind'] == 'issue' and
               set(e['response']) == {'blindSignature'} for e in issues)
    assert all(e['request']['kind'] == 'redeem' and
               e['response']['valueSompi'] == 10 * UNIT for e in redeems)
    assert len({e['request']['blindMessage'] for e in issues}) == 3
    assert len({e['response']['recipientKey'] for e in redeems}) == 3
    assert len(approvals['operations']) == 3
    assert replay['genuineEligibilityProofs'] == replay['finalRfc9474Signatures'] == 3
    assert replay['independentArkworksVerification'] is True
    assert replay['negativeResponses'] == 9 and replay['privateMaterialUsed'] is False
    assert main['nativeFull'] is True and main['chainAccepted'] is False
    assert main['reserve'] == main['liability'] == 0
    assert len(main['records']) == 7 and len(main['restoredPayoutSpends']) == 8
    assert main['principalSompi'] == 40 * UNIT and main['usefulPaymentSompi'] == 47 * UNIT
    records = main['records']
    assert [r['payoutPrincipalSompi'] for r in records[1:]] == [0, 0, 30 * UNIT, 0, 0, 10 * UNIT]
    group_tx, final_tx = records[3]['transaction'], records[6]['transaction']
    group_outputs = group_tx['outputs']
    final_outputs = final_tx['outputs']
    assert [o['value'] for o in group_outputs[1:]] == [10 * UNIT] * 3
    assert [o['value'] for o in final_outputs[:5]] == [2 * UNIT, UNIT, UNIT, 3 * UNIT, 3 * UNIT]
    funding_script = records[0]['transaction']['outputs'][1]['scriptPublicKey']
    assert final_outputs[5]['scriptPublicKey'] == funding_script
    owner_totals = [0, 0, 0, 0]
    group_owners = []
    for spend in main['restoredPayoutSpends']:
        who = spend['ownerDisclosureControl']
        assert type(who) is int and 0 <= who < 4
        prev = spend['transaction']['inputs'][0]['previousOutpoint']
        tx = group_tx if prev['transactionId'] == group_tx['id'] else final_tx
        assert prev['transactionId'] == tx['id']
        index = prev['index']
        assert (1 <= index <= 3) if tx is group_tx else (0 <= index <= 4)
        if tx is group_tx:
            group_owners.append(who)
        else:
            owner_totals[who] += tx['outputs'][index]['value']
    assert sorted(group_owners) == [0, 1, 2]
    assert owner_totals == [3 * UNIT, UNIT, 3 * UNIT, 3 * UNIT]
    assert privacy['serviceOnlyCompatibleAssignments'] == math.factorial(3)
    assert privacy['oneParticipantOwnKeyKnown'] == 2
    board = {'version': 1, 'round': config['round'],
             'entries': [{'issue': e['request'],
                          'blindSignature': e['response']['blindSignature']} for e in issues]}
    board_path = outdir / 'BOARD.json'
    write_compact_new(board_path, board)
    assert board_path.stat().st_size < 24_000
    subprocess.run([str(HOST), 'board-public-check', str(SOURCE / 'registration/config.json'),
                    str(board_path)], check=True)
    principal = main['principalSompi']
    group = [o['value'] for o in group_outputs[1:]]
    ranges, grid_ranges, grid_count = amounts(principal, group, owner_totals)
    prediction = {
        'sourceCommit': 'b151fe72', 'sourceHashes': PINS,
        'nativeFullTransactions': 6, 'chainAccepted': False,
        'actualWalletIssueAndRedeemEvents': 6,
        'board': {'actualRepliesRepackaged': 3, 'publicRelationVerified': True,
                  'bytes': board_path.stat().st_size, 'sha256': digest(board_path),
                  'walletsRedeemedThisBoardIn47KASRun': False},
        'principalSompi': principal, 'groupPayoutsSompi': group,
        'knownOwnerFinalPrincipalSompi': owner_totals,
        'feeRefundUsesFundingScript': True,
        'ordinaryServiceOnlyCompatibleMappings': 6,
        'boardServiceOnlyCompatibleMappings': 6,
        'oneParticipantKnownCompatibleMappings': 2,
        'allPayoutOwnersKnownCompatibleMappings': 1,
        'knownContactEdgesAndOrderSupplied': True,
        'relationshipDiscoveryMeasured': False,
        'balanceNecessaryRangesSompi': ranges,
        'wholeKASGridAuxiliaryRangesSompi': grid_ranges,
        'wholeKASGridFeasibleTuples': grid_count,
        'ordinaryAndBoardPublicBalanceEquationsIdentical': True,
        'bundleFeeForThis47KASWorkloadMeasured': False,
        'independentPeopleOrNetworkTimingMeasured': False,
        'actualPaymentAmountsRead': False,
    }
    write_new(outdir / 'PREDICTION.json', prediction)
    print('prediction_sha256=' + digest(outdir / 'PREDICTION.json'))


def score(outdir, truth_path):
    prediction = read(outdir / 'PREDICTION.json')
    truth = read(truth_path)
    values = tuple(truth[label] for label in LABELS)
    assert model(values, prediction['principalSompi'], prediction['groupPayoutsSompi'],
                 prediction['knownOwnerFinalPrincipalSompi']), 'truth contradicts fixed workload'
    assert all(prediction['balanceNecessaryRangesSompi'][label]['min'] <= v <=
               prediction['balanceNecessaryRangesSompi'][label]['max']
               for label, v in zip(LABELS, values))
    exact = [label for label, v in zip(LABELS, values)
             if prediction['balanceNecessaryRangesSompi'][label] == {'min': v, 'max': v}]
    grid_exact = [label for label, v in zip(LABELS, values)
                  if prediction['wholeKASGridAuxiliaryRangesSompi'][label] == {'min': v, 'max': v}]
    result = {
        'predictionSha256': digest(outdir / 'PREDICTION.json'),
        'truthRetained': True,
        'exactActualAmountsFromNecessaryBalances': exact,
        'exactActualAmountsOnAuxiliaryWholeKASGrid': grid_exact,
        'samePublicBalanceInputsAndDeclaredContactsInBothArms': True,
        'stopBundleEscalationForPaymentPrivacy': True,
        'decision': 'retain board only as separately tested optional service-timing repair',
        'limits': ['synthetic UTXO and offline 47-KAS native transactions',
                   'board repackaged after the fact; no board wallet redemption in this workload',
                   'owner/contact knowledge is auxiliary; relationship discovery not scored',
                   'balance intervals are necessary constraints, not all-public-transcript anonymity',
                   'no independent-person, network timing, or 47-KAS bundle-fee measurement'],
    }
    write_new(outdir / 'RESULT.json', result)
    print('exact_primary=' + str(len(exact)) + ' exact_grid=' + str(len(grid_exact)) +
          ' stop=' + str(result['stopBundleEscalationForPaymentPrivacy']).lower())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('predict', 'score'))
    parser.add_argument('output_dir', type=Path)
    parser.add_argument('--truth', type=Path)
    args = parser.parse_args()
    if args.mode == 'predict':
        assert args.truth is None
        predict(args.output_dir)
    else:
        assert args.truth is not None
        score(args.output_dir, args.truth)


if __name__ == '__main__':
    main()
