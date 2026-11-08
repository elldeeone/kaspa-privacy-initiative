#!/usr/bin/env python3
"""Pinned public-payload audit and offline one-note/merge privacy screen."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN = ROOT / 'research/cached-approval-verification-2026-11-07/run'
UNIT = 100_000_000
TEN = 10 * UNIT
THREE = 3 * UNIT
LABELS = ('A_to_B', 'B_to_C', 'A_to_D', 'D_to_A_before_group',
          'D_to_B_after_group', 'D_to_C_after_group', 'D_to_A_after_group')
PINS = {
    'research/cached-approval-verification-2026-11-07/run/combined/MAIN.json': '07c0e4fedf81d3776d66f2042c986ca1baf471b3fb6e0fbafb2bba798be45f69',
    'research/cached-approval-verification-2026-11-07/run/combined/APPROVALS.json': '1f221b5be0ea2b0f83f9115bd0dd6c1bcdb0f12dc9b4e32f219f9926c4e69ebd',
    'research/cached-approval-verification-2026-11-07/run/combined/ARRIVALS.json': '233b75b508f1f3052d72645c689cc9f764edb25e39d2f0bab2972e9f6b53b84d',
    'research/cached-approval-verification-2026-11-07/run/registration/operator.jsonl': 'aae893908071bd6e5b9ce30976bdd6ddb691bf598f31245419e30fcf0f508255',
    'poc/private-note-wallet/src/protocol.rs': '2bf0e6e9d22acc68c61121671beb3b2ff2332e15ff06a0b4b5d75e4a5a0b5526',
    'poc/private-note-wallet/src/wallet.rs': '2e2d8a0baf5414afadf4576da076d9ebd8b9ed47f3fab0e1b922f7addc1521a9',
    'poc/private-note-wallet/src/circuit.rs': '2522a17d8a4251472bf06947860f028ec1658733f6db11b62e22385857fd5cdf',
    'poc/cached-approval-verification/host/src/flow.rs': 'c57f03aaf475cf8b92771b02ec0f05ccec85096afe608c3124be072c8270cbbc',
    'poc/cached-approval-verification/host/src/actor.rs': '05f30ec31bd4e9645ee735706c124e85d84ad047b8e468e6b9a67f20106b1a88',
    'poc/cached-approval-verification/common/src/lib.rs': 'f3d4ab70074485242374acff825ac3be7774e66c7c97a71ff8d7d3a576b0cd06',
}


def read(path):
    return json.loads(path.read_text())


def write_new(path, value):
    with path.open('x') as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write('\n')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Bytes:
    def __init__(self, raw):
        self.raw = raw
        self.at = 0

    def take(self, size):
        end = self.at + size
        if size < 0 or end > len(self.raw):
            raise ValueError('truncated public packet')
        value = self.raw[self.at:end]
        self.at = end
        return value

    def number(self, size=8):
        return int.from_bytes(self.take(size), 'little')

    def vector(self):
        size = self.number()
        if size > len(self.raw):
            raise ValueError('impossible public vector length')
        return self.take(size)


def packet(hex_payload):
    b = Bytes(bytes.fromhex(hex_payload))
    mode = b.number(1)
    count = b.number()
    if count > 20:
        raise ValueError('unexpected public operation count')
    operations = []
    for _ in range(count):
        version, kind = b.number(1), b.number(1)
        hashes = [b.take(32) for _ in range(10)]
        deposit_value = b.number()
        exit_destination = b.take(32)
        exit_value = b.number()
        fee_recipient = b.take(32)
        fee = b.number()
        deliveries = []
        for index in range(2):
            commitment, ciphertext = b.take(32), b.vector()
            if commitment != hashes[4 + index]:
                raise ValueError('public delivery/statement commitment mismatch')
            deliveries.append(len(ciphertext))
        proof_length = len(b.vector())
        operations.append({
            'version': version, 'kind': kind,
            'depositValueSompi': deposit_value, 'exitValueSompi': exit_value,
            'nullifier': hashes[3].hex(),
            'outputCount': sum(h != bytes(32) for h in hashes[4:6]),
            'deliveryBytes': deliveries, 'proofBytes': proof_length,
            'exitDestinationPresent': exit_destination != bytes(32),
            'feeRecipientPresent': fee_recipient != bytes(32), 'feeSompi': fee,
        })
    has_intent = b.number(1)
    if has_intent not in (0, 1) or (has_intent == 0 and b.at != len(b.raw)):
        raise ValueError('public packet option/trailing bytes')
    return {'mode': mode, 'operations': operations, 'hasIntent': bool(has_intent),
            'intentBincodeBytes': len(b.raw) - b.at}


def public_audit():
    assert all(sha(ROOT / name) == expected for name, expected in PINS.items())
    main = read(RUN / 'combined/MAIN.json')
    approvals = read(RUN / 'combined/APPROVALS.json')
    arrivals = read(RUN / 'combined/ARRIVALS.json')
    service = [json.loads(row) for row in
               (RUN / 'registration/operator.jsonl').read_text().splitlines()]
    assert main['nativeFull'] is True and main['chainAccepted'] is False
    assert main['principalSompi'] == 40 * UNIT and main['reserve'] == main['liability'] == 0
    assert len(main['records']) == 7 and len(main['restoredPayoutSpends']) == 8
    assert [e['request']['kind'] for e in service[:6]] == ['issue'] * 3 + ['redeem'] * 3
    assert arrivals['fixedScheduleSeconds'] == [90, 330, 570]
    assert [e['index'] for e in arrivals['events']] == [0, 1, 2]
    records = main['records']
    packets = [packet(r['transaction']['payload']) for r in records[1:]]
    assert [p['mode'] for p in packets] == [1, 1, 2, 1, 1, 4]
    assert [[o['kind'] for o in p['operations']] for p in packets] == [
        [1, 2, 2, 2], [2], [3, 3, 3], [2, 2], [2], [3] * 5]
    assert packets[0]['operations'][0]['depositValueSompi'] == 40 * UNIT
    assert all(op['version'] == 1 and op['feeSompi'] == 0
               for p in packets for op in p['operations'])
    assert [o['exitValueSompi'] for o in packets[2]['operations']] == [TEN] * 3
    assert [o['exitValueSompi'] for o in packets[-1]['operations']] == [
        2 * UNIT, UNIT, UNIT, 3 * UNIT, 3 * UNIT]
    assert [p['hasIntent'] for p in packets] == [False, False, True, False, False, False]
    assert len(approvals['operations']) == 3
    approval_nfs = sorted(bytes(approval['statement']['nullifier']).hex()
                          for approval in approvals['operations'])
    packet_nfs = sorted(op['nullifier'] for op in packets[2]['operations'])
    assert approval_nfs == packet_nfs
    transfer_ops = [op for p in packets for op in p['operations'] if op['kind'] == 2]
    assert len(transfer_ops) == 7
    assert all(op['exitValueSompi'] == 0 and op['depositValueSompi'] == 0
               and op['outputCount'] == 2 and op['deliveryBytes'] == [185, 185]
               for op in transfer_ops)
    assert all(op['proofBytes'] == 128 for p in packets for op in p['operations'])
    group_outputs = records[3]['transaction']['outputs']
    final_outputs = records[6]['transaction']['outputs']
    assert [o['value'] for o in group_outputs[1:]] == [TEN] * 3
    assert [o['value'] for o in final_outputs[:5]] == [2 * UNIT, UNIT, UNIT, 3 * UNIT, 3 * UNIT]
    fund_change_script = records[0]['transaction']['outputs'][1]['scriptPublicKey']
    assert final_outputs[-1]['scriptPublicKey'] == fund_change_script
    owner_map = []
    for spend in main['restoredPayoutSpends']:
        prev = spend['transaction']['inputs'][0]['previousOutpoint']
        source = records[3] if prev['transactionId'] == records[3]['transaction']['id'] else records[6]
        assert prev['transactionId'] == source['transaction']['id']
        owner_map.append((3 if source is records[3] else 6,
                          prev['index'], spend['ownerDisclosureControl']))
    assert owner_map == [(3, 1, 1), (3, 2, 2), (3, 3, 0),
                         (6, 0, 0), (6, 1, 0), (6, 2, 1), (6, 3, 2), (6, 4, 3)]
    return {
        'sourceHashes': PINS, 'nativeFull': True, 'chainAccepted': False,
        'funding': {'id': records[0]['transaction']['id'],
                    'outputValuesSompi': [o['value'] for o in records[0]['transaction']['outputs']],
                    'quotedFeeSompi': records[0]['report']['feeSompi']},
        'transactions': [{'id': record['transaction']['id'],
                          'payloadBytes': len(bytes.fromhex(record['transaction']['payload'])),
                          'quotedFeeSompi': record['report']['feeSompi'],
                          'outputValuesSompi': [o['value'] for o in record['transaction']['outputs']],
                          'packet': public} for record, public in zip(records[1:], packets)],
        'ownerMapIsAuxiliary': True, 'groupPayoutOwners': ['A', 'B', 'C'],
        'finalPayoutsByOwnerSompi': {'A': [2 * UNIT, UNIT], 'B': [UNIT],
                                    'C': [3 * UNIT], 'D': [3 * UNIT]},
        'fundingChangeAndFinalFeeRefundSameScript': True,
        'controllerFixedArrivalScheduleSeconds': arrivals['fixedScheduleSeconds'],
        'chainTimingMeasured': False,
        'actualRegistrationEvents': 6,
        'publicTransferCount': len(transfer_ops),
        'transferStatementExitValueFieldsSompi': [op['exitValueSompi'] for op in transfer_ops],
        'transferStatementsPublishAmountField': False,
        'serviceHasPrivatePaymentInstructions': False,
        'networkOwnerInferenceMeasured': False,
    }


def replay(values, group_a_exits, merge):
    """Replay note inventories, not just aggregate balances."""
    if len(values) != 7 or any(type(v) is not int or v <= 0 for v in values):
        return False
    notes = {'A': [40 * UNIT], 'B': [], 'C': [], 'D': []}

    def pay(src, dst, amount):
        if len(notes[src]) != 1 or amount >= notes[src][0]:
            return False
        notes[src][0] -= amount
        notes[dst].append(amount)
        return True

    x, y, z, w, u, v, t = values
    if not (pay('A', 'B', x) and pay('B', 'C', y) and
            pay('A', 'D', z) and pay('D', 'A', w)):
        return False
    if len(notes['A']) != 2 or notes['B'] != [TEN] or notes['C'] != [TEN]:
        return False
    selected = 0 if group_a_exits == 'old' else 1
    if notes['A'][selected] != TEN:
        return False
    notes['A'].pop(selected)
    notes['B'].clear(); notes['C'].clear()
    if not (pay('D', 'B', u) and pay('D', 'C', v) and pay('D', 'A', t)):
        return False
    if merge:
        if len(notes['A']) != 2:
            return False
        notes['A'] = [sum(notes['A'])]
    expected_a = [THREE] if merge else [UNIT, 2 * UNIT]
    return (sorted(notes['A']) == expected_a and notes['B'] == [UNIT] and
            notes['C'] == [3 * UNIT] and notes['D'] == [3 * UNIT])


def candidates(step, merge):
    if step <= 0 or UNIT % step:
        raise ValueError('grid must divide one KAS')
    # B and C each hold one note before the 10-KAS group exits, so y=10 and
    # x-y=10. Afterward B/C hold nothing, so their final 1/3-KAS notes are
    # exactly D's later transfers. A can exit either its old change or D's
    # earlier payment. Its other note and D's later A payment form A's end.
    remaining_values = (UNIT, 2 * UNIT) if not merge else range(step, THREE, step)
    rows = []
    for choice in ('old', 'received'):
        for remaining in remaining_values:
            if choice == 'old':
                z, w = TEN, remaining
            else:
                z, w = 20 * UNIT - remaining, TEN
            t = THREE - remaining
            values = (20 * UNIT, TEN, z, w, UNIT, THREE, t)
            assert replay(values, choice, merge)
            rows.append({'groupAExited': choice,
                         'amountsSompi': dict(zip(LABELS, values))})
    assert len(rows) == (4 if not merge else 2 * (THREE // step - 1))
    return rows


def summary(rows):
    unique = {tuple(row['amountsSompi'][key] for key in LABELS) for row in rows}
    assert len(unique) == len(rows)
    return {'completeAmountHistories': len(unique),
            'rangesSompi': {key: {'min': min(row['amountsSompi'][key] for row in rows),
                                  'max': max(row['amountsSompi'][key] for row in rows)}
                            for key in LABELS},
            'exactAmounts': [key for key in LABELS if len({row['amountsSompi'][key]
                                                          for row in rows}) == 1]}


def predict(outdir):
    public = public_audit()
    baseline = candidates(UNIT, False)
    merge_whole = candidates(UNIT, True)
    merge_tenth = candidates(UNIT // 10, True)
    assert len(baseline) == len(merge_whole) == 4 and len(merge_tenth) == 58
    prediction = {
        'sourceCommit': '2b48c812', 'publicAuditSha256': None,
        'observer': 'known owners, directed contacts/order, public note and exit shape',
        'primaryAmounts': 'positive integer sompi; finite baseline derived by note shape',
        'baselineWholeKAS': summary(baseline),
        'baselinePositiveSompi': summary(baseline),
        'mergeWholeKAS': summary(merge_whole),
        'mergeTenthKAS': summary(merge_tenth),
        'mergePositiveSompi': {
            'completeAmountHistories': 2 * (THREE - 1),
            'exactAmounts': summary(merge_tenth)['exactAmounts'],
            'A_remainingAndLaterPaymentSompi': {'min': 1, 'max': THREE - 1}},
        'actualAmountsRead': False,
        'mergeImplemented': False,
        'mergeNativeTransactionAccepted': False,
        'matchedOlafComparison': False,
        'networkInferenceMeasured': False,
    }
    write_new(outdir / 'PUBLIC-AUDIT.json', public)
    prediction['publicAuditSha256'] = sha(outdir / 'PUBLIC-AUDIT.json')
    write_new(outdir / 'BASELINE-CANDIDATES.json', baseline)
    write_new(outdir / 'MERGE-WHOLE-CANDIDATES.json', merge_whole)
    write_new(outdir / 'PREDICTION.json', prediction)
    print('prediction_sha256=' + sha(outdir / 'PREDICTION.json'))


def score(outdir, truth_path):
    prediction = read(outdir / 'PREDICTION.json')
    assert prediction['publicAuditSha256'] == sha(outdir / 'PUBLIC-AUDIT.json')
    truth = read(truth_path)
    values = tuple(truth[key] for key in LABELS)
    baseline = read(outdir / 'BASELINE-CANDIDATES.json')
    merge = read(outdir / 'MERGE-WHOLE-CANDIDATES.json')
    assert any(tuple(row['amountsSompi'][key] for key in LABELS) == values for row in baseline)
    assert any(tuple(row['amountsSompi'][key] for key in LABELS) == values for row in merge)
    assert replay(values, 'old', False) and replay(values, 'old', True)
    exact = prediction['baselinePositiveSompi']['exactAmounts']
    assert all(truth[key] == prediction['baselinePositiveSompi']['rangesSompi'][key]['min']
               for key in exact)
    a_known = ('A_to_B', 'A_to_D', 'D_to_A_before_group', 'D_to_A_after_group')
    disclosure = [row for row in baseline if all(row['amountsSompi'][key] == truth[key]
                                                  for key in a_known)]
    assert len(disclosure) == 1
    no_material_merge_gain = (prediction['mergeWholeKAS']['exactAmounts'] == exact and
                              prediction['mergeWholeKAS']['completeAmountHistories'] ==
                              prediction['baselineWholeKAS']['completeAmountHistories'])
    assert no_material_merge_gain
    result = {
        'predictionSha256': sha(outdir / 'PREDICTION.json'),
        'truthRetained': True,
        'baselineExactActualAmounts': exact,
        'baselineCompleteWholeKASHistories': len(baseline),
        'singleParticipantADisclosureHistories': len(disclosure),
        'singleParticipantADisclosureExactActualAmounts': list(LABELS),
        'mergeWholeKASExactActualAmounts': prediction['mergeWholeKAS']['exactAmounts'],
        'mergeWholeKASCompleteHistories': len(merge),
        'mergeTenthKASCompleteHistories': prediction['mergeTenthKAS']['completeAmountHistories'],
        'mergeMaterialGainOnDeclaredPrimary': False,
        'mergeImplementationGatePassed': False,
        'completeCostCampaignGatePassed': False,
        'decision': 'correct amount-privacy claim; retain offline merge proposal but do not implement for this workload',
    }
    write_new(outdir / 'RESULT.json', result)
    print('exact=' + str(len(exact)) + '/7 merge_gate=false cost_gate=false')


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
