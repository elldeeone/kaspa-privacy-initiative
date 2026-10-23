#!/usr/bin/env python3
"""Run only fixed public analytical controls; the observer child sees no expectations."""
import concurrent.futures
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

from certificate import CertificateError, check_certificate
from public_cases import analytic_cases, negative_cases
from public_ledger import decode

HERE = Path(__file__).resolve().parent


def ask(item):
    name, request = item
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
           'PYTHONNOUSERSITE': '1', 'PYTHONHASHSEED': '0'}
    process = subprocess.run([sys.executable, str(HERE / 'observe.py')],
                             input=json.dumps(request), text=True, capture_output=True, env=env)
    if process.returncode:
        raise RuntimeError('public-observer-child-failed:' + name)
    return name, json.loads(process.stdout)


def event(result, ordinal):
    return next(row for row in result['private_events'] if row['event'] == ordinal)


def forced(row, value):
    assert row['status'] == 'FORCED_VALUE' and row['value_sompi'] == value, row


def alternative(row):
    assert row['status'] == 'ARITHMETIC_ALTERNATIVE_ONLY' and row['alternative_check'] == 'SAT', row


def reject_certificate(ledger, certificate):
    try:
        check_certificate(ledger, certificate)
    except CertificateError:
        return
    raise AssertionError('invalid-arithmetic-certificate-accepted')


def run():
    cases = analytic_cases()
    negative = negative_cases(cases)
    requests = {**cases, **{name: pair[0] for name, pair in negative.items()}}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        predictions = dict(pool.map(ask, requests.items()))
    for name, result in predictions.items():
        assert result['owner_link'] == 'NOT_MODELLED'
        assert result['financial_privacy_or_crypto_qualification'] is False
        assert result.get('queries', 0) <= 37
    for name in cases:
        assert predictions[name]['status'] == ('INCONSISTENT' if name == 'TERMINAL_LEFTOVER'
                                                else 'COMPLETE'), (name, predictions[name])
    million = 1_000_000
    row = event(predictions['WHOLE_CLAIM'], 2)
    forced(row['input_sum'], 980 * million)
    alternative(row['selection'])
    for position in [1, 2]:
        alternative(predictions['WHOLE_CLAIM']['note_amounts'][position]['amount'])
    row = event(predictions['SINGLETON_PARTIAL'], 1)
    forced(row['input_sum'], 1000 * million)
    forced(row['new_output_sum'], 581 * million)
    for position in [1, 2]:
        alternative(predictions['SINGLETON_PARTIAL']['note_amounts'][position]['amount'])
    row = event(predictions['MULTI_INGRESS_CHANGE'], 3)
    for kind in ['input_sum', 'new_output_sum', 'selection']:
        alternative(row[kind])
    forced(predictions['ALL_BUT_ONE']['note_amounts'][2]['amount'], 580 * million)
    row1, row2 = event(predictions['TERMINAL_VALID'], 2), event(predictions['TERMINAL_VALID'], 3)
    assert row1['selection']['status'] == row2['selection']['status'] == 'FORCED_POSITIONED_CM_TO_PAYOUT'
    assert row1['selection']['position'] == 0 and row2['selection']['position'] == 1
    for position in [2, 3]:
        forced(predictions['TERMINAL_VALID']['note_amounts'][position]['amount'], 0)
    row = event(predictions['LARGE_INTEGER'], 1)
    forced(row['input_sum'], 9007199254740993)
    forced(row['new_output_sum'], 9007199254740993 - 419 * million)
    repeat = predictions['REPEATED_CM']
    assert len(repeat['note_amounts']) == 4
    assert repeat['note_amounts'][0]['cm'] == repeat['note_amounts'][1]['cm']
    alternative(event(repeat, 2)['selection'])
    alternative(event(repeat, 3)['selection'])
    for name, (_, expected) in negative.items():
        assert predictions[name]['status'] == expected, (name, predictions[name])
    ledger = decode(**cases['TERMINAL_VALID']) if False else decode(
        cases['TERMINAL_VALID']['public'], cases['TERMINAL_VALID']['value_priors'])
    valid = predictions['TERMINAL_VALID']['baseline_arithmetic_certificate']
    wrong = copy.deepcopy(valid)
    wrong['selected_positions'][1]['position'] = wrong['selected_positions'][0]['position']
    reject_certificate(ledger, wrong)
    wrong = copy.deepcopy(valid)
    wrong['selected_positions'][0]['position'] = 2
    reject_certificate(ledger, wrong)
    wrong = copy.deepcopy(valid)
    wrong['values'][2] = 60 * million
    reject_certificate(ledger, wrong)
    repeated_ledger = decode(cases['REPEATED_CM']['public'], cases['REPEATED_CM']['value_priors'])
    wrong = copy.deepcopy(repeat['baseline_arithmetic_certificate'])
    wrong['values'].pop()
    reject_certificate(repeated_ledger, wrong)
    from change_model import IntegerModel, analyze
    with patch.object(IntegerModel, '_solve', return_value=('UNKNOWN', None, 'TEST_ONLY_UNKNOWN')):
        unknown = analyze(cases['SINGLETON_PARTIAL']['public'], cases['SINGLETON_PARTIAL']['value_priors'])
    assert unknown['status'] == 'INCOMPLETE' and unknown['baseline_status'] == 'UNKNOWN'
    assert not unknown.get('note_amounts') and not unknown.get('private_events')
    predictions['UNKNOWN_BACKEND'] = unknown
    source = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(HERE.glob('*.py'))}
    return {
        'schema': 'kpx3-change-public-analytical-controls/v1', 'passed': True,
        'fixed_analytic_ledgers': len(cases), 'negative_public_requests': len(negative),
        'invalid_certificate_checks': 4, 'unknown_backend_checks': 1,
        'max_parallel_observer_children': 4, 'source_sha256': source,
        'predictions': predictions,
        'hidden_truth_old_population_or_qualification_evaluation': False,
        'interpretation': 'Exact arithmetic controls only. SAT alternatives are not owner anonymity or cryptographic witnesses.',
    }


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: run_controls.py NEW_RESULT_JSON')
    result = run()
    output = Path(sys.argv[1])
    with output.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({k: result[k] for k in ['passed', 'fixed_analytic_ledgers',
          'negative_public_requests', 'invalid_certificate_checks', 'unknown_backend_checks']}))
