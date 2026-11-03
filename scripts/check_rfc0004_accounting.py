#!/usr/bin/env python3
"""Check RFC-0004 arithmetic examples; this verifies no notes, proofs or chain."""
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / 'docs/rfc/0004-native-value-accounting-vectors.json'
# Reviewed rusty-kaspa b85380d: consensus/core/src/constants.rs.
MAX_SOMPI = 29_000_000_000 * 100_000_000
FIELDS = {'T_in', 'T_out', 'S_in', 'S_out', 'F', 'b', 'B'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def classify(raw):
    require(set(raw) == FIELDS, 'vector fields differ from the RFC statement')
    for value in raw.values():
        if not isinstance(value, str) or not re.fullmatch(r'-?(0|[1-9][0-9]*)', value) or value == '-0':
            return 'encoding'
    values = {name: int(value) for name, value in raw.items()}
    if any(not 0 <= values[k] <= MAX_SOMPI for k in FIELDS - {'b'}):
        return 'range'
    if not -MAX_SOMPI <= values['b'] <= MAX_SOMPI:
        return 'range'
    if values['S_in'] - values['S_out'] != values['b']:
        return 'hidden_balance'
    if values['T_in'] + values['b'] != values['T_out'] + values['F']:
        return 'public_balance'
    if not 0 <= values['B'] - values['b'] <= MAX_SOMPI:
        return 'pool_balance'
    return None


def check():
    data = json.loads(VECTORS.read_text())
    require(data['schema'] == 'rfc0004-arithmetic-vectors-v1', 'vector schema')
    require(data['max_sompi'] == str(MAX_SOMPI), 'monetary bound needs source review')
    names = set()
    positives = negatives = 0
    for row in data['cases']:
        require(row['name'] not in names, 'duplicate vector name')
        names.add(row['name'])
        require(type(row['arithmetic_valid']) is bool, 'nonboolean expected result')
        result = classify(row['values'])
        if row['arithmetic_valid']:
            require(result is None, row['name'] + ': unexpected rejection ' + str(result))
            values = {k: int(v) for k, v in row['values'].items()}
            require(values['S_in'] + values['T_in'] == values['S_out'] + values['T_out'] + values['F'], 'combined balance')
            require(int(row['expected_B_next']) == values['B'] - values['b'], 'next pool balance')
            positives += 1
        else:
            require(result is not None and result == row['expected_rejection'], row['name'] + ': wrong rejection ' + str(result))
            negatives += 1
    balance = fees = previous_private = 0
    for raw in data['arithmetic_sequence']:
        require(classify(raw) is None, 'sequence arithmetic')
        values = {k: int(v) for k, v in raw.items()}
        require(values['B'] == balance and values['S_in'] == previous_private, 'sequence predecessor')
        balance -= values['b']
        fees += values['F']
        previous_private = values['S_out']
    require(balance == int(data['sequence_expected_final_pool_balance']) == previous_private == 0, 'sequence must drain modeled claims')
    require(fees == int(data['sequence_expected_total_network_fee']), 'sequence network fees')
    require(sum(int(v['T_in']) - int(v['T_out']) for v in data['arithmetic_sequence']) == fees, 'sequence total conservation')
    print(f'RFC-0004 arithmetic: {positives} positive and {negatives} negative vectors, {len(data["arithmetic_sequence"])} sequence steps: OK. No proof/native/privacy validation.')


if __name__ == '__main__':
    try:
        check()
    except (ValueError, KeyError, OSError) as error:
        print('RFC-0004 accounting: ' + str(error), file=sys.stderr)
        sys.exit(1)
