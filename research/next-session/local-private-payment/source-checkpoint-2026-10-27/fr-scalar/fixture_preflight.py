"""Source-only public-fixture validator; no files, processes or network access.

The caller must first admit raw bytes through unchanged helper09. This module
does not invoke a compiler or engine and cannot accept actual owner material.
"""
import json

FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
VECTORS = (
    ('zero', 0, 0, 0),
    ('one', 1, 1, 1),
    ('minus_one', FR - 1, FR - 1, FR - 1),
    ('wrap_add', FR - 1, 1, 0),
    ('wrap_mul', FR - 1, FR - 1, 1),
    ('small_mixed', 3, 7, 11),
    ('large_mixed', FR - 2, FR - 3, FR - 4),
)


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def closed_object(pairs):
    result = {}
    for name, value in pairs:
        need(name not in result, 'duplicate JSON key')
        result[name] = value
    return result


def canonical_uint(text):
    need(type(text) is str and text.isascii() and text.isdecimal(), 'ASCII decimal field')
    need(text == '0' or not text.startswith('0'), 'canonical decimal field')
    value = int(text)
    need(0 <= value < FR, 'field representative outside exact Fr')
    return value


def validate_fixture(raw):
    need(type(raw) is bytes, 'admitted immutable public bytes required')
    value = json.loads(raw, object_pairs_hook=closed_object)
    need(type(value) is dict and set(value) == {'schema', 'modulus_decimal', 'vectors'}, 'closed fixture')
    need(value['schema'] == 'kpxa-public-bn254-fr-scalar-fixture/v1', 'exact public fixture schema')
    need(value['modulus_decimal'] == str(FR), 'exact BN254 Fr modulus')
    rows = value['vectors']
    need(type(rows) is list and len(rows) == len(VECTORS), 'complete fixed vector count')
    streams = [[], [], []]
    for row, expected in zip(rows, VECTORS):
        need(type(row) is dict and set(row) == {'name', 'values_decimal'}, 'closed vector')
        need(row['name'] == expected[0], 'exact vector order and name')
        fields = row['values_decimal']
        need(type(fields) is list and len(fields) == 3, 'exact three public inputs')
        values = tuple(canonical_uint(item) for item in fields)
        need(values == expected[1:], 'exact frozen synthetic values')
        for party, item in enumerate(fields):
            streams[party].append(item)
    return tuple(('\n'.join(stream) + '\n').encode('ascii') for stream in streams)
