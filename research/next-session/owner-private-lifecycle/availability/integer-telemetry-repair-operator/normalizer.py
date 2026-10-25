#!/usr/bin/env python3
"""One selected public E5 fetch: exact transport seconds -> integer milliseconds.

Default is read-only inspection. --write requires an externally selected source
SHA. No page payload, wallet, network, transaction or client artifact is opened.
"""
import argparse
import ast
import copy
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import runpy

HANDOFF = Path('/var/tmp/kpi-owner-private-lifecycle-01/public/live-01/confirm-exit-05/HANDOFF.json')
HANDOFF_SHA = '718e113ef39dd27cbbee2becfa2751d6cd00df509456aa112652d37ca12633e9'
FETCH = HANDOFF.parent / 'prefix/fetch.json'
FETCH_SHA = 'ab906cf89ea05f9c8dddecbf3c959a5daa4fb9b48101c1748b114ffc046a620e'
PARSER = Path('/var/tmp/kpi-owner-private-lifecycle-01/assets/recovery-full-runtime-01/software/poc/owner-private-lifecycle/recovery/replay_closed.py')
PARSER_SHA = 'eaf2fd951211faecefee7019f2fe1d7caaf908b18f71f6a4e00958b6cef8f863'
SOURCE02_SHA = '9006cb70accfcb8cf8e0bb35336e2b51daec151983670b45044f7c8fc1c43f7b'
OUTPUT_NAME = 'fetch-integer-telemetry-01.json'
PROVENANCE_NAME = 'fetch-integer-telemetry-01.PROVENANCE.json'
FLOAT_PATH = ('source', 'transport', 'cache_preparation_seconds')


def need(ok, code):
    if not ok:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(rows):
    result = {}
    for key, value in rows:
        need(key not in result, 'duplicate-JSON-field')
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError('nonfinite-JSON-number')


def decimal_parse(raw):
    return json.loads(raw, object_pairs_hook=pairs, parse_float=Decimal,
                      parse_constant=reject_constant)


def typed_equal(a, b):
    if type(a) is not type(b):
        return False
    if type(a) is dict:
        return a.keys() == b.keys() and all(typed_equal(a[k], b[k]) for k in a)
    if type(a) is list:
        return len(a) == len(b) and all(typed_equal(x, y) for x, y in zip(a, b))
    return a == b


def decimal_paths(value, at=()):
    if type(value) is Decimal:
        return [at]
    if type(value) is dict:
        return [p for key, item in value.items() for p in decimal_paths(item, (*at, key))]
    if type(value) is list:
        return [p for index, item in enumerate(value) for p in decimal_paths(item, (*at, index))]
    return []


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def frozen_parser(raw_source):
    need(digest(raw_source) == PARSER_SHA, 'exact-frozen-parser-source')
    tree = ast.parse(raw_source)
    names = {'Refused', 'need', 'parse'}
    selected = [node for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names]
    need({node.name for node in selected} == names, 'frozen-parser-definition-set')
    namespace = {'json': json}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(PARSER), 'exec'), namespace)
    return namespace['parse']


def normalize(raw, parse):
    """Pure metadata transform; callers must authenticate the selected raw bytes."""
    old = decimal_parse(raw)
    need(type(old) is dict and old.get('schema') == 'kpx8-gn3-network-fetch/v1'
         and old.get('status') == 'FETCHED_PENDING_REPLAY', 'selected-fetch-schema')
    need(old.get('source', {}).get('collector', {}).get('name') == 'whole-main-page-delta/v2'
         and old['source']['collector'].get('sources', {}).get('delta.mjs') == SOURCE02_SHA,
         'preserve-actual-Source02-collector-identity')
    need(decimal_paths(old) == [FLOAT_PATH], 'exactly-one-permitted-float-path')
    transport = old['source']['transport']
    need('cache_preparation_milliseconds' not in transport, 'no-preexisting-milliseconds-field')
    seconds = transport['cache_preparation_seconds']
    need(seconds.is_finite() and seconds >= 0, 'nonnegative-finite-seconds')
    # Integer ratio arithmetic cannot round, even for long decimal lexemes.
    numerator, denominator = seconds.as_integer_ratio()
    ticks = numerator * 1000
    need(ticks % denominator == 0, 'milliseconds-must-be-exact-without-rounding')
    milliseconds = ticks // denominator
    new = copy.deepcopy(old)
    del new['source']['transport']['cache_preparation_seconds']
    new['source']['transport']['cache_preparation_milliseconds'] = milliseconds
    before, after = copy.deepcopy(old), copy.deepcopy(new)
    del before['source']['transport']['cache_preparation_seconds']
    del after['source']['transport']['cache_preparation_milliseconds']
    need(typed_equal(before, after), 'all-other-fields-and-types-must-match')
    output = encoded(new)
    need(typed_equal(parse(output), new), 'unchanged-frozen-parser-boundary')
    try:
        parse(raw)
    except ValueError as error:
        need(str(error) == 'non-integer-public-JSON-number', 'original-parser-failure-category')
    else:
        raise ValueError('selected-original-must-reproduce-frozen-parser-rejection')
    return output, {'original_seconds_decimal': str(seconds),
                    'cache_preparation_milliseconds': milliseconds,
                    'all_other_fields_and_types_identical': True,
                    'all_other_fields_projection_sha256': digest(encoded(before)),
                    'original_frozen_parser_rejection': 'non-integer-public-JSON-number',
                    'derived_frozen_parser_pass': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--source-sha256')
    args = parser.parse_args()
    guard = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
    source = guard['read'](str(Path(__file__).absolute()))
    source_sha = digest(source)
    if args.write:
        need(args.source_sha256 == source_sha, 'externally-selected-normalizer-source')
    raw_handoff = guard['read'](str(HANDOFF), HANDOFF_SHA)
    handoff = decimal_parse(raw_handoff)
    selected = handoff['selectors']['fetch.json']
    need(selected == {'path': str(FETCH), 'sha256': FETCH_SHA}, 'exact-Root-selected-E5-fetch')
    raw = guard['read'](str(FETCH), FETCH_SHA)
    parse = frozen_parser(guard['read'](str(PARSER), PARSER_SHA))
    output, checks = normalize(raw, parse)
    provenance = {'schema': 'kpx8-selected-E5-transport-metadata-normalization/v1',
        'normalizer_source_sha256': source_sha, 'original_handoff_sha256': HANDOFF_SHA,
        'original_fetch': {'path': str(FETCH), 'sha256': FETCH_SHA, 'bytes': len(raw)},
        'derived_fetch': {'path': str(FETCH.parent / OUTPUT_NAME), 'sha256': digest(output), 'bytes': len(output)},
        'frozen_parser_sha256': PARSER_SHA, 'actual_original_collector_source_sha256': SOURCE02_SHA,
        'original_collector_identity_preserved': True, 'checks': checks,
        'page_payloads_opened_or_copied_or_reserialized': False,
        'original_fetch_reports_handoff_HEAD_or_advance_modified': False,
        'network_or_transactions_or_private_inputs': False,
        'complete_unchanged_cold_replay_still_required': True}
    receipt = encoded(provenance)
    if args.write:
        # Same existing prefix directory preserves every relative page reference.
        parent = os.open(FETCH.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for name, data in ((OUTPUT_NAME, output), (PROVENANCE_NAME, receipt)):
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o400, dir_fd=parent)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.fsync(parent)
        finally:
            os.close(parent)
    print(json.dumps({'status': 'WRITTEN_PENDING_COMPLETE_COLD_REPLAY' if args.write else 'CHECK_ONLY_NO_WRITES',
        'normalizer_source_sha256': source_sha, 'derived_fetch': provenance['derived_fetch'],
        'provenance_path': str(FETCH.parent / PROVENANCE_NAME),
        'provenance_sha256': digest(receipt), 'checks': checks}, sort_keys=True))


if __name__ == '__main__':
    main()
