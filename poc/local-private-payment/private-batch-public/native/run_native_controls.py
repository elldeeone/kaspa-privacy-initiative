#!/usr/bin/env python3
"""Run selected public cases through the real Native Full/input-script engine.

No proving, signing, funding, RPC, wallet or private state is supported. Use an
isolated public-only namespace. A frozen plan selects exact engine/codecs and
case bytes. Negative cases reach the VM after ID/storage-mass canonicalization.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def need(condition, message):
    if not condition:
        raise ValueError(message)


def parse(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    def noninteger(_):
        raise ValueError('noninteger-json-number')
    return json.loads(raw, object_pairs_hook=pairs, parse_float=noninteger,
                      parse_constant=noninteger)


def fields(value, names):
    need(type(value) is dict and set(value) == set(names), 'exact-selected-fields')


def read(record):
    fields(record, ('path', 'sha256'))
    path = Path(record['path'])
    need(path.is_absolute() and path.is_relative_to('/public'), 'public-file-path')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'public-no-symlinks')
    need(path.is_file() and path.stat().st_nlink == 1, 'public-regular-single-link')
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == record['sha256'], 'selected-public-sha256')
    return raw


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    with path.open('xb') as handle:
        handle.write(raw)
    return hashlib.sha256(raw).hexdigest()


def codec(binary, parameters, operation, case):
    request = {'operation': operation, 'parameters': parameters, 'case': case}
    result = subprocess.run([binary], input=json.dumps(request).encode(), capture_output=True)
    need(result.returncode == 0, 'selected-public-codec-refusal')
    return parse(result.stdout)


def run(plan, plan_sha):
    fields(plan, ('schema', 'scope', 'engine', 'codec', 'parameters', 'cases'))
    need(plan['schema'] == 'private-batch-native-vm-controls/v1', 'control-plan-schema')
    need(plan['scope'] in ('payment', 'exit', 'both'), 'control-plan-scope')
    need(type(plan['cases']) is list and plan['cases'], 'selected-control-cases')
    read(plan['engine'])
    read(plan['codec'])
    parameters = parse(read(plan['parameters']))
    engine, binary = plan['engine']['path'], plan['codec']['path']
    results, ids, positives, negatives = [], set(), set(), set()
    for selected in plan['cases']:
        fields(selected, ('id', 'mode', 'expected', 'case'))
        identity = selected['id']
        need(type(identity) is str and 1 <= len(identity) <= 80
             and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in identity)
             and identity not in ids, 'fresh-canonical-control-id')
        ids.add(identity)
        need(selected['mode'] in ('payment', 'exit'), 'selected-control-mode')
        need(selected['expected'] in ('accept', 'reject'), 'selected-control-expectation')
        source = parse(read(selected['case']))
        if selected['expected'] == 'accept':
            original = codec(binary, parameters, 'body', source)
            need(original['case'] == source and original['mode'] == selected['mode'],
                 'canonical-positive-selected-policy-case')
            native_case = source
        else:
            canonical = codec(binary, parameters, 'canonicalize-control', source)
            native_case = canonical['case']
            # Canonicalization may alter only the cached ID and storage mass.
            expected = json.loads(json.dumps(source))
            expected['transaction']['id'] = native_case['transaction']['id']
            expected['transaction']['mass'] = native_case['transaction']['mass']
            need(expected == native_case, 'control-canonicalization-changed-effects')
        out = Path('/out') / identity
        out.mkdir(exist_ok=False)
        case_sha = save(out / 'CASE.json', native_case)
        process = subprocess.run([engine, 'validate-transaction', str(out / 'CASE.json'),
                                  str(out / 'native')], capture_output=True)
        (out / 'stdout.log').write_bytes(process.stdout)
        (out / 'stderr.log').write_bytes(process.stderr)
        report = parse((out / 'native/native-validation.json').read_bytes())
        need(report.get('isolation') == 'PASS', 'native-transaction-isolation-required')
        scripts = report.get('per_input_ScriptEngine')
        need(type(scripts) is list and len(scripts) == len(native_case['transaction']['inputs'])
             and scripts and all(type(row.get('accepted')) is bool for row in scripts),
             'actual-input-script-engine-results-required')
        if selected['expected'] == 'accept':
            need(process.returncode == 0 and report.get('isolation') == 'PASS'
                 and report['Full']['accepted'] is True
                 and report.get('all_input_engines_accepted') is True
                 and all(row['accepted'] for row in scripts), 'actual-positive-native-full-and-scripts')
            positives.add(selected['mode'])
        else:
            # Full rejection alone is not script coverage; require the script
            # engine to reject after the malformed transaction reached it.
            need(report['Full']['accepted'] is False
                 and report.get('all_input_engines_accepted') is False
                 and any(not row['accepted'] for row in scripts), 'actual-negative-native-script-rejection')
            negatives.add(selected['mode'])
        results.append({'id': identity, 'mode': selected['mode'], 'expected': selected['expected'],
                        'case_sha256': case_sha, 'engine_exit': process.returncode,
                        'Full': report['Full'], 'per_input_ScriptEngine': scripts})
    required = {'payment', 'exit'} if plan['scope'] == 'both' else {plan['scope']}
    need(positives == required and negatives == required, 'complete-positive-and-negative-branch-coverage')
    result = {'schema': 'private-batch-native-vm-controls-result/v1', 'plan_sha256': plan_sha,
              'scope': plan['scope'], 'classification': 'REAL_NATIVE_VM_SUPPLIED_CONTEXT_NOT_CHAIN_CONFIRMATION',
              'cases': results, 'actual_positive_native_full_and_scripts': True,
              'actual_negative_script_rejections': True, 'funding_or_broadcast': False,
              'accepted_backing_or_chain_confirmation': False, 'private_wallet_contents_read': False}
    digest = save(Path('/out/RESULT.json'), result)
    print(json.dumps({'result_sha256': digest, 'case_count': len(results), 'scope': plan['scope']}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--plan', required=True)
    parser.add_argument('--plan-sha', required=True)
    args = parser.parse_args()
    need(Path('/out').is_dir() and not Path('/home').exists() and not Path('/var').exists(),
         'isolated-public-only-namespace')
    plan = parse(read({'path': args.plan, 'sha256': args.plan_sha}))
    run(plan, args.plan_sha)


if __name__ == '__main__':
    main()
