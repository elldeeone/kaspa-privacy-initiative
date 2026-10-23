#!/usr/bin/env python3
"""One separately frozen three-case original-NF private/revealing race check."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess

import assemble as a
import execute as run


def validate_control_freeze(args):
    sha = run.validate_freeze(args, proofs=True)
    freeze = a.load(args.freeze)
    pinned = set()
    for entry in freeze['files']:
        path = Path(entry['path'])
        pinned.add((path if path.is_absolute() else a.ROOT / path).resolve())
    required = {Path(__file__).resolve(), (args.controls / 'CONTROL-PLAN.json').resolve(),
                (args.main_execution / 'RESULTS.json').resolve()}
    for stage in ('spend', 'bob-partial'):
        required.update((args.main_execution / stage / name).resolve() for name in
                        ('transaction.json', 'supplied-context.json', 'native-validation.json'))
    required.update((args.controls / name).resolve() for name in
                    ('reveal-first-native-vector.json', 'reveal-after-private-native-vector.json',
                     'race-after-reveal-native-vector.json', 'race-after-reveal-fixture.json'))
    for case in ('reveal-first-positive', 'reveal-after-private-negative', 'private-after-reveal-negative'):
        required.update((args.controls / case / name).resolve() for name in
                        ('transaction.json', 'supplied-context.json', 'validation-case.json'))
    required.update((args.proof_root / 'race-after-reveal' / name).resolve() for name in
                    ('report.json', 'proof128.bin', 'verification-key.bin', 'authorization528.bin'))
    if not required <= pinned:
        raise ValueError('race freeze omitted source/current-body/control/proof files')
    return sha


def native_case(binary, body_directory, output):
    if output.exists():
        raise ValueError('fresh native validation output required')
    process = subprocess.run([str(binary), 'validate-transaction',
        str(body_directory / 'validation-case.json'), str(output)], text=True, capture_output=True)
    output.mkdir(parents=True, exist_ok=True)
    a.save(output / 'command-result.json', {'returncode': process.returncode,
        'stdout': process.stdout, 'stderr': process.stderr, 'binary_sha256': a.digest(binary)})
    if process.returncode:
        raise ValueError('native validation process failed')
    return a.load(output / 'native-validation.json')


def rejected_current_nf(report):
    return (report['Full'].get('accepted') is False
        and report['Full'].get('typed_error') == 'SignatureInvalid(VerifyError)'
        and report['ScriptEngine'].get('accepted') is False
        and report['ScriptEngine'].get('typed_error') == 'VerifyError'
        and report['ScriptEngine']['units'] < 14_750_000)


def execute(args):
    frozen = validate_control_freeze(args)
    main = a.load(args.main_execution / 'RESULTS.json')
    if (main.get('complete_supplied_context_native_sequence_passed') is not True
            or main.get('native_Full_operations') != 7 or main.get('genuine_private_proofs') != 4):
        raise ValueError('completed exact mainline required; alternatives are not extra mainline payouts')
    if args.output.exists():
        raise ValueError('fresh race runtime required')
    args.output.mkdir(parents=True)
    setup = run.checked_setup(args, a.load(args.prepared / 'MATERIALIZED.json'))
    vector = a.load(args.controls / 'reveal-first-native-vector.json')
    positive = args.output / 'reveal-first'
    a.native_call(args.native, 'reveal-run', vector, positive)
    links = [a.verify_link(args.main_execution / 'spend', positive)]
    if a.outpoint(positive) != a.outpoint(args.controls / 'reveal-first-positive'):
        raise ValueError('actual accepted fork differs from proof current outpoint')
    losing_reveal = args.controls / 'reveal-after-private-negative'
    links.append(a.verify_link(args.main_execution / 'bob-partial', losing_reveal))
    reveal_report = native_case(args.native, losing_reveal, args.output / 'reveal-after-private')
    vector = a.load(args.controls / 'race-after-reveal-native-vector.json')
    proof = run.checked_proof(args.controls, args.proof_root, 'race-after-reveal', vector, setup)
    vector['proof_hex'] = proof.hex()
    private_body = args.output / 'private-after-reveal-proof-body'
    a.native_call(args.native, 'private-freeze', vector, private_body)
    expected = copy.deepcopy(a.load(args.controls / 'private-after-reveal-negative/transaction.json'))
    script = bytes.fromhex(expected['inputs'][0]['signatureScript'])
    expected['inputs'][0]['signatureScript'] = (script[:68] + proof + script[196:]).hex()
    if a.load(private_body / 'transaction.json') != expected:
        raise ValueError('genuine race proof changed authorized body fields')
    links.append(a.verify_link(positive, private_body))
    private_report = native_case(args.native, private_body, args.output / 'private-after-reveal')
    outcomes = {'reveal-first-accept': a.load(positive / 'native-validation.json')['Full']['accepted'] is True,
                'old-reveal-after-private-current-nf-reject': rejected_current_nf(reveal_report),
                'genuine-private-after-reveal-current-nf-reject': rejected_current_nf(private_report)}
    result = {'classification': a.CLASS, 'source_input_freeze_sha256': frozen,
        'three_expectations_matched': all(outcomes.values()), 'outcomes': outcomes,
        'separate_alternatives_not_extra_mainline_payouts': True, 'actual_prior_output_links': links,
        'extra_race_private_proof_genuinely_verified': True,
        'race_fixture_sha256': a.digest(args.controls / 'race-after-reveal-fixture.json'),
        'reveal_reject_units': reveal_report['ScriptEngine']['units'],
        'private_reject_units': private_report['ScriptEngine']['units'],
        'current_nf_rejections_before_Groth16': outcomes['old-reveal-after-private-current-nf-reject']
                                                and outcomes['genuine-private-after-reveal-current-nf-reject'],
        'accepted_chain_backing': False, 'testnet_broadcast': False}
    a.save(args.output / 'RESULTS.json', result)
    validate_control_freeze(args)
    if not all(outcomes.values()):
        raise ValueError('retained race prediction failure')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native', 'prepared', 'freeze', 'output', 'prefix', 'proof-root', 'crypto',
                 'setup-report', 'proof-source', 'controls', 'main-execution'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(execute(args), sort_keys=True))


if __name__ == '__main__':
    main()
