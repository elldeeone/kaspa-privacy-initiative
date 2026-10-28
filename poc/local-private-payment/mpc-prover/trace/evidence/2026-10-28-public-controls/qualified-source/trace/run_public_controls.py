#!/usr/bin/env python3
"""Public parser/arithmetic controls; no MPC context or private input is used."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
SOURCE = '1' * 64
MODEL = '2' * 64


def digest(data):
    return hashlib.sha256(data).hexdigest()


def layout(owners=((0, (2,)), (1, (3,))), model_variables=5, instances=2):
    rows = ['KPB_TRACE_LAYOUT_V1', f'MODEL_VARIABLES {model_variables}',
            f'INSTANCES {instances}', f'OWNERS {len(owners)}']
    rows += ['OWNER owner' + str(role) + ' ' + str(len(columns)) + ' ' +
             ' '.join(map(str, columns)) for role, columns in owners]
    return ('\n'.join(rows) + '\nEND\n').encode()


def trace(layout_sha, ops=None, inputs=(2, 3), model_variables=5,
          variables=5, instances=2, source=SOURCE, model=MODEL):
    if ops is None:
        ops = ['MULADD 4 1 1 2 1 1 3 0',
               'MULADD 1 2 1 0 1 4 2 1 2 1 3 0']
    rows = ['KPB_TRACE_V1', f'FIELD {P}', f'SOURCE_SHA256 {source}',
            f'MODEL_SHA256 {model}', f'LAYOUT_SHA256 {layout_sha}',
            f'MODEL_VARIABLES {model_variables}', f'VARIABLES {variables}',
            f'INSTANCES {instances}', 'INPUTS ' + str(len(inputs)) + ' ' +
            ' '.join(map(str, inputs)), f'OPS {len(ops)}', *ops, 'END']
    return ('\n'.join(rows) + '\n').encode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--rust-fixture', type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    binary = args.binary.resolve()
    records = []

    def run(name, expected=None, *, owner_layout=None, body=None, transform=None,
            owners=(0, 1), model_variables=5, instances=2,
            variables=5, inputs=(2, 3), ops=None, trace_pin=None, layout_pin=None):
        here = args.output / name
        here.mkdir(mode=0o700)
        selected_layout = layout() if owner_layout is None else owner_layout
        layout_sha = digest(selected_layout)
        selected = trace(layout_sha, ops, inputs, model_variables,
                         variables, instances) if body is None else body
        if transform:
            selected = transform(selected)
        (here / 'trace.txt').write_bytes(selected)
        (here / 'layout.txt').write_bytes(selected_layout)
        argv = [str(binary), 'inspect', str(here / 'trace.txt'),
                trace_pin or digest(selected), SOURCE, MODEL,
                layout_pin or layout_sha, str(model_variables), str(instances),
                str(here / 'layout.txt'), ','.join(map(str, owners)) or '-']
        result = subprocess.run(argv, capture_output=True, text=True)
        if expected is None:
            passed = result.returncode == 0 and result.stdout.startswith('PUBLIC_TRACE_INSPECT_PASS ')
        else:
            passed = result.returncode == 1 and result.stdout == 'PUBLIC_CONTROL_REFUSED ' + expected + '\n'
        record = {'name': name, 'expected': expected or 'accept',
                  'exit_code': result.returncode, 'stdout': result.stdout,
                  'stderr': result.stderr, 'pass': passed}
        records.append(record)
        if not passed:
            raise RuntimeError(json.dumps(record))

    run('complete-derived-prefix')
    run('bad-trace-pin', 'trace-file-digest', trace_pin='f' * 64)
    run('bad-layout-pin', 'trace-layout-file-digest', layout_pin='f' * 64)
    run('changed-source', 'trace-binding-or-shape',
        transform=lambda b: b.replace(SOURCE.encode(), b'3' * 64))
    run('changed-model', 'trace-binding-or-shape',
        transform=lambda b: b.replace(MODEL.encode(), b'3' * 64))
    run('owner-alias', 'trace-layout-owner-role',
        owner_layout=layout().replace(b'owner0', b'client0'))
    run('wrong-owner-role', 'trace-layout-owner-role', owners=(0, 2))
    run('unsorted-expected-owners', 'trace-expected-owner-roles', owners=(1, 0))
    run('overlapping-owner-columns', 'trace-layout-owner-column',
        owner_layout=layout(((0, (2,)), (1, (2,)))))
    run('owner-input-is-derived-instance', 'trace-layout-owner-column',
        owner_layout=layout(((0, (1,)), (1, (3,)))))
    run('owner-input-is-scratch', 'trace-layout-owner-column',
        owner_layout=layout(((0, (2,)), (1, (5,)))), variables=6)
    run('unsorted-owner-columns', 'trace-layout-owner-column',
        owner_layout=layout(((0, (3, 2)),)), owners=(0,))
    run('changed-input-union', 'trace-input-layout-union', inputs=(2, 4))
    run('duplicate-input', 'trace-input-column', inputs=(2, 2))
    run('input-overwrites-one', 'trace-input-column', inputs=(0, 3))
    run('unknown-operation', 'trace-unknown-operation', ops=['BOGUS 4'])
    run('overwrite-one', 'trace-output-column', ops=['LINEAR 0 0'])
    run('write-outside-shape', 'trace-output-column', ops=['LINEAR 5 0'])
    run('undefined-read', 'trace-undefined-reference',
        ops=['MULADD 4 1 1 1 1 1 3 0'])
    run('duplicate-write', 'trace-duplicate-assignment',
        ops=['MULADD 4 1 1 2 1 1 3 0', 'LINEAR 4 0'])
    run('incomplete-assignment', 'trace-incomplete-assignment-shape',
        ops=['MULADD 4 1 1 2 1 1 3 0'])
    run('field-alias', 'Fr-alias-or-range',
        ops=[f'MULADD 4 1 {P} 2 1 1 3 0'])
    run('coefficient-leading-zero', 'noncanonical-Fr',
        ops=['MULADD 4 1 01 2 1 1 3 0'])
    run('zero-coefficient', 'trace-linear-canonicality', ops=['LINEAR 4 1 0 2'])
    run('unsorted-linear-terms', 'trace-linear-canonicality',
        ops=['LINEAR 4 2 1 3 1 2'])
    run('trailing-data', 'trace-trailing-data', transform=lambda b: b + b'EXTRA\n')
    run('missing-end', 'trace-unexpected-end', transform=lambda b: b[:-4])
    run('integer-leading-zero', 'trace-noncanonical-integer',
        transform=lambda b: b.replace(b'VARIABLES 5\n', b'VARIABLES 05\n'))
    run('add-truncates-carry', 'trace-add-overflow-shape',
        ops=['ADD_BITS 1 4 2 1 1 2 1 1 3'])
    run('add-nonbit-constant', 'trace-nonbit-constant',
        ops=['ADD_BITS 1 4 1 1 2 0'])
    run('add-duplicate-target', 'trace-duplicate-assignment',
        ops=['ADD_BITS 2 1 1 1 1 1 2 1 1 3'])
    run('add-undefined-self-read', 'trace-undefined-reference',
        ops=['ADD_BITS 1 4 1 1 1 4'])
    run('add-zero-width', 'trace-add-width', ops=['ADD_BITS 0'])
    run('add-excess-width', 'trace-add-width', ops=['ADD_BITS 257'])
    run('enormous-linear-count', 'trace-linear-arity',
        ops=['LINEAR 4 18446744073709551615'])
    run('enormous-word-count', 'trace-add-arity',
        ops=['ADD_BITS 1 4 18446744073709551615'])
    run('random-must-be-scratch', 'trace-random-bit-not-scratch',
        ops=['RANDOM_BIT 1'])
    run('random-scratch-shape', variables=6,
        ops=['MULADD 4 1 1 2 1 1 3 0',
             'MULADD 1 2 1 0 1 4 2 1 2 1 3 0', 'RANDOM_BIT 5'])
    run('full-carry-width', owner_layout=layout(((0, (1,)), (1, (2,))), 6, 1),
        model_variables=6, variables=6, instances=1, inputs=(1, 2),
        ops=['ADD_BITS 2 3 4 2 1 1 1 0 1 1 2 0',
             'LINEAR 5 2 1 3 2 4'])

    arithmetic = subprocess.run([str(binary), 'arithmetic'], capture_output=True, text=True)
    if arithmetic.returncode != 0 or arithmetic.stdout != 'PUBLIC_ARITHMETIC_PASS 1123\n':
        raise RuntimeError('public arithmetic differential failed: ' + arithmetic.stdout)
    schedule = args.output / 'schedule-differential'
    schedule.mkdir()
    selected_layout = layout(((0, (1,)), (1, (2,))), 11, 1)
    (schedule / 'layout.txt').write_bytes(selected_layout)
    operations = [
        'MULADD 11 1 1 1 1 1 1 0',
        'ASSERT_ZERO 1 1 11', 'ASSERT_ZERO 2 7 0 1 2',
        'MULADD 12 1 1 1 1 1 0 0', 'LINEAR 13 2 1 11 1 12',
        'MULADD 14 1 1 11 1 1 12 1 1 13', 'LINEAR 3 1 1 14',
        'MULADD 15 1 1 1 1 1 2 0',
        'ADD_BITS 2 4 5 2 1 1 11 0 1 1 15 0',
        'LINEAR 6 1 1 13', 'LINEAR 16 1 9 0', 'LINEAR 17 1 10 0',
        'LINEAR 7 1 1 17', 'LINEAR 8 1 1 11', 'LINEAR 9 1 1 12',
        'LINEAR 10 2 1 3 1 4', 'ASSERT_ZERO 1 1 14',
    ]
    selected = trace(digest(selected_layout), operations, (1, 2), 11, 18, 1)
    (schedule / 'trace.txt').write_bytes(selected)
    (schedule / 'inputs.txt').write_text('PUBLIC_FIXTURE_INPUTS_V1 2\n1 1\n2 0\n')
    expected = [1, 1, 0, 3, 1, 0, 2, 10, 1, 1, 4]
    (schedule / 'expected.txt').write_text('PUBLIC_FIXTURE_EXPECTED_V1 11\n' +
        ''.join(f'{i} {value}\n' for i, value in enumerate(expected)))
    (schedule / 'checks.txt').write_text('PUBLIC_FIXTURE_EXPECTED_CHECKS_V1 3\n0 1\n1 7\n2 3\n')
    schedule_records = []
    for batch in (1, 2, 3, 17, 4096):
        argv = [str(binary), 'evaluate', str(schedule / 'trace.txt'), digest(selected),
            SOURCE, MODEL, digest(selected_layout), '11', '1',
            str(schedule / 'layout.txt'), '0,1', str(schedule / 'inputs.txt'),
            str(schedule / 'expected.txt'), str(schedule / 'checks.txt'), str(batch)]
        result = subprocess.run(argv, capture_output=True, text=True)
        passed = result.returncode == 0 and result.stdout == 'PUBLIC_TRACE_EVALUATION_PASS 11 3\n'
        schedule_records.append({'window': batch, 'exit_code': result.returncode,
                                 'stdout': result.stdout, 'pass': passed})
        if not passed:
            raise RuntimeError('public schedule differential: ' + result.stdout + result.stderr)
    if args.rust_fixture:
        fixture = args.rust_fixture.resolve()
        manifest = json.loads((fixture / 'manifest.json').read_text())
        argv = [str(binary), 'inspect', str(fixture / 'trace.txt'),
                manifest['trace_sha256'], manifest['source_sha256'], manifest['model_sha256'],
                manifest['layout_sha256'], str(manifest['model_variables']),
                str(manifest['instances']), str(fixture / 'layout.txt'), '0,1']
        result = subprocess.run(argv, capture_output=True, text=True)
        if result.returncode != 0 or not result.stdout.startswith('PUBLIC_TRACE_INSPECT_PASS '):
            raise RuntimeError('actual Rust trace compatibility: ' + result.stdout)
        records.append({'name': 'actual-rust-sha3-trace', 'exit_code': result.returncode,
                        'stdout': result.stdout, 'pass': True,
                        'trace_sha256': manifest['trace_sha256'],
                        'actual_R1CS_rows': manifest['r1cs_rows'],
                        'actual_model_variables': manifest['model_variables']})
        for batch in (1, 17, 4096):
            evaluate = list(argv)
            evaluate[1] = 'evaluate'
            evaluate += [str(fixture / 'public-inputs.txt'), str(fixture / 'PUBLIC-expected-aux.txt'),
                         '-', str(batch)]
            result = subprocess.run(evaluate, capture_output=True, text=True)
            passed = result.returncode == 0 and result.stdout.startswith('PUBLIC_TRACE_EVALUATION_PASS ')
            schedule_records.append({'fixture': 'actual-rust-sha3', 'window': batch,
                'exit_code': result.returncode, 'stdout': result.stdout, 'pass': passed})
            if not passed:
                raise RuntimeError('actual Rust assignment/scheduler differential: ' + result.stdout)
    summary = {'schema': 'public-trace-controls/v1',
               'scope': 'PUBLIC_PARSER_AND_ARITHMETIC_ONLY',
               'parser_cases_passed': len(records), 'arithmetic_cases_passed': 1123,
               'scheduler_cases_passed': len(schedule_records), 'schedule_records': schedule_records,
               'records': records, 'MPC_or_private_input_executed': False}
    (args.output / 'PUBLIC-RESULT.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k != 'records'}, indent=2))


if __name__ == '__main__':
    main()
