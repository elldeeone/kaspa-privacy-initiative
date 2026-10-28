#!/usr/bin/env python3
"""Public recipe/independence controls; no MPC or wallet data is used."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def recipe(outputs, variables, instances, field=P):
    result = b'KPI_PREFIX_LC_V1' + field.to_bytes(32, 'little') + struct.pack('<QQQ', variables, instances, len(outputs))
    for linear in outputs:
        result += struct.pack('<Q', len(linear))
        for coefficient, column in linear:
            result += coefficient.to_bytes(32, 'little') + struct.pack('<Q', column)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--public-fixture', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(exist_ok=False)
    binary = args.binary.resolve(); fixture = args.public_fixture.resolve()
    manifest = json.loads((fixture / 'manifest.json').read_text())
    sha = lambda data: hashlib.sha256(data).hexdigest()
    variables, instances = manifest['model_variables'], manifest['instances']
    outputs = []
    for limb in range(2):
        terms = {}
        for byte in range(16):
            for bit, column in enumerate(manifest['digest_columns_le_bits'][16 * limb + byte]):
                terms[column] = (terms.get(column, 0) + (1 << (byte * 8 + bit))) % P
        outputs.append([(value, column) for column, value in sorted(terms.items()) if value])
    good_recipe = recipe(outputs, variables, instances)
    base = [str(binary), 'inspect-prefix', str(fixture / 'trace.txt'), manifest['trace_sha256'],
        manifest['source_sha256'], manifest['model_sha256'], manifest['layout_sha256'],
        str(variables), str(instances), str(fixture / 'layout.txt'), '0,1']
    records = []

    def run(name, body=good_recipe, expected=None, command=None, selected_pin=None):
        path = args.output / (name + '.prefix'); path.write_bytes(body)
        argv = list(base if command is None else command) + [str(path), selected_pin or sha(body)]
        result = subprocess.run(argv, capture_output=True, text=True)
        passed = result.returncode == 0 and result.stdout.startswith('PUBLIC_TRACE_')
        if expected: passed = result.returncode == 1 and result.stdout == 'PUBLIC_CONTROL_REFUSED ' + expected + '\n'
        record = {'name': name, 'expected': expected or 'accept', 'exit_code': result.returncode,
                  'stdout': result.stdout, 'stderr': result.stderr, 'passed': passed}
        records.append(record)
        if not passed: raise RuntimeError(json.dumps(record))

    run('actual-sha-recipe-independent')
    evaluate = list(base); evaluate[1] = 'evaluate-prefix'
    evaluate += [str(fixture / 'public-inputs.txt'), str(fixture / 'PUBLIC-expected-aux.txt'), '-', '4096']
    run('actual-sha-recipe-value-differential', command=evaluate)
    run('wrong-file-pin', selected_pin='0' * 64, expected='prefix-recipe-file-identity')
    run('wrong-field', recipe(outputs, variables, instances, P + 1), 'prefix-recipe-header-or-shape')
    run('wrong-model-count', recipe(outputs, variables + 1, instances), 'prefix-recipe-header-or-shape')
    run('wrong-instance-count', recipe(outputs, variables, instances + 1), 'prefix-recipe-header-or-shape')
    run('missing-output', recipe(outputs[:1], variables, instances), 'prefix-recipe-header-or-shape')
    for name, first in [('zero-coefficient', [(0, outputs[0][0][1])]),
                        ('field-alias', [(P, outputs[0][0][1])]),
                        ('self-prefix-alias', [(1, 1)]), ('scratch-reference', [(1, variables)]),
                        ('duplicate-column', [outputs[0][0], outputs[0][0]]),
                        ('unsorted-columns', [outputs[0][1], outputs[0][0]])]:
        run(name, recipe([first, outputs[1]], variables, instances), 'prefix-recipe-term-canonicality')
    run('empty-output', recipe([[], outputs[1]], variables, instances), 'prefix-recipe-linear-arity')
    run('constant-placeholder', recipe([[(1, 0)], outputs[1]], variables, instances), 'prefix-recipe-constant-output')
    run('trailing-bytes', good_recipe + b'0', 'prefix-recipe-trailing-data')
    run('truncated-term', good_recipe[:-1], 'prefix-recipe-truncated')
    # Fully defined later columns are still disallowed: the actual recipe
    # must be fixed before the first global public-instance write.
    local = args.output / 'ordering'; local.mkdir()
    layout = b'KPB_TRACE_LAYOUT_V1\nMODEL_VARIABLES 5\nINSTANCES 2\nOWNERS 2\nOWNER owner0 1 2\nOWNER owner1 1 3\nEND\n'
    (local / 'layout.txt').write_bytes(layout)
    for name, operations, expected in [
        ('early-independent-recipe', ['MULADD 4 1 1 2 1 1 3 0', 'LINEAR 1 1 1 4'], None),
        ('late-independent-recipe', ['LINEAR 1 1 1 2', 'MULADD 4 1 1 2 1 1 3 0'],
         'trace-prefix-recipe-not-defined-before-first-instance-write'),
        ('transitive-prefix-alias', ['LINEAR 1 1 1 2', 'LINEAR 4 1 1 1'],
         'trace-prefix-recipe-not-defined-before-first-instance-write')]:
        text = ('KPB_TRACE_V1\nFIELD ' + str(P) + '\nSOURCE_SHA256 ' + '1' * 64 +
            '\nMODEL_SHA256 ' + '2' * 64 + '\nLAYOUT_SHA256 ' + sha(layout) +
            '\nMODEL_VARIABLES 5\nVARIABLES 5\nINSTANCES 2\nINPUTS 2 2 3\nOPS 2\n' +
            '\n'.join(operations) + '\nEND\n').encode()
        trace = local / (name + '.trace'); trace.write_bytes(text)
        command = [str(binary), 'inspect-prefix', str(trace), sha(text), '1' * 64, '2' * 64,
                   sha(layout), '5', '2', str(local / 'layout.txt'), '0,1']
        run(name, recipe([[(1, 4)]], 5, 2), expected, command)
    summary = {'schema': 'public-prefix-recipe-controls/v1', 'cases_passed': len(records),
        'actual_digest_recipe_sha256': sha(good_recipe), 'actual_digest_recipe_bytes': len(good_recipe),
        'MPC_or_private_input_executed': False, 'records': records}
    (args.output / 'PUBLIC-RESULT.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k != 'records'}, indent=2))


if __name__ == '__main__': main()
