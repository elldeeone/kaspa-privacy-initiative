#!/usr/bin/env python3
"""Direct PUBLIC compiler adapter for ADR-0079.

Executed only through a compiled RegisteredService program selection. The
namespace exposes the pinned pre-existing native row probe and trace exporter,
their fixed public input, libraries and gzip, and a fresh public workspace.
No wallet, owner input, WTNS, key, journal or MAC/share descriptor is admitted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

FINGERPRINT = 'c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            result.update(block)
    return result.hexdigest()


def pin(value):
    require(isinstance(value, str) and len(value) == 64 and
            all(x in '0123456789abcdef' for x in value), 'canonical identity required')
    return value


def admitted(record):
    require(set(record) == {'path', 'sha256'}, 'exact public file record required')
    path = Path(record['path'])
    require(path.is_absolute() and not path.is_symlink(), 'fixed public absolute path required')
    require(sha(path) == pin(record['sha256']), 'selected public file changed')
    return path


def run(argv):
    # Every executable and dependency is an immutable namespace mount selected
    # by the service. This environment cannot inject Rust/Cargo/loader options.
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
    require(result.returncode == 0, 'selected public compiler refused')
    return [json.loads(line) for line in result.stdout.splitlines() if line]


def compile_program(specification, public_input, output):
    original = specification.read_bytes()
    spec = json.loads(original)
    require(set(spec) == {'schema', 'row_probe', 'trace_exporter', 'signature_matrix',
            'signature_mapping_sha256', 'source_closures', 'gzip', 'model_sha256',
            'source_sha256', 'layout_sha256', 'prefix_recipe_sha256'}, 'exact compiler specification required')
    require(spec['schema'] == 'kpb-registered-public-compiler/v1', 'registered compiler schema')
    probe = admitted(spec['row_probe'])
    exporter = admitted(spec['trace_exporter'])
    signature = admitted(spec['signature_matrix'])
    require(admitted(spec['gzip']) == Path('/usr/bin/gzip'), 'selected gzip path')
    require(len(spec['source_closures']) == 2, 'both native consumed source closures required')
    for closure in spec['source_closures']:
        admitted(closure)
    matrix = pin(spec['signature_matrix']['sha256'])
    mapping, source, model = (pin(spec[k]) for k in
                              ('signature_mapping_sha256', 'source_sha256', 'model_sha256'))
    input_before = public_input.read_bytes()
    require(not output.exists(), 'fresh output required')
    # budget=0 measures every finalized row and writes no multi-GB row spool.
    # The fixed probe always reports full row geometry and the actual complete
    # matrix fingerprint, before considering the artifact byte budget.
    events = run([str(probe), str(public_input), str(signature), matrix, mapping,
                  source, str(output.with_name(output.name + '-rows')), '0'])
    geometry = [e for e in events if e.get('stage') == 'stock_matrix_synthesis_done']
    complete = [e for e in events if e.get('stage') == 'measurement_complete_artifact_budget_exceeded']
    require(len(geometry) == len(complete) == 1, 'complete finalized row measurement required')
    require(geometry[0]['variables'] == 12949821 and geometry[0]['instances'] == 3 and
            geometry[0]['actual_constraint_rows'] == 13093029 and
            complete[0]['canonical_r1cs_fingerprint'] == FINGERPRINT and
            complete[0]['all_rows_measured'] is True and complete[0]['artifact_written'] is False,
            'selected key incompatible with actual finalized rows or physical columns')
    run([str(exporter), str(public_input), str(signature), matrix, mapping, model, source, str(output)])
    manifest = json.loads((output / 'PUBLIC-TRACE-MANIFEST.json').read_bytes())
    require(manifest['schema'] == 'kpb-financial-authenticated-trace-gzip/v1' and
            manifest['model_sha256'] == model and manifest['source_sha256'] == source and
            manifest['model_variables'] == 12949821 and manifest['model_instances'] == 3 and
            manifest['owner_input_counts'] == [2635409] * 3 and
            manifest['layout']['sha256'] == pin(spec['layout_sha256']) and
            manifest['prefix_recipe']['sha256'] == pin(spec['prefix_recipe_sha256']) and
            manifest['public_context_sha256'] == hashlib.sha256(bytes.fromhex(
                json.loads(input_before)['context_hex'])).hexdigest(), 'complete source/layout/recipe mapping refused')
    lines = ['KPB_REGISTERED_EXPORT_V1', 'MODEL ' + model, 'SOURCE ' + source,
             'MATRIX ' + FINGERPRINT, 'VARIABLES 12949821', 'INSTANCES 3', 'ROWS 13093029',
             'DOMAIN 16777216', 'HISTORY ' + hashlib.sha256(input_before).hexdigest()]
    for label, key in [('TRACE', 'trace'), ('LAYOUT', 'layout')]:
        part = manifest[key]
        require(part['file'] == ('trace.txt.gz' if key == 'trace' else 'layout.txt.gz'), 'artifact name')
        require(sha(output / part['file']) == pin(part['container_sha256']) and
                (output / part['file']).stat().st_size == part['container_bytes'], 'actual container changed')
        lines.append(f'{label} {pin(part["sha256"])} {part["uncompressed_bytes"]} '
                     f'{pin(part["container_sha256"])} {part["container_bytes"]}')
    recipe = manifest['prefix_recipe']
    require(recipe['file'] == 'PREFIX-RECIPE.bin' and sha(output / recipe['file']) == recipe['sha256'], 'recipe file')
    lines.extend([f'RECIPE {pin(recipe["sha256"])} {recipe["bytes"]}', 'END'])
    require(public_input.read_bytes() == input_before and specification.read_bytes() == original,
            'public compiler input/specification changed')
    for item in [spec['row_probe'], spec['trace_exporter'], spec['signature_matrix'], spec['gzip'], *spec['source_closures']]:
        admitted(item)
    with (output / 'REGISTERED-EXPORT.txt').open('x') as file:
        file.write('\n'.join(lines) + '\n')
        file.flush()
        os.fsync(file.fileno())
    descriptor = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--specification', required=True, type=Path)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    compile_program(args.specification, args.input, args.output)
