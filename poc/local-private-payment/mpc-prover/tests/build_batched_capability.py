#!/usr/bin/env python3
"""Compile one tests-only TU against an unchanged selected qualified build."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-build', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent.parent
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    selected_build = args.base_build.resolve() / 'BUILD-RESULT.json'
    parent = json.loads(selected_build.read_text())
    if not parent['success']:
        raise SystemExit('selected base build failed')
    selected = set(parent['source_sha256']) | {
        'run_toy.py', 'tests/batched_capability_gate.cpp',
        'tests/build_batched_capability.py', 'tests/run_batched_capability.py'}
    before = {name: digest(source / name) for name in sorted(selected)}
    if any(before[name] != expected for name, expected in parent['source_sha256'].items()):
        raise SystemExit('base sources changed; no object reuse')
    for artifact in parent['vendor_artifacts']:
        if digest(Path(artifact['path'])) != artifact['sha256']:
            raise SystemExit('base vendor artifact changed')
    original = next(record for record in parent['compile'] if record['source'] == 'auth_field.cpp')
    flags = original['argv'][:original['argv'].index('-c')]
    target = output / 'batched_capability_gate.cpp.o'
    command = [*flags, '-c', str(source / 'tests/batched_capability_gate.cpp'), '-o', str(target)]
    compile_result = subprocess.run(command, capture_output=True)
    (output / 'compile.stdout').write_bytes(compile_result.stdout)
    (output / 'compile.stderr').write_bytes(compile_result.stderr)
    original_main = next(record for record in parent['compile']
                         if record['source'] == 'fullproof_gate_main.cpp')['object']
    original_link = next(record for record in parent['link'] if record['binary'] == 'mpc-fullproof')
    binary = output / 'mpc-batched-capability'
    link_command = list(original_link['argv'])
    link_command[link_command.index('-o') + 1] = str(binary)
    link_command[link_command.index(original_main)] = str(target)
    linked = None
    if compile_result.returncode == 0:
        linked = subprocess.run(link_command, capture_output=True)
        (output / 'link.stdout').write_bytes(linked.stdout)
        (output / 'link.stderr').write_bytes(linked.stderr)
    after = {name: digest(source / name) for name in sorted(selected)}
    objects = [{'source': record['source'], 'path': record['object'],
                'sha256': digest(Path(record['object']))}
               for record in parent['compile'] if record['object'] and
               record['source'] not in ('fullproof_gate_main.cpp', 'owner_client_main.cpp')]
    owner_record = next(record for record in parent['link'] if record['binary'] == 'owner-client')
    owner_path = args.base_build.resolve() / 'owner-client'
    if digest(owner_path) != owner_record['sha256']:
        raise SystemExit('selected owner helper changed')
    passed = compile_result.returncode == 0 and linked is not None and \
        linked.returncode == 0 and before == after
    result = {'schema': 'kpi-batched-capability-control-build/v1',
        'success': passed, 'source_sha256': before,
        'sources_unchanged_after_build': before == after,
        'base_build_path': str(selected_build), 'base_build_sha256': digest(selected_build),
        'vendor_artifacts': parent['vendor_artifacts'], 'reused_objects': objects,
        'compile': {'argv': command, 'exit_code': compile_result.returncode},
        'link': {'argv': link_command, 'exit_code': None if linked is None else linked.returncode,
                 'sha256': digest(binary) if passed else None},
        'owner_client': {'path': str(owner_path), 'sha256': owner_record['sha256']},
        'private_input_or_MPC_executed': False}
    (output / 'BUILD-RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'success': passed, 'build_result': str(output / 'BUILD-RESULT.json')}))
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
