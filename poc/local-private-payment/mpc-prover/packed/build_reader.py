#!/usr/bin/env python3
"""Compile only the packed public prototype; reuse an unchanged qualified core."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys


def digest(path):
    with Path(path).open('rb') as stream:
        value = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
        return value.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scope-id', default=None)
    parser.add_argument('--inside-scope', action='store_true')
    args = parser.parse_args()
    if args.scope_id is None:
        args.scope_id = secrets.token_hex(16)
    if len(args.scope_id) != 32 or any(c not in '0123456789abcdef' for c in args.scope_id):
        raise SystemExit('Canonical build scope identity required')
    unit = 'kpi-packed-reader-build-' + args.scope_id
    if not args.inside_scope:
        command = ['systemd-run', '--user', '--scope', '--quiet', '--collect', '--unit', unit,
                   '-p', 'MemoryMax=2G', '-p', 'CPUQuota=100%', sys.executable,
                   str(Path(__file__).resolve()), *sys.argv[1:], '--scope-id', args.scope_id,
                   '--inside-scope']
        raise SystemExit(subprocess.run(command).returncode)
    paths = [line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
             if line.startswith('0::')]
    if len(paths) != 1 or unit + '.scope' not in paths[0]:
        raise SystemExit('Selected build scope missing')
    scope = Path('/sys/fs/cgroup') / paths[0].lstrip('/')
    memory = (scope / 'memory.max').read_text().strip()
    cpu = (scope / 'cpu.max').read_text().strip()
    quota, period = cpu.split()
    if memory != str(2 * 1024**3) or quota == 'max' or int(quota) > int(period):
        raise SystemExit('Selected build scope changed')
    resources = {'memory_max_bytes': int(memory), 'cpu_max': cpu, 'unit': unit}
    source = Path(__file__).resolve().parent.parent
    previous_path = args.base_build.resolve() / 'BUILD-RESULT.json'
    previous_bytes = previous_path.read_bytes()
    previous = json.loads(previous_bytes)
    previous_identity = hashlib.sha256(previous_bytes).hexdigest()
    if not previous['success']:
        raise SystemExit('Selected core build did not pass')
    for name, expected in previous['source_sha256'].items():
        if digest(source / name) != expected:
            raise SystemExit('Selected core source/header changed: ' + name)
    for artifact in previous['vendor_artifacts']:
        if digest(artifact['path']) != artifact['sha256']:
            raise SystemExit('Selected public vendor artifact changed')
    base_link = next(r['argv'] for r in previous['link'] if r['binary'] == 'mpc-fullproof')
    by_name = {r['source']: r for r in previous['compile']}
    main_object = by_name['fullproof_gate_main.cpp']['object']
    reused_objects = {p: digest(p) for p in base_link[4:] if p.endswith('.o') and p != main_object}
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    names = ['packed/packed_model.hpp', 'packed/packed_model.cpp', 'packed/compare_existing.cpp', 'packed/build_reader.py']
    before = {name: digest(source / name) for name in names}
    first = previous['compile'][0]['argv']
    flags = first[:first.index('-c')]
    compiled = []
    for name in names[1:3]:
        target = output / (Path(name).name + '.o')
        command = [*flags, '-c', str(source / name), '-o', str(target)]
        result = subprocess.run(command, capture_output=True)
        (output / (target.stem + '.stdout')).write_bytes(result.stdout)
        (output / (target.stem + '.stderr')).write_bytes(result.stderr)
        compiled.append({'source': name, 'argv': command, 'exit_code': result.returncode,
                         'object': str(target), 'sha256': digest(target) if result.returncode == 0 else None})
        print(name, 'compile exit', result.returncode, flush=True)
        if result.returncode:
            break
    link = None
    if len(compiled) == 2 and all(r['exit_code'] == 0 for r in compiled):
        target = output / 'compare-existing'
        command = [base_link[0], '-pthread', '-o', str(target)]
        command += [r['object'] for r in compiled]
        command += [value for value in base_link[4:] if value != main_object]
        result = subprocess.run(command, capture_output=True)
        (output / 'link.stdout').write_bytes(result.stdout)
        (output / 'link.stderr').write_bytes(result.stderr)
        link = {'argv': command, 'exit_code': result.returncode,
                'binary_sha256': digest(target) if result.returncode == 0 else None}
        print('compare-existing link exit', result.returncode, flush=True)
    after = {name: digest(source / name) for name in names}
    core_unchanged = all(digest(source / n) == h for n, h in previous['source_sha256'].items())
    vendor_unchanged = all(digest(a['path']) == a['sha256'] for a in previous['vendor_artifacts'])
    reused_unchanged = all(digest(p) == h for p, h in reused_objects.items())
    compiled_unchanged = all(r['sha256'] is not None and digest(r['object']) == r['sha256'] for r in compiled)
    provenance_unchanged = digest(previous_path) == previous_identity
    stable = before == after and core_unchanged and vendor_unchanged and reused_unchanged and compiled_unchanged and provenance_unchanged
    receipt = {'schema': 'kpi-packed-public-reader-build/v1', 'source_sha256': before,
               'resources': resources,
               'base_build_sha256': previous_identity, 'compile': compiled, 'link': link,
               'reused_objects_sha256': reused_objects,
               'closure_unchanged': {'packed_source': before == after, 'base_source': core_unchanged,
                   'vendor': vendor_unchanged, 'reused_objects': reused_unchanged, 'compiled_objects': compiled_unchanged,
                   'base_provenance': provenance_unchanged},
               'success': stable and link is not None and link['exit_code'] == 0,
               'private_input_MPC_or_setup_executed': False}
    (output / 'BUILD-RESULT.json').write_text(json.dumps(receipt, indent=2) + '\n')
    raise SystemExit(0 if receipt['success'] else 1)


if __name__ == '__main__':
    main()
