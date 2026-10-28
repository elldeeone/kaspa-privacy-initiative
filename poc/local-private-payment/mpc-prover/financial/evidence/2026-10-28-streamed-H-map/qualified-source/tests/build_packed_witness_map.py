#!/usr/bin/env python3
"""Build the separate PUBLIC H-map/packed proof control with retained checks."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    for name in ['base-build', 'sealed-build', 'fixture', 'output']:
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent.parent
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    base_path = args.base_build.resolve() / 'BUILD-RESULT.json'
    base = json.loads(base_path.read_text())
    sealed_path = args.sealed_build.resolve() / 'BUILD-RESULT.json'
    sealed = json.loads(sealed_path.read_text())
    if not base['success'] or not sealed['success']:
        raise SystemExit('selected source build failed')
    names = ['financial/streamed_h_map.cpp', 'financial/packed_assignment.cpp',
             'financial/packed_groth16.cpp', 'packed/packed_model.cpp',
             'packed/gzip_queries.cpp', 'tests/packed_witness_map_gate.cpp']
    selected = set(base['source_sha256']) | set(names) | {
        'financial/streamed_h_map.hpp', 'financial/packed_assignment.hpp',
        'packed/packed_model.hpp', 'packed/gzip_queries.hpp',
        'trace/sealed_trace.cpp', 'trace/sealed_trace.hpp', 'run_toy.py',
        'tests/build_packed_witness_map.py', 'tests/run_packed_witness_map.py'}
    before = {name: digest(source / name) for name in sorted(selected)}
    if any(before[name] != expected for name, expected in base['source_sha256'].items()):
        raise SystemExit('qualified base source changed')
    for name in ['trace/sealed_trace.cpp', 'trace/sealed_trace.hpp']:
        if before[name] != sealed['source_before'][name] or before[name] != sealed['source_after'][name]:
            raise SystemExit('selected sealed object source differs')
    artifacts = list(base['vendor_artifacts'])
    for path in [Path('/usr/lib/x86_64-linux-gnu/libz.so.1').resolve(), Path('/usr/include/zlib.h'), Path('/usr/include/zconf.h')]:
        artifacts.append({'path': str(path), 'sha256': digest(path)})
    for item in artifacts:
        if digest(Path(item['path'])) != item['sha256']:
            raise SystemExit('selected vendor artifact changed')
    flags = base['compile'][0]['argv']
    flags = flags[:flags.index('-c')] + ['-DKPI_STREAMED_H_MAP_PUBLIC_FIXTURE_CONTROL']

    def compile_file(name):
        target = output / (name.replace('/', '_') + '.o')
        argv = flags + ['-c', str(source / name), '-o', str(target)]
        run = subprocess.run(argv, capture_output=True)
        (output / (name.replace('/', '_') + '.compile.stderr')).write_bytes(run.stderr)
        return {'source': name, 'argv': argv, 'exit_code': run.returncode, 'object': str(target)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        compiled = list(pool.map(compile_file, names))
    objects = []
    for record in base['compile']:
        if record['source'] not in ['fullproof_gate_main.cpp', 'owner_client_main.cpp']:
            objects.append({'path': record['object'], 'sha256': digest(Path(record['object']))})
    sealed_object = args.sealed_build.resolve() / 'sealed_trace.cpp.o'
    objects.append({'path': str(sealed_object), 'sha256': digest(sealed_object)})
    old_link = next(item for item in base['link'] if item['binary'] == 'mpc-fullproof')['argv']
    old_main = next(item['object'] for item in base['compile'] if item['source'] == 'fullproof_gate_main.cpp')
    binary = output / 'mpc-packed-witness-map'
    link = list(old_link)
    link[link.index('-o') + 1] = str(binary)
    at = link.index(old_main)
    link[at:at + 1] = [item['object'] for item in compiled] + [str(sealed_object)]
    link += ['-lz', '-ldl']
    linked = None
    if all(item['exit_code'] == 0 for item in compiled):
        linked = subprocess.run(link, capture_output=True)
        (output / 'PUBLIC-link.stderr').write_bytes(linked.stderr)
    after = {name: digest(source / name) for name in selected}
    fixture = args.fixture.resolve()
    fixture_names = ['model.meta', 'A.rows.gz', 'B.rows.gz', 'C.rows.gz', 'pk.bin', 'vk.bin']
    fixture_hashes = {name: digest(fixture / name) for name in fixture_names}
    passed = before == after and linked is not None and linked.returncode == 0
    owner = args.base_build.resolve() / 'owner-client'
    result = {'schema': 'kpi-packed-witness-map-control-build/v1', 'success': passed,
        'source_sha256': before, 'vendor_artifacts': artifacts, 'reused_objects': objects,
        'fixture_sha256': fixture_hashes, 'compile': compiled,
        'link': {'argv': link, 'exit_code': None if linked is None else linked.returncode},
        'binary_sha256': digest(binary) if passed else None,
        'owner_client': {'path': str(owner), 'sha256': digest(owner)},
        'public_fixture_macro_only': True, 'MPC_or_private_input_executed': False}
    (output / 'BUILD-RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'success': passed, 'result': str(output / 'BUILD-RESULT.json')}), flush=True)
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
