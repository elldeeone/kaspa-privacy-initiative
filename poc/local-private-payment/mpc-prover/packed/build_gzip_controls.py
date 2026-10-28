#!/usr/bin/env python3
"""Build the bounded PUBLIC gzip-key controls using existing pinned dependencies."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root, out = args.root.resolve(), args.out.resolve()
    out.mkdir(exist_ok=False)
    source = root / 'poc/local-private-payment/mpc-prover'
    base = source / 'packed/evidence/2026-10-28/BUILD-04.json'
    recipe = json.loads(base.read_text())
    if not recipe['success']:
        raise SystemExit('Qualified public reader build is required')
    common = recipe['compile'][0]['argv']
    common = common[:common.index('-c')]
    names = ['packed/packed_model.cpp', 'packed/gzip_queries.cpp', 'packed/gzip_query_controls.cpp']
    selected = names + ['packed/packed_model.hpp', 'packed/gzip_queries.hpp', 'packed/point_codec.hpp',
                        'packed/build_gzip_controls.py', 'trace/sealed_trace.cpp', 'trace/sealed_trace.hpp']
    before = {name: digest(source / name) for name in selected}
    reused = recipe['reused_objects_sha256'].copy()
    sealed = root / '.local/trace-witness-controls-build-08/sealed_trace.cpp.o'
    reused[str(sealed)] = '843c4fa8e7ab1ac767a38be9df92caa90ebe7ee89cf31ee3981b479b2d9ccdab'
    if before['trace/sealed_trace.cpp'] != '0066aef17aa953b6eec058b0996d3074ef41e379c909430c60c808fe492695f2':
        raise SystemExit('Sealed codec source differs from the admitted object')
    if any(digest(p) != h for p, h in reused.items()):
        raise SystemExit('Qualified dependency object changed')

    def compile_one(name):
        target = out / (Path(name).name + '.o')
        argv = common + ['-c', str(source / name), '-o', str(target)]
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        (out / (Path(name).name + '.log')).write_text(result.stdout)
        return {'source': name, 'argv': argv, 'exit_code': result.returncode,
                'object': str(target), 'sha256': digest(target) if result.returncode == 0 else None}

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        compiled = list(pool.map(compile_one, names))
    old = recipe['link']['argv']
    dependency_start = old.index(str(root / '.local/mpc-prover-build-13/auth_field.cpp.o'))
    binary = out / 'gzip-query-controls'
    argv = ['g++', '-pthread', '-o', str(binary)] + [c['object'] for c in compiled]
    argv += [str(sealed)] + old[dependency_start:]
    if all(c['exit_code'] == 0 for c in compiled):
        linked = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        (out / 'link.log').write_text(linked.stdout)
        link = {'argv': argv, 'exit_code': linked.returncode,
                'binary': str(binary), 'sha256': digest(binary) if linked.returncode == 0 else None}
    else:
        link = {'argv': argv, 'exit_code': None}
    unchanged = before == {name: digest(source / name) for name in selected}
    unchanged = unchanged and all(digest(p) == h for p, h in reused.items())
    receipt = {'schema': 'kpi-gzip-query-public-controls-build/v1', 'source_sha256': before,
               'base_build_receipt_sha256': digest(base), 'reused_objects_sha256': reused,
               'compile': compiled, 'link': link, 'closure_unchanged': unchanged,
               'success': unchanged and link['exit_code'] == 0,
               'private_input_MPC_or_setup_executed': False}
    (out / 'BUILD-RESULT.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'success': receipt['success'], 'receipt': str(out / 'BUILD-RESULT.json')}))
    raise SystemExit(0 if receipt['success'] else 1)


if __name__ == '__main__':
    main()
