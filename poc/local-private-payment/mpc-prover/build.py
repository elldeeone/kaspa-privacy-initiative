#!/usr/bin/env python3
"""Build the finite C++ functional gate against an admitted local vendor tree."""
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
    parser.add_argument('--vendor-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        raise SystemExit('jobs must be positive')
    source = Path(__file__).resolve().parent
    vendor = args.vendor_root.resolve()
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    mp = vendor / 'MP-SPDZ'
    mcl = vendor / 'mcl'
    prefix = vendor / 'prefix/usr'
    lib = prefix / 'lib/x86_64-linux-gnu'
    objects = [mp / 'OT' / name for name in (
        'BaseOT.o', 'OTExtension.o', 'OTExtensionWithMatrix.o',
        'BitDiagonal.o', 'OTTripleSetup.o', 'MascotParams.o')]
    # Use the pinned upstream default SoftSpoken route. MP-SPDZ explicitly
    # guards its optional KOS implementation as insecure benchmarking; that
    # guard is never disabled here.
    static_libraries = [mp / 'deps/SimplestOT_C/ref10/libSimplestOT.a',
                        mcl / 'lib/libmcl.a',
                        mp / 'local/lib/liblibOTe.a',
                        mp / 'local/lib/libcoproto.a',
                        mp / 'local/lib/libcryptoTools.a',
                        mp / 'local/lib/libmacoro.a']
    libraries = static_libraries + [mp / 'libSPDZ.so']
    for path in objects + libraries:
        if not path.is_file():
            raise SystemExit('Missing selected vendor artifact: ' + str(path))

    names = ['auth_field.cpp', 'public_model.cpp', 'auth_fft.cpp', 'batched_assignment.cpp',
             'owner_inputs_active.cpp', 'bn254_values.cpp', 'proof_codec.cpp',
             'auth_groups.cpp', 'auth_groth16.cpp', 'fullproof_gate_main.cpp',
             'owner_client_main.cpp']
    selected = sorted(set(names) | {p.name for p in source.glob('*.hpp')})
    before = {name: digest(source / name) for name in selected}
    flags = ['-std=c++20', '-O1', '-g0', '-march=native', '-pthread',
             '-Wall', '-Wextra', '-Werror', '-Wno-overloaded-virtual',
             '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT',
             '-DUSE_GF2N_LONG', '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
             '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0']
    for path in [source, mp, mp / 'deps', mp / 'local/include', mcl / 'include', prefix / 'include',
                 prefix / 'include/x86_64-linux-gnu']:
        flags += ['-I', str(path)]
    commands = []

    def compile_file(name):
        target = output / (name + '.o')
        command = ['g++', *flags, '-c', str(source / name), '-o', str(target)]
        result = subprocess.run(command, capture_output=True)
        (output / (name + '.stdout')).write_bytes(result.stdout)
        (output / (name + '.stderr')).write_bytes(result.stderr)
        return {'source': name, 'argv': command, 'exit_code': result.returncode,
                'object': str(target) if result.returncode == 0 else None}

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for result in pool.map(compile_file, names):
            commands.append(result)
            print(result['source'], 'compile exit', result['exit_code'], flush=True)
    failures = [r for r in commands if r['exit_code']]
    links = []
    if not failures:
        common = ['auth_field.cpp', 'public_model.cpp', 'auth_fft.cpp', 'batched_assignment.cpp',
                  'owner_inputs_active.cpp', 'bn254_values.cpp', 'proof_codec.cpp',
                  'auth_groups.cpp', 'auth_groth16.cpp']
        for binary, entry in [('mpc-fullproof', 'fullproof_gate_main.cpp'),
                              ('owner-client', 'owner_client_main.cpp')]:
            target = output / binary
            command = ['g++', '-pthread', '-o', str(target)]
            command += [str(output / (name + '.o')) for name in common + [entry]]
            command += [str(path) for path in objects]
            # libSPDZ.so has no upstream SONAME. Linking its absolute filename
            # would bake a host path into DT_NEEDED and defeat the finite /app
            # library mount. Select it by library name instead.
            command += ['-L' + str(mp), '-lSPDZ']
            command += ['-Wl,--start-group', *map(str, static_libraries), '-Wl,--end-group']
            command += ['-L' + str(lib), '-Wl,-rpath,' + str(lib),
                        '-Wl,-rpath,' + str(mp), '-lgmpxx', '-lgmp', '-lsodium',
                        '-lssl', '-lcrypto', '-lboost_filesystem', '-lboost_iostreams',
                        '-lboost_thread', '-lrt', '-lz', '-ldl', '-z', 'noexecstack']
            result = subprocess.run(command, capture_output=True)
            (output / (binary + '.link.stdout')).write_bytes(result.stdout)
            (output / (binary + '.link.stderr')).write_bytes(result.stderr)
            links.append({'binary': binary, 'argv': command, 'exit_code': result.returncode,
                          'sha256': digest(target) if result.returncode == 0 else None})
            print(binary, 'link exit', result.returncode, flush=True)
    after = {name: digest(source / name) for name in selected}
    if before != after:
        raise SystemExit('Source changed during compilation; build is not qualified')
    receipt = {'schema': 'kpi-mascot-fullproof-build/v1', 'source_sha256': before,
               'vendor_artifacts': [{'path': str(p), 'sha256': digest(p)}
                                    for p in objects + libraries],
               'compile': commands, 'link': links,
               'success': not failures and len(links) == 2 and all(r['exit_code'] == 0 for r in links),
               'proof_or_private_input_executed': False}
    (output / 'BUILD-RESULT.json').write_text(json.dumps(receipt, indent=2) + '\n')
    raise SystemExit(0 if receipt['success'] else 1)


if __name__ == '__main__':
    main()
