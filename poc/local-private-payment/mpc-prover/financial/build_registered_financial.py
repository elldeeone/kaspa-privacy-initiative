#!/usr/bin/env python3
"""Build the full registered financial closure and default-refusing gate."""
import argparse
import concurrent.futures
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def selected_tool(name, compiler):
    result = subprocess.run([str(compiler), '-print-prog-name=' + name],
                            capture_output=True, check=True, env={})
    value = result.stdout.decode('ascii').strip()
    path = Path(value)
    if not path.is_absolute():
        found = shutil.which(value)
        if found is None:
            raise SystemExit('Selected compiler subtool is unavailable: ' + name)
        path = Path(found)
    path = path.resolve()
    if not path.is_file():
        raise SystemExit('Selected compiler subtool is not a file: ' + name)
    return {'path': str(path), 'sha256': digest(path),
            'bytes': path.stat().st_size}


def command_identity(argv):
    result = subprocess.run(argv, capture_output=True, check=True, env={})
    return {'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
            'stderr_sha256': hashlib.sha256(result.stderr).hexdigest(),
            'exit_code': result.returncode}


def parse_depfile(path):
    raw = path.read_text().replace('\\\n', ' ')
    if ':' not in raw:
        raise SystemExit('Malformed compiler dependency file: ' + str(path))
    dependencies = raw.split(':', 1)[1].strip().split()
    if not dependencies:
        raise SystemExit('Empty compiler dependency file: ' + str(path))
    return [Path(value.replace('\\ ', ' ')).resolve()
            for value in dependencies]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--vendor-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--base-build', type=Path)
    parser.add_argument('--reproduce-authority', type=Path)
    args = parser.parse_args()
    if args.jobs < 1:
        raise SystemExit('jobs must be positive')
    if args.base_build:
        raise SystemExit('Object reuse is forbidden for registered build authority')
    source = Path(__file__).resolve().parent.parent
    vendor = args.vendor_root.resolve()
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    compiler_name = shutil.which('g++')
    if compiler_name is None:
        raise SystemExit('Selected g++ compiler is unavailable')
    compiler = Path(compiler_name).resolve()
    if not compiler.is_file():
        raise SystemExit('Selected g++ compiler is not a regular file')
    compiler_record = {'path': str(compiler), 'sha256': digest(compiler),
                       'bytes': compiler.stat().st_size}
    interpreter = Path(sys.executable).resolve()
    runtime_inspector = Path('/usr/bin/ldd').resolve()
    toolchain = {
        'schema': 'kpi-registered-build-toolchain/v1',
        'compiler': compiler_record,
        'build_interpreter': {
            'path': str(interpreter), 'sha256': digest(interpreter),
            'bytes': interpreter.stat().st_size,
        },
        'runtime_inspector': {
            'path': str(runtime_inspector),
            'sha256': digest(runtime_inspector),
            'bytes': runtime_inspector.stat().st_size,
        },
        'subtools': {name: selected_tool(name, compiler)
                     for name in ('cc1plus', 'collect2', 'as', 'ld')},
        'version': command_identity([str(compiler), '--version']),
        'specs': command_identity([str(compiler), '-dumpspecs']),
        'search_directories': command_identity(
            [str(compiler), '-print-search-dirs']),
        'sysroot': command_identity([str(compiler), '-print-sysroot']),
    }
    mp = vendor / 'MP-SPDZ'
    mcl = vendor / 'mcl'
    prefix = vendor / 'prefix/usr'
    lib = prefix / 'lib/x86_64-linux-gnu'
    zlib_binary = Path('/usr/lib/x86_64-linux-gnu/libz.so.1').resolve()
    zlib_headers = [Path('/usr/include/zlib.h'), Path('/usr/include/zconf.h')]
    zlib_header_hashes = {p.name: digest(p) for p in zlib_headers}
    zlib_headers_identity = hashlib.sha256(json.dumps(zlib_header_hashes,
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
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
    libraries = static_libraries + [mp / 'libSPDZ.so', zlib_binary, *zlib_headers]
    decoder_before = {str(p): digest(p) for p in [zlib_binary, *zlib_headers]}
    for path in objects + libraries:
        if not path.is_file():
            raise SystemExit('Missing selected vendor artifact: ' + str(path))

    names = ['auth_field.cpp', 'p1_capture_stream.cpp',
             'p1_capturing_player.cpp', 'p1_capture_seams.cpp',
             'p1_entropy_ingress_capture.cpp',
             'p1_mascot_secret_state_hook.cpp',
             'public_model.cpp', 'auth_fft.cpp', 'batched_assignment.cpp',
             'owner_input_ddnnt.cpp', 'owner_inputs_active.cpp', 'owner_connections.cpp', 'bn254_values.cpp', 'proof_codec.cpp',
             'auth_groups.cpp', 'auth_groth16.cpp', 'trace/sealed_trace.cpp',
             'trace/prefix_recipe.cpp', 'trace/trace_witness.cpp',
             'packed/packed_model.cpp', 'packed/gzip_queries.cpp',
             'history/epoch_journal.cpp', 'history/epoch_policy.cpp', 'history/epoch_ticket.cpp',
             'financial/construction.cpp', 'financial/registered_construction.cpp',
             'financial/financial_assignment.cpp',
             'financial/streamed_h_map.cpp', 'financial/financial_prover.cpp',
             'financial/financial_release.cpp', 'financial/accepted_head.cpp',
             'financial/fixed_public_run.cpp', 'financial/registered_service.cpp',
             'financial/fresh_owner_trial_issuance.cpp',
             'financial/fresh_owner_process_adapter.cpp',
             'financial/fresh_owner_arm_isolation.cpp',
             'financial/candidate_owner_truth_post_barrier_bridge.cpp',
             'financial/registered_selection.cpp',
             'financial/registered_identity_registry.cpp',
             'financial/docker_monotonic_anchor_client.cpp',
             'financial/registered_attempt_supervisor.cpp',
             'financial/registered_parent_role_fork.cpp',
             'financial/registered_preidentity_ready.cpp',
             'financial/registered_persistent_fresh_trial_activation.cpp',
             'financial/registered_projection_route.cpp',
             'financial/registered_projection_route_capture_bridge.cpp',
             'financial/registered_full_cohort_release_barrier.cpp',
             'financial/registered_party_completion_transport.cpp',
             'financial/registered_supervisor_parent_transport.cpp',
             'financial/registered_parent_role_delivery_bridge.cpp',
             'financial/registered_parent_bootstrap.cpp',
             'financial/registered_parent_bootstrap_model.cpp',
             'financial/registered_role_model_admission.cpp',
             'financial/registered_role_child_program.cpp',
             'financial/registered_parent_round_completion.cpp',
             'financial/registered_producer_route_bridge.cpp',
             'financial/registered_persistent_role_exit_history.cpp',
             'financial/registered_selected_producer_run_binding.cpp',
             'financial/registered_selected_parent_orchestrator.cpp',
             'financial/registered_trial_attempt_history.cpp',
             'financial/registered_fresh_trial_history_ledger.cpp',
             'financial/registered_proposal_bridge.cpp',
             'financial/registered_driver_bridge.cpp',
             'financial/registered_capture_plan_roster_bridge.cpp',
             'financial/registered_p1_capture_bridge.cpp',
             'financial/registered_p1_context.cpp',
             'financial/registered_p1_private_state_context.cpp',
             'financial/registered_p1_state_archive_scm.cpp',
             'financial/registered_roster_crypto_player.cpp',
             'financial/registered_driver_history_bridge.cpp',
             'financial/registered_capture_session.cpp',
             'financial/baseline_public_effects_collector.cpp',
             'financial/authenticated_baseline_owner_receiver.cpp',
             'financial/authenticated_baseline_owner_receiver_tls.cpp',
             'financial/baseline_owner_effects_recipe.cpp',
             'financial/baseline_owner_effects_recipe_bridge.cpp',
             'financial/baseline_public_effects_bridge.cpp',
             '../private_batch_trial/privacy_capture_hook.cpp',
             '../private_batch_trial/privacy_capture_producer_archive.cpp',
             '../private_batch_trial/privacy_capture_producer_runtime.cpp',
             '../private_batch_trial/privacy_fresh_owner_transactional_replay_authority.cpp',
             '../private_batch_trial/privacy_all_branch_fresh_trial_owner_authority.cpp',
             '../private_batch_trial/privacy_fresh_owner_round1_outcome_consumer_authority.cpp',
             '../private_batch_trial/privacy_registered_fresh_trial_capture_topology_reservation.cpp',
             '../private_batch_trial/privacy_registered_fresh_trial_capture_topology_permit.cpp',
             '../private_batch_trial/privacy_registered_fresh_trial_producer_closure.cpp',
             '../private_batch_trial/privacy_measurement_authority.cpp',
             '../private_batch_trial/privacy_measurement_child_output_authority.cpp',
             '../private_batch_trial/privacy_measurement_output_abi.cpp',
             '../private_batch_trial/privacy_p1_corrupt_state_capsule_authority.cpp',
             '../private_batch_trial/privacy_registered_measurement_capture_bridge.cpp',
             'financial/registered_gate_main.cpp']
    selected = set(names) | {
        'financial/build_registered_financial.py',
        'financial/REGISTERED-ACTUAL-HEAD-SELECTION.json',
    }
    selected.update(str(p.relative_to(source)) for p in source.glob('*.hpp'))
    for folder in ('trace', 'packed', 'financial', 'history'):
        selected.update(str(p.relative_to(source)) for p in (source / folder).rglob('*.hpp'))
    selected.add('../private_batch_trial/privacy_capture_hook.hpp')
    selected = sorted(selected)
    before = {name: digest(source / name) for name in selected}
    selection_name = 'financial/registered_service_selection.hpp'
    selection_raw = (source / selection_name).read_text()
    configured_matches = re.findall(
        r'^\s*#define\s+KPI_REGISTERED_FINANCIAL_CONFIGURED\s+([01])\s*$',
        selection_raw, re.MULTILINE)
    if configured_matches != ['0']:
        raise SystemExit('This source-only qualifier requires the exact unconfigured selection')
    if re.search(r'^\s*#define\s+KPI_REGISTERED_FINANCIAL_DRIVER_HEADER\b',
                 selection_raw, re.MULTILINE):
        raise SystemExit('Unconfigured selection must not name a registered driver header')
    flags = ['-std=c++20', '-O1', '-g0', '-march=native', '-pthread',
             '-Wall', '-Wextra', '-Werror', '-Wno-overloaded-virtual',
             '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT',
             '-DUSE_GF2N_LONG', '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
             '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0']
    entropy_wrap_flags = [
        '-Wl,--wrap=_ZN4PRNG6ReSeedEv',
        '-Wl,--wrap=simplestot_randombytes',
        '-Wl,--wrap=_ZN9osuCrypto13sysRandomSeedEv',
    ]
    for path in [source, mp, mp / 'deps', mp / 'local/include', mcl / 'include', prefix / 'include',
                 prefix / 'include/x86_64-linux-gnu']:
        flags += ['-I', str(path)]
    commands = []

    def compile_file(name):
        target = output / (name.replace('/', '_') + '.o')
        depfile = output / (name.replace('/', '_') + '.d')
        command = [str(compiler), *flags, '-MD', '-MF', str(depfile),
                   '-c', str(source / name), '-o', str(target)]
        if name == 'trace/sealed_trace.cpp':
            command[1:1] = ['-DKPI_TRACE_ZLIB_BINARY_SHA256="' + digest(zlib_binary) + '"',
                           '-DKPI_TRACE_ZLIB_HEADERS_SHA256="' + zlib_headers_identity + '"']
        result = subprocess.run(command, capture_output=True)
        (output / (name.replace('/', '_') + '.stdout')).write_bytes(result.stdout)
        (output / (name.replace('/', '_') + '.stderr')).write_bytes(result.stderr)
        return {'source': name, 'argv': command, 'exit_code': result.returncode,
                'object': str(target) if result.returncode == 0 else None,
                'object_sha256': digest(target) if result.returncode == 0 else None,
                'dependency_file': str(depfile) if result.returncode == 0 else None}

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for result in pool.map(compile_file, names):
            commands.append(result)
            print(result['source'], 'compile exit', result['exit_code'], flush=True)
    failures = [r for r in commands if r['exit_code']]

    def logical(path):
        path = Path(path).resolve()
        for label, selected_root in (
                ('${OUTPUT}', output), ('${SOURCE}', source),
                ('${VENDOR}', vendor)):
            try:
                return label + '/' + str(path.relative_to(selected_root))
            except ValueError:
                pass
        return str(path)

    compile_dependency_paths = set()
    if not failures:
        for record in commands:
            compile_dependency_paths.update(
                parse_depfile(Path(record['dependency_file'])))
    compile_dependencies = {}
    for path in sorted(compile_dependency_paths):
        if not path.is_file():
            raise SystemExit('Missing transitive compile dependency: ' + str(path))
        compile_dependencies[logical(path)] = digest(path)
    if not failures and not compile_dependencies:
        raise SystemExit('No transitive compile dependencies captured')
    compile_dependencies_before = dict(compile_dependencies)
    links = []
    if not failures:
        common = [name for name in names if name != 'financial/registered_gate_main.cpp']
        for binary, entry in [
                ('mpc-registered-financial-gate', 'financial/registered_gate_main.cpp')]:
            target = output / binary
            link_map = output / (binary + '.link.map')
            command = [str(compiler), '-pthread', *entropy_wrap_flags,
                       '-o', str(target),
                       '-Wl,-Map,' + str(link_map)]
            by_name = {record['source']: record for record in commands}
            command += [by_name[name]['object'] for name in common + [entry]]
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
                          'sha256': digest(target) if result.returncode == 0 else None,
                          'map': str(link_map) if result.returncode == 0 else None})
            print(binary, 'link exit', result.returncode, flush=True)
    link_dependency_paths = set(objects + libraries)
    if links and links[0]['exit_code'] == 0:
        map_text = Path(links[0]['map']).read_text(errors='strict')
        for value in re.findall(r'(?<!\S)(/[^\s()]+)', map_text):
            path = Path(value.rstrip(',')).resolve()
            if path.is_file() and path not in {
                    output / 'mpc-registered-financial-gate',
                    Path(links[0]['map'])}:
                link_dependency_paths.add(path)
        runtime = subprocess.run(
            [str(runtime_inspector), str(output / 'mpc-registered-financial-gate')],
            capture_output=True, env={}, check=True)
        for value in re.findall(rb'/[^\s()]+', runtime.stdout):
            path = Path(value.decode('utf-8').rstrip(',')).resolve()
            if path.is_file():
                link_dependency_paths.add(path)
    link_dependencies = {
        logical(path): digest(path) for path in sorted(link_dependency_paths)
    }
    link_dependencies_before = dict(link_dependencies)
    controls = []
    if links and links[0]['exit_code'] == 0:
        binary = output / 'mpc-registered-financial-gate'
        result = subprocess.run([binary], cwd=output, env={}, capture_output=True)
        (output / 'default.stdout').write_bytes(result.stdout)
        (output / 'default.stderr').write_bytes(result.stderr)
        controls.append({
            'name': 'default-unconfigured-refusal',
            'argv': [str(binary)],
            'exit_code': result.returncode,
            'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
            'stderr_sha256': hashlib.sha256(result.stderr).hexdigest(),
            'pass': result.returncode == 78 and result.stdout == b'' and
                    result.stderr == b'KPI_REGISTERED_FINANCIAL_UNCONFIGURED_REFUSED\n',
            'file_network_owner_or_mpc_input_supplied': False
        })
    after = {name: digest(source / name) for name in selected}
    if before != after:
        raise SystemExit('Source changed during compilation; build is not qualified')
    if decoder_before != {str(p): digest(p) for p in [zlib_binary, *zlib_headers]}:
        raise SystemExit('Decoder closure changed during compilation; build is not qualified')
    toolchain_after = {
        'schema': 'kpi-registered-build-toolchain/v1',
        'compiler': {'path': str(compiler), 'sha256': digest(compiler),
                     'bytes': compiler.stat().st_size},
        'build_interpreter': {
            'path': str(interpreter), 'sha256': digest(interpreter),
            'bytes': interpreter.stat().st_size,
        },
        'runtime_inspector': {
            'path': str(runtime_inspector),
            'sha256': digest(runtime_inspector),
            'bytes': runtime_inspector.stat().st_size,
        },
        'subtools': {name: selected_tool(name, compiler)
                     for name in ('cc1plus', 'collect2', 'as', 'ld')},
        'version': command_identity([str(compiler), '--version']),
        'specs': command_identity([str(compiler), '-dumpspecs']),
        'search_directories': command_identity(
            [str(compiler), '-print-search-dirs']),
        'sysroot': command_identity([str(compiler), '-print-sysroot']),
    }
    if toolchain != toolchain_after:
        raise SystemExit('Compiler toolchain changed during build')
    compile_dependencies_after = {
        logical(path): digest(path) for path in sorted(compile_dependency_paths)
    }
    link_dependencies_after = {
        logical(path): digest(path) for path in sorted(link_dependency_paths)
    }
    if compile_dependencies_before != compile_dependencies_after:
        raise SystemExit('Compile dependency closure changed during build')
    if link_dependencies_before != link_dependencies_after:
        raise SystemExit('Link/runtime dependency closure changed during build')
    vendor_records = [{'path': str(p), 'sha256': digest(p)}
                      for p in objects + libraries]
    object_sha256 = {record['source']: record['object_sha256']
                     for record in commands}
    build_contract = {
        'schema': 'kpi-registered-financial-build-contract/v2',
        'compiler': compiler_record,
        'toolchain_sha256': json_digest(toolchain),
        'configuration_selection': {
            'path': selection_name,
            'sha256': before[selection_name],
            'configured': False,
            'driver_header': None,
            'default_action':
                'REFUSE_BEFORE_FILE_NETWORK_OWNER_OR_MPC_ACCESS',
        },
        'compile_units': names,
        'compile_flags': flags,
        'link_flags': entropy_wrap_flags,
        'dependency_mode': 'GCC_MD_FULL_SYSTEM_HEADERS',
        'source_closure_sha256': json_digest(before),
        'compile_dependency_closure_sha256':
            json_digest(compile_dependencies),
        'object_closure_sha256': json_digest(object_sha256),
        'link_dependency_closure_sha256': json_digest(link_dependencies),
        'vendor_closure_sha256': json_digest(vendor_records),
        'zlib_headers_sha256': zlib_headers_identity,
        'default_control': {
            'exit_code': 78,
            'stdout_sha256': hashlib.sha256(b'').hexdigest(),
            'stderr_sha256': hashlib.sha256(
                b'KPI_REGISTERED_FINANCIAL_UNCONFIGURED_REFUSED\n').hexdigest(),
            'file_network_owner_or_mpc_input_supplied': False,
        },
    }
    reproduction = None
    if args.reproduce_authority:
        authority_root = args.reproduce_authority.resolve()
        authority_path = authority_root / 'BUILD-RESULT.json'
        authority = json.loads(authority_path.read_text())
        authority_binary = authority_root / 'mpc-registered-financial-gate'
        reproduced_binary = output / 'mpc-registered-financial-gate'
        authority_binary_sha = digest(authority_binary)
        reproduced_binary_sha = digest(reproduced_binary)
        authority_ok = (
            authority_root != output and
            authority.get('schema') ==
                'kpi-registered-financial-gate-build/v3' and
            authority.get('success') is True and
            authority.get('configured') is False and
            authority.get('source_sha256') == before and
            authority.get('compiler') == compiler_record and
            authority.get('toolchain') == toolchain and
            authority.get('build_contract') == build_contract and
            authority.get('compile_dependencies') == compile_dependencies and
            authority.get('link_dependencies') == link_dependencies and
            authority.get('object_sha256') == object_sha256 and
            authority.get('vendor_artifacts') == vendor_records and
            authority.get('link', [{}])[0].get('sha256') ==
                authority_binary_sha and
            authority_binary_sha == reproduced_binary_sha and
            authority.get('controls', [{}])[0].get('pass') is True and
            bool(controls) and controls[0]['pass'])
        reproduction = {
            'schema': 'kpi-registered-financial-build-reproduction/v2',
            'authority_build_receipt_sha256': digest(authority_path),
            'authority_binary_sha256': authority_binary_sha,
            'reproduced_binary_sha256': reproduced_binary_sha,
            'independent_output_directory': authority_root != output,
            'exact_build_contract_match':
                authority.get('build_contract') == build_contract,
            'exact_toolchain_and_dependency_closure_match':
                authority.get('toolchain') == toolchain and
                authority.get('compile_dependencies') == compile_dependencies and
                authority.get('link_dependencies') == link_dependencies,
            'exact_object_closure_match':
                authority.get('object_sha256') == object_sha256,
            'default_refusal_reexecuted': bool(controls) and
                controls[0]['pass'],
            'pass': authority_ok,
        }
    receipt = {'schema': 'kpi-registered-financial-gate-build/v3',
               'configured': False, 'compiler': compiler_record,
               'toolchain': toolchain,
               'configuration_selection':
                    build_contract['configuration_selection'],
               'build_contract': build_contract,
               'source_sha256': before,
               'compile_dependencies': compile_dependencies,
               'object_sha256': object_sha256,
               'link_dependencies': link_dependencies,
               'zlib_binary': {'path': str(zlib_binary), 'sha256': digest(zlib_binary)},
               'zlib_headers_sha256': zlib_headers_identity,
               'vendor_artifacts': vendor_records,
               'compile': commands, 'link': links, 'controls': controls,
               'reproduction': reproduction,
               'success': not failures and len(links) == 1 and
                          all(r['exit_code'] == 0 for r in links) and
                          bool(compile_dependencies) and
                          bool(link_dependencies) and
                          len(object_sha256) == len(names) and
                          len(controls) == 1 and controls[0]['pass'] and
                          (reproduction is None or reproduction['pass']),
               'proof_or_private_input_executed': False}
    (output / 'BUILD-RESULT.json').write_text(json.dumps(receipt, indent=2) + '\n')
    raise SystemExit(0 if receipt['success'] else 1)


if __name__ == '__main__':
    main()
