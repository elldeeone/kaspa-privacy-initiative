#!/usr/bin/env python3
"""Materialize one immutable CONFIGURED0 Observer artifact-set candidate."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[3]
ARTIFACT_ROOT = REPOSITORY / 'artifacts'
BUILDER = HERE / 'build_static_observer_runtime.py'
PYTHON = Path('/usr/bin/python3.14')
READELF = Path('/usr/bin/x86_64-linux-gnu-readelf')
OUTPUT_ABI = HERE / 'observer_output_abi_v3.json'
MODULE_MANIFEST = HERE / 'frozen_modules.json'
TOOLCHAIN_LOCK = HERE / 'toolchain_lock.json'
DEPENDENCY_LOCK = HERE / 'transitive_dependency_lock.json'
SUPERVISOR = HERE.parent / 'privacy_measurement_child_supervisor.cpp'
SANDBOX = HERE.parent / 'privacy_measurement_preexec_sandbox.cpp'

SIX_ARTIFACTS = (
    (1, 'source', 'canonical-source-archive', 'observer-source.kpb', False),
    (2, 'build', 'reproducible-build-receipt', 'build-receipt.json', False),
    (3, 'runtime', 'transitive-runtime-closure',
     'observer-runtime-closure.json', False),
    (4, 'assets', 'canonical-assets-archive', 'observer-assets.kpb', False),
    (5, 'pinned-executable', 'final-selected-child-image',
     'kpb-static-observer', True),
    (6, 'launcher', 'source-owned-launch-plan',
     'observer-launch-plan.json', False),
)


def refuse(message):
    raise SystemExit('observer-selected-snapshot-refused: ' + message)


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) +
            '\n').encode()


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_file(path):
    return sha256_bytes(path.read_bytes())


def read_json(path):
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        refuse(f'invalid-json:{path.name}:{error}')
    if type(value) is not dict:
        refuse('non-object-json:' + path.name)
    return value


def build(output):
    completed = subprocess.run(
        [str(PYTHON), str(BUILDER), '--output', str(output)],
        cwd=HERE.parent, capture_output=True, text=True, check=False,
        env={'PATH': '/usr/bin', 'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC'})
    if completed.returncode != 0:
        refuse('build:\n' + completed.stdout + completed.stderr)
    try:
        receipt = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        refuse('build-receipt-stdout:' + str(error))
    if type(receipt) is not dict or receipt.get('configured') is not False:
        refuse('build-receipt')
    return receipt


def compare_builds(first, second):
    names = (
        'observer-source.kpb', 'observer-assets.kpb',
        'build-receipt.json', 'kpb-static-observer')
    for name in names:
        if first.joinpath(name).read_bytes() != second.joinpath(name).read_bytes():
            refuse('two-build-mismatch:' + name)


def require_static(executable):
    completed = subprocess.run(
        [str(READELF), '-l', '-d', str(executable)],
        capture_output=True, text=True, check=False,
        env={'PATH': '/usr/bin', 'LC_ALL': 'C', 'LANG': 'C'})
    if (completed.returncode != 0 or ' INTERP ' in completed.stdout or
            '(NEEDED)' in completed.stdout):
        refuse('final-executable-not-static')
    mode = executable.stat().st_mode
    if not stat.S_ISREG(mode) or not mode & stat.S_IXUSR:
        refuse('final-executable-mode')


def write_exclusive(path, value, mode=0o444):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    descriptor = os.open(path, flags, mode)
    try:
        at = 0
        while at < len(value):
            amount = os.write(descriptor, value[at:])
            if amount <= 0:
                refuse('short-write:' + path.name)
            at += amount
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def runtime_closure(build_receipt, executable_hash, abi, manifest,
                    source_hash, assets_hash):
    return {
        'schema': 'kpb-selected-observer-runtime-closure/v1',
        'configured': False,
        'selected': False,
        'role': 'observer',
        'entrypoint': manifest['entrypoint'],
        'output_abi': {
            'schema': abi['schema'],
            'version': abi['version'],
            'identity': abi['identity'],
            'exact_bytes': abi['exact_bytes'],
            'used_bytes': abi['used_bytes'],
            'phase_offset': abi['phase_offset'],
            'phase_bytes': abi['phase_bytes'],
            'step2_offset': abi['step2_offset'],
            'step2_bytes': abi['step2_bytes'],
            'step2_registry_identity': abi['step2_registry_identity'],
            'step2_model_identity': abi['step2_model_identity'],
            'authorizing': False,
        },
        'archives': {
            'source_sha256': source_hash,
            'source_bytes': build_receipt['source_archive_bytes'],
            'assets_sha256': assets_hash,
            'assets_bytes': build_receipt['asset_archive_bytes'],
        },
        'executable': {
            'sha256': executable_hash,
            'bytes': build_receipt['executable_bytes'],
            'static': True,
            'pt_interp_absent': True,
            'dt_needed': [],
        },
        'build_inputs': {
            'build_recipe_sha256': build_receipt['build_recipe_sha256'],
            'toolchain_lock_sha256': sha256_file(TOOLCHAIN_LOCK),
            'transitive_dependency_lock_sha256': sha256_file(DEPENDENCY_LOCK),
            'transitive_dependency_identity_sha256':
                build_receipt['transitive_dependency_identity_sha256'],
            'transitive_dependency_count':
                build_receipt['transitive_dependency_count'],
            'module_manifest_sha256': sha256_file(MODULE_MANIFEST),
            'frozen_manifest_sha256':
                build_receipt['frozen_manifest_sha256'],
        },
        'runtime_boundary': {
            'fixed_descriptors': {'capsule': 40, 'source': 60,
                                  'assets': 61, 'output': 62},
            'sealed_read_only_inputs': [40, 60, 61],
            'single_fixed_output': {'fd': 62, 'offset': 0,
                                    'exact_bytes': abi['exact_bytes']},
            'filesystem_imports_after_exec': False,
            'network_syscalls': False,
            'arbitrary_code_imports': False,
        },
    }


def launch_plan(build_receipt_hash, runtime_hash, executable_hash,
                source_hash, assets_hash, abi):
    return {
        'schema': 'kpb-selected-observer-launch-plan/v1',
        'configured': False,
        'selected': False,
        'role': 'observer',
        'artifacts': {
            'source_sha256': source_hash,
            'build_receipt_sha256': build_receipt_hash,
            'runtime_closure_sha256': runtime_hash,
            'assets_sha256': assets_hash,
            'executable_sha256': executable_hash,
        },
        'output_abi_identity': abi['identity'],
        'output_abi_authorizing': False,
        'supervisor': {
            'source': str(SUPERVISOR.relative_to(REPOSITORY)),
            'source_sha256': sha256_file(SUPERVISOR),
            'sandbox_source': str(SANDBOX.relative_to(REPOSITORY)),
            'sandbox_source_sha256': sha256_file(SANDBOX),
            'execution': 'sealed-execveat-after-authenticated-offer',
            'fixed_descriptors': [40, 60, 61, 62],
            'require_credentials': True,
            'require_kernel_eof': True,
            'require_clean_waitpid': True,
        },
        'network': False,
        'funding': False,
        'broadcast': False,
        'selection_authority': False,
    }


def artifact_rows(snapshot, hashes, sizes, origins):
    rows = []
    for field, name, kind, relative, final in SIX_ARTIFACTS:
        rows.append({
            'component': 7,
            'component_name': 'observer',
            'field': field,
            'field_name': name,
            'kind': kind,
            'relative_path': relative,
            'path': str((snapshot / relative).resolve()),
            'bytes': sizes[relative],
            'sha256': hashes[relative],
            'origin_contract': origins[relative],
            'origin_contract_sha256': sha256_file(
                REPOSITORY / origins[relative]),
            'final_executable': final,
        })
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-root', required=True, type=Path)
    args = parser.parse_args()
    artifact_root = ARTIFACT_ROOT.resolve(strict=True)
    output = args.output_root.resolve(strict=False)
    if (not output.is_absolute() or output.parent != artifact_root or
            output.exists()):
        refuse('output-root-must-be-new-direct-child-of-artifacts')

    abi = read_json(OUTPUT_ABI)
    manifest = read_json(MODULE_MANIFEST)
    if (abi.get('schema') != 'kpb-measurement-private-output-abi/v3' or
            abi.get('configured') is not False or
            abi.get('identity') !=
            '1e28e13affa3c23b39cf781bb003b69827ec37154514180f012e44bc072fa16f' or
            manifest.get('configured') is not False or
            manifest.get('selected_fd40_authority_consumer') is not False or
            manifest.get('selected_fd62_output_authority') is not False):
        refuse('source-status')

    with tempfile.TemporaryDirectory(
            prefix='.observer-selected-build-', dir=artifact_root) as raw:
        temporary = Path(raw)
        first = temporary / 'first'
        second = temporary / 'second'
        first_receipt = build(first)
        second_receipt = build(second)
        if first_receipt != second_receipt:
            refuse('two-build-receipt-mismatch')
        compare_builds(first, second)
        require_static(first / 'kpb-static-observer')

        # Build and cross-check before creating the requested immutable root.
        # Once created, every file is O_EXCL and the root is never replaced.
        os.mkdir(output, 0o700)
        stage = output
        source = (first / 'observer-source.kpb').read_bytes()
        assets = (first / 'observer-assets.kpb').read_bytes()
        receipt = (first / 'build-receipt.json').read_bytes()
        executable = (first / 'kpb-static-observer').read_bytes()
        source_hash = sha256_bytes(source)
        assets_hash = sha256_bytes(assets)
        receipt_hash = sha256_bytes(receipt)
        executable_hash = sha256_bytes(executable)
        runtime = canonical_json(runtime_closure(
            first_receipt, executable_hash, abi, manifest,
            source_hash, assets_hash))
        runtime_hash = sha256_bytes(runtime)
        launcher = canonical_json(launch_plan(
            receipt_hash, runtime_hash, executable_hash,
            source_hash, assets_hash, abi))

        values = {
            'observer-source.kpb': source,
            'build-receipt.json': receipt,
            'observer-runtime-closure.json': runtime,
            'observer-assets.kpb': assets,
            'kpb-static-observer': executable,
            'observer-launch-plan.json': launcher,
        }
        for name, value in values.items():
            write_exclusive(stage / name, value,
                            0o555 if name == 'kpb-static-observer' else 0o444)
        hashes = {name: sha256_bytes(value) for name, value in values.items()}
        sizes = {name: len(value) for name, value in values.items()}
        builder_origin = str(BUILDER.relative_to(REPOSITORY))
        snapshot_origin = str(Path(__file__).resolve().relative_to(REPOSITORY))
        origins = {
            'observer-source.kpb': builder_origin,
            'build-receipt.json': builder_origin,
            'observer-runtime-closure.json': snapshot_origin,
            'observer-assets.kpb': builder_origin,
            'kpb-static-observer': snapshot_origin,
            'observer-launch-plan.json': snapshot_origin,
        }
        manifest_value = {
            'schema': 'kpb-observer-selected-artifact-set/v1',
            'status': 'open-only-v3-reproducibility-candidate',
            'configured': False,
            'selected': False,
            'final_table_eligible': False,
            'blocker': 'feasibility-aware-v4-required',
            'snapshot_root': str(output),
            'two_builds_byte_identical': True,
            'pt_interp_absent': True,
            'dt_needed': [],
            'output_abi_identity': abi['identity'],
            'artifacts': artifact_rows(output, hashes, sizes, origins),
            'cross_bindings': {
                'source_archive_sha256': source_hash,
                'build_receipt_sha256': receipt_hash,
                'runtime_closure_sha256': runtime_hash,
                'assets_archive_sha256': assets_hash,
                'final_executable_sha256': executable_hash,
                'launch_plan_sha256': hashes['observer-launch-plan.json'],
            },
            'network': False,
            'funding': False,
            'broadcast': False,
        }
        write_exclusive(stage / 'observer-selected-artifact-set.json',
                        canonical_json(manifest_value), 0o444)
        os.chmod(stage, 0o555)
        directory_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        parent_fd = os.open(artifact_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)

    expected = {row[3] for row in SIX_ARTIFACTS}
    expected.add('observer-selected-artifact-set.json')
    if {path.name for path in output.iterdir()} != expected:
        refuse('final-file-universe')
    for path in output.iterdir():
        if not path.is_file() or path.is_symlink():
            refuse('final-file-type')
    print(json.dumps({
        'snapshot_root': str(output),
        'manifest': str(output / 'observer-selected-artifact-set.json'),
        'manifest_sha256': sha256_file(
            output / 'observer-selected-artifact-set.json'),
        'configured': False,
        'selected': False,
    }, sort_keys=True))


if __name__ == '__main__':
    main()
