#!/usr/bin/env python3
"""Build an unselected, byte-pinned static CPython observer closure."""

import argparse
import hashlib
import json
import marshal
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys


HERE = Path(__file__).resolve().parent
SOURCE_MAGIC = b'KPBSRC1\0'
ASSET_MAGIC = b'KPBAST1\0'
GCC_PREFIX_FLAGS = (
    '-B/usr/libexec/gcc/x86_64-linux-gnu/15/',
    '-B/usr/bin/x86_64-linux-gnu-',
)
TOOLCHAIN_LOCK = HERE / 'toolchain_lock.json'
HEADER_LOCK = HERE / 'transitive_dependency_lock.json'
MODULE_MANIFEST = HERE / 'frozen_modules.json'
# This reviewed recipe anchors the otherwise caller-substitutable lock file.
# Update only after independently reviewing every changed lock row.
EXPECTED_TOOLCHAIN_LOCK_SHA256 = (
    '55dc229f90e48e07906f8660d34885c8ef0dbb11225bf04707cef633246f890f')


def refuse(message):
    raise SystemExit('static-observer-build-refused: ' + message)


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def read_json(path):
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        refuse(f'invalid-json:{path.name}:{error}')
    if type(value) is not dict:
        refuse(f'non-object-json:{path.name}')
    return value


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))
            + '\n').encode()


def exact_file(path, wanted):
    try:
        raw = path.read_bytes()
    except OSError as error:
        refuse(f'missing-input:{path}:{error}')
    actual = sha256(raw)
    if actual != wanted:
        refuse(f'input-digest:{path}:{actual}')
    return raw


def tree_identity(root):
    identity = hashlib.sha256()
    files = sorted(path for path in root.rglob('*') if path.is_file())
    if not files:
        refuse('empty-include-tree')
    for path in files:
        identity.update(path.relative_to(root).as_posix().encode())
        identity.update(b'\0')
        identity.update(hashlib.sha256(path.read_bytes()).digest())
    return identity.hexdigest()


def validate_toolchain(lock):
    if lock.get('schema') != 'kpb-static-observer-toolchain-lock/v1':
        refuse('toolchain-schema')
    if sys.version.split()[0] != lock.get('python_version'):
        refuse('python-version')
    by_name = {}
    rows = lock.get('files')
    if type(rows) is not list or not rows:
        refuse('toolchain-files')
    for row in rows:
        if (type(row) is not list or len(row) != 3
                or not all(type(item) is str and item for item in row)):
            refuse('toolchain-file-row')
        name, raw_path, wanted = row
        if name in by_name or not re.fullmatch(r'[A-Za-z0-9_]+', name):
            refuse('toolchain-file-name')
        path = Path(raw_path)
        exact_file(path, wanted)
        by_name[name] = path
    required = {
        'python', 'gcc', 'cc1', 'cc1plus', 'collect2', 'as', 'ld',
        'readelf', 'libpython', 'libm', 'libdl',
        'libpthread', 'libutil', 'libc', 'libgcc', 'libgcc_eh',
        'crt1', 'crti', 'crtbeginT', 'crtend', 'crtn',
        'rt_loader', 'rt_bfd', 'rt_libc', 'rt_ctf_nobfd', 'rt_ctf',
        'rt_expat', 'rt_gmp', 'rt_isl', 'rt_jansson', 'rt_libm',
        'rt_mpc', 'rt_mpfr', 'rt_sframe', 'rt_z', 'rt_zstd',
    }
    if set(by_name) != required:
        refuse('toolchain-file-universe')
    if sha256(Path(sys.executable).read_bytes()) != sha256(
            by_name['python'].read_bytes()):
        refuse('running-python')
    include = lock.get('python_include_tree')
    if type(include) is not dict or set(include) != {'path', 'sha256'}:
        refuse('include-tree-row')
    include_root = Path(include['path'])
    if tree_identity(include_root) != include['sha256']:
        refuse('include-tree-digest')
    for option, field in (
            ('-dumpspecs', 'gcc_specs_sha256'),
            ('-print-search-dirs', 'gcc_search_dirs_sha256')):
        value = subprocess.run(
            [str(by_name['gcc']), option], capture_output=True,
            check=False,
            env={'PATH': '/usr/bin', 'LC_ALL': 'C', 'LANG': 'C'}).stdout
        if sha256(value) != lock.get(field):
            refuse(field)
    expected_programs = {
        'cc1': by_name['cc1'], 'cc1plus': by_name['cc1plus'],
        'collect2': by_name['collect2'], 'as': by_name['as'],
        'ld': by_name['ld'],
    }
    for program, expected in expected_programs.items():
        completed = subprocess.run(
            [str(by_name['gcc']), *GCC_PREFIX_FLAGS,
             '-print-prog-name=' + program],
            capture_output=True, text=True, check=False,
            env={'PATH': '/usr/bin', 'LC_ALL': 'C', 'LANG': 'C'})
        try:
            actual = Path(completed.stdout.strip()).resolve(strict=True)
        except OSError:
            refuse('compiler-program-' + program)
        if completed.returncode != 0 or actual != expected.resolve():
            refuse('compiler-program-' + program)
    if Path('/usr/bin/ld').resolve() != by_name['ld'].resolve():
        refuse('linker-alias')
    validate_build_runtime_closure(lock, by_name)
    return by_name, include_root


def elf_dynamic(tools, path):
    completed = subprocess.run(
        [str(tools['readelf']), '-d', '-l', str(path)],
        capture_output=True, text=True, check=False,
        env={'PATH': '/usr/bin', 'LC_ALL': 'C', 'LANG': 'C'})
    if completed.returncode != 0:
        refuse('runtime-elf:' + str(path))
    needed = set(re.findall(r'Shared library: \[([^]]+)\]',
                            completed.stdout))
    match = re.search(r'Requesting program interpreter: ([^]]+)\]',
                      completed.stdout)
    return needed, None if match is None else Path(match.group(1)).resolve()


def validate_build_runtime_closure(lock, tools):
    rows = lock.get('build_runtime_sonames')
    if type(rows) is not list or not rows:
        refuse('build-runtime-rows')
    runtime = {}
    for row in rows:
        if (type(row) is not list or len(row) != 2 or
                not all(type(item) is str and item for item in row)):
            refuse('build-runtime-row')
        soname, tool_name = row
        if (soname in runtime or tool_name not in tools or
                not tool_name.startswith('rt_')):
            refuse('build-runtime-row')
        runtime[soname] = tools[tool_name]
    roots = lock.get('build_runtime_roots')
    expected_roots = {
        'python', 'gcc', 'cc1', 'cc1plus', 'collect2', 'as', 'ld',
        'readelf',
    }
    if type(roots) is not list or set(roots) != expected_roots:
        refuse('build-runtime-roots')
    visited = set()
    pending = [tools[name] for name in roots]
    loader = tools['rt_loader'].resolve()
    while pending:
        path = pending.pop()
        needed, interpreter = elf_dynamic(tools, path)
        if interpreter is not None and interpreter != loader:
            refuse('build-runtime-interpreter')
        for soname in needed:
            if soname not in runtime:
                refuse('build-runtime-missing:' + soname)
            if soname not in visited:
                visited.add(soname)
                pending.append(runtime[soname])
    if visited != set(runtime):
        refuse('build-runtime-extra')


def resolve_source(manifest_path, raw_path):
    path = Path(raw_path)
    return path if path.is_absolute() else manifest_path.parent / path


def freeze_modules(manifest, manifest_path):
    if manifest.get('schema') != 'kpb-static-observer-frozen-modules/v1':
        refuse('module-schema')
    if manifest.get('configured') is not False:
        refuse('configured-must-remain-false')
    if (manifest.get('selected_fd40_authority_consumer') is not False or
            manifest.get('selected_fd62_output_authority') is not False):
        refuse('selected-authority-must-remain-false')
    crypto = manifest.get('crypto_backend')
    if type(crypto) is not dict or set(crypto) != {'path', 'sha256'}:
        refuse('crypto-backend')
    exact_file(
        resolve_source(manifest_path, crypto['path']), crypto['sha256'])
    entrypoint = manifest.get('entrypoint')
    if (type(entrypoint) is not dict or
            set(entrypoint) != {'module', 'function'} or
            not all(type(value) is str and re.fullmatch(
                r'[A-Za-z_][A-Za-z0-9_.]*', value)
                for value in entrypoint.values())):
        refuse('entrypoint')
    modules = manifest.get('modules')
    if type(modules) is not list or not modules:
        refuse('modules')
    result = []
    seen = set()
    for row in modules:
        if (type(row) is not dict or set(row) != {
                'name', 'path', 'is_package', 'source_sha256'}):
            refuse('module-row')
        name = row['name']
        if (type(name) is not str or not re.fullmatch(
                r'[A-Za-z_][A-Za-z0-9_.]*', name) or name in seen):
            refuse('module-name')
        seen.add(name)
        if type(row['is_package']) is not bool:
            refuse('module-package-flag')
        path = resolve_source(manifest_path, row['path'])
        source = exact_file(path, row['source_sha256'])
        try:
            text = source.decode('utf-8')
            code = compile(
                text, 'kpb-frozen/' + name.replace('.', '/') + '.py',
                'exec', dont_inherit=True, optimize=2)
        except (UnicodeError, SyntaxError) as error:
            refuse(f'module-compile:{name}:{error}')
        # Python 3.14 emits code constants that require its pinned v5 marshal
        # grammar. The runtime and generator are the same byte-pinned build.
        frozen = marshal.dumps(code, 5)
        result.append({
            'name': name,
            'is_package': row['is_package'],
            'source_path': ('python/' + name.replace('.', '/') +
                            ('/__init__.py' if row['is_package'] else '.py')),
            'source': source,
            'source_sha256': row['source_sha256'],
            'frozen': frozen,
            'frozen_sha256': sha256(frozen),
            'frozen_bytes': len(frozen),
        })
    if entrypoint['module'] not in seen:
        refuse('entrypoint-not-frozen')
    return entrypoint, result


def build_archive(magic, entries):
    if len(magic) != 8 or not entries:
        refuse('archive-header')
    previous = None
    out = bytearray(magic)
    out.extend(struct.pack('<I', len(entries)))
    for path, content in sorted(entries):
        try:
            encoded = path.encode('ascii')
        except UnicodeError:
            refuse('archive-path-ascii')
        if (not encoded or len(encoded) > 65535 or not content or
                path.startswith('/') or path.endswith('/') or
                any(part in ('', '.', '..') for part in path.split('/')) or
                not re.fullmatch(r'[A-Za-z0-9._/-]+', path)):
            refuse('archive-path')
        if previous is not None and previous >= encoded:
            refuse('archive-order')
        previous = encoded
        out.extend(struct.pack('<HQ', len(encoded), len(content)))
        out.extend(encoded)
        out.extend(hashlib.sha256(content).digest())
        out.extend(content)
    return bytes(out)


def validate_asset_semantics(path, raw):
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        refuse(f'asset-json:{path}:{error}')
    if canonical_json(value) != raw:
        refuse('asset-noncanonical:' + path)
    if path == 'privacy-assumption-selection.json':
        if value != {
                'schema': 'kpb-private-observer-assumption-selection/v1',
                'configured': False,
                'selected_assumptions': [],
                'selection_authority': False,
        }:
            refuse('assumption-selection-must-remain-empty')
    elif path == 'observer-output-abi-v3.json':
        if value != {
                'schema': 'kpb-measurement-private-output-abi/v3',
                'configured': False,
                'role': 'observer', 'version': 3,
                'magic': 'KPBOABI3', 'used_bytes': 151449,
                'exact_bytes': 151552,
                'identity': ('1e28e13affa3c23b39cf781bb003b69827ec37154'
                             '514180f012e44bc072fa16f'),
                'phase_magic': 'KPBPHV01', 'phase_offset': 151049,
                'phase_bytes': 144,
                'step2_magic': 'KPBSTP21', 'step2_offset': 151193,
                'step2_bytes': 256,
                'step2_registry_identity': (
                    'ee700075720da629ecfed7bc43f9725d14826fc2d0ecd201878'
                    'a1c2d6bf86708'),
                'step2_model_identity': (
                    '3e22997c8932709496c843929e4a0752b3bc7f001690c2119'
                    'a6692b6388a645a'),
        }:
            refuse('observer-output-abi')
    else:
        refuse('asset-universe:' + path)


def compile_flags(output, include_root):
    return [
        *GCC_PREFIX_FLAGS,
        '-O2', '-pipe', '-Wall', '-Wextra', '-Werror',
        '-fno-ident', '-fno-record-gcc-switches',
        '-ffunction-sections', '-fdata-sections',
        '-frandom-seed=kpb-static-observer-v1',
        f'-ffile-prefix-map={HERE}=kpb-source',
        f'-ffile-prefix-map={output}=kpb-output',
        f'-fdebug-prefix-map={HERE}=kpb-source',
        f'-fdebug-prefix-map={output}=kpb-output',
        '-I', include_root, '-I', output, '-I', HERE.parent,
    ]


def dependency_identity(rows):
    identity = hashlib.sha256()
    for logical, path in rows:
        identity.update(logical.encode('ascii'))
        identity.update(b'\0')
        identity.update(hashlib.sha256(path.read_bytes()).digest())
    return identity.hexdigest()


def make_dependencies(command, environment):
    completed = subprocess.run(
        [str(value) for value in command], capture_output=True, text=True,
        check=False, env=environment)
    if completed.returncode != 0:
        refuse('dependency-command:\n' + completed.stdout + completed.stderr)
    try:
        raw = completed.stdout.replace('\\\n', ' ').split(':', 1)[1]
        return {Path(value).resolve(strict=True) for value in shlex.split(raw)}
    except (IndexError, OSError, ValueError) as error:
        refuse('dependency-output:' + str(error))


def validate_transitive_dependencies(lock, lock_path, output, tools,
                                     include_root, generated):
    expected_lock_digest = lock.get('transitive_dependency_lock_sha256')
    if type(expected_lock_digest) is not str:
        refuse('dependency-lock-digest')
    exact_file(lock_path, expected_lock_digest)
    value = read_json(lock_path)
    if value.get('schema') != 'kpb-static-observer-dependencies/v1':
        refuse('dependency-schema')
    roots = {
        'repo': HERE.parents[3],
        'usr-include': Path('/usr/include'),
        'gcc-include': Path('/usr/lib/gcc/x86_64-linux-gnu/15/include'),
    }
    if value.get('roots') != {
            'repo': '.', 'usr-include': '/usr/include',
            'gcc-include': '/usr/lib/gcc/x86_64-linux-gnu/15/include'}:
        refuse('dependency-roots')
    common = compile_flags(output, include_root)
    environment = build_environment()
    commands = (
        [tools['gcc'], *common, '-std=c11', '-M',
         HERE / 'static_observer_runtime.c'],
        [tools['gcc'], *common, '-std=c11', '-M', generated],
        [tools['gcc'], *common, '-x', 'c++', '-std=c++20', '-M',
         HERE / 'static_observer_sha256.cpp'],
    )
    dependencies = set()
    for command in commands:
        dependencies.update(make_dependencies(command, environment))
    dependencies = {path for path in dependencies
                    if not path.is_relative_to(output)}
    rows = []
    for path in dependencies:
        matches = []
        for name, root in roots.items():
            try:
                relative = path.relative_to(root)
            except ValueError:
                continue
            matches.append((len(root.parts), name, relative))
        if not matches:
            refuse('dependency-outside-roots:' + str(path))
        _, name, relative = max(matches)
        rows.append((name + ':' + relative.as_posix(), path))
    rows.sort(key=lambda row: row[0])
    groups = value.get('dependency_groups')
    if type(groups) is not dict or set(groups) != set(roots):
        refuse('dependency-groups')
    expected = []
    for name in sorted(groups):
        if (type(groups[name]) is not list or
                not all(type(item) is str and item for item in groups[name])):
            refuse('dependency-group')
        expected.extend(name + ':' + item for item in groups[name])
    expected.sort()
    if expected != [row[0] for row in rows]:
        refuse('dependency-universe')
    if value.get('identity_sha256') != dependency_identity(rows):
        refuse('dependency-identity')
    return len(rows), value['identity_sha256']


def c_array(name, value):
    rows = []
    for at in range(0, len(value), 16):
        rows.append('    ' + ', '.join(
            f'0x{byte:02x}' for byte in value[at:at + 16]))
    return (f'static const unsigned char {name}[] = {{\n'
            + ',\n'.join(rows) + '\n};\n')


def generate_frozen_sources(output, entrypoint, modules,
                            source_archive, asset_archive):
    header = output / 'generated_observer_frozen.h'
    source = output / 'generated_observer_frozen.c'
    header.write_text('''#pragma once
#include <Python.h>
#include <stdint.h>
extern const struct _frozen kpb_observer_frozen_modules[];
extern const unsigned char kpb_source_archive_sha256[32];
extern const unsigned char kpb_asset_archive_sha256[32];
extern const uint64_t kpb_source_archive_size;
extern const uint64_t kpb_asset_archive_size;
extern const char kpb_entrypoint_module[];
extern const char kpb_entrypoint_function[];
''', encoding='ascii')
    chunks = ['#include "generated_observer_frozen.h"\n\n']
    identifiers = []
    for index, module in enumerate(modules):
        identifier = f'kpb_frozen_{index}'
        identifiers.append(identifier)
        chunks.append(c_array(identifier, module['frozen']))
    chunks.append('\nconst struct _frozen kpb_observer_frozen_modules[] = {\n')
    for module, identifier in zip(modules, identifiers):
        chunks.append(
            f'    {{"{module["name"]}", {identifier}, '
            f'(int)sizeof({identifier}), '
            f'{1 if module["is_package"] else 0}}},\n')
    chunks.append('    {0, 0, 0, 0}\n};\n\n')
    chunks.append(c_array(
        'kpb_source_archive_sha256',
        hashlib.sha256(source_archive).digest()).replace('static ', ''))
    chunks.append(c_array(
        'kpb_asset_archive_sha256',
        hashlib.sha256(asset_archive).digest()).replace('static ', ''))
    chunks.append(
        f'const uint64_t kpb_source_archive_size = {len(source_archive)}ULL;\n'
        f'const uint64_t kpb_asset_archive_size = {len(asset_archive)}ULL;\n'
        f'const char kpb_entrypoint_module[] = '
        f'"{entrypoint["module"]}";\n'
        f'const char kpb_entrypoint_function[] = '
        f'"{entrypoint["function"]}";\n')
    source.write_text(''.join(chunks), encoding='ascii')
    return header, source


def generate_crypto_header(output, manifest, manifest_path):
    row = manifest['crypto_backend']
    original = exact_file(
        resolve_source(manifest_path, row['path']), row['sha256'])
    marker = b'#include "privacy_measurement_authority.hpp"'
    replacement = (
        b'#include <array>\n'
        b'namespace kpb::measurement {\n'
        b'using Digest = std::array<unsigned char, 32>;\n'
        b'}')
    if original.count(marker) != 1:
        refuse('crypto-backend-alias-include')
    generated = original.replace(marker, replacement)
    path = output / 'generated_privacy_measurement_sha256.hpp'
    path.write_bytes(generated)
    return path


def run(command, environment):
    completed = subprocess.run(
        [str(value) for value in command], capture_output=True, text=True,
        check=False, env=environment)
    if completed.returncode != 0:
        refuse('command-failed:\n' + completed.stdout + completed.stderr)
    return completed


def build_environment():
    return {
        'PATH': '/usr/libexec/gcc/x86_64-linux-gnu/15:/usr/bin',
        'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC',
        'SOURCE_DATE_EPOCH': '1', 'ZERO_AR_DATE': '1',
    }


def require_program_trace(completed, programs):
    for path in programs:
        if str(path) not in completed.stderr:
            refuse('compiler-program-not-invoked:' + path.name)


def require_exact_link_inputs(completed, tools, generated_inputs):
    command = None
    for line in completed.stderr.splitlines():
        if 'collect2' in line and '--start-group' in line:
            command = shlex.split(line)
            break
    if command is None or Path(command[0]).resolve() != tools['collect2'].resolve():
        refuse('collect2-command')
    actual = {
        Path(token).resolve() for token in command
        if token.startswith('/') and token.endswith(('.a', '.o', '.so'))
    }
    expected = {Path(path).resolve() for path in generated_inputs}
    expected.update(tools[name].resolve() for name in (
        'crt1', 'crti', 'crtbeginT', 'crtend', 'crtn',
        'libpython', 'libm', 'libdl', 'libpthread', 'libutil', 'libc',
        'libgcc', 'libgcc_eh'))
    if actual != expected:
        refuse('static-link-input-universe')
    if any('lto' in token for token in command):
        refuse('unexpected-lto-input')


def compile_runtime(output, tools, include_root, generated):
    template = HERE / 'static_observer_runtime.c'
    sha_bridge = HERE / 'static_observer_sha256.cpp'
    template_hash = sha256(template.read_bytes())
    common = compile_flags(output, include_root)
    environment = build_environment()
    runtime_object = output / 'static_observer_runtime.o'
    frozen_object = output / 'generated_observer_frozen.o'
    sha_object = output / 'static_observer_sha256.o'
    runtime_compile = run([tools['gcc'], *common, '-v', '-std=c11',
                           '-c', template, '-o', runtime_object], environment)
    require_program_trace(runtime_compile, (tools['cc1'], tools['as']))
    frozen_compile = run([tools['gcc'], *common, '-v', '-std=c11',
                          '-c', generated, '-o', frozen_object], environment)
    require_program_trace(frozen_compile, (tools['cc1'], tools['as']))
    sha_compile = run([
        tools['gcc'], *common, '-v', '-x', 'c++', '-std=c++20',
        '-fno-exceptions', '-fno-rtti', '-c', sha_bridge, '-o', sha_object,
    ], environment)
    require_program_trace(sha_compile, (tools['cc1plus'], tools['as']))
    executable = output / 'kpb-static-observer'
    libraries = [tools[name] for name in (
        'libpython', 'libm', 'libdl',
        'libpthread', 'libutil', 'libc', 'libgcc', 'libgcc_eh')]
    link = run([
        tools['gcc'], *GCC_PREFIX_FLAGS, '-v',
        '-static', '-no-pie', '-nodefaultlibs', '-fno-use-linker-plugin',
        '-Wl,-v', '-Wl,--build-id=none', '-Wl,--gc-sections',
        '-Wl,-z,noexecstack',
        runtime_object, frozen_object, sha_object,
        '-Wl,--start-group', *libraries,
        '-Wl,--end-group', '-o', executable,
    ], environment)
    require_program_trace(link, (tools['collect2'],))
    require_exact_link_inputs(
        link, tools, (runtime_object, frozen_object, sha_object))
    if 'GNU ld' not in link.stdout + link.stderr:
        refuse('linker-not-invoked')
    executable.chmod(0o500)
    readelf = subprocess.run(
        [str(tools['readelf']), '-l', '-d', str(executable)],
        capture_output=True, text=True, check=False, env=environment)
    if (readelf.returncode != 0 or ' INTERP ' in readelf.stdout or
            '(NEEDED)' in readelf.stdout):
        refuse('runtime-not-static')
    return executable, template_hash, sha256(sha_bridge.read_bytes())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--manifest', type=Path,
                        default=MODULE_MANIFEST)
    parser.add_argument('--dependency-lock', type=Path,
                        default=HEADER_LOCK)
    args = parser.parse_args()
    exact_file(TOOLCHAIN_LOCK, EXPECTED_TOOLCHAIN_LOCK_SHA256)
    lock = read_json(TOOLCHAIN_LOCK)
    try:
        manifest_raw = args.manifest.read_bytes()
    except OSError as error:
        refuse('module-manifest-missing:' + str(error))
    if sha256(manifest_raw) != lock.get('module_manifest_sha256'):
        refuse('module-manifest-digest')
    manifest = read_json(args.manifest)
    tools, include_root = validate_toolchain(lock)
    entrypoint, modules = freeze_modules(manifest, args.manifest)
    args.output.mkdir(parents=True, exist_ok=False)

    frozen_manifest = {
        'schema': 'kpb-static-observer-frozen-manifest/v1',
        'configured': False,
        'entrypoint': entrypoint,
        'modules': [{key: module[key] for key in (
            'name', 'is_package', 'source_path', 'source_sha256',
            'frozen_sha256', 'frozen_bytes')} for module in modules],
        'selected_fd40_authority_consumer': False,
        'selected_fd62_output_authority': False,
    }
    source_entries = [('frozen-manifest.json',
                       canonical_json(frozen_manifest))]
    source_entries.extend(
        (module['source_path'], module['source']) for module in modules)
    source_archive = build_archive(SOURCE_MAGIC, source_entries)

    assets = manifest.get('assets')
    if type(assets) is not list or not assets:
        refuse('assets')
    asset_entries = []
    for row in assets:
        if (type(row) is not dict or set(row) != {
                'path', 'source', 'sha256'}):
            refuse('asset-row')
        raw = exact_file(resolve_source(args.manifest, row['source']),
                         row['sha256'])
        validate_asset_semantics(row['path'], raw)
        asset_entries.append((row['path'], raw))
    if [row[0] for row in asset_entries] != [
            'privacy-assumption-selection.json',
            'observer-output-abi-v3.json']:
        refuse('asset-universe')
    asset_archive = build_archive(ASSET_MAGIC, asset_entries)
    (args.output / 'observer-source.kpb').write_bytes(source_archive)
    (args.output / 'observer-assets.kpb').write_bytes(asset_archive)
    generated_header, generated = generate_frozen_sources(
        args.output, entrypoint, modules, source_archive, asset_archive)
    generated_crypto = generate_crypto_header(
        args.output, manifest, args.manifest)
    dependency_count, dependency_identity_value = \
        validate_transitive_dependencies(
            lock, args.dependency_lock, args.output, tools, include_root,
            generated)
    executable, template_hash, sha_bridge_hash = compile_runtime(
        args.output, tools, include_root, generated)
    receipt = {
        'schema': 'kpb-static-observer-build-receipt/v1',
        'configured': False,
        'entrypoint': entrypoint,
        'build_recipe_sha256': sha256(Path(__file__).read_bytes()),
        'toolchain_lock_sha256': sha256(TOOLCHAIN_LOCK.read_bytes()),
        'transitive_dependency_lock_sha256': sha256(
            args.dependency_lock.read_bytes()),
        'transitive_dependency_identity_sha256': dependency_identity_value,
        'transitive_dependency_count': dependency_count,
        'module_manifest_sha256': sha256(args.manifest.read_bytes()),
        'runtime_template_sha256': template_hash,
        'sha256_bridge_sha256': sha_bridge_hash,
        'generated_header_sha256': sha256(generated_header.read_bytes()),
        'generated_source_sha256': sha256(generated.read_bytes()),
        'generated_crypto_header_sha256': sha256(
            generated_crypto.read_bytes()),
        'crypto_backend_sha256': manifest['crypto_backend']['sha256'],
        'frozen_manifest_sha256': sha256(
            canonical_json(frozen_manifest)),
        'source_archive_sha256': sha256(source_archive),
        'source_archive_bytes': len(source_archive),
        'asset_archive_sha256': sha256(asset_archive),
        'asset_archive_bytes': len(asset_archive),
        'executable_sha256': sha256(executable.read_bytes()),
        'executable_bytes': executable.stat().st_size,
        'selected_fd40_authority_consumer': False,
        'selected_fd62_output_authority': False,
        'network_or_filesystem_imports_after_exec': False,
        'runtime_loader_absent': True,
        'dynamic_runtime_dependencies': [],
    }
    (args.output / 'build-receipt.json').write_bytes(
        canonical_json(receipt))
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
