#!/usr/bin/env python3
"""Canonical source/runtime identities for privacy diagnostics.

The v1 role manifests below make repository-local Python import drift fail
closed for the current diagnostic workers. They are not a complete actual
producer/build/runtime closure and must never be promoted as one: C/C++ and
JavaScript call sites, subprocess/assets, build products, the loader, shared
libraries, and kernel identity require the separately verified v2 manifest.
"""
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat


HERE = Path(__file__).absolute().parent
# Flat legacy namespaces import this module from /software.  Repository-only
# dependency discovery is needed on the host and in the preserved v2 layout,
# but must not make a v1 worker import fail before it reaches its own checks.
REPOSITORY = HERE.parents[2] if len(HERE.parents) > 2 else None
NAMESPACE_SOURCE_ROOT = Path(
    '/repo/poc/local-private-payment/private_batch_trial')
ROOT_GUARD = Path('/var/tmp/kpi-root-guard-helper-09.py')
PYTHON_RUNTIME = Path('/usr/bin/python3')
NAMESPACE_TOOL = Path('/usr/bin/bwrap')
HOST_RUNTIME_TRUST_BOUNDARY = (
    'LINUX_KERNEL_DYNAMIC_LOADER_AND_SYSTEM_LIBRARIES_'
    'TRUSTED_NOT_REPRODUCIBLY_PINNED'
)

ACTUAL_CLOSURE_SCHEMA = (
    'kpb-selected-multilanguage-source-build-runtime-closure/v1')
ACTUAL_CLOSURE_FIELDS = (
    'schema', 'source_search_roots', 'entrypoints', 'members', 'edges',
    'source_identity_sha256', 'build_identity_sha256',
    'runtime_identity_sha256', 'closure_identity_sha256',
)
ACTUAL_MEMBER_FIELDS = (
    'id', 'scope', 'path', 'kind', 'bytes', 'sha256')
ACTUAL_EDGE_FIELDS = ('consumer', 'dependency', 'kind')
ACTUAL_KINDS = {
    'source': {
        'python', 'cpp', 'c', 'cpp-header', 'c-header', 'javascript',
        'json', 'shell', 'asset', 'build-policy',
    },
    'build': {
        'executable', 'launcher', 'shared-library', 'static-library',
        'object', 'build-receipt', 'build-log',
    },
    'runtime': {
        'interpreter', 'namespace-tool', 'dynamic-loader',
        'shared-library', 'system-executable', 'root-guard',
        'kernel-image', 'kernel-config', 'kernel-identity',
    },
}
ACTUAL_EDGE_KINDS = {
    'python-import', 'cpp-include', 'javascript-import',
    'asset-read', 'subprocess-exec', 'compiled-from', 'generated-from',
    'launch-plan-for', 'linked-with', 'build-receipt', 'interpreter', 'namespace-tool',
    'loader', 'shared-library', 'root-guard', 'kernel',
}
STATIC_EDGE_KINDS = {
    'python-import', 'cpp-include', 'javascript-import'}
ACTUAL_ROLE_SELECTION_SCHEMA = 'kpb-selected-capture-role-closure/v2'
ACTUAL_ROLE_SELECTION_FIELDS = (
    'schema', 'classification', 'actual_closure_sha256',
    'authority_entrypoints', 'authority_sources', 'roles',
    'role_closure_identity_sha256')
ACTUAL_AUTHORITY_ENTRYPOINTS = (
    'outer-supervisor', 'capture-producer', 'actual-capture-worker',
    'diagnostic-launcher', 'owner-comparison-launcher')
ACTUAL_ROLE_FIELDS = (
    'round', 'kind', 'role', 'fixed_fd', 'source_member', 'build_member',
    'launch_plan_member')
ACTUAL_CHANNEL_ORDER = tuple(
    (round_number, kind) for round_number in (1, 2) for kind in (
        'public-projection', 'terminal-history', 'dispatcher-capture',
        'corrupt-server-capture', 'colluder-wallet-capture'))
ACTUAL_ROLE_BY_KIND = {
    'public-projection': 'financial-release',
    'terminal-history': 'terminal-controller',
    'dispatcher-capture': 'private-dispatcher',
    'corrupt-server-capture': 'server-P1',
    'colluder-wallet-capture': 'owner-C1',
}

ROLE_MEMBERS = {
    'acceptance': (
        'privacy_acceptance.py', 'privacy_owner_comparison_launch.py',
        'privacy_owner_comparison.py', 'privacy_codec.py',
        'privacy_source_closure.py'),
    'bundle': (
        'privacy_capture_bundle.py', 'privacy_acceptance.py',
        'privacy_actual_capture_launch.py', 'privacy_actual_capture.py',
        'privacy_launch.py',
        'privacy_owner_comparison_launch.py',
        'privacy_owner_comparison.py',
        'privacy_capture_model.py', 'privacy_fd40_archive.py',
        'privacy_fd40_structural.py', 'privacy_public_state.py',
        'privacy_observer.py',
        'privacy_codec.py', 'wallet_profile.py', 'fresh_self_payout.py',
        'exit_wire.py', '../verification/wire.py',
        '../../future-recipient/v2/recipient.py',
        'privacy_source_closure.py'),
    'observer': (
        'privacy_roles.py', 'privacy_codec.py',
        'privacy_capture_model.py', 'privacy_fd40_archive.py',
        'privacy_fd40_structural.py', 'privacy_public_state.py',
        'privacy_observer.py',
        'privacy_owner.py', 'wallet_profile.py', 'private_worker.py',
        'output_producer.py', 'fresh_self_payout.py', 'exit_wire.py',
        '../../future-recipient/v2/recipient.py',
        '../verification/wire.py',
        'privacy_source_closure.py'),
    'diagnostic-launcher': (
        'privacy_launch.py', 'privacy_roles.py', 'privacy_codec.py',
        'privacy_capture_model.py', 'privacy_fd40_archive.py',
        'privacy_fd40_structural.py', 'privacy_public_state.py',
        'privacy_observer.py',
        'privacy_owner.py', 'wallet_profile.py', 'private_worker.py',
        'output_producer.py', 'fresh_self_payout.py', 'exit_wire.py',
        '../../future-recipient/v2/recipient.py',
        '../verification/wire.py',
        'privacy_source_closure.py'),
    'owner-comparison': (
        'privacy_owner_comparison.py', 'privacy_acceptance.py',
        'privacy_owner_comparison_launch.py',
        'privacy_codec.py', 'privacy_source_closure.py'),
    'owner-comparison-launcher': (
        'privacy_owner_comparison_launch.py',
        'privacy_owner_comparison.py', 'privacy_acceptance.py',
        'privacy_codec.py', 'privacy_source_closure.py'),
    'actual-capture': (
        'privacy_actual_capture.py', 'privacy_capture_model.py',
        'privacy_fd40_archive.py', 'privacy_fd40_structural.py',
        'privacy_public_state.py',
        'privacy_codec.py', 'privacy_observer.py',
        'wallet_profile.py', 'fresh_self_payout.py', 'exit_wire.py',
        '../../future-recipient/v2/recipient.py',
        '../verification/wire.py',
        'privacy_source_closure.py',
        '../mpc-prover/financial/qualify_public_release.py'),
    'actual-capture-launcher': (
        'privacy_actual_capture_launch.py', 'privacy_actual_capture.py',
        'privacy_capture_model.py', 'privacy_fd40_archive.py',
        'privacy_fd40_structural.py', 'privacy_public_state.py',
        'privacy_codec.py',
        'privacy_observer.py', 'wallet_profile.py',
        'fresh_self_payout.py', 'exit_wire.py',
        '../../future-recipient/v2/recipient.py',
        '../verification/wire.py',
        'privacy_source_closure.py',
        '../mpc-prover/financial/qualify_public_release.py'),
    # This source is deliberately source-only today.  Keeping it in the
    # canonical closure prevents a future actual receipt from silently
    # substituting a different producer while the rest of the privacy chain
    # still carries an older closure map.
    'capture-producer': (
        'privacy_capture_producer.py', 'privacy_capture_hook.hpp',
        'privacy_capture_hook.cpp', 'privacy_capture_private_hook.hpp',
        'privacy_capture_private_hook.cpp',
        'privacy_source_closure.py'),
}


def need(condition, category):
    if not condition:
        raise ValueError('privacy-source-closure-' + category)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def word(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
         'canonical-word')
    return value


def digest_path(path):
    path = Path(path)
    need(path.is_absolute() and path.is_file() and not path.is_symlink(),
         'fixed-regular-source')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _path_expression(node):
    """Resolve the finite Path expressions used by local dynamic imports."""
    if isinstance(node, ast.Name) and node.id == 'HERE':
        return HERE
    if isinstance(node, ast.Attribute) and node.attr == 'parent':
        base = _path_expression(node.value)
        return None if base is None else base.parent
    if isinstance(node, ast.Subscript) \
            and isinstance(node.value, ast.Attribute) \
            and node.value.attr == 'parents' \
            and isinstance(node.slice, ast.Constant) \
            and type(node.slice.value) is int:
        base = _path_expression(node.value.value)
        if base is None or node.slice.value < 0 \
                or node.slice.value >= len(base.parents):
            return None
        return base.parents[node.slice.value]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) \
            and isinstance(node.right, ast.Constant) \
            and type(node.right.value) is str:
        base = _path_expression(node.left)
        return None if base is None else base / node.right.value
    return None


def _local_imports(name):
    """Return repository-local Python dependencies imported by one member."""
    if not name.endswith('.py'):
        return set()
    path = (HERE / name).resolve()
    if REPOSITORY is None or not path.is_relative_to(REPOSITORY.resolve()):
        return set()
    tree = ast.parse(path.read_bytes(), filename=name)
    candidates = set()
    for node in ast.walk(tree):
        modules = []
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 \
                and node.module:
            modules.append(node.module)
            modules.extend(node.module + '.' + alias.name
                           for alias in node.names if alias.name != '*')
        for module in modules:
            relative = Path(*module.split('.'))
            for candidate in (relative.with_suffix('.py'),
                              relative / '__init__.py'):
                if (HERE / candidate).is_file():
                    candidates.add(str(candidate))
        if isinstance(node, ast.Call) and len(node.args) >= 2 \
                and isinstance(node.func, ast.Attribute) \
                and node.func.attr == 'spec_from_file_location':
            target = _path_expression(node.args[1])
            if REPOSITORY is not None and target is not None \
                    and target.resolve().is_file() \
                    and target.resolve().is_relative_to(
                        REPOSITORY.resolve()):
                candidates.add(os.path.relpath(target.resolve(), HERE.resolve()))
    return candidates


def transitive_missing(role):
    """Expose deterministic missing imports for controls and diagnostics."""
    need(role in ROLE_MEMBERS, 'known-role')
    declared = set(ROLE_MEMBERS[role])
    imported = set()
    for name in ROLE_MEMBERS[role]:
        imported.update(_local_imports(name))
    return tuple(sorted(imported - declared))


def require_transitive(role):
    need(not transitive_missing(role), 'incomplete-' + role + '-closure')


def manifest(role):
    need(role in ROLE_MEMBERS, 'known-role')
    require_transitive(role)
    return {
        'schema': 'kpb-transitive-source-closure/v1',
        'role': role,
        'members': [
            {'name': name, 'sha256': digest_path(HERE / name)}
            for name in ROLE_MEMBERS[role]
        ],
    }


def digest(role):
    return hashlib.sha256(encoded(manifest(role))).hexdigest()


def all_digests():
    return {role: digest(role) for role in ROLE_MEMBERS}


def validate_manifest(value, role):
    need(value == manifest(role), 'exact-' + role + '-manifest')
    return value


def _relative(value, category, *, dot=False):
    need(type(value) is str and value != '' and '\\' not in value,
         'actual-' + category + '-relative')
    path = PurePosixPath(value)
    need(not path.is_absolute()
         and (dot or value != '.')
         and (value == '.' or
              all(part not in ('', '.', '..') for part in path.parts))
         and str(path) == value,
         'actual-' + category + '-relative')
    return value


def _root(root, scope):
    root = Path(root)
    need(root.is_absolute() and root.is_dir() and not root.is_symlink(),
         'actual-' + scope + '-root')
    return root


def _fd_signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_gid, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _directory_fd(root, relative):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(root, flags)
    try:
        if relative != '.':
            for part in PurePosixPath(relative).parts:
                next_fd = os.open(part, flags, dir_fd=fd)
                os.close(fd); fd = next_fd
        need(stat.S_ISDIR(os.fstat(fd).st_mode),
             'actual-member-directory')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_under(root, relative, expected_bytes):
    parts = PurePosixPath(relative).parts
    parent = _directory_fd(
        root, '.' if len(parts) == 1 else str(PurePosixPath(*parts[:-1])))
    try:
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                 'actual-member-type')
            need(before.st_size == expected_bytes, 'actual-member-bytes')
            chunks = []
            remaining = expected_bytes
            while remaining:
                block = os.read(fd, min(remaining, 1 << 20))
                need(block, 'actual-member-complete-read')
                chunks.append(block); remaining -= len(block)
            need(os.read(fd, 1) == b''
                 and _fd_signature(before) == _fd_signature(os.fstat(fd)),
                 'actual-member-stable-read')
            return b''.join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _enumerate_regular_files(root, relative):
    """Enumerate a no-symlink selected source subtree via directory FDs."""
    result = set()
    base = '' if relative == '.' else relative

    def visit(fd, prefix):
        with os.scandir(fd) as scanned:
            entries = sorted(scanned, key=lambda entry: entry.name)
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            need(not stat.S_ISLNK(info.st_mode),
                 'actual-source-snapshot-no-alias')
            name = posixpath.join(prefix, entry.name) if prefix else entry.name
            if stat.S_ISDIR(info.st_mode):
                child = os.open(entry.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                    os.O_CLOEXEC, dir_fd=fd)
                try: visit(child, name)
                finally: os.close(child)
            else:
                need(stat.S_ISREG(info.st_mode),
                     'actual-source-snapshot-regular')
                result.add(name)

    directory = _directory_fd(root, relative)
    try: visit(directory, base)
    finally: os.close(directory)
    return result


def _candidate_paths(current, spec, suffixes, search_roots,
                     available_source_paths):
    """Resolve a repository-local import/include without host search paths."""
    if not spec or spec.startswith('/'):
        return set()
    bases = []
    current_parent = str(PurePosixPath(current).parent)
    for base in (current_parent, *search_roots):
        combined = posixpath.normpath(posixpath.join(base, spec))
        if combined == '..' or combined.startswith('../'):
            continue
        bases.append(combined)
    candidates = set()
    for base in bases:
        forms = [base]
        if not PurePosixPath(base).suffix:
            forms.extend(base + suffix for suffix in suffixes)
            forms.extend(posixpath.join(base, 'index' + suffix)
                         for suffix in suffixes)
            forms.append(posixpath.join(base, '__init__.py'))
        candidates.update(form for form in forms
                          if form in available_source_paths)
    need(len(candidates) <= 1, 'actual-ambiguous-local-dependency')
    return candidates


def _python_dependencies(path, raw, search_roots, available_source_paths):
    tree = ast.parse(raw, filename=path)
    result = set()

    def resolve(module, current=path):
        if not module:
            return
        result.update(_candidate_paths(
            current, module.replace('.', '/'), ('.py',),
            search_roots, available_source_paths))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                resolve(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parent = PurePosixPath(path).parent
                for _ in range(node.level - 1):
                    parent = parent.parent
                base = str(parent / (node.module or '').replace('.', '/'))
                resolve(base, '.')
                for alias in node.names:
                    if alias.name != '*':
                        resolve(posixpath.join(base, alias.name), '.')
            elif node.module:
                resolve(node.module)
                for alias in node.names:
                    if alias.name != '*':
                        resolve(node.module + '.' + alias.name)
    return result


def _cpp_dependencies(path, raw, search_roots, available_source_paths):
    text = raw.decode('utf-8')
    result = set()
    for spec in re.findall(r'^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]',
                           text, flags=re.MULTILINE):
        result.update(_candidate_paths(
            path, spec, ('.h', '.hpp', '.hh', '.inc'),
            search_roots, available_source_paths))
    return result


def _javascript_dependencies(path, raw, search_roots,
                             available_source_paths):
    text = raw.decode('utf-8')
    specs = set(re.findall(
        r'(?:\bfrom\s+|\brequire\s*\(|\bimport\s*\()'
        r'[\"\']([^\"\']+)[\"\']', text))
    specs.update(re.findall(
        r'\bimport\s*[\"\']([^\"\']+)[\"\']', text))
    result = set()
    for spec in specs:
        result.update(_candidate_paths(
            path, spec, ('.js', '.mjs', '.cjs', '.json'),
            search_roots, available_source_paths))
    return result


def _identity(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def validate_actual_closure(value, expected_sha256, roots):
    """Verify one externally selected, finite actual execution closure.

    ``expected_sha256`` and the three roots must come from the future outer
    supervisor, not from the manifest. Every listed byte is re-read and every
    local Python/C/C++/JavaScript dependency is independently rediscovered.
    Explicit asset/subprocess/build/runtime edges are graph-closed and hashed;
    the verifier does not infer authority from the manifest itself.
    """
    need(type(value) is dict and set(value) == set(ACTUAL_CLOSURE_FIELDS),
         'actual-fields')
    need(value['schema'] == ACTUAL_CLOSURE_SCHEMA,
         'actual-schema')
    need(word(expected_sha256) == hashlib.sha256(encoded(value)).hexdigest(),
         'actual-outer-selected-manifest')
    need(type(roots) is dict and set(roots) == {'source', 'build', 'runtime'},
         'actual-roots')
    trusted_roots = {scope: _root(roots[scope], scope)
                     for scope in ('source', 'build', 'runtime')}

    search_roots = value['source_search_roots']
    need(type(search_roots) is list and search_roots == sorted(set(search_roots))
         and search_roots, 'actual-search-roots')
    for item in search_roots:
        _relative(item, 'search-root', dot=True)
        directory_fd = _directory_fd(trusted_roots['source'], item)
        os.close(directory_fd)
    available_source_paths = set()
    for item in search_roots:
        available_source_paths.update(
            _enumerate_regular_files(trusted_roots['source'], item))

    members = value['members']
    need(type(members) is list and members, 'actual-members')
    by_id = {}
    for member in members:
        need(type(member) is dict
             and set(member) == set(ACTUAL_MEMBER_FIELDS),
             'actual-member-fields')
        scope = member['scope']
        need(scope in ACTUAL_KINDS and member['kind'] in ACTUAL_KINDS[scope],
             'actual-member-kind')
        path = _relative(member['path'], 'member-path')
        identifier = scope + ':' + path
        need(member['id'] == identifier and identifier not in by_id,
             'actual-member-id')
        need(type(member['bytes']) is int and member['bytes'] >= 0,
             'actual-member-bytes')
        raw = _read_under(trusted_roots[scope], path, member['bytes'])
        need(member['bytes'] == len(raw)
             and word(member['sha256']) == hashlib.sha256(raw).hexdigest(),
             'actual-member-bytes')
        by_id[identifier] = (member, raw)
        if scope == 'source':
            need(path in available_source_paths,
                 'actual-source-member-outside-search-roots')
    need([row['id'] for row in members] == sorted(by_id),
         'actual-member-order')

    edges = value['edges']
    need(type(edges) is list, 'actual-edges')
    edge_keys = []
    for edge in edges:
        need(type(edge) is dict and set(edge) == set(ACTUAL_EDGE_FIELDS),
             'actual-edge-fields')
        key = (edge['consumer'], edge['dependency'], edge['kind'])
        need(edge['consumer'] in by_id and edge['dependency'] in by_id
             and edge['consumer'] != edge['dependency']
             and edge['kind'] in ACTUAL_EDGE_KINDS,
             'actual-edge')
        edge_keys.append(key)
    need(edge_keys == sorted(set(edge_keys)), 'actual-edge-order')

    entrypoints = value['entrypoints']
    need(type(entrypoints) is list and entrypoints
         and entrypoints == sorted(set(entrypoints))
         and all(item in by_id for item in entrypoints),
         'actual-entrypoints')
    adjacency = {identifier: set() for identifier in by_id}
    for consumer, dependency, _ in edge_keys:
        adjacency[consumer].add(dependency)
    reached = set(entrypoints)
    pending = list(entrypoints)
    while pending:
        for dependency in adjacency[pending.pop()]:
            if dependency not in reached:
                reached.add(dependency); pending.append(dependency)
    need(reached == set(by_id), 'actual-transitive-graph')

    expected_static = set()
    for identifier, (member, raw) in by_id.items():
        if member['scope'] != 'source':
            continue
        kind = member['kind']
        if kind == 'python':
            dependencies = _python_dependencies(
                member['path'], raw, search_roots,
                available_source_paths)
            edge_kind = 'python-import'
        elif kind in ('cpp', 'c', 'cpp-header', 'c-header'):
            dependencies = _cpp_dependencies(
                member['path'], raw, search_roots,
                available_source_paths)
            edge_kind = 'cpp-include'
        elif kind == 'javascript':
            dependencies = _javascript_dependencies(
                member['path'], raw, search_roots,
                available_source_paths)
            edge_kind = 'javascript-import'
        else:
            continue
        expected_static.update(
            (identifier, 'source:' + dependency, edge_kind)
            for dependency in dependencies)
    actual_static = {key for key in edge_keys if key[2] in STATIC_EDGE_KINDS}
    need(actual_static == expected_static,
         'actual-independent-static-dependency-closure')

    source_kinds = {row['kind'] for row in members
                    if row['scope'] == 'source'}
    build_kinds = {row['kind'] for row in members
                   if row['scope'] == 'build'}
    runtime_kinds = {row['kind'] for row in members
                     if row['scope'] == 'runtime'}
    present_edges = {row['kind'] for row in edges}
    need('python' in source_kinds
         and bool(source_kinds & {'cpp', 'c'})
         and 'javascript' in source_kinds and 'asset' in source_kinds
         and 'build-receipt' in build_kinds
         and {'dynamic-loader', 'shared-library', 'kernel-identity'} <=
             runtime_kinds
         and {'asset-read', 'subprocess-exec', 'compiled-from',
              'build-receipt', 'loader', 'shared-library', 'kernel'} <=
             present_edges,
         'actual-required-multilanguage-build-runtime-coverage')

    source_members = [row for row in members if row['scope'] == 'source']
    build_members = [row for row in members if row['scope'] == 'build']
    runtime_members = [row for row in members if row['scope'] == 'runtime']
    source_edges = [row for row in edges
                    if row['consumer'].startswith('source:')]
    build_edges = [row for row in edges
                   if row['consumer'].startswith('build:')]
    runtime_edges = [row for row in edges
                     if row['consumer'].startswith('runtime:')
                     or row['dependency'].startswith('runtime:')]
    source_identity = _identity({
        'schema': ACTUAL_CLOSURE_SCHEMA,
        'source_search_roots': search_roots,
        'members': source_members, 'edges': source_edges})
    build_identity = _identity({
        'schema': ACTUAL_CLOSURE_SCHEMA,
        'source_identity_sha256': source_identity,
        'members': build_members, 'edges': build_edges})
    runtime_identity_value = _identity({
        'schema': ACTUAL_CLOSURE_SCHEMA,
        'build_identity_sha256': build_identity,
        'members': runtime_members, 'edges': runtime_edges})
    closure_payload = {
        'schema': ACTUAL_CLOSURE_SCHEMA,
        'source_search_roots': search_roots,
        'entrypoints': entrypoints, 'members': members, 'edges': edges,
        'source_identity_sha256': source_identity,
        'build_identity_sha256': build_identity,
        'runtime_identity_sha256': runtime_identity_value,
    }
    closure_identity = _identity(closure_payload)
    need(value['source_identity_sha256'] == source_identity
         and value['build_identity_sha256'] == build_identity
         and value['runtime_identity_sha256'] == runtime_identity_value
         and value['closure_identity_sha256'] == closure_identity,
         'actual-recomputed-identities')
    return value


def validate_actual_role_selection(value, manifest, expected_manifest_sha256,
                                   roots):
    """Bind all capture call sites to members of one verified actual closure.

    The v2 role selection contains member identifiers, never caller-authored
    source/build/launch digest words. The parent authority must first verify
    the full manifest, then consume this derived role identity once.
    """
    validate_actual_closure(manifest, expected_manifest_sha256, roots)
    need(type(value) is dict
         and set(value) == set(ACTUAL_ROLE_SELECTION_FIELDS),
         'actual-role-fields')
    need(value['schema'] == ACTUAL_ROLE_SELECTION_SCHEMA
         and value['classification'] in (
             'ACTUAL_TRANSPARENT_BASELINE',
             'ACTUAL_HIDDEN_MAPPING_CANDIDATE')
         and value['actual_closure_sha256'] == expected_manifest_sha256,
         'actual-role-schema')
    members = {row['id']: row for row in manifest['members']}
    adjacency = {identifier: set() for identifier in members}
    typed_edges = set()
    for edge in manifest['edges']:
        adjacency[edge['consumer']].add(edge['dependency'])
        typed_edges.add((edge['consumer'], edge['dependency'], edge['kind']))

    def reaches(start, target):
        seen = {start}; pending = [start]
        while pending:
            current = pending.pop()
            if current == target:
                return True
            for dependency in adjacency[current]:
                if dependency not in seen:
                    seen.add(dependency); pending.append(dependency)
        return False

    authority = value['authority_entrypoints']
    authority_sources = value['authority_sources']
    need(type(authority) is dict
         and tuple(sorted(authority)) ==
            tuple(sorted(ACTUAL_AUTHORITY_ENTRYPOINTS))
         and len(set(authority.values())) == len(authority),
         'actual-authority-entrypoints')
    need(type(authority_sources) is dict
         and tuple(sorted(authority_sources)) ==
            tuple(sorted(ACTUAL_AUTHORITY_ENTRYPOINTS))
         and len(set(authority_sources.values())) == len(authority_sources),
         'actual-authority-sources')
    outer = authority['outer-supervisor']
    need(outer in manifest['entrypoints'], 'actual-outer-entrypoint')
    for name in ACTUAL_AUTHORITY_ENTRYPOINTS:
        identifier = authority[name]
        source_identifier = authority_sources[name]
        source = members.get(source_identifier)
        need(identifier in members
             and members[identifier]['scope'] == 'build'
             and members[identifier]['kind'] in ('launcher', 'executable')
             and reaches(outer, identifier)
             and (identifier == outer or
                  (outer, identifier, 'subprocess-exec') in typed_edges)
             and source is not None and source['scope'] == 'source'
             and source['kind'] in (
                 'python', 'cpp', 'c', 'javascript', 'shell')
             and ((identifier, source_identifier, 'compiled-from') in
                  typed_edges
                  or (identifier, source_identifier, 'generated-from') in
                  typed_edges),
             'actual-authority-entrypoint-' + name)

    roles = value['roles']
    need(type(roles) is list and len(roles) == len(ACTUAL_CHANNEL_ORDER),
         'actual-role-count')
    by_kind = {}
    for index, (row, expected) in enumerate(zip(roles,
                                                ACTUAL_CHANNEL_ORDER)):
        need(type(row) is dict and set(row) == set(ACTUAL_ROLE_FIELDS),
             'actual-role-row-fields')
        need(row['round'] == expected[0] and row['kind'] == expected[1]
             and row['role'] == ACTUAL_ROLE_BY_KIND[expected[1]]
             and row['fixed_fd'] == 20 + index,
             'actual-role-fixed-map')
        source = members.get(row['source_member'])
        build = members.get(row['build_member'])
        plan = members.get(row['launch_plan_member'])
        need(source is not None and source['scope'] == 'source'
             and source['kind'] in (
                 'python', 'cpp', 'c', 'javascript', 'shell')
             and build is not None and build['scope'] == 'build'
             and build['kind'] in (
                 'executable', 'launcher', 'shared-library')
             and plan is not None
             and ((plan['scope'] == 'source'
                   and plan['kind'] in (
                       'build-policy', 'json', 'python', 'shell'))
                  or (plan['scope'] == 'build'
                      and plan['kind'] in ('launcher', 'executable')))
             and reaches(outer, row['launch_plan_member'])
             and reaches(outer, row['build_member'])
             and ((outer, row['launch_plan_member'], 'asset-read') in
                  typed_edges
                  or (outer, row['launch_plan_member'],
                      'subprocess-exec') in typed_edges)
             and (row['launch_plan_member'], row['build_member'],
                  'launch-plan-for') in typed_edges
             and ((row['build_member'], row['source_member'],
                   'compiled-from') in typed_edges
                  or (row['build_member'], row['source_member'],
                      'generated-from') in typed_edges),
             'actual-role-member-closure')
        identity = (row['source_member'], row['build_member'],
                    row['launch_plan_member'])
        if row['kind'] in by_kind:
            need(by_kind[row['kind']] == identity,
                 'actual-role-cross-round-identity')
        else:
            by_kind[row['kind']] = identity
    need(len({identity[0] for identity in by_kind.values()}) == 5
         and len({identity[2] for identity in by_kind.values()}) == 5,
         'actual-five-distinct-callsite-and-launch-plans')
    role_identity = _identity({
        'schema': ACTUAL_ROLE_SELECTION_SCHEMA,
        'classification': value['classification'],
        'actual_closure_sha256': value['actual_closure_sha256'],
        'authority_entrypoints': authority,
        'authority_sources': authority_sources,
        'roles': roles,
    })
    need(value['role_closure_identity_sha256'] == role_identity,
         'actual-recomputed-role-identity')
    return value


def require_selected_actual_closure():
    """Fail until an outer supervisor selects a real v2 manifest/build."""
    need(False, 'actual-multilanguage-build-runtime-selection-absent')


def actual_closure_source_status():
    """Report necessary format work without implying executable authority."""
    return {
        'schema': 'kpb-actual-closure-source-status/v1',
        'status': 'CONFIGURED0_UNQUALIFIED',
        'manifest_bytes_and_static_graph_validated': True,
        'role_members_bound_without_caller_digest_words': True,
        'parent_sealed_snapshot_consumed_by_launch': False,
        'dynamic_import_asset_exec_dlopen_instrumented': False,
        'build_recipe_flags_outputs_verified': False,
        'elf_interpreter_and_runtime_graph_resolved': False,
        'running_kernel_identity_attested': False,
        'outer_supervisor_completion_authority': False,
        'actual_authority': False,
    }


def runtime_identity(root_guard_source=None):
    """Hash runtime members, optionally through a namespace-mounted helper.

    The returned identity retains the canonical host path so its aggregate
    digest is identical inside and outside the namespace.  Only the bytes may
    be supplied through a different, explicitly mounted path.
    """
    root_guard_source = (ROOT_GUARD if root_guard_source is None else
                         Path(root_guard_source))
    need(PYTHON_RUNTIME.exists() and NAMESPACE_TOOL.exists()
         and root_guard_source.exists() and root_guard_source.is_file()
         and not root_guard_source.is_symlink(), 'runtime-member-present')
    return {
        'schema': 'kpb-privacy-runtime-identity/v1',
        'python_path': str(PYTHON_RUNTIME),
        'python_runtime_sha256': hashlib.sha256(
            PYTHON_RUNTIME.read_bytes()).hexdigest(),
        'namespace_tool_path': str(NAMESPACE_TOOL),
        'namespace_tool_sha256': hashlib.sha256(
            NAMESPACE_TOOL.read_bytes()).hexdigest(),
        'root_guard_helper_path': str(ROOT_GUARD),
        'root_guard_helper_sha256': hashlib.sha256(
            root_guard_source.read_bytes()).hexdigest(),
        'host_runtime_trust_boundary': HOST_RUNTIME_TRUST_BOUNDARY,
    }


def runtime_digest():
    return hashlib.sha256(encoded(runtime_identity())).hexdigest()
