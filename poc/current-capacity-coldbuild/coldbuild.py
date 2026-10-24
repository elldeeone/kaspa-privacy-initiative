#!/usr/bin/env python3
"""Rebuild only the externally selected current public private-prover source."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import time
import tomllib

SOURCE = 'c341fbfbce61ce9d3bf1f198a8ef8be800416d3d99f9910dc0bd0ff0b10160b3'
INVENTORY = 'ee5d1be3c54b6a308daf655c3d4b2cad1465a14ed7b5ec856f089ec595230b17'
SELECTED = '4ef4fc4f6290bc1c5472e732e118476b6ad20b692438c0957e27cf3f6bc00621'
ROLE = 'd6f0e2bbafab39a72106ef0a0ebd6483362a858926117721a8be5aa37a459011'
BUILD = 'fcf6e8c757613e6fea9a5dd776727f1c2456865f1185c545ac9751ef9fb26419'
DOMAIN = 'd55d006a9bb253963db4f4e44495e60333df9fcc83c1c3ae220806d0f326a0bb'
VK = '074c06a5f21f46c7c87a948c8ca6a0896198cc9fc255b8d5e08cc01ceb73a987'
ARCHIVE = '17654e748f4c03542646af9d782279cc4e1bd040d5bc97eb0493796515632a46'
OLD_INVENTORY = 'd8f96ce9f133d846b94ad5219f45d8664acba8972355fccd2d27b3315a06b808'
TOOLCHAIN = Path('/home/luke/.rustup/toolchains/stable-x86_64-unknown-linux-gnu')
REGISTRY = '/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f'
PREFIX = 'poc/private-exit-stress/prover/'


def need(ok, code):
    if not ok:
        raise ValueError(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b'\n'


def relative(name):
    need(type(name) is str and name and '\\' not in name and '\0' not in name,
         'relative-path')
    path = PurePosixPath(name)
    need(not path.is_absolute() and path.as_posix() == name
         and all(p not in ('', '.', '..') for p in path.parts), 'relative-path')
    return name


def public(path, size=None, expected=None):
    path = Path(path).absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'public-symlink')
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and (size is None or before.st_size == size),
         'public-regular-size')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as file:
        opened = os.fstat(file.fileno())
        need((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino),
             'public-replaced')
        raw = file.read()
        after = os.fstat(file.fileno())
    need((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
         == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
         and len(raw) == opened.st_size, 'public-mutated')
    need(expected is None or hashlib.sha256(raw).hexdigest() == expected, 'public-digest')
    return raw


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'json-constant'))


def save(root, name, value):
    (root / name).write_bytes(encoded(value))


def copy_bytes(root, name, raw):
    path = root / relative(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as file:
        file.write(raw)
    return {'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def prepare_current(assets, source):
    freeze_raw = public(assets / 'current-prover-source-freeze.json', 3754, SOURCE)
    inventory_raw = public(assets / 'current-software-source-inventory.json', 5331, INVENTORY)
    freeze, inventory = parse(freeze_raw), parse(inventory_raw)
    need(freeze['schema'] == 'kpx-capacity-selected-prover-source-freeze/v1'
         and len(freeze['files']) == 19, 'current-source-schema')
    need(inventory['schema'] == 'kpi-current-cap-public-software-source-inventory/v1'
         and inventory['source_freeze_sha256'] == SOURCE
         and inventory['selected_prover_sha256'] == SELECTED
         and inventory['role_manifest_sha256'] == ROLE
         and inventory['domain_hex32'] == DOMAIN
         and len(inventory['files']) == 19, 'current-inventory-schema')
    index = {}
    for row in inventory['files']:
        name = relative(row['path'])
        need(name not in index and name.startswith(PREFIX), 'current-source-path')
        relative(row['asset_basename'])
        need('/' not in row['asset_basename'], 'current-asset-basename')
        index[name] = row
    copied = []
    seen = set()
    for row in freeze['files']:
        name = relative(row['path'])
        need(name not in seen and name in index, 'current-source-membership')
        seen.add(name)
        other = index[name]
        need(row['sha256'] == other['sha256'] and row['bytes'] == other['bytes']
             and type(row['bytes']) is int and row['bytes'] >= 0, 'current-source-join')
        raw = public(assets / other['asset_basename'], row['bytes'], row['sha256'])
        copied.append(copy_bytes(source, name.removeprefix(PREFIX), raw))
    role = parse(public(source / 'pins/compact2/public-parameters.json', expected=ROLE))
    need(role['compiled_build_identity_sha256'] == BUILD and role['domain_hex32'] == DOMAIN
         and role['vk_sha256'] == VK and role['role'] == 'compact2', 'current-role-identity')
    public(source / 'pins/compact2/verification-key.bin', 328, VK)
    return copied


def dependencies(archive, old_inventory, source, vendor):
    old_raw = public(old_inventory, expected=OLD_INVENTORY)
    old = parse(old_raw)
    need(old['schema'] == 'kpx4-public-software-bundle/v1', 'old-dependency-inventory')
    lock = tomllib.loads(public(source / 'Cargo.lock').decode())
    packages = {}
    for row in lock['package']:
        if 'source' not in row:
            continue
        need(row['source'] == 'registry+https://github.com/rust-lang/crates.io-index'
             and re.fullmatch('[0-9a-f]{64}', row['checksum']), 'current-lock-source')
        folder = relative(row['name'] + '-' + row['version'])
        need('/' not in folder and folder not in packages, 'current-lock-package')
        packages[folder] = row['checksum']
    need(len(packages) == 148, 'current-registry-package-count')
    selected = {}
    for row in old['files']:
        name = relative(row['path'])
        parts = PurePosixPath(name).parts
        if len(parts) >= 3 and parts[0] == 'vendor' and parts[1] in packages:
            need(row['kind'] == 'cargo-vendor' and name not in selected,
                 'dependency-inventory-entry')
            selected[name] = row
    need(selected, 'dependency-files-missing')
    # Entire immutable public archive authenticated before decompression.
    public(archive, 66501581, ARCHIVE)
    seen = set()
    decoder = subprocess.Popen(['/usr/bin/zstd', '-dc', str(archive)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=decoder.stdout, mode='r|') as tar:
            for member in tar:
                # Never extract/import old programs/config/source; read only selected dependencies.
                if member.name not in selected:
                    continue
                row = selected[member.name]
                need(member.name not in seen and member.isfile() and not member.issym()
                     and not member.islnk() and member.size == row['bytes'], 'dependency-tar-member')
                seen.add(member.name)
                file = tar.extractfile(member)
                need(file is not None, 'dependency-tar-read')
                raw = file.read()
                need(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
                     'dependency-file-digest')
                copy_bytes(vendor, member.name.removeprefix('vendor/'), raw)
        need(decoder.wait() == 0, 'dependency-decompression')
    finally:
        if decoder.poll() is None:
            decoder.kill()
        decoder.stdout.close()
        decoder.stderr.close()
        decoder.wait()
    need(seen == set(selected), 'dependency-tar-coverage')
    checked = 0
    for folder, expected in sorted(packages.items()):
        checksum = parse(public(vendor / folder / '.cargo-checksum.json'))
        need(set(checksum) == {'files', 'package'} and checksum['package'] == expected,
             'current-lock-registry-checksum')
        names = {f'vendor/{folder}/.cargo-checksum.json'}
        for name, digest in checksum['files'].items():
            relative(name)
            public(vendor / folder / name, expected=digest)
            names.add(f'vendor/{folder}/{name}')
            checked += 1
        need(names == {name for name in selected if name.startswith('vendor/' + folder + '/')},
             'dependency-checksum-file-coverage')
    return {'packages': len(packages), 'files_copied': len(selected),
            'package_content_files_checked': checked, 'current_lock_checksums_all_matched': True,
            'old_archive_sha256': ARCHIVE, 'old_inventory_sha256': OLD_INVENTORY,
            'old_program_or_old_source_copied_or_mounted': False}


def inspection(selected):
    raw = public(selected, 3898832, SELECTED)
    prefixes = [REGISTRY + '/', str(TOOLCHAIN) + '/lib/rustlib/src/rust/library/',
                '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/']
    counts = {prefix: raw.count(prefix.encode()) for prefix in prefixes}
    need(all(counts.values()), 'current-embedded-layout-evidence')
    return {'selected_ELF_sha256': SELECTED, 'selected_ELF_bytes': len(raw),
            'static_embedded_public_path_occurrence_counts': counts,
            'selected_ELF_executed': False, 'recipe_uses_observed_registry_and_rust_src_paths': True}


def build(args):
    output = args.output.absolute()
    need(not output.exists() and output.is_absolute(), 'fresh-output')
    output.mkdir(parents=True, mode=0o700)
    started = time.monotonic()
    cgroup = Path('/sys/fs/cgroup') / Path('/proc/self/cgroup').read_text().split(':', 2)[2].strip().lstrip('/')
    caps = {n: (cgroup / n).read_text().strip() for n in ('cpu.max', 'memory.max', 'memory.swap.max')}
    need(caps == {'cpu.max': '400000 100000', 'memory.max': '6442450944',
                  'memory.swap.max': '0'}, 'required-cgroup-caps')
    work = output / 'work'
    source, vendor = work / 'source', output / 'vendor'
    source.mkdir(parents=True)
    vendor.mkdir()
    source_rows = prepare_current(args.assets, source)
    save(output, 'CURRENT-SOURCE-RESTORE.json', {'files': source_rows, 'source_files': 19,
         'source_freeze_sha256': SOURCE, 'current_source_inventory_sha256': INVENTORY,
         'only_selected_current_sources_restored': True})
    save(output, 'SELECTED-ELF-INSPECTION.json', inspection(args.assets / 'current-compact-prover'))
    save(output, 'DEPENDENCIES.json', dependencies(args.archive, args.old_inventory, source, vendor))
    config = source / '.cargo/config.toml'
    config.parent.mkdir()
    config.write_text('[source.crates-io]\nreplace-with = "cold-public-dependencies"\n'
                      '[source.cold-public-dependencies]\ndirectory = "' + REGISTRY + '"\n'
                      '[net]\noffline = true\n')
    (work / 'cargo-home').mkdir()
    (work / 'empty-home').mkdir()
    inside = Path(__file__).with_name('inside.py')
    public(inside)
    tool_rows = {}
    for name, relative_tool in (
        ('cargo', 'bin/cargo'), ('rustc', 'bin/rustc'),
        ('rust-lld', 'lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld'),
    ):
        path = TOOLCHAIN / relative_tool
        raw = public(path)
        tool_rows[name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    rustc_verbose = subprocess.check_output([str(TOOLCHAIN / 'bin/rustc'), '-vV'], text=True)
    environment = {'PATH': str(TOOLCHAIN / 'bin') + ':/usr/bin:/bin', 'LANG': 'C.UTF-8',
        'TZ': 'UTC', 'HOME': '/build/empty-home', 'CARGO_HOME': '/build/cargo-home',
        'CARGO_TARGET_DIR': '/build/target', 'RUSTC': str(TOOLCHAIN / 'bin/rustc'),
        'CARGO_ENCODED_RUSTFLAGS': '', 'CARGO_NET_OFFLINE': 'true', 'RAYON_NUM_THREADS': '4'}
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        '--ro-bind', str(TOOLCHAIN), str(TOOLCHAIN), '--ro-bind', str(vendor), REGISTRY,
        '--bind', str(work), '/build', '--ro-bind', str(inside), '/inside.py', '--chdir', '/build/source']
    for name, value in environment.items():
        command += ['--setenv', name, value]
    command += ['/usr/bin/python3', '-B', '/inside.py']
    save(output, 'BUILD-COMMAND.json', {'command': command, 'environment': environment,
         'tool_hashes': tool_rows, 'rustc_verbose': rustc_verbose,
         'trusted_existing_compiler_toolchain_OS_linker_libc': True,
         'optional_rust_source_visible_at_observed_current_path': True,
         'outer_network_namespace': os.readlink('/proc/self/ns/net')})
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output / 'STDOUT.log').write_bytes(result.stdout)
    (output / 'STDERR.log').write_bytes(result.stderr)
    binary = work / 'target/release/kpi-private-capacity-prover'
    actual = hashlib.sha256(public(binary)).hexdigest() if result.returncode == 0 else None
    report = {'schema': 'kpi-current-capacity-coldsource-build/v1',
         'source_commit': 'ad18b65e1472d904d0528520104936592cda65b7',
         'current_source_freeze_sha256': SOURCE, 'current_source_inventory_sha256': INVENTORY,
         'current_role_manifest_sha256': ROLE, 'current_domain_hex32': DOMAIN,
         'selected_compiled_build_identity_sha256': BUILD, 'externally_selected_ELF_sha256': SELECTED,
         'rebuilt_ELF_sha256': actual, 'returncode': result.returncode,
         'byte_identical_to_selected_current_ELF': actual == SELECTED,
         'mismatch_never_selects_output': True, 'wall_seconds': time.monotonic() - started,
         'actual_cgroup_caps': caps, 'network_disabled_for_actual_compile': True,
         'private_backup_witness_PK_or_proof_read_or_mounted': False,
         'selected_executable_executed': False, 'original_HOST_checkout_registry_cache_targets_mounted': False,
         'public_vendor_recreates_original_logical_registry_path': True,
         'trusted_preinstalled_compiler_OS': True, 'independent_machine_reproducibility': False,
         'complete_W_wallet_software_closure_or_financial_recovery': False,
         'native_acceptance_chain_currentness_privacy_or_spend_authority': False}
    save(output, 'RESULT.json', report)
    save(output, 'RESOURCES.json', {'actual_caps': caps,
         'cgroup_end_stats': {n: (cgroup / n).read_text().strip()
            for n in ('cpu.stat', 'memory.peak', 'memory.swap.peak', 'memory.events')}})
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('assets', type=Path)
    parser.add_argument('archive', type=Path)
    parser.add_argument('old_inventory', type=Path)
    parser.add_argument('output', type=Path)
    arguments = parser.parse_args()
    print(json.dumps(build(arguments), sort_keys=True))
