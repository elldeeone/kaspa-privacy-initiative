#!/usr/bin/env python3
"""One-command bootstrap for one unregistered, fixed unfunded qualification.

No owner input, private key, MPC, RPC, settlement, live registration or reset
interface exists. Build inputs are public guarded source; the initializer runs
without network and sees only a fresh empty output parent plus its executable.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

HERE = Path(__file__).resolve().parent
BOOTSTRAP = Path('/var/tmp/kpi-root-guard-helper-09.py')
BOOTSTRAP_SHA = '0f8ff562a4364c1db7729d98d7daf57f75ff5e882936e06e9907a4e936bd82fd'
SCOPE = 'PUBLIC_UNFUNDED_UNREGISTERED_QUALIFICATION_ONLY'
SOURCES = ('epoch_journal.hpp', 'epoch_journal.cpp', 'qualification_descriptor.hpp', 'qualification_init.cpp')
BASE_EPOCH = '1719a11d82194639da551cd7302ad3ea94e42a0e424962ac40719f5634d38b94'


def need(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def plain(path):
    need(path.is_absolute() and path == Path(os.path.normpath(path)), 'canonical absolute path')
    need(not any(item.is_symlink() for item in (path, *path.parents)), 'no symlink ancestors')
    return path


def write_new(path, raw, mode=0o400):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def load_guard():
    plain(BOOTSTRAP)
    before = BOOTSTRAP.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'public guard bootstrap')
    fd = os.open(BOOTSTRAP, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as source:
        opened = os.fstat(source.fileno())
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
             == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns),
             'guard bootstrap race')
        raw = source.read()
        after = os.fstat(source.fileno())
    stable = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
    need(tuple(getattr(opened, field) for field in stable)
         == tuple(getattr(after, field) for field in stable)
         and sha(raw) == BOOTSTRAP_SHA, 'selected guard bootstrap bytes')
    namespace = {'__file__': str(BOOTSTRAP), '__name__': 'qualification_guard09'}
    exec(compile(raw, str(BOOTSTRAP), 'exec'), namespace)
    namespace['refresh']()  # Metadata only; no excluded body is opened.
    return namespace['read'], tuple(namespace['m'].GUARD.directories)


def admit_output_paths(paths, excluded_directories):
    for path in paths:
        for excluded in excluded_directories:
            excluded = Path(excluded).absolute()
            need(not path.is_relative_to(excluded) and not excluded.is_relative_to(path),
                 'output/private directory overlap')


def namespace():
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
            '--clearenv', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
            '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
            '--ro-bind', '/etc/alternatives', '/etc/alternatives',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--server-certificate-sha256', action='append', required=True)
    arguments = parser.parse_args()
    certificates = arguments.server_certificate_sha256
    need(len(certificates) == 3 and len(set(certificates)) == 3, 'three distinct public server certificate digests')
    for value in certificates:
        need(len(value) == 64 and value != '00' * 32
             and all(char in '0123456789abcdef' for char in value), 'canonical nonzero digest')
    output = plain(arguments.output.absolute())
    build = plain(output.with_name(output.name + '-build'))
    need(output.parent.is_dir() and output.parent.stat().st_uid == os.getuid(), 'owned output parent')
    need(not any(char in str(output) for char in '\r\n\t'), 'role-spec path delimiter')
    need(not output.exists() and not build.exists(), 'fresh output and build directories required')
    read, excluded_directories = load_guard()
    admit_output_paths((output, build), excluded_directories)
    selected = {name: read(HERE / name) for name in SOURCES}
    wrapper = read(Path(__file__).resolve())
    compiler = plain(Path('/usr/bin/g++').resolve(strict=True))
    compiler_raw = read(compiler)
    compiler_identity = {'path': str(compiler), 'sha256': sha(compiler_raw), 'bytes': len(compiler_raw)}
    output.mkdir(mode=0o700)
    build.mkdir(mode=0o700)
    sync_directory(output.parent)
    snapshot, objects = build / 'source', build / 'objects'
    snapshot.mkdir(mode=0o700)
    objects.mkdir(mode=0o700)
    for name, raw in selected.items():
        write_new(snapshot / name, raw)
    snapshot.chmod(0o500)
    flags = ['-std=c++20', '-O1', '-g0', '-Wall', '-Wextra', '-Werror',
             '-DKPI_HISTORY_UNFUNDED_SETUP']
    selection = {'schema': 'kpb-qualification-bootstrap-build/v2', 'scope': SCOPE,
                 'source_sha256': {name: sha(raw) for name, raw in selected.items()},
                 'wrapper_sha256': sha(wrapper), 'compiler': compiler_identity,
                 'flags': flags, 'registered_financial_service': False,
                 'MPC_owner_input_network_or_settlement': False}
    selection_raw = encoded(selection)
    selection_sha = sha(selection_raw)
    write_new(build / 'BUILD-SELECTION.json', selection_raw)
    command = namespace() + ['--ro-bind', str(snapshot), '/source',
        '--bind', str(objects), '/build', '/usr/bin/g++', *flags,
        '-DKPI_QUALIFICATION_BUILD_SHA256="' + selection_sha + '"',
        '/source/epoch_journal.cpp', '/source/qualification_init.cpp',
        '-pthread', '-lcrypto', '-o', '/build/qualification-init']
    compiled = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, close_fds=True)
    write_new(build / 'compile.stdout', compiled.stdout)
    write_new(build / 'compile.stderr', compiled.stderr)
    need(compiled.returncode == 0, 'qualification initializer compile refused; see public build log')
    binary = objects / 'qualification-init'
    binary.chmod(0o500)
    binary_raw = read(binary)
    # The build/source directory is a separate sibling. It never becomes a
    # writable alias inside the initializer's otherwise empty output mount.
    initialized = subprocess.run(namespace() + ['--ro-bind', str(binary), '/public/qualification-init',
        '--bind', str(output), str(output), '/public/qualification-init',
        str(output / 'qualification'), *certificates], stdin=subprocess.DEVNULL,
        capture_output=True, close_fds=True)
    write_new(build / 'initialize.stdout', initialized.stdout)
    write_new(build / 'initialize.stderr', initialized.stderr)
    need(initialized.returncode == 0, 'qualification initializer refused; no reset or cleanup performed')
    summary = json.loads(initialized.stdout)
    need(summary['scope'] == SCOPE and summary['registered_financial_service'] is False,
         'unregistered qualification result')
    registration_file = output / 'qualification/REGISTRATION.json'
    raw = read(registration_file, summary['registration_file_sha256'])
    registration = json.loads(raw)
    need(registration['registration']['registered_financial_service'] is False,
         'qualification cannot become registered')
    need(registration['registration']['initializer_executable_sha256'] == sha(binary_raw)
         and registration['registration']['source_build_selection_sha256'] == selection_sha,
         'actual source/tool/binary identity')
    canonical = json.dumps(registration['registration'], sort_keys=True,
                           separators=(',', ':'), ensure_ascii=False).encode()
    need(sha(b'KPBH/UNREGISTERED-QUALIFICATION/REGISTRATION/v2\0' + canonical)
         == registration['registration_sha256'] == summary['registration_sha256'],
         'canonical registration commitment')
    inner = registration['registration']
    key = inner['epoch_key']
    base_encoded = b'KPBHKEY1' + b''.join(bytes.fromhex(key[field]) for field in
        ('chain_hex32', 'pool_hex32', 'domain_hex32', 'profile_hex32', 'service_hex32'))
    base_encoded += bytes.fromhex(BASE_EPOCH) + b''.join(bytes.fromhex(value) for value in certificates)
    derived_epoch = sha(b'KPBH/UNREGISTERED-QUALIFICATION/EPOCH/v1\0' + base_encoded
        + bytes.fromhex(inner['fixture_context_sha256']) + bytes.fromhex(inner['fixture_head_sha256'])
        + bytes.fromhex(inner['registration_nonce_hex32']))
    need(derived_epoch == key['epoch_hex32'] == summary['qualification_epoch_hex32']
         and derived_epoch not in (BASE_EPOCH, '00' * 32)
         and inner['base_service_epoch_hex32'] == BASE_EPOCH
         and key['server_certificate_sha256'] == certificates,
         'distinct independently derived unregistered qualification epoch')
    need(len(summary['role_specs']) == 3, 'three role specifications')
    for party, record in enumerate(summary['role_specs']):
        need(record['party_id'] == party, 'ordered role specifications')
        role_path = output / 'qualification' / ('party-' + str(party)) / 'role.spec'
        need(record['path'] == str(role_path), 'exact role specification path')
        role_raw = read(role_path, record['sha256'])
        need(role_raw.startswith(b'KPBQROLE2\n') and role_raw.endswith(b'END\n'), 'qualification role schema')
    result = {'schema': 'kpb-qualification-bootstrap-handoff/v2', 'scope': SCOPE,
              'registration': summary, 'build_selection_sha256': selection_sha,
              'initializer_sha256': sha(binary_raw), 'build_directory': str(build),
              'financial_registered_or_settlement_authority': False}
    write_new(output / 'BUILD-SELECTION.json', selection_raw)
    write_new(output / 'BOOTSTRAP.json', encoded(result))
    sync_directory(output)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError):
        raise SystemExit('qualification bootstrap refused; no live state initialized') from None
