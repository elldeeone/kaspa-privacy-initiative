#!/usr/bin/env python3
"""Build the new public guest offline; an unselected template is build evidence only.

The guest embeds component-profile.json. Selecting different role keys therefore
requires a new build and image. This command never executes or proves a guest.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile
import time

ROOT = Path(__file__).resolve().parents[4]
PACKAGE = Path(__file__).resolve().parents[1]
TOOLS = ROOT.parent / 'proof-target/tools'
TARGET = Path('/var/tmp/kpi-local-private-guest-target-01')
SDK_RECORD = ROOT / 'research/next-session/independent-payments/fees/SDK-AUTHENTICATION-01.json'
BOOTSTRAP = Path('/var/tmp/kpi-root-guard-helper-09.py')
BOOTSTRAP_SHA = '0f8ff562a4364c1db7729d98d7daf57f75ff5e882936e06e9907a4e936bd82fd'
FLAGS = '-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"'
NAME = 'kpi-private-batch-public-guest'


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def save(path, value):
    with path.open('x') as destination:
        json.dump(value, destination, indent=2, sort_keys=True)
        destination.write('\n')


def load_guard(exclusions):
    # This retained bootstrap is the same fixed code as the execution wrapper.
    # Fresh private roots are metadata-only and are registered before all source
    # and tool admissions. The bootstrap itself is selected public source.
    private = []
    inodes = set()
    for value in exclusions:
        directory = Path(value).absolute()
        need(directory.is_dir() and '..' not in directory.parts
             and not any(p.is_symlink() for p in (directory, *directory.parents)),
             'whole-private-directory-metadata')
        private.append(directory)
        def failed(error):
            raise ValueError('private-metadata-enumeration-failed') from error
        for current, directories, files in os.walk(directory, followlinks=False, onerror=failed):
            directories[:] = [name for name in directories
                              if not (Path(current) / name).is_symlink()]
            for name in files:
                info = (Path(current) / name).lstat()
                if stat.S_ISREG(info.st_mode):
                    inodes.add((info.st_dev, info.st_ino))
    need(not any(p.is_symlink() for p in (BOOTSTRAP, *BOOTSTRAP.parents))
         and all(not BOOTSTRAP.is_relative_to(p) for p in private),
         'canonical-public-bootstrap')
    before = BOOTSTRAP.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and (before.st_dev, before.st_ino) not in inodes, 'public-bootstrap-metadata')
    attributes = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
    descriptor = os.open(BOOTSTRAP, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        opened = os.fstat(source.fileno())
        need(tuple(getattr(before, k) for k in attributes)
             == tuple(getattr(opened, k) for k in attributes), 'bootstrap-open-race')
        raw = source.read()
        after = os.fstat(source.fileno())
    need(tuple(getattr(before, k) for k in attributes)
         == tuple(getattr(after, k) for k in attributes)
         and len(raw) == before.st_size
         and hashlib.sha256(raw).hexdigest() == BOOTSTRAP_SHA, 'trusted-bootstrap-pin')
    guard = {'__file__': str(BOOTSTRAP), '__name__': 'private_batch_build_guard09'}
    exec(compile(raw, str(BOOTSTRAP), 'exec'), guard)
    guard['m'].GUARD.directories = tuple(dict.fromkeys(
        (*guard['m'].GUARD.directories, *private)))
    guard['m'].GUARD.inodes.update(inodes)
    return guard


def source_records(guard, snapshot=None):
    paths = [PACKAGE / 'component-profile.json', PACKAGE / 'proving/build_guest.py', SDK_RECORD]
    for directory in (PACKAGE / 'common', PACKAGE / 'guest', PACKAGE.parent / 'relation'):
        paths.extend(path for path in directory.rglob('*')
                     if path.is_file() and 'target' not in path.parts)
    result = []
    for path in sorted(set(paths)):
        raw = guard['read'](path)
        if snapshot is not None:
            destination = snapshot / path.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open('xb') as target:
                target.write(raw)
            destination.chmod(0o400)
        result.append({'path': str(path.relative_to(ROOT)), 'bytes': len(raw),
                       'sha256': hashlib.sha256(raw).hexdigest()})
    return result


def admit_new_elf(guard, path):
    """Keep the new canonical ELF, closing only an exact new Cargo deps alias."""
    info = path.lstat()
    guard['refresh']()
    guard['m'].GUARD.metadata(path)
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), 'new-guest-regular-owned')
    alias = None
    if info.st_nlink != 1:
        matches = []
        for child in (path.parent / 'deps').iterdir():
            other = child.lstat()
            if (other.st_dev, other.st_ino) == (info.st_dev, info.st_ino):
                matches.append((child, other))
        need(info.st_nlink == 2 and len(matches) == 1, 'exact-two-owned-guest-aliases')
        child, other = matches[0]
        guard['m'].GUARD.metadata(child)
        need(child.name.startswith(NAME.replace('-', '_') + '-')
             and stat.S_ISREG(other.st_mode) and other.st_uid == os.getuid()
             and not child.is_symlink(), 'only-new-generated-guest-deps-alias')
        alias = {'path': str(child), 'dev': other.st_dev, 'ino': other.st_ino,
                 'bytes': other.st_size, 'nlink_before': other.st_nlink}
        child.unlink()
        after = path.lstat()
        need((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
             == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
             and after.st_nlink == 1, 'canonical-guest-unchanged-single-link')
    raw = guard['read'](path)
    return raw, alias


def materialize_toolchain(guard, row, output):
    """Use only leaves derived from the authenticated archive, not live SDK libs.

    The official archive has internal hardlinks. Independent regular copies
    preserve their bytes while keeping guard09's single-link admission rule.
    The original archive and installed toolchain are never modified.
    """
    raw = guard['read'](Path(row['path']), row['sha256'])
    need(len(raw) == row['bytes'], 'toolchain-archive-length')
    destination = output / 'toolchain'
    destination.mkdir(mode=0o700)
    records = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        members = {}
        def relative(name):
            name = PurePosixPath(name)
            need(not name.is_absolute() and '..' not in name.parts, 'archive-canonical-relative-path')
            return name.as_posix()
        for member in archive.getmembers():
            name = relative(member.name)
            need(member.isdir() or member.isfile() or member.islnk(), 'archive-supported-entry-type')
            if name == '.':
                need(member.isdir(), 'archive-root-directory')
                continue
            need(name not in members, 'archive-duplicate-path')
            members[name] = member
        def original(name, seen=None):
            seen = set() if seen is None else seen
            need(name in members and name not in seen, 'archive-internal-hardlink-target')
            member = members[name]
            if member.islnk():
                seen.add(name)
                return original(relative(member.linkname), seen)
            need(member.isfile(), 'archive-hardlink-target-regular')
            return name
        leaves = {name: original(name) for name, m in members.items() if not m.isdir()}
        logical_bytes = sum(members[name].size for name in leaves.values())
        disk = os.statvfs(output)
        need(disk.f_bavail * disk.f_frsize > logical_bytes + 256 * 1024 * 1024,
             'fresh-public-toolchain-disk-headroom')
        for name, member in members.items():
            if not member.isfile():
                continue
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            count = 0
            source = archive.extractfile(member)
            need(source is not None, 'archive-regular-body')
            with source, path.open('xb') as target:
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    target.write(chunk)
                    count += len(chunk)
                    digest.update(chunk)
            need(count == member.size, 'complete-archive-regular-body')
            path.chmod(0o555 if member.mode & 0o111 else 0o444)
            records[name] = {'bytes': count, 'sha256': digest.hexdigest(),
                             'archive_entry': 'regular', 'mode': oct(path.stat().st_mode & 0o777)}
        for name, member in members.items():
            if not member.islnk():
                continue
            source_name = leaves[name]
            body = guard['read'](destination / source_name, records[source_name]['sha256'])
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as target:
                target.write(body)
            path.chmod(0o555 if member.mode & 0o111 else 0o444)
            records[name] = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
                             'archive_entry': 'flattened-internal-hardlink', 'target': source_name,
                             'mode': oct(path.stat().st_mode & 0o777)}
        need(set(records) == set(leaves), 'complete-derived-toolchain-file-set')
        for name in records:
            info = (destination / name).lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1,
                 'derived-toolchain-owned-single-link-regular')
        directories = [p for p in destination.rglob('*') if p.is_dir()]
        for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
            path.chmod(0o555)
        destination.chmod(0o555)
    save(output / 'TOOLCHAIN-DERIVATION.json', {'schema': 'risc0-public-toolchain-archive-derivation/v1',
         'archive': row, 'path': str(destination), 'files': records,
         'installed_toolchain_bound': False, 'old_toolchain_modified': False,
         'all_runtime_compiler_linker_and_rustlib_leaves_from_authenticated_archive': True})
    return destination, records


def admit_derived_toolchain(guard, row, receipt, receipt_sha):
    """Reuse an explicitly hash-selected archive derivation after leaf parity.

    The receipt SHA is an external selection of a previously retained build
    artifact. Matching archive identity alone is insufficient: every installed
    regular leaf is reauthenticated before this tree is bound into the build.
    """
    raw = guard['read'](receipt, receipt_sha)
    manifest = json.loads(raw)
    need(set(manifest) == {'schema', 'archive', 'path', 'files',
         'installed_toolchain_bound', 'old_toolchain_modified',
         'all_runtime_compiler_linker_and_rustlib_leaves_from_authenticated_archive'}
         and manifest['schema'] == 'risc0-public-toolchain-archive-derivation/v1'
         and manifest['archive'] == row
         and manifest['installed_toolchain_bound'] is False
         and manifest['old_toolchain_modified'] is False
         and manifest['all_runtime_compiler_linker_and_rustlib_leaves_from_authenticated_archive'] is True,
         'selected-authenticated-archive-derivation-receipt')
    sdk = Path(manifest['path'])
    need(sdk.is_absolute() and sdk.is_dir() and sdk.stat().st_uid == os.getuid()
         and not any(p.is_symlink() for p in (sdk, *sdk.parents))
         and all(not sdk.is_relative_to(p) and not p.is_relative_to(sdk)
                 for p in guard['m'].GUARD.directories), 'public-derived-toolchain-root')
    records = manifest['files']
    need(type(records) is dict and records, 'selected-derived-leaf-manifest')
    seen = set()
    for current, directories, files in os.walk(sdk, followlinks=False):
        for path in (Path(current), *(Path(current) / name for name in directories)):
            info = path.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                 and stat.S_IMODE(info.st_mode) == 0o555, 'readonly-owned-derived-directory')
        for name in files:
            path = Path(current) / name
            key = path.relative_to(sdk).as_posix()
            need(key in records, 'no-unselected-derived-leaf')
            record = records[key]
            expected = {'bytes', 'sha256', 'archive_entry', 'mode'}
            if record.get('archive_entry') == 'flattened-internal-hardlink':
                expected.add('target')
            need(set(record) == expected and record['archive_entry'] in
                 ('regular', 'flattened-internal-hardlink'), 'selected-derived-leaf-record')
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                 and info.st_nlink == 1 and record['mode'] in ('0o444', '0o555')
                 and stat.S_IMODE(info.st_mode) == int(record['mode'], 8),
                 'readonly-owned-derived-leaf')
            body = guard['read'](path, record['sha256'])
            need(len(body) == record['bytes'], 'selected-derived-leaf-length')
            seen.add(key)
    need(seen == set(records), 'complete-selected-derived-toolchain-file-set')
    return sdk, records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--allow-unselected-template', action='store_true')
    parser.add_argument('--derived-toolchain-receipt')
    parser.add_argument('--derived-toolchain-receipt-sha256')
    parser.add_argument('--exclude-private-directory', action='append', required=True)
    arguments = parser.parse_args()
    need(arguments.jobs >= 1, 'positive-job-count')
    guard = load_guard(arguments.exclude_private_directory)
    profile = json.loads(guard['read'](PACKAGE / 'component-profile.json'))
    selected = profile.get('selected') is True
    need(selected or arguments.allow_unselected_template, 'explicit-unselected-template-mode')
    output = Path(arguments.output).absolute()
    need(output.parent.is_dir() and output.parent.stat().st_uid == os.getuid()
         and not any(p.is_symlink() for p in (output, *output.parents))
         and all(not output.is_relative_to(p) for p in guard['m'].GUARD.directories),
         'fresh-public-build-output-parent')
    output.mkdir(mode=0o700)
    before = source_records(guard, output / 'source')
    save(output / 'SOURCE-BEFORE.json', before)
    record = json.loads(guard['read'](SDK_RECORD))
    # Compiler/runtime provenance is retained exactly; no download/install.
    tools = []
    archive = None
    for row in record['whole_bytes_reauthenticated']:
        if row['path'].endswith(('/r0vm', '/r0vm-cuda')):
            continue
        if row['path'].endswith('/risc0-rust.tgz'):
            archive = row
            tools.append(row)
            continue
        raw = guard['read'](Path(row['path']), row['sha256'])
        need(len(raw) == row['bytes'], 'selected-SDK-length')
        tools.append(row)
    need(archive is not None, 'selected-toolchain-archive')
    need(bool(arguments.derived_toolchain_receipt) == bool(arguments.derived_toolchain_receipt_sha256),
         'derived-toolchain-receipt-and-sha256-together')
    reused = arguments.derived_toolchain_receipt is not None
    if reused:
        sdk, leaves = admit_derived_toolchain(guard, archive,
            Path(arguments.derived_toolchain_receipt), arguments.derived_toolchain_receipt_sha256)
        toolchain_receipt = {'path': arguments.derived_toolchain_receipt,
                             'sha256': arguments.derived_toolchain_receipt_sha256}
    else:
        sdk, leaves = materialize_toolchain(guard, archive, output)
        receipt = output / 'TOOLCHAIN-DERIVATION.json'
        toolchain_receipt = {'path': str(receipt),
            'sha256': hashlib.sha256(guard['read'](receipt)).hexdigest()}
    for row in tools:
        for leaf in ('cargo', 'rustc'):
            if row['path'].endswith('/bin/' + leaf):
                need(leaves['bin/' + leaf]['sha256'] == row['sha256'], 'derived-selected-compiler-entry')
    need(TARGET.is_dir() and TARGET.stat().st_uid == os.getuid()
         and not any(p.is_symlink() for p in (TARGET, *TARGET.parents))
         and all(not TARGET.is_relative_to(p) and not p.is_relative_to(TARGET)
                 for p in guard['m'].GUARD.directories),
         'existing-owned-public-build-cache')
    # No home, wallet, private parent, network, or whole repository is mounted.
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
               '--clearenv', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
               '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
               '--ro-bind', '/etc/alternatives', '/etc/alternatives',
               '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--tmpfs', '/cargo',
               '--ro-bind', '/home/luke/.cargo/registry', '/cargo/registry',
               '--ro-bind', '/home/luke/.cargo/git', '/cargo/git',
               '--ro-bind', str(sdk), '/toolchain',
               '--ro-bind', str(PACKAGE / 'guest'), '/source/private-batch-public/guest',
               '--ro-bind', str(PACKAGE / 'common'), '/source/private-batch-public/common',
               '--ro-bind', str(PACKAGE / 'component-profile.json'), '/source/private-batch-public/component-profile.json',
               '--ro-bind', str(PACKAGE.parent / 'relation'), '/source/relation',
               '--bind', str(TARGET), '/target', '--setenv', 'PATH', '/toolchain/bin:/usr/bin:/bin',
               '--setenv', 'RUSTC', '/toolchain/bin/rustc', '--setenv', 'CARGO_HOME', '/cargo',
               '--setenv', 'CARGO_TARGET_DIR', '/target', '--setenv', 'CARGO_INCREMENTAL', '0',
               '--setenv', 'RUSTFLAGS', FLAGS, '--setenv', 'RISC0_FEATURE_bigint2', '1',
               '--setenv', 'LANG', 'C.UTF-8', '--chdir', '/source/private-batch-public/guest',
               '/toolchain/bin/cargo', 'build', '--offline', '--frozen', '--release',
               '--jobs', str(arguments.jobs), '--target', 'riscv32im-risc0-zkvm-elf',
               '--manifest-path', '/source/private-batch-public/guest/Cargo.toml']
    save(output / 'BUILD-PLAN.json', {'schema': 'private-batch-public-guest-build/v1',
         'mode': 'SELECTED_COMPONENT_BUILD' if selected else 'UNSELECTED_TEMPLATE_BUILD_ONLY',
         'component_profile_sha256': hashlib.sha256(guard['read'](PACKAGE / 'component-profile.json')).hexdigest(),
         'command': command, 'tools': tools, 'toolchain_derivation': toolchain_receipt,
         'reused_derived_toolchain': reused, 'guest_execution_or_proof': False})
    began = time.monotonic()
    with (output / 'stdout.log').open('xb') as stdout, (output / 'stderr.log').open('xb') as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)
    outcome = {'schema': 'private-batch-public-guest-build-result/v1',
               'exit_code': result.returncode, 'seconds': time.monotonic() - began,
               'selected_component_profile': selected, 'guest_execution_or_proof': False,
               'native_or_chain_acceptance': False}
    save(output / 'BUILD-RESULT.json', outcome)
    need(result.returncode == 0, 'guest-build-failed-see-public-compiler-log')
    after = source_records(guard)
    save(output / 'SOURCE-AFTER.json', after)
    need(before == after, 'selected-source-changed-during-build')
    raw, alias = admit_new_elf(guard, TARGET / 'riscv32im-risc0-zkvm-elf/release' / NAME)
    destination = output / 'guest.raw.elf'
    with destination.open('xb') as file:
        file.write(raw)
    destination.chmod(0o400)
    save(output / 'ELF-ADMISSION.json', {'schema': 'new-public-guest-elf/v1',
         'path': str(destination), 'sha256': hashlib.sha256(raw).hexdigest(),
         'bytes': len(raw), 'only_removed_new_deps_alias': alias,
         'old_selected_guest_modified': False, 'guest_execution_or_proof': False,
         'selected_component_profile': selected})
    print(json.dumps(outcome, sort_keys=True))


if __name__ == '__main__':
    main()
