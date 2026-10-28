"""Offline archive/install parity check; imports no JavaScript or native addon.

Run in the closed source/tools namespace before owner or verifier jobs. Every
installed regular file must equal a pinned public npm archive member. The only
installer additions admitted are the matching hidden lock and internal .bin
symlinks to admitted files. No package install script is run.
"""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import tarfile


def need(value, code):
    if not value:
        raise ValueError(code)


def read_regular(path, root):
    need(not path.is_symlink(), 'SYMLINK_FILE:' + str(path))
    need(path.resolve().is_relative_to(root), 'OUTSIDE_TOOLS')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'REGULAR_SINGLE_LINK:' + str(path))
    return path.read_bytes()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tools', type=Path, required=True)
    args = parser.parse_args()
    tools = args.tools.resolve(strict=True)
    source = Path(__file__).resolve().parents[1]
    closure_bytes = (source / 'tool-provenance/TOOL-ARCHIVE-CLOSURE-01.json').read_bytes()
    closure = json.loads(closure_bytes)
    lock_bytes = (source / 'EXISTING-JS-LOCK-01.json').read_bytes()
    need(hashlib.sha256(lock_bytes).hexdigest() == closure['lock_sha256'], 'LOCK_PIN')
    lock = json.loads(lock_bytes)['packages']
    packages = closure['packages']
    need(len(packages) == 96 and len({p['package_path'] for p in packages}) == 96, 'ARCHIVE_CLOSURE')
    need(set(lock) - {''} == {p['package_path'] for p in packages}, 'LOCK_PACKAGE_SET')
    expected = {}
    for package in packages:
        package_path = PurePosixPath(package['package_path'])
        need(not package_path.is_absolute() and '..' not in package_path.parts, 'PACKAGE_PATH')
        entry = lock[str(package_path)]
        need(all(entry.get(k) == package.get(k) for k in ['version', 'integrity', 'resolved']), 'LOCK_PACKAGE_PIN')
        cache_rel = Path(package['cache_path']).relative_to('/var/tmp/kpi-signature-predicate-tools-20261026-01')
        raw = read_regular(tools / cache_rel, tools)
        need(len(raw) == package['archive_bytes'] and hashlib.sha256(raw).hexdigest() == package['archive_sha256'], 'ARCHIVE_SHA256:' + str(package_path))
        algorithm, digest = package['integrity'].split('-', 1)
        need(algorithm == 'sha512' and hashlib.sha512(raw).digest() == base64.b64decode(digest, validate=True), 'ARCHIVE_INTEGRITY')
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            members = archive.getmembers()
            roots = {PurePosixPath(m.name).parts[0] for m in members if not m.isdir()}
            need(len(roots) == 1, 'ARCHIVE_ROOT')
            for member in members:
                if member.isdir():
                    continue
                member_path = PurePosixPath(member.name)
                need(member.isfile() and not member_path.is_absolute() and len(member_path.parts) > 1 and '..' not in member_path.parts, 'ARCHIVE_MEMBER:' + member.name)
                relative = package_path.joinpath(*member_path.parts[1:])
                need(relative not in expected, 'DUPLICATE_MEMBER:' + str(relative))
                content = archive.extractfile(member).read()
                installed = read_regular(tools / str(relative), tools)
                need(installed == content, 'INSTALLED_BYTE_MISMATCH:' + str(relative))
                expected[relative] = hashlib.sha256(content).hexdigest()

    actual = set()
    bins = 0
    for path in (tools / 'node_modules').rglob('*'):
        relative = PurePosixPath(path.relative_to(tools).as_posix())
        if path.is_symlink():
            need('.bin' in relative.parts and path.resolve().is_relative_to(tools), 'UNEXPECTED_SYMLINK:' + str(relative))
            target = PurePosixPath(path.resolve().relative_to(tools).as_posix())
            need(target in expected, 'BIN_TARGET:' + str(relative))
            bins += 1
            continue
        need(path.resolve().is_relative_to(tools), 'OUTSIDE_TOOLS')
        if path.is_dir():
            continue
        if relative == PurePosixPath('node_modules/.package-lock.json'):
            hidden = json.loads(read_regular(path, tools))['packages']
            need(set(hidden) == set(lock) - {''}, 'INSTALLED_LOCK_PACKAGE_SET')
            for name, entry in hidden.items():
                need(all(entry.get(k) == lock[name].get(k) for k in ['version', 'resolved', 'integrity']), 'INSTALLED_LOCK_PIN:' + name)
            continue
        actual.add(relative)
    need(actual == set(expected), 'INSTALLED_FILE_SET')
    digest = hashlib.sha256(json.dumps({str(k): v for k, v in sorted(expected.items())}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    print(json.dumps({'schema': 'kpi-nativeauth-installed-js-closure/v1', 'status': 'EXACT_ARCHIVE_INSTALL_PARITY', 'packages': len(packages), 'files': len(expected), 'binSymlinks': bins, 'installedFileMapSha256': digest, 'archiveClosureSha256': hashlib.sha256(closure_bytes).hexdigest(), 'lockSha256': closure['lock_sha256'], 'javascriptImported': False, 'installScriptsRun': False}, sort_keys=True))


if __name__ == '__main__':
    main()
