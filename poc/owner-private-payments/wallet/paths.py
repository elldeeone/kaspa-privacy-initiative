"""Metadata-only private exclusions and descriptor checks before public reads."""
import hashlib
import json
import os
from pathlib import Path
import stat

ROOT = Path(__file__).absolute().parents[3]


def need(value, code):
    if not value:
        raise ValueError(code)


def checked(value):
    path = Path(value)
    need('..' not in path.parts, 'canonical-path')
    path = path.absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink-path')
    return path


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def parse(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate-JSON-field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite-JSON')))


def fields(value, names, code):
    need(type(value) is dict and set(value) == set(names), code)


def hx(value, width):
    need(type(value) is str and len(value) == 2 * width
         and all(c in '0123456789abcdef' for c in value), 'canonical-hex-width')
    return bytes.fromhex(value)


def uint(value, bits=64):
    need(type(value) is int and 0 <= value < 1 << bits, 'unsigned-integer')
    return value


def attributes(info):
    return tuple(getattr(info, name) for name in
        ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


class HostPolicy:
    """Never opens old backups or any new owner/MPC private-file contents."""
    def __init__(self, old_trials, new_directories):
        roots = tuple(checked(p) for p in old_trials)
        new = tuple(checked(p) for p in new_directories)
        need(len(roots) == len(set(roots)) == 2, 'two-old-trial-exclusions')
        need(len(new) == len(set(new)) == 3, 'three-new-private-party-roots')
        need(all(not p.is_relative_to(ROOT) for p in (*roots, *new)), 'private-fixtures-outside-source')
        need(all(not a.is_relative_to(b) for a in new for b in new if a != b),
             'separate-new-private-directories')
        identities, directories = set(), []
        for root in roots:
            for role in ('A', 'B', 'C', 'D'):
                folder = checked(root / 'owners' / role)
                need(folder.is_dir(), 'old-owner-directory-metadata')
                path = checked(folder / 'backup.json'); info = path.lstat()
                need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                     and info.st_nlink == 1, 'old-original-backup-metadata')
                identities.add((info.st_dev, info.st_ino)); directories.append(folder)
        need(len(identities) == 8, 'eight-distinct-old-originals')
        for folder in new:
            need(folder.is_dir() and stat.S_IMODE(folder.stat().st_mode) == 0o700,
                 'new-private-directory-mode')
            # Metadata only, including all prior attempt files. Generic private
            # names must not themselves expose output commitments or maps.
            for current, dirs, files in os.walk(folder, followlinks=False):
                for name in dirs:
                    # Stock OpenSSL creates certificate-hash symlinks in
                    # engine scratch. Inspect the lexical entry only: never
                    # follow/readlink it. The full private parent is excluded.
                    info = (Path(current) / name).lstat()
                    need(stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode),
                         'private-subdirectory-type')
                for name in files:
                    info = (Path(current) / name).lstat()
                    if stat.S_ISLNK(info.st_mode):
                        continue
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                         'new-private-file-type-or-hardlink')
                    identities.add((info.st_dev, info.st_ino))
            directories.append(folder)
        need(all(not p.is_relative_to(Path('/usr'))
                 and not p.is_relative_to(Path('/etc/alternatives')) for p in directories),
             'private-trees-outside-system-mounts')
        self.directories, self.identities = tuple(directories), frozenset(identities)
        self.new_directories = new

    def guard(self, paths):
        result = []
        for value in paths:
            path = checked(value)
            need(all(not path.is_relative_to(folder) for folder in self.directories),
                 'public-input-inside-private-tree')
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode)
                 and (info.st_dev, info.st_ino) not in self.identities,
                 'public-input-private-alias-or-type')
            result.append((path, info))
        return tuple(result)

    def read(self, path, expected=None):
        ((path, before),) = self.guard((path,))
        raw = stable_read(path, before, forbidden=self.identities)
        need(expected is None or digest(raw) == hx(expected, 32).hex(), 'selected-public-file-pin')
        return raw


def stable_read(path, before=None, *, forbidden=(), private=False):
    path = checked(path); before = before or path.lstat()
    need(stat.S_ISREG(before.st_mode) and (not private or before.st_nlink == 1),
         'regular-file-required')
    if private:
        need(stat.S_IMODE(before.st_mode) in (0o400, 0o600), 'private-file-mode')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        need(stat.S_ISREG(opened.st_mode) and attributes(opened) == attributes(before)
             and (opened.st_dev, opened.st_ino) not in forbidden,
             'file-swapped-before-first-byte')
        with os.fdopen(os.dup(fd), 'rb') as source:
            raw = source.read()
        need(attributes(os.fstat(fd)) == attributes(before) and len(raw) == before.st_size,
             'file-mutated-during-read')
        return raw
    finally:
        os.close(fd)


def write_new(path, raw, mode=0o600):
    path = checked(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), mode); output.write(raw); output.flush(); os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
