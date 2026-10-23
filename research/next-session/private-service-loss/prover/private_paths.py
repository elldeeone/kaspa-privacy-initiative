"""Metadata-only private execution path checks; errors never contain paths."""
import os
from pathlib import Path
import stat
import subprocess


class PrivatePathError(Exception):
    pass


def need(condition):
    if not condition:
        raise PrivatePathError('private_path_invalid')


def checked(path):
    value = Path(path)
    need('..' not in value.parts)
    value = value.absolute()
    for part in (value, *value.parents):
        try:
            metadata = part.lstat()
        except FileNotFoundError:
            continue
        need(not stat.S_ISLNK(metadata.st_mode))
    directory = value if value.is_dir() else value.parent
    while not directory.exists():
        directory = directory.parent
    # Empty .git placeholders exist on this host. Probe actual repositories,
    # including higher marked ancestors hidden by an invalid nested marker.
    probes = [directory] + [part for part in directory.parents if os.path.lexists(part / '.git')]
    for candidate in probes:
        result = subprocess.run(['/usr/bin/git', '-C', str(candidate), 'rev-parse', '--show-toplevel'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1',
                 'GIT_CONFIG_GLOBAL':'/dev/null','GIT_DISCOVERY_ACROSS_FILESYSTEM':'1'})
        need(result.returncode == 128 and not result.stdout
             and result.stderr.startswith(b'fatal: not a git repository'))
    return value


def private_directory(path):
    path = checked(path)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid())
    return path


def private_file(path):
    path = checked(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) in (0o400,0o600)
         and info.st_uid == os.geteuid())
    private_directory(path.parent)
    return path


def new_private_directory(path):
    path = checked(path)
    need(not os.path.lexists(path))
    private_directory(path.parent)
    return path
