"""Metadata-first private-path and alias guards; no backup content/hash API."""
import os
from pathlib import Path
import stat
import subprocess
from reuse import ROOT


def need(value, code):
    if not value:
        raise ValueError(code)


def checked(path):
    path = Path(path).absolute()
    need('..' not in path.parts, 'path-parent-components-forbidden')
    need(not any(part.is_symlink() for part in (path, *path.parents)), 'path-symlink')
    return path


def outside_git(path):
    path = checked(path)
    need(not path.is_relative_to(ROOT), 'private-path-inside-project')
    probe = path if path.is_dir() else path.parent
    while not probe.exists():
        probe = probe.parent
    need(probe.is_dir(), 'path-parent-directory')
    result = subprocess.run(['/usr/bin/git', '-c', 'safe.directory=*', '-C', str(probe),
                             'rev-parse', '--is-inside-work-tree'], capture_output=True, text=True,
                            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})
    need(result.returncode != 0 or result.stdout.strip() != 'true', 'private-path-inside-Git')
    return path


def guard(backup, public_paths, output):
    backup = outside_git(backup)
    info = backup.stat()
    need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600, 'own-backup-metadata')
    forbidden = (info.st_dev, info.st_ino)
    for candidate in tuple(public_paths):
        candidate = checked(candidate)
        row = candidate.stat()
        need(stat.S_ISREG(row.st_mode) and (row.st_dev, row.st_ino) != forbidden,
             'public-input-backup-alias-or-type')
    output = outside_git(output)
    need(not output.exists(), 'fresh-private-output-required')
    return backup, output
