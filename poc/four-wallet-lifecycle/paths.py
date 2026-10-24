"""Metadata guards before caller-selected public reads or owner backup bytes."""
from pathlib import Path
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def need(value, reason):
    if not value:
        raise ValueError(reason)


def checked(path):
    path = Path(path)
    need('..' not in path.parts, 'canonical-path-no-parent-component')
    path = path.absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'no-symlink-path')
    return path


def outside(path):
    path = checked(path)
    need(not path.is_relative_to(ROOT), 'private-output-outside-repository')
    probe = path if path.is_dir() else path.parent
    while not probe.exists():
        probe = probe.parent
    need(probe.is_dir(), 'private-path-parent-directory')
    result = subprocess.run(['/usr/bin/git', '-c', 'safe.directory=*', '-C', str(probe),
        'rev-parse', '--is-inside-work-tree'], capture_output=True, text=True,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})
    need(result.returncode != 0 or result.stdout.strip() != 'true', 'private-path-inside-Git')
    return path


def regular(path, forbidden=None):
    path = checked(path)
    info = path.stat()
    need(stat.S_ISREG(info.st_mode), 'regular-file-required')
    need(forbidden is None or (info.st_dev, info.st_ino) != forbidden,
         'public-file-aliases-original-backup')
    return path, info


def guard(backup, public_paths, output):
    backup, info = regular(outside(backup))
    need(stat.S_IMODE(info.st_mode) == 0o600, 'one-original-backup-mode')
    forbidden = info.st_dev, info.st_ino
    public_paths = tuple(public_paths)
    # Keep exclusion material reusable through every pass. An iterator that is
    # exhausted after the first read must not disable later alias exclusions.
    for path in public_paths:
        regular(path, forbidden)
    output = outside(output)
    need(not output.exists(), 'fresh-owner-output-required')
    return backup, output
