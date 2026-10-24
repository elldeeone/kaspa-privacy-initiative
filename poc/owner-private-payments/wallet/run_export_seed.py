#!/usr/bin/env python3
"""Trusted literal canary launcher: one RO OWNER leaf, finite public files."""
import argparse
import os
from pathlib import Path
import stat
import subprocess

from paths import (ROOT, HostPolicy, checked, digest, encoded, fields, need,
                   parse, write_new)
from export_seed_worker import allowlist

CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


class ExportPolicy(HostPolicy):
    """Existing old8+first3 guard, extended by metadata only to ALL worlds."""
    def __init__(self, old, private_directories):
        directories = tuple(checked(p) for p in private_directories)
        need(len(directories) >= 3 and len(directories) == len(set(directories)), 'all-private-parents')
        super().__init__(old, directories[:3])
        identities = set(self.identities); protected = list(self.directories)
        for directory in directories[3:]:
            need(directory.is_dir() and stat.S_IMODE(directory.stat().st_mode) == 0o700
                 and not directory.is_relative_to(ROOT) and not directory.is_relative_to(Path('/usr'))
                 and not directory.is_relative_to(Path('/etc/alternatives')), 'additional-private-parent')
            for current, dirs, files in os.walk(directory, followlinks=False):
                for name in (*dirs, *files):
                    info = (Path(current) / name).lstat()
                    if stat.S_ISLNK(info.st_mode) or stat.S_ISDIR(info.st_mode):
                        continue
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'private-leaf-type-or-link')
                    identities.add((info.st_dev, info.st_ino))
            protected.append(directory)
        self.identities = frozenset(identities); self.directories = tuple(protected)
        self.new_directories = directories


def run(a):
    policy = ExportPolicy(a.exclude_old_trial, a.exclude_new_private_parent)
    owner = checked(a.owner_leaf); info = owner.lstat()
    need(any(owner == d / 'owner' / 'OWNER.json' for d in policy.new_directories)
         and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o600, 'one-original-new-owner-leaf')
    root, output = checked(a.public_root), checked(a.output)
    need(not output.exists() and not output.is_relative_to(ROOT)
         and all(not output.is_relative_to(d) for d in policy.directories), 'fresh-canary-controller-output')
    parent = output.parent
    while not parent.exists():
        parent = parent.parent
    result = subprocess.run(['/usr/bin/git', '-c', 'safe.directory=*', '-C', str(parent),
        'rev-parse', '--is-inside-work-tree'], stdin=subprocess.DEVNULL, capture_output=True, env=CLEAN)
    need(result.returncode != 0 or result.stdout.strip() != b'true', 'canary-output-outside-Git')
    worker = Path(__file__).parent / 'export_seed_worker.py'
    # Exclude every private parent/inode BEFORE first public content/hash.
    policy.guard([worker, a.allowlist])
    raw_list = policy.read(a.allowlist, a.allowlist_sha256)
    rows, _ = allowlist(raw_list, a.allowlist_sha256)
    candidates = [checked(root / row['path']) for row in rows]
    policy.guard(candidates)
    output.mkdir(parents=True, mode=0o700)
    source = output / 'worker.py'; write_new(source, policy.read(worker), 0o400)
    public_list = output / 'ALLOWLIST.json'; write_new(public_list, raw_list, 0o400)
    copied = output / 'candidates'; copied.mkdir(mode=0o700)
    for index, (original, row) in enumerate(zip(candidates, rows)):
        raw = policy.read(original, row['sha256']); need(len(raw) == row['bytes'], 'candidate-whole-byte-identity')
        write_new(copied / (str(index) + '.bin'), raw, 0o400)
    public = output / 'public'; public.mkdir(mode=0o700)
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        '--ro-bind', str(source), '/check.py', '--ro-bind', str(public_list), '/ALLOWLIST.json',
        '--ro-bind', str(owner), '/OWNER.json']
    for index in range(len(rows)):
        command += ['--ro-bind', str(copied / (str(index) + '.bin')), '/candidates/' + str(index) + '.bin']
    command += ['--bind', str(public), '/out', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
        '/usr/bin/python3', '-B', '/check.py', '--owner', '/OWNER.json', '--allowlist', '/ALLOWLIST.json',
        '--allowlist-sha256', a.allowlist_sha256, '--candidates', '/candidates', '--output', '/out/PUBLIC.json']
    # This private operational plan may contain paths, never OWNER contents.
    write_new(output / 'PRIVATE-PLAN.json', encoded({'command': command, 'publish_or_hash': False}) + b'\n')
    if not a.execute:
        return {'staged': True, 'executed': False}
    process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, env=CLEAN)
    write_new(output / 'PRIVATE-STDOUT.log', process.stdout); write_new(output / 'PRIVATE-STDERR.log', process.stderr)
    need(process.returncode == 0, 'seed-canary-not-complete')
    refreshed = ExportPolicy(a.exclude_old_trial, a.exclude_new_private_parent)
    value = parse(refreshed.read(public / 'PUBLIC.json'))
    fields(value, ('schema', 'status', 'candidate_count', 'candidate_bytes', 'matched_candidate_count', 'scope'),
           'literal-canary-result-fields')
    need(value['schema'] == 'kpx7-new-owner-seed-export-result/v1' and value['status'] in ('PASS', 'FAIL')
         and type(value['candidate_count']) is int and value['candidate_count'] == len(rows) + 1
         and type(value['candidate_bytes']) is int
         and value['candidate_bytes'] == sum(row['bytes'] for row in rows) + len(raw_list)
         and type(value['matched_candidate_count']) is int and 0 <= value['matched_candidate_count'] <= len(rows) + 1
         and (value['status'] == 'PASS') == (value['matched_candidate_count'] == 0)
         and value['scope'] == 'LITERAL_SEED_CANARY_ONLY_NOT_SECURITY_OR_PRIVACY_PROOF', 'bounded-canary-result')
    return value


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('owner-leaf', 'public-root', 'allowlist', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('exclude-old-trial', 'exclude-new-private-parent'):
        p.add_argument('--' + name, type=Path, action='append', required=True)
    p.add_argument('--allowlist-sha256', required=True)
    p.add_argument('--execute', action='store_true')
    return p


if __name__ == '__main__':
    os.umask(0o077); p = parser()
    try:
        print(encoded(run(p.parse_args())).decode())
    except Exception:
        p.exit(2, 'seed export canary refused; no private material exported\n')
