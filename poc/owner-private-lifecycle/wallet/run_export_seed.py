#!/usr/bin/env python3
"""Finite public export canary; one original backup leaf per closed child."""
import argparse
import os
from pathlib import Path
import re
import stat
import subprocess
from paths import ROOT, HostPolicy, checked, digest, encoded, fields, need, parse, write_new
from export_seed_worker import allowlist

CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
PRIVATE_PARENT = Path('/var/tmp/kpi-owner-private-lifecycle-01/private')
WORKER_SHA = '64527cadcd85df584fd3c36b945c2c263978cdd6d055376631027d616c8e6711'


class ExportPolicy(HostPolicy):
    def __init__(self, old, directories):
        super().__init__(old, directories)
        need(checked(PRIVATE_PARENT) in self.new_directories, 'whole-current-private-parent-required')


def registered_originals(labels):
    need(type(labels) is list and len(labels) == len(set(labels)) == 2
         and all(type(label) is str and re.fullmatch('[a-z][a-z0-9-]{0,63}', label) for label in labels),
         'two-explicitly-registered-original-trials')
    return tuple(checked(PRIVATE_PARENT / label / ('party-' + str(i)) / 'owner' / 'BACKUP.json')
                 for label in labels for i in range(3))


def run(a):
    policy = ExportPolicy(a.exclude_old_trial, a.exclude_new_private_parent)
    originals = registered_originals(a.registered_trial)
    identities = set()
    for path in originals:
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600, 'six-original-backup-metadata')
        identities.add((info.st_dev, info.st_ino))
    need(len(identities) == 6, 'six-distinct-original-backups')
    owner = checked(a.owner_leaf)
    need(owner in originals, 'one-exact-registered-original-backup')
    root, private, output = checked(a.public_root), checked(a.private_output), checked(a.output)
    need(root.is_dir() and not private.exists() and private.is_relative_to(PRIVATE_PARENT)
         and not private.is_relative_to(ROOT) and not output.exists()
         and not output.is_relative_to(ROOT)
         and all(not output.is_relative_to(d) for d in policy.directories), 'fresh-public-private-output-boundary')
    need(all(not private.is_relative_to(path.parent) for path in originals), 'controller-outside-original-owners')
    for path in (private, output):
        parent = path.parent
        while not parent.exists():
            parent = parent.parent
        result = subprocess.run(['/usr/bin/git', '-c', 'safe.directory=*', '-C', str(parent),
            'rev-parse', '--is-inside-work-tree'], stdin=subprocess.DEVNULL, capture_output=True, env=CLEAN)
        need(result.returncode != 0 or result.stdout.strip() != b'true', 'canary-output-outside-Git')
    worker = Path(__file__).parent / 'export_seed_worker.py'
    policy.guard([worker, a.allowlist])
    raw_list = policy.read(a.allowlist, a.allowlist_sha256)
    rows, _ = allowlist(raw_list, a.allowlist_sha256)
    candidates = [checked(root / row['path']) for row in rows]
    policy.guard(candidates)
    private.mkdir(parents=True, mode=0o700); output.mkdir(parents=True, mode=0o700)
    source = private / 'worker.py'; write_new(source, policy.read(worker, WORKER_SHA), 0o400)
    public_list = private / 'ALLOWLIST.json'; write_new(public_list, raw_list, 0o400)
    copied = private / 'candidates'; copied.mkdir(mode=0o700)
    for index, (original, row) in enumerate(zip(candidates, rows)):
        raw = policy.read(original, row['sha256']); need(len(raw) == row['bytes'], 'candidate-whole-byte-identity')
        write_new(copied / (str(index) + '.bin'), raw, 0o400)
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        '--ro-bind', str(source), '/check.py', '--ro-bind', str(public_list), '/ALLOWLIST.json',
        '--ro-bind', str(owner), '/BACKUP.json']
    for index in range(len(rows)):
        command += ['--ro-bind', str(copied / (str(index) + '.bin')), '/candidates/' + str(index) + '.bin']
    command += ['--bind', str(output), '/out', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
        '/usr/bin/python3', '-B', '/check.py', '--owner', '/BACKUP.json', '--allowlist', '/ALLOWLIST.json',
        '--allowlist-sha256', a.allowlist_sha256, '--candidates', '/candidates', '--output', '/out/PUBLIC.json']
    write_new(private / 'PRIVATE-PLAN.json', encoded({'command': command, 'publish_or_hash': False}) + b'\n')
    if not a.execute:
        return {'staged': True, 'executed': False}
    process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, env=CLEAN)
    write_new(private / 'PRIVATE-STDOUT.log', process.stdout); write_new(private / 'PRIVATE-STDERR.log', process.stderr)
    need(process.returncode == 0, 'seed-canary-not-complete')
    refreshed = ExportPolicy(a.exclude_old_trial, a.exclude_new_private_parent)
    value = parse(refreshed.read(output / 'PUBLIC.json'))
    fields(value, ('schema', 'status', 'candidate_count', 'candidate_bytes', 'matched_candidate_count', 'scope'),
           'literal-canary-result-fields')
    need(value['schema'] == 'kpx8-new-owner-seed-export-result/v1' and value['status'] in ('PASS', 'FAIL')
         and type(value['candidate_count']) is int and value['candidate_count'] == len(rows) + 1
         and type(value['candidate_bytes']) is int
         and value['candidate_bytes'] == sum(row['bytes'] for row in rows) + len(raw_list)
         and type(value['matched_candidate_count']) is int and 0 <= value['matched_candidate_count'] <= len(rows) + 1
         and (value['status'] == 'PASS') == (value['matched_candidate_count'] == 0)
         and value['scope'] == 'LITERAL_SEED_CANARY_ONLY_NOT_SECURITY_OR_PRIVACY_PROOF', 'bounded-canary-result')
    return value


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('owner-leaf', 'public-root', 'allowlist', 'private-output', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('exclude-old-trial', 'exclude-new-private-parent'):
        p.add_argument('--' + name, type=Path, action='append', required=True)
    p.add_argument('--registered-trial', action='append', required=True)
    p.add_argument('--allowlist-sha256', required=True)
    p.add_argument('--execute', action='store_true')
    return p


if __name__ == '__main__':
    os.umask(0o077); p = parser()
    try:
        print(encoded(run(p.parse_args())).decode())
    except Exception:
        p.exit(2, 'seed export canary refused; no private material exported\n')
