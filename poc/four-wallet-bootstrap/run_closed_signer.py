#!/usr/bin/env python3
"""Stage one frozen GN2 signer with one original backup; default is no execution.

The externally pinned public constructor export replaces host access to the
original owner's private directory. Original backup bytes are never opened,
copied or hashed by this host launcher. This remains a trusted-host experiment.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import uuid

ROOT = Path(__file__).absolute().parents[2]
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
SOURCES = {
    'poc/four-wallet-bootstrap/gn2_common.py': '2f0742ef22eec589978cbc55df20e7acc1c3a95458c46a77b311fc647dcf037b',
    'poc/four-wallet-bootstrap/gn2_backup.py': '8fdf5e01d9b81c99802406276704ddaacd4927d4f48b8432240ec18e6a17efc0',
    'poc/four-wallet-bootstrap/gn2.py': 'cdfcebe9edf2a44306284a38892e44d347a0d68ad901bed03b394e9ce9e51f8c',
    'poc/four-wallet-bootstrap/gn2_selection.py': '5ce6c33efd666ead4aea509f5375e6fb44be639119dbd7b9bf49926c853cec00',
    'poc/four-wallet-bootstrap/gn2_runtime.py': 'bd54ef8e96c0d98e15c16bca4e4100a9d13e999abd96309a7d784f3498628c95',
    'poc/four-wallet-bootstrap/gn2_entry.py': '44982581776a0198e8850ba2622138dbe19dd7c4e0f36e450ec14462d084fcb1',
    'poc/four-wallet-bootstrap/gn2_owner.py': '4e3eecc8eafea01ba811418365bec47c840f41664aa154262985705918817526',
    'poc/four-wallet-bootstrap/sdk.mjs': 'f89eac5f941ac1ed21d5d13b421586448f0a2002f11728599391795aae117af7',
    'poc/compact-batch-lifecycle/primitives.py': '184463d416a8e3c5605ce929bf2cead378c00e82d3827d30c83f8a6e19de5986',
    'poc/future-recipient/v2/recipient.py': '93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2',
    'poc/four-wallet-profile/selection.py': '425469f9e5ed012d43132ae17ac965f7c1bc3b0fdacd7a2ecf8a36a881d90553',
}
RUNTIMES = {
    'crypto': '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff',
    'node': 'd1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c',
    'native-validator': '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061',
}
SDK = {
    'kaspa.js': '6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
    'kaspa_bg.wasm': 'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
    'package.json': '8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0',
}


def need(value, category):
    if not value:
        raise ValueError(category)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def parse(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate-public-JSON-field')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite-public-JSON')))


def sha(value):
    need(type(value) is str and len(value) == 64
         and all(c in '0123456789abcdef' for c in value), 'external-public-SHA256')
    return value


def checked(value):
    path = Path(value)
    need('..' not in path.parts, 'canonical-path')
    path = path.absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink-path')
    return path


def attributes(info):
    return tuple(getattr(info, name) for name in
                 ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


class Exclusions:
    """Metadata-only inventory of exactly two complete original owner trees."""
    def __init__(self, trial_roots):
        roots = tuple(checked(path) for path in trial_roots)
        need(len(roots) == len(set(roots)) == 2, 'two-distinct-original-trials')
        need(all(not root.is_relative_to(ROOT) for root in roots), 'original-trials-outside-project')
        self.backups, directories, identities = {}, [], set()
        for root in roots:
            for role in ('A', 'B', 'C', 'D'):
                folder = checked(root / 'owners' / role)
                need(folder.is_dir(), 'original-owner-directory-metadata')
                need(not folder.is_relative_to(Path('/usr'))
                     and not folder.is_relative_to(Path('/etc/alternatives')),
                     'original-owner-tree-outside-system-mounts')
                path = checked(folder / 'backup.json')
                info = path.lstat()
                need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                     and info.st_nlink == 1, 'original-single-link-backup-metadata')
                self.backups[path] = (role, attributes(info))
                directories.append(folder); identities.add((info.st_dev, info.st_ino))
        need(len(identities) == 8, 'eight-distinct-original-backups')
        self.directories, self.identities = tuple(directories), frozenset(identities)

    def guard(self, paths):
        result = []
        for value in paths:
            path = checked(value)
            need(all(not path.is_relative_to(folder) for folder in self.directories),
                 'public-input-inside-original-owner-tree')
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode)
                 and (info.st_dev, info.st_ino) not in self.identities,
                 'public-input-original-backup-alias-or-type')
            result.append((path, info))
        return tuple(result)

    def read(self, path, expected):
        sha(expected)
        raw = self.read_generated(path)
        need(digest(raw) == expected, 'pinned-public-input')
        return raw

    def read_generated(self, path):
        """Stable public output read; only input read() accepts external pins."""
        ((path, before),) = self.guard((path,))
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            need(stat.S_ISREG(opened.st_mode)
                 and attributes(opened) == attributes(before)
                 and (opened.st_dev, opened.st_ino) not in self.identities,
                 'public-input-swapped-before-first-byte')
            with os.fdopen(os.dup(fd), 'rb') as source:
                raw = source.read()
            after = os.fstat(fd)
            need(attributes(after) == attributes(before) and len(raw) == before.st_size,
                 'stable-public-file')
            return raw
        finally:
            os.close(fd)

    def original(self, value, role):
        path = checked(value)
        need(path in self.backups and self.backups[path][0] == role,
             'one-designated-original-contributor-backup')
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
             and info.st_nlink == 1 and attributes(info) == self.backups[path][1],
             'original-backup-metadata-unchanged')
        return path


def members():
    result = [('runtime-source/' + name, '/work/' + name, pin, False)
              for name, pin in SOURCES.items()]
    result += [('runtime/' + name, '/runtime/' + name, pin, True)
               for name, pin in RUNTIMES.items()]
    result += [('runtime-sdk/' + name, '/runtime/sdk/' + name, pin, False)
               for name, pin in SDK.items()]
    return tuple(result)


def write_new(path, raw, mode=0o400):
    path = checked(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as target:
        os.fchmod(target.fileno(), mode); target.write(raw); target.flush(); os.fsync(target.fileno())


def outside_git(path):
    parent = path if path.is_dir() else path.parent
    while not parent.exists():
        parent = parent.parent
    result = subprocess.run(['/usr/bin/git', '-c', 'safe.directory=*', '-C', str(parent),
        'rev-parse', '--is-inside-work-tree'], capture_output=True, text=True, env=CLEAN)
    need(result.returncode != 0 or result.stdout.strip() != 'true', 'controller-outside-Git')


def fresh_output(value, excluded, software_root):
    path = checked(value)
    need(not path.exists() and not path.is_relative_to(ROOT)
         and not path.is_relative_to(software_root)
         and all(not path.is_relative_to(folder) for folder in excluded.directories),
         'fresh-controller-outside-source-and-original-owner-trees')
    outside_git(path)
    return path


def run(a):
    started = time.monotonic()
    trial = uuid.UUID(a.trial_id)
    need(trial.version == 4 and trial.variant == uuid.RFC_4122 and str(trial) == a.trial_id,
         'canonical-trial-UUIDv4')
    need(a.role in ('A', 'C'), 'initial-contributor-role')
    excluded = Exclusions(a.exclude_trial_directory)
    backup = excluded.original(a.backup, a.role)
    root = checked(a.software_root)
    rows = members()
    public = [('profile.json', a.profile, sha(a.profile_sha256)),
              ('case.json', a.case, sha(a.case_sha256)),
              ('owner-init.json', a.owner_public, sha(a.owner_public_sha256))]
    output, staged, inputs = stage(excluded, root, a.output, rows, public, a.exclude_trial_directory)
    client = output / 'client'; client.mkdir(mode=0o700)
    command = sandbox(staged, inputs, ('profile.json', 'case.json'))
    command += ['--ro-bind', str(backup), '/owner/backup.json',
        '--ro-bind', str(inputs / 'owner-init.json'), '/owner/owner-init.json',
        '--bind', str(client), '/out', '--chdir', '/work/poc/four-wallet-bootstrap',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC',
        '/usr/bin/python3', '-B', '/work/poc/four-wallet-bootstrap/gn2_owner.py', 'sign-entry',
        '--owner', '/owner', '--profile', '/profile.json', '--profile-sha256', a.profile_sha256,
        '--case', '/case.json', '--trial-id', a.trial_id, '--output', '/out/run',
        '--fee-rate', '100', '--crypto', '/runtime/crypto', '--node', '/runtime/node',
        '--native', '/runtime/native-validator', '--sdk-dir', '/runtime/sdk']
    # This private local plan contains the opaque original backup handle. Do
    # not publish/hash it or treat preparation as an executed owner approval.
    write_new(output / 'PRIVATE-PLAN.json', encoded({'command': command,
        'publish_or_hash': False}) + b'\n', 0o600)
    receipt = {'schema': 'kpx6-closed-GN2-signer-launch/v1', 'role': a.role,
        'trial_id': a.trial_id, 'financial_profile_sha256': a.profile_sha256,
        'proposed_case_sha256': a.case_sha256, 'owner_public_sha256': a.owner_public_sha256,
        'excluded_original_backup_count': 8, 'excluded_original_owner_directory_count': 8,
        'original_backup_contents_read_copied_or_hashed_by_host': False,
        'original_owner_directories_mounted': False, 'one_original_backup_readonly_mount_planned': True,
        'public_record_readonly_mode': '0400', 'reference_fee_rate': 100,
        'executed': False, 'approval_exported': False, 'PK_prover_network_or_submission': False,
        'source_members': [{'path': relative, 'sha256': pin} for relative, _, pin, _ in rows]}
    if a.execute:
        excluded.original(backup, a.role)
        result = subprocess.run(command, capture_output=True, text=True, env=CLEAN)
        write_new(output / 'PRIVATE-STDOUT.log', result.stdout.encode(), 0o600)
        write_new(output / 'PRIVATE-STDERR.log', result.stderr.encode(), 0o600)
        need(result.returncode == 0, 'isolated-owner-signature-refused')
        approval = parse(result.stdout)
        path = client / 'run/APPROVAL.json'
        ((_, info),) = excluded.guard((path,))
        need(stat.S_IMODE(info.st_mode) == 0o400, 'immutable-public-signature-export')
        actual = parse(excluded.read(path, digest(encoded(approval) + b'\n')))
        need(actual == approval and approval['schema'] == 'kpx6-GN2-owner-approval/v1'
             and approval['trial_id'] == a.trial_id
             and approval['financial_profile_sha256'] == a.profile_sha256
             and approval['input_index'] == (0 if a.role == 'A' else 1)
             and approval['own_receipt_rederived'] is True, 'exact-own-public-signature-export')
        receipt.update({'executed': True, 'approval_exported': True,
                        'approval_path': str(path), 'wall_seconds': time.monotonic() - started})
    write_new(output / 'RESULTS.json', encoded(receipt) + b'\n')
    return receipt


def stage(excluded, root, output_value, rows, public, trial_roots):
    """Shared fixed public ingress; source-only and no backup content IO."""
    # The complete fixed list is materialized before the FIRST public byte.
    excluded.guard([*(root / row[0] for row in rows), *(row[1] for row in public)])
    for original_root in trial_roots:
        outside_git(checked(original_root))
    output = fresh_output(output_value, excluded, root)
    output.mkdir(parents=True, mode=0o700)
    staged = []
    for relative, destination, pin, executable in rows:
        raw = excluded.read(root / relative, pin)
        if executable:
            need(raw[:4] == b'\x7fELF', 'selected-runtime-ELF')
        target = output / 'software' / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, raw, 0o500 if executable else 0o400)
        staged.append((target, destination))
    inputs = output / 'public-inputs'; inputs.mkdir(mode=0o700)
    for name, path, pin in public:
        write_new(inputs / name, excluded.read(path, pin))
    return output, staged, inputs


def sandbox(staged, inputs, names):
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']
    for source, destination in staged:
        command += ['--ro-bind', str(source), destination]
    for name in names:
        command += ['--ro-bind', str(inputs / name), '/' + name]
    return command


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('software-root', 'backup', 'owner-public', 'profile', 'case', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('owner-public-sha256', 'profile-sha256', 'case-sha256', 'trial-id'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--role', choices=('A', 'C'), required=True)
    p.add_argument('--exclude-trial-directory', type=Path, action='append', required=True)
    p.add_argument('--execute', action='store_true')
    return p


if __name__ == '__main__':
    os.umask(0o077)
    p = parser()
    try:
        print(encoded(run(p.parse_args())).decode())
    except (ValueError, OSError, KeyError, TypeError, UnicodeError):
        p.exit(1, 'closed owner approval incomplete; no submission performed\n')
