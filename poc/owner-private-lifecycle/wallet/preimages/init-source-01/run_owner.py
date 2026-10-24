#!/usr/bin/env python3
"""Trusted launcher: private staging/logs and one public export leaf."""
import argparse
import os
from pathlib import Path
import stat
import subprocess
from paths import ROOT, HostPolicy, checked, digest, encoded, fields, hx, need, parse, write_new
from support import DOMAIN, CRYPTO_SHA

OWN = ('paths.py', 'support.py', 'worker.py', 'history.py', 'trees.py')
REFERENCE = 'poc/future-recipient/v2/recipient.py'
REFERENCE_SHA = '93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
PRIVATE_PARENT = Path('/var/tmp/kpi-owner-private-lifecycle-01/private')
SCHEMAS = {'init': 'kpx8-owner-initial-public/v1', 'restore': 'kpx8-owner-restored/v1',
    'invoice': 'kpx8-owner-invoices-ready/v1', 'scan': 'kpx8-owner-scan-complete/v1',
    'prepare': 'kpx8-owner-input-ready/v1', 'authorize': 'kpx8-owner-spend-authorization/v1',
    'exit-ready': 'kpx8-owner-exit-ready/v1', 'exit': 'kpx8-owner-exit-authorization/v1'}


def directory(value, private, policy):
    path = checked(value)
    need(not path.exists() and not path.is_relative_to(ROOT), 'fresh-outside-source-directory')
    need(any(path.is_relative_to(p) for p in policy.new_directories) == private, 'private-public-runtime-boundary')
    need(private or not any(path.is_relative_to(p) for p in policy.directories), 'public-output-outside-private-trees')
    parent = path.parent
    while not parent.exists():
        parent = parent.parent
    result = subprocess.run(['/usr/bin/git', '-c', 'safe.directory=*', '-C', str(parent),
        'rev-parse', '--is-inside-work-tree'], capture_output=True, text=True, env=CLEAN)
    need(result.returncode != 0 or result.stdout.strip() != 'true', 'runtime-outside-Git')
    path.mkdir(parents=True, mode=0o700)
    return path


def run(a):
    policy = HostPolicy(a.exclude_old_trial, a.exclude_new_private_directory)
    need(checked(PRIVATE_PARENT) in policy.new_directories, 'whole-private-parent-required')
    owner, mpc = checked(a.owner_directory), checked(a.mpc_directory)
    need(owner.is_dir() and mpc.is_dir() and owner != mpc
         and not owner.is_relative_to(mpc) and not mpc.is_relative_to(owner)
         and all(any(p.is_relative_to(d) for d in policy.new_directories) for p in (owner, mpc)), 'own-private-mounts')
    peers = tuple(checked(p) for p in (a.peer_owner_directory or []))
    if a.operation == 'prepare':
        need(len(peers) == len(set(peers)) == 3 and owner in peers
             and all(p.is_dir() and any(p.is_relative_to(d) for d in policy.new_directories) for p in peers), 'three-private-peers')
    sources = [Path(__file__).parent / n for n in OWN] + [ROOT / REFERENCE]
    public_paths = list(sources)
    for name in ('assets', 'session', 'context', 'projection', 'history'):
        if getattr(a, name) is not None:
            public_paths.append(getattr(a, name))
    if a.operation == 'init':
        need(a.crypto is not None and a.participant_id is not None and a.position is not None
             and a.admission_sompi is not None, 'complete-init-selection')
        public_paths.append(a.crypto)
    if a.operation not in ('init', 'restore'):
        need(all(getattr(a, n) is not None for n in ('assets', 'assets_sha256', 'context',
             'context_sha256', 'history', 'history_sha256')), 'complete-selected-history')
    if a.operation in ('invoice', 'prepare', 'authorize'):
        need(a.session is not None and a.session_sha256 is not None, 'selected-session')
    if a.operation in ('authorize', 'exit'):
        need(a.projection is not None and a.projection_sha256 is not None, 'selected-projection')
    if a.operation == 'prepare':
        need(type(a.party) is int and 0 <= a.party < 3, 'prepare-party')
    policy.guard(public_paths)
    assets = None; binaries, parameters, extras = [], [], []
    if a.operation == 'init':
        binaries.append(('crypto', checked(a.crypto), CRYPTO_SHA))
    elif a.operation != 'restore':
        assets = parse(policy.read(a.assets, a.assets_sha256))
        fields(assets, ('schema', 'domain_hex32', 'component_profile', 'component_profile_sha256', 'relation',
            'crypto', 'spend', 'output', 'exit', 'codec_sha256', 'wire_sha256', 'program_source_sha256'), 'assets-fields')
        need(assets['schema'] == 'kpx8-wallet-assets/v1' and assets['domain_hex32'] == DOMAIN.hex(), 'new-lifecycle-assets')
        parameters.append(('component-profile.json', checked(assets['component_profile']), assets['component_profile_sha256']))
        for role in ('relation', 'crypto'):
            fields(assets[role], ('path', 'sha256'), 'selected-program-fields')
            binaries.append((role, checked(assets[role]['path']), assets[role]['sha256']))
        need(assets['crypto']['sha256'] == CRYPTO_SHA, 'fixed-crypto-identity')
        for role in ('spend', 'output', 'exit'):
            row = assets[role]; fields(row, ('manifest', 'manifest_sha256', 'pk', 'pk_sha256'), 'parameter-fields')
            parameters.append((role + '.json', checked(row['manifest']), row['manifest_sha256']))
            if (a.operation, role) in (('prepare', 'output'), ('authorize', 'spend'), ('exit', 'exit')):
                parameters.append((role + '.pk', checked(row['pk']), row['pk_sha256']))
        extras = [(ROOT / 'poc/owner-private-lifecycle/integration/construction/codec.py',
                   'poc/owner-private-lifecycle/integration/construction/codec.py', assets['codec_sha256']),
                  (ROOT / 'poc/owner-private-lifecycle/verification/wire.py',
                   'poc/owner-private-lifecycle/verification/wire.py', assets['wire_sha256'])]
        policy.guard([*(p for _, p, _ in binaries), *(p for _, p, _ in parameters), *(p for p, _, _ in extras)])
    if a.operation == 'restore':
        need(a.backup is not None, 'one-original-backup-required')
        backup = checked(a.backup); info = backup.lstat()
        need(any(backup.is_relative_to(d) for d in policy.new_directories)
             and not backup.is_relative_to(owner) and not backup.is_relative_to(mpc)
             and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600, 'one-original-backup-leaf-metadata')
    if a.operation == 'authorize':
        need(a.own_mpc_result is not None and not a.own_mpc_result.is_absolute()
             and '..' not in a.own_mpc_result.parts and a.own_mpc_result.name == 'OWN-MPC-PROJECTION.json', 'own-engine-selector')
        info = checked(mpc / a.own_mpc_result).lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'own-engine-result-metadata')
    if a.operation == 'prepare':
        for peer in peers:
            info = checked(peer / ('RECEIVE-INVOICE-' + str(a.party) + '.bin')).lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                 and stat.S_IMODE(info.st_mode) == 0o400 and info.st_size == 240, 'designated-peer-invoice')
    private_run = directory(a.private_run_directory, True, policy)
    need(not private_run.is_relative_to(owner) and not private_run.is_relative_to(mpc), 'separate-private-controller')
    output = directory(a.output, False, policy)
    software = private_run / 'software'; software.mkdir(mode=0o700)
    staged = []
    for path in sources:
        relative = str(path.relative_to(ROOT)); raw = policy.read(path)
        if relative == REFERENCE:
            need(digest(raw) == REFERENCE_SHA, 'selected-recipient-source')
        target = software / relative; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, raw, 0o400); staged.append((target, '/work/' + relative))
    for path, relative, pin in extras:
        raw = policy.read(path, pin); target = software / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, raw, 0o400); staged.append((target, '/work/' + relative))
    runtime = private_run / 'runtime'; runtime.mkdir(mode=0o700)
    for role, path, pin in binaries:
        raw = policy.read(path, pin); need(raw[:4] == b'\x7fELF', 'selected-runtime-ELF')
        write_new(runtime / role, raw, 0o500); staged.append((runtime / role, '/runtime/' + role))
    for name, path, pin in parameters:
        policy.read(path, pin); staged.append((path, '/parameters/' + name))
    inputs = private_run / 'inputs'; inputs.mkdir(mode=0o700)
    for name in ('session', 'context', 'projection', 'history'):
        path = getattr(a, name)
        if path is not None:
            pin = getattr(a, name + '_sha256'); need(pin is not None, 'externally-pinned-public-input')
            write_new(inputs / name, policy.read(path, pin), 0o400); staged.append((inputs / name, '/' + name))
    if assets is not None:
        assets['component_profile'] = '/parameters/component-profile.json'
        for role in ('relation', 'crypto'):
            assets[role]['path'] = '/runtime/' + role
        for role in ('spend', 'output', 'exit'):
            assets[role]['manifest'] = '/parameters/' + role + '.json'; assets[role]['pk'] = '/parameters/' + role + '.pk'
        assets_raw = encoded(assets) + b'\n'; write_new(inputs / 'assets.json', assets_raw, 0o400)
        staged.append((inputs / 'assets.json', '/assets.json'))
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']
    for original, target in staged:
        command += ['--ro-bind', str(original), target]
    command += ['--bind', str(owner), '/private', '--bind', str(mpc), '/mpc', '--bind', str(output), '/out']
    if a.operation == 'restore':
        command += ['--ro-bind', str(backup), '/backup.json']
    if a.operation == 'prepare':
        for index, peer in enumerate(peers):
            command += ['--ro-bind', str(peer / ('RECEIVE-INVOICE-' + str(a.party) + '.bin')), '/peers/' + str(index) + '.bin']
    command += ['--chdir', '/work/poc/owner-private-lifecycle/wallet', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC', '/usr/bin/python3', '-B',
        '/work/poc/owner-private-lifecycle/wallet/worker.py', a.operation,
        '--owner', '/private', '--mpc', '/mpc', '--output', '/out']
    if a.operation == 'init':
        command += ['--crypto', '/runtime/crypto', '--participant-id', a.participant_id,
            '--position', str(a.position), '--admission-sompi', str(a.admission_sompi)]
    elif a.operation == 'restore':
        command += ['--backup', '/backup.json']
    else:
        command += ['--assets', '/assets.json', '--assets-sha256', digest(assets_raw),
            '--context', '/context', '--context-sha256', a.context_sha256,
            '--history', '/history', '--history-sha256', a.history_sha256]
        if a.operation in ('invoice', 'prepare', 'authorize'):
            command += ['--session', '/session', '--session-sha256', a.session_sha256]
        if a.operation == 'prepare':
            command += ['--party', str(a.party)]
        if a.operation in ('prepare', 'exit-ready'):
            command += ['--note-kind', a.note_kind]
        if a.operation in ('authorize', 'exit'):
            command += ['--projection', '/projection', '--projection-sha256', a.projection_sha256]
        if a.operation == 'authorize':
            command += ['--own-mpc-result', str(a.own_mpc_result)]
    write_new(private_run / 'PRIVATE-PLAN.json', encoded({'command': command, 'publish_or_hash': False}) + b'\n')
    if not a.execute:
        return {'operation': a.operation, 'staged': True, 'executed': False}
    result = subprocess.run(command, capture_output=True, env=CLEAN)
    write_new(private_run / 'PRIVATE-STDOUT.log', result.stdout); write_new(private_run / 'PRIVATE-STDERR.log', result.stderr)
    need(result.returncode == 0, 'isolated-owner-operation-refused')
    refreshed = HostPolicy(a.exclude_old_trial, a.exclude_new_private_directory)
    value = parse(refreshed.read(output / 'PUBLIC.json'))
    need(value.get('schema') == SCHEMAS[a.operation], 'fixed-public-owner-export')
    return {'operation': a.operation, 'completed': True}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=tuple(SCHEMAS))
    for name in ('owner-directory', 'mpc-directory', 'output', 'private-run-directory'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('exclude-old-trial', 'exclude-new-private-directory'):
        p.add_argument('--' + name, type=Path, action='append', required=True)
    p.add_argument('--peer-owner-directory', type=Path, action='append')
    for name in ('crypto', 'assets', 'session', 'context', 'projection', 'history', 'backup'):
        p.add_argument('--' + name, type=Path)
    for name in ('assets-sha256', 'session-sha256', 'context-sha256', 'projection-sha256', 'history-sha256', 'participant-id'):
        p.add_argument('--' + name)
    for name in ('position', 'admission-sompi', 'party'):
        p.add_argument('--' + name, type=int)
    p.add_argument('--note-kind', choices=('initial', 'received', 'change', 'any', 'received-or-change'), default='any')
    p.add_argument('--own-mpc-result', type=Path)
    p.add_argument('--execute', action='store_true')
    return p


if __name__ == '__main__':
    os.umask(0o077); p = parser()
    try:
        print(encoded(run(p.parse_args())).decode())
    except Exception:
        p.exit(2, 'owner launcher refused; no private material exported\n')
