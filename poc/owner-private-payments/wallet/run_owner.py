#!/usr/bin/env python3
"""Trusted launcher; coordinator never receives private mounts, argv or maps."""
import argparse
import os
from pathlib import Path
import stat
import subprocess

from paths import (ROOT, HostPolicy, checked, digest, encoded, fields, hx,
                   need, parse, write_new)
from support import CRYPTO_SHA, DOMAIN

OWN = ('paths.py', 'support.py', 'worker.py')
REFERENCE = 'poc/future-recipient/v2/recipient.py'
REFERENCE_SHA = '93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def output_directory(value, policy):
    path = checked(value)
    need(not path.exists() and not path.is_relative_to(ROOT)
         and all(not path.is_relative_to(d) for d in policy.directories),
         'fresh-public-export-outside-all-private-trees')
    parent = path.parent
    while not parent.exists():
        parent = parent.parent
    result = subprocess.run(['/usr/bin/git', '-c', 'safe.directory=*', '-C', str(parent),
        'rev-parse', '--is-inside-work-tree'], capture_output=True, text=True, env=CLEAN)
    need(result.returncode != 0 or result.stdout.strip() != 'true', 'owner-output-outside-Git')
    return path


def run(a):
    policy = HostPolicy(a.exclude_old_trial, a.exclude_new_private_directory)
    owner, mpc = checked(a.owner_directory), checked(a.mpc_directory)
    peers = tuple(checked(p) for p in a.peer_owner_directory)
    parents = set(policy.new_directories)
    need(len(peers) == len(set(peers)) == 3
         and {p.parent for p in peers} == parents
         and all(p.name == 'owner' for p in peers)
         and owner in peers and mpc == owner.parent / 'mpc'
         and owner.is_dir() and mpc.is_dir(), 'one-own-owner-and-MPC-leaf')
    for parent in parents:
        need((parent / 'owner').is_dir() and (parent / 'mpc').is_dir(), 'private-owner-and-MPC-children')
    # Selected launcher code is trusted. Every source copied into a child and
    # every caller data/asset path is excluded BEFORE its first byte/hash.
    source_paths = [Path(__file__).parent / name for name in OWN]
    source_paths += [ROOT / REFERENCE]
    public_paths = list(source_paths)
    for name in ('assets', 'session', 'context', 'projection'):
        value = getattr(a, name)
        if value is not None:
            public_paths.append(value)
    if a.operation == 'init':
        need(a.crypto is not None and a.participant_id is not None
             and a.position is not None and a.admission_sompi is not None, 'complete-init-selection')
        public_paths.append(a.crypto)
    else:
        need(a.assets is not None and a.assets_sha256 is not None
             and a.session is not None and a.session_sha256 is not None, 'complete-owner-public-selection')
    policy.guard(public_paths)
    assets = None
    binaries, parameters, extra_sources = [], [], []
    if a.operation == 'init':
        binaries = [('crypto', checked(a.crypto), CRYPTO_SHA)]
    else:
        assets = parse(policy.read(a.assets, a.assets_sha256))
        fields(assets, ('schema', 'domain_hex32', 'component_profile', 'component_profile_sha256', 'relation', 'crypto',
            'spend', 'output', 'codec_sha256', 'wire_sha256'), 'wallet-assets-fields')
        need(assets['schema'] == 'kpx7-wallet-assets/v1' and assets['domain_hex32'] == DOMAIN.hex(),
             'new-domain-wallet-assets')
        hx(assets['component_profile_sha256'], 32)
        parameters.append(('component-profile.json', checked(assets['component_profile']),
                           assets['component_profile_sha256']))
        for role in ('relation', 'crypto'):
            fields(assets[role], ('path', 'sha256'), 'fixed-program-selection')
            hx(assets[role]['sha256'], 32)
            binaries.append((role, checked(assets[role]['path']), assets[role]['sha256']))
        need(assets['crypto']['sha256'] == CRYPTO_SHA, 'existing-crypto-identity')
        for role in ('spend', 'output'):
            fields(assets[role], ('manifest', 'manifest_sha256', 'pk', 'pk_sha256'), 'parameter-selection')
            hx(assets[role]['manifest_sha256'], 32); hx(assets[role]['pk_sha256'], 32)
            parameters += [(role + '.json', checked(assets[role]['manifest']), assets[role]['manifest_sha256'])]
            # Authorization verifies Output proofs using its VK, so the
            # output PK need not be present for that operation.
            if a.operation == 'prepare' and role == 'output' or a.operation == 'authorize' and role == 'spend':
                parameters += [(role + '.pk', checked(assets[role]['pk']), assets[role]['pk_sha256'])]
        for family, name in (('construction', 'codec.py'), ('verification', 'wire.py')):
            relative = 'poc/owner-private-payments/' + family + '/' + name
            expected = assets['codec_sha256'] if family == 'construction' else assets['wire_sha256']
            hx(expected, 32); extra_sources.append((ROOT / relative, relative, expected))
        policy.guard([*(p for _, p, _ in binaries), *(p for _, p, _ in parameters),
                      *(p for p, _, _ in extra_sources)])
    if a.operation == 'prepare':
        need(a.context is not None and a.context_sha256 is not None
             and type(a.party) is int and 0 <= a.party < 3, 'complete-prepare-selection')
    if a.operation == 'authorize':
        need(a.projection is not None and a.projection_sha256 is not None
             and a.own_mpc_result is not None, 'complete-authorize-selection')
        relative = a.own_mpc_result
        need(not relative.is_absolute() and '..' not in relative.parts
             and str(relative) != '.' and relative.name == 'OWN-MPC-PROJECTION.json',
             'own-private-engine-result-selector')
        # Metadata only; its contents go directly to its owning worker.
        own_result = checked(mpc / relative); info = own_result.stat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'own-MPC-result-metadata')
    if a.operation == 'prepare':
        for peer in peers:
            path = checked(peer / ('RECEIVE-INVOICE-' + str(a.party) + '.bin')); info = path.stat()
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                 and stat.S_IMODE(info.st_mode) == 0o400 and info.st_size == 240,
                 'designated-private-peer-invoice-metadata')
    output = output_directory(a.output, policy)
    output.mkdir(parents=True, mode=0o700)
    software = output / 'software'; software.mkdir(mode=0o700)
    staged = []
    for path in source_paths:
        relative = str(path.relative_to(ROOT)); raw = policy.read(path)
        if relative == REFERENCE:
            need(digest(raw) == REFERENCE_SHA, 'existing-recipient-source')
        target = software / relative; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, raw, 0o400); staged.append((target, '/work/' + relative))
    for path, relative, expected in extra_sources:
        raw = policy.read(path, expected); target = software / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, raw, 0o400); staged.append((target, '/work/' + relative))
    runtime = output / 'runtime'; runtime.mkdir(mode=0o700)
    for role, original, expected in binaries:
        raw = policy.read(original, expected); need(raw[:4] == b'\x7fELF', 'selected-runtime-ELF')
        write_new(runtime / role, raw, 0o500)
        staged.append((runtime / role, '/runtime/' + role))
    for name, original, expected in parameters:
        # Authenticate full public parameter bytes before binding their
        # immutable source into a worker. No private material is copied.
        policy.read(original, expected); staged.append((original, '/parameters/' + name))
    inputs = output / 'inputs'; inputs.mkdir(mode=0o700)
    for name in ('session', 'context', 'projection'):
        path = getattr(a, name)
        if path is not None:
            expected = getattr(a, name + '_sha256')
            need(expected is not None, 'externally-pinned-public-input')
            write_new(inputs / name, policy.read(path, expected), 0o400)
            staged.append((inputs / name, '/' + name))
    if assets is not None:
        assets['component_profile'] = '/parameters/component-profile.json'
        for role in ('relation', 'crypto'):
            assets[role]['path'] = '/runtime/' + role
        for role in ('spend', 'output'):
            assets[role]['manifest'] = '/parameters/' + role + '.json'
            assets[role]['pk'] = '/parameters/' + role + '.pk'
        raw_assets = encoded(assets) + b'\n'; write_new(inputs / 'assets.json', raw_assets, 0o400)
        staged.append((inputs / 'assets.json', '/assets.json'))
    public = output / 'public'; public.mkdir(mode=0o700)
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']
    for original, target in staged:
        command += ['--ro-bind', str(original), target]
    command += ['--bind', str(owner), '/private', '--bind', str(mpc), '/mpc',
                '--bind', str(public), '/out']
    if a.operation == 'prepare':
        for index, peer in enumerate(peers):
            command += ['--ro-bind', str(peer / ('RECEIVE-INVOICE-' + str(a.party) + '.bin')),
                        '/peers/' + str(index) + '.bin']
    command += ['--chdir', '/work/poc/owner-private-payments/wallet', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC', '/usr/bin/python3', '-B',
        '/work/poc/owner-private-payments/wallet/worker.py', a.operation,
        '--owner', '/private', '--mpc', '/mpc', '--output', '/out']
    if a.operation == 'init':
        command += ['--crypto', '/runtime/crypto', '--participant-id', a.participant_id,
                    '--position', str(a.position), '--admission-sompi', str(a.admission_sompi)]
    else:
        command += ['--assets', '/assets.json', '--assets-sha256', digest(raw_assets),
                    '--session', '/session', '--session-sha256', a.session_sha256]
    if a.operation == 'prepare':
        command += ['--context', '/context', '--context-sha256', a.context_sha256, '--party', str(a.party)]
    if a.operation == 'authorize':
        command += ['--projection', '/projection', '--projection-sha256', a.projection_sha256,
                    '--own-mpc-result', str(a.own_mpc_result)]
    write_new(output / 'PRIVATE-PLAN.json', encoded({'command': command, 'publish_or_hash': False}) + b'\n')
    if not a.execute:
        return {'operation': a.operation, 'staged': True, 'executed': False}
    # No public completion timing or private handles are exported. The trusted
    # supervisor waits for all owners before starting the untrusted coordinator.
    result = subprocess.run(command, capture_output=True, env=CLEAN)
    write_new(output / 'PRIVATE-STDOUT.log', result.stdout)
    write_new(output / 'PRIVATE-STDERR.log', result.stderr)
    need(result.returncode == 0, 'isolated-owner-operation-refused')
    refreshed = HostPolicy(a.exclude_old_trial, a.exclude_new_private_directory)
    value = parse(refreshed.read(public / 'PUBLIC.json'))
    expected = {'init': 'kpx7-unfunded-owner-public/v1', 'prepare': 'kpx7-owner-input-ready/v1',
                'authorize': 'kpx7-owner-spend-authorization/v1'}[a.operation]
    need(value.get('schema') == expected, 'fixed-public-owner-export')
    return {'operation': a.operation, 'completed': True}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('init', 'prepare', 'authorize'))
    for name in ('owner-directory', 'mpc-directory', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('exclude-old-trial', 'exclude-new-private-directory', 'peer-owner-directory'):
        p.add_argument('--' + name, type=Path, action='append', required=True)
    for name in ('crypto', 'assets', 'session', 'context', 'projection'):
        p.add_argument('--' + name, type=Path)
    for name in ('assets-sha256', 'session-sha256', 'context-sha256', 'projection-sha256', 'participant-id'):
        p.add_argument('--' + name)
    for name in ('position', 'admission-sompi', 'party'):
        p.add_argument('--' + name, type=int)
    p.add_argument('--own-mpc-result', type=Path)
    p.add_argument('--execute', action='store_true')
    return p


if __name__ == '__main__':
    os.umask(0o077)
    p = parser()
    try:
        print(encoded(run(p.parse_args())).decode())
    except Exception:
        p.exit(2, 'owner launcher refused; no private material exported\n')
