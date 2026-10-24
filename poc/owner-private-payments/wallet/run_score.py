#!/usr/bin/env python3
"""Trusted supervisor for sealed observer/count-only diagnostic namespaces."""
import argparse
import os
from pathlib import Path
import stat
import subprocess

from paths import ROOT, HostPolicy, checked, digest, encoded, fields, hx, need, parse, write_new
from support import CRYPTO_SHA, DOMAIN
from score_codec import EXPERIMENT, CAPSULE_BYTES, COUNT_BYTES

CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
FIXED = {
    'paths.py': 'd998d2d7a65199c8742ec4a35f81cf7aeb83316003c73e663e8566c74840c1a2',
    'support.py': 'eab2f445918277e3309c2f5c69e86843b92d16c701b3a02ac93f66e7b13b7e59',
    'worker.py': '83ab974132abfe0e285e8ffbdb8604ec1fdaaae4e3d7274a28dd37dda98fd8ba',
}
REFERENCE = 'poc/future-recipient/v2/recipient.py'
REFERENCE_SHA = '93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2'
PUBLIC_NAMES = ('assets', 'session', 'projection', 'registry', 'predictions', 'observer_receipt', 'bundle')


def private_leaf(path, name, width, policy):
    path = checked(path)
    need(any(path == root / 'owner' / 'diagnostics' / name for root in policy.new_directories),
         'only-exact-restricted-diagnostic-leaf')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o400 and info.st_size == width,
         'fixed-private-leaf-metadata')
    return path, (info.st_dev, info.st_ino)


def fresh_output(path, policy):
    path = checked(path)
    need(not path.exists() and not path.is_relative_to(ROOT)
         and all(not path.is_relative_to(d) for d in policy.directories), 'fresh-private-controller-output')
    parent = path.parent
    while not parent.exists():
        parent = parent.parent
    probe = subprocess.run(['/usr/bin/git', '-c', 'safe.directory=*', '-C', str(parent),
                            'rev-parse', '--is-inside-work-tree'], capture_output=True, env=CLEAN)
    need(probe.returncode != 0 or probe.stdout.strip() != b'true', 'diagnostic-controller-outside-Git')
    return path


def run(a):
    need(a.experiment_sha256 == EXPERIMENT, 'hard-selected-frozen-experiment')
    policy = HostPolicy(a.exclude_old_trial, a.exclude_new_private_directory)
    source = Path(__file__).parent
    sources = [(source / name, 'poc/owner-private-payments/wallet/' + name, pin)
               for name, pin in FIXED.items()]
    sources += [(source / name, 'poc/owner-private-payments/wallet/' + name, None)
                for name in ('score_codec.py', 'score_worker.py')]
    if a.operation != 'aggregate':
        sources.append((ROOT / REFERENCE, REFERENCE, REFERENCE_SHA))
        for name in ('assets', 'session', 'projection'):
            need(getattr(a, name) is not None and getattr(a, name + '_sha256') is not None,
                 'complete-selected-diagnostic-public-inputs')
        owner = checked(a.owner_directory); mpc = owner.parent / 'mpc'
        need(owner.name == 'owner' and owner.parent in policy.new_directories
             and owner.is_dir() and mpc.is_dir(), 'one-own-original-private-party')
        if a.operation == 'observe':
            need(a.registry is not None and a.registry_sha256 is not None, 'actual-public-admission-priors')
        else:
            for name in ('predictions', 'observer_receipt', 'bundle'):
                need(getattr(a, name) is not None and getattr(a, name + '_sha256') is not None,
                     'complete-presealed-two-view-bundle')
    public = [p for p, _, _ in sources]
    public += [getattr(a, name) for name in PUBLIC_NAMES if getattr(a, name) is not None]
    policy.guard(public)
    assets, assets_raw, binaries, parameters = None, None, [], []
    if a.operation != 'aggregate':
        assets_raw = policy.read(a.assets, a.assets_sha256); assets = parse(assets_raw)
        fields(assets, ('schema', 'domain_hex32', 'component_profile', 'component_profile_sha256',
            'relation', 'crypto', 'spend', 'output', 'codec_sha256', 'wire_sha256'), 'fixed-wallet-assets-fields')
        need(assets['schema'] == 'kpx7-wallet-assets/v1' and assets['domain_hex32'] == DOMAIN.hex(),
             'selected-new-domain-assets')
        hx(assets['component_profile_sha256'], 32)
        parameters.append((checked(assets['component_profile']), '/parameters/component-profile.json',
                           assets['component_profile_sha256']))
        for role in ('relation', 'crypto'):
            fields(assets[role], ('path', 'sha256'), 'fixed-program-fields')
            binaries.append((checked(assets[role]['path']), '/runtime/' + role, assets[role]['sha256']))
        need(assets['crypto']['sha256'] == CRYPTO_SHA, 'selected-existing-crypto-identity')
        for role in ('spend', 'output'):
            fields(assets[role], ('manifest', 'manifest_sha256', 'pk', 'pk_sha256'), 'parameter-selector-fields')
            parameters.append((checked(assets[role]['manifest']), '/parameters/' + role + '.json',
                               assets[role]['manifest_sha256']))
        # No PK is collected, copied, read, hashed or mounted for diagnostics.
        for family, name, key in (('construction', 'codec.py', 'codec_sha256'),
                                  ('verification', 'wire.py', 'wire_sha256')):
            relative = 'poc/owner-private-payments/' + family + '/' + name
            sources.append((ROOT / relative, relative, assets[key]))
        policy.guard([*(p for p, _, _ in sources), *(p for p, _, _ in binaries),
                      *(p for p, _, _ in parameters)])
    restricted = []
    if a.operation == 'score':
        capsule, _ = private_leaf(a.capsule, 'OBSERVER-CAPSULE.bin', CAPSULE_BYTES, policy)
        restricted.append((capsule, '/observer/CAPSULE.bin'))
    if a.operation == 'aggregate':
        need(a.observer_receipt is not None and a.observer_receipt_sha256 is not None
             and a.bundle is not None and a.bundle_sha256 is not None, 'presealed-public-ambiguity-before-aggregation')
        need(a.count_file is not None and len(a.count_file) == 3, 'all-three-private-count-leaves')
        leaves = [private_leaf(p, 'COUNTS.bin', COUNT_BYTES, policy) for p in a.count_file]
        need(len({identity for _, identity in leaves}) == 3
             and {p.parents[2] for p, _ in leaves} == set(policy.new_directories),
             'three-distinct-complete-private-count-parents')
        restricted = [(p, '/counts/' + str(i) + '.bin') for i, (p, _) in enumerate(leaves)]
        for pin in (a.session_sha256, a.projection_sha256, a.bundle_sha256):
            hx(pin, 32)
    output = fresh_output(a.output, policy); output.mkdir(parents=True, mode=0o700)
    staged = []
    for original, relative, pin in sources:
        raw = policy.read(original, pin)
        target = output / 'software' / relative; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, raw, 0o400); staged.append((target, '/work/' + relative))
    runtime = output / 'runtime'; runtime.mkdir(mode=0o700)
    for original, target, pin in binaries:
        raw = policy.read(original, pin); need(raw[:4] == b'\x7fELF', 'selected-readonly-ELF')
        copy = runtime / Path(target).name; write_new(copy, raw, 0o500); staged.append((copy, target))
    for original, target, pin in parameters:
        raw = policy.read(original, pin); copy = output / Path(target).name
        write_new(copy, raw, 0o400); staged.append((copy, target))
    inputs = output / 'inputs'; inputs.mkdir(mode=0o700)
    for name in PUBLIC_NAMES:
        original = getattr(a, name)
        if original is not None and name != 'assets':
            pin = getattr(a, name + '_sha256'); need(pin is not None, 'externally-selected-public-pin')
            target = inputs / name; write_new(target, policy.read(original, pin), 0o400)
            staged.append((target, '/' + name))
    if assets is not None:
        assets['component_profile'] = '/parameters/component-profile.json'
        for role in ('relation', 'crypto'):
            assets[role]['path'] = '/runtime/' + role
        for role in ('spend', 'output'):
            assets[role]['manifest'] = '/parameters/' + role + '.json'
            assets[role]['pk'] = '/NO-PK-MOUNT'
        assets_raw = encoded(assets) + b'\n'
        write_new(inputs / 'assets', assets_raw, 0o400); staged.append((inputs / 'assets', '/assets'))
    result_directory = output / 'public'; result_directory.mkdir(mode=0o700)
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']
    for original, target in (*staged, *restricted):
        command += ['--ro-bind', str(original), target]
    if a.operation != 'aggregate':
        command += ['--bind', str(owner), '/private']
        if a.operation == 'observe':
            command += ['--ro-bind', str(mpc), '/mpc']
    command += ['--bind', str(result_directory), '/out', '--chdir', '/work/poc/owner-private-payments/wallet',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC',
        '/usr/bin/python3', '-B', '/work/poc/owner-private-payments/wallet/score_worker.py', a.operation,
        '--output', '/out', '--experiment-sha256', EXPERIMENT]
    if a.operation != 'aggregate':
        command += ['--owner', '/private', '--attempt', a.attempt,
            '--assets', '/assets', '--assets-sha256', digest(assets_raw), '--session', '/session',
            '--session-sha256', a.session_sha256, '--projection', '/projection',
            '--projection-sha256', a.projection_sha256]
    if a.operation == 'observe':
        command += ['--mpc', '/mpc', '--registry', '/registry', '--registry-sha256', a.registry_sha256]
    if a.operation == 'score':
        for name in ('predictions', 'observer_receipt', 'bundle'):
            command += ['--' + name.replace('_', '-'), '/' + name,
                        '--' + name.replace('_', '-') + '-sha256', getattr(a, name + '_sha256')]
        command += ['--capsule', '/observer/CAPSULE.bin']
    if a.operation == 'aggregate':
        command += ['--session-sha256', a.session_sha256, '--projection-sha256', a.projection_sha256,
                    '--bundle-sha256', a.bundle_sha256, '--bundle', '/bundle',
                    '--observer-receipt', '/observer_receipt',
                    '--observer-receipt-sha256', a.observer_receipt_sha256]
        for _, target in restricted:
            command += ['--count-file', target]
    write_new(output / 'PRIVATE-PLAN.json', encoded({'command': command, 'publish_or_hash': False}) + b'\n')
    if not a.execute:
        return {'operation': a.operation, 'staged': True, 'executed': False}
    process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, env=CLEAN)
    write_new(output / 'PRIVATE-STDOUT.log', process.stdout); write_new(output / 'PRIVATE-STDERR.log', process.stderr)
    need(process.returncode == 0, 'diagnostic-INCOMPLETE')
    refreshed = HostPolicy(a.exclude_old_trial, a.exclude_new_private_directory)
    if a.operation in ('observe', 'aggregate'):
        value = parse(refreshed.read(result_directory / 'PUBLIC.json'))
        need(value['schema'] == {'observe': 'kpx7-colluder-observer-seal/v1',
                                'aggregate': 'kpx7-owner-privacy-global-counts/v1'}[a.operation],
             'fixed-diagnostic-public-result')
    else:
        private_leaf(owner / 'diagnostics' / 'COUNTS.bin', 'COUNTS.bin', COUNT_BYTES, refreshed)
    return {'operation': a.operation, 'completed': True}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('observe', 'score', 'aggregate'))
    for name in ('owner-directory', 'output', 'assets', 'session', 'projection', 'registry',
                 'predictions', 'observer-receipt', 'bundle', 'capsule'):
        p.add_argument('--' + name, type=Path, required=name == 'output')
    for name in ('exclude-old-trial', 'exclude-new-private-directory', 'count-file'):
        p.add_argument('--' + name, type=Path, action='append', required=name != 'count-file')
    for name in ('assets-sha256', 'session-sha256', 'projection-sha256', 'registry-sha256',
                 'predictions-sha256', 'observer-receipt-sha256', 'bundle-sha256', 'experiment-sha256'):
        p.add_argument('--' + name, required=name == 'experiment-sha256')
    p.add_argument('--attempt', default='000001'); p.add_argument('--execute', action='store_true')
    return p


if __name__ == '__main__':
    os.umask(0o077); p = parser()
    try:
        print(encoded(run(p.parse_args())).decode())
    except Exception:
        p.exit(2, 'diagnostic INCOMPLETE; no private result exported\n')
