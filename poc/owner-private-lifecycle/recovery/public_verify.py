#!/usr/bin/env python3
"""Public-only terminal evidence placement and existing isolated replay on CI.

This operator has no chain RPC, signing, owner, PK or proving interface. Financial
acceptance remains exclusively in the unchanged downloaded replay bootstrap.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[3]
PROFILE = '69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f'
DOMAIN = 'be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480'
RELEASE = 'https://github.com/elldeeone/kaspa-privacy-initiative/releases/download/owner-private-kas-recovery-2026-10-24/'
HOSTS = ('github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com')
DENIED = ('forge', '10.0.3.141', 'localhost', '127.0.0.1')
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}
PINS = {
    'poc/owner-private-lifecycle/recovery/replay_closed.py': 'eaf2fd951211faecefee7019f2fe1d7caaf908b18f71f6a4e00958b6cef8f863',
    'poc/four-wallet-storage/restore.py': '68a0d7ca0e5cdc7b3a6b5ca06e334d8abdf6545794e9522f36af76d39608a343',
    'poc/recovery-coldbuild/unpack_bundle.py': '19c41c96b41c968a0ed0dfefe3a38fe855a323ce366b1f1aba46ef155a6d2a22',
    'poc/recovery-coldbuild/software_bundle.py': 'b3e933ca76cfad21e70b50568824b6f9fff3034c58c4cbf5d8d36d7932e1a705',
    'poc/current-wrapper-runtime/transport/public_fetch.py': '37f1a3aa6a7b0c9e4f5363ffb15f2deebde087295c49b60d1cd9b2b9f6eb32ae',
    'poc/current-wrapper-runtime/transport/trusted_util.py': '78633b9e62a57796d609b600139cea77f4e1866ec362aa5bdd2588516baad9a6',
    'poc/current-wrapper-runtime/transport/vendor/capsule.py': 'ba6fba072eb00e54297e47473c61ce7ef2230356183c9dfd60d0a8741cc492d2',
    'poc/current-wrapper-runtime/transport/vendor/chunk_public.py': 'c713a4871079acd040f5c434ceed47c4d6f71885c8e5256199a86488a5f724aa',
}
STATIC = {
    'software-archive': (52866973, '6b5a60ddd37eefbff871c61a257aa0173899940df9faf3c042d932ad4de7a0fa'),
    'software-members': (11061, '74d08130fe997890a44fb4b1cb85a85836107f69866f6f14b854a8a22afa61ce'),
    'software-inventory': (10510, '24067398ebec6624c2e7bd677404c7c01523341b0ec2e5fdcb0e140516c09bca'),
    'closed-replay-bootstrap': (None, PINS['poc/owner-private-lifecycle/recovery/replay_closed.py']),
}
ROLES = {'financial-profile', 'component-profile', 'native-policy', 'native-codec',
    'software-archive', 'software-inventory', 'software-members', 'software-archive-metadata',
    'closed-replay-bootstrap', 'chain-selection', 'founding-descriptor', 'terminal-fetch',
    'native-parameters', 'public-sessions', 'replay-source-pins', 'terminal-history',
    'terminal-checkpoint', 'terminal-current-entry', 'terminal-replay-report', 'terminal-sdk',
    'terminal-accounting', 'original-service-outage', 'initial-recovery-selection',
    'initial-recovery-closure', 'terminal-observer-handoff', 'terminal-replay-packet',
    'terminal-payout-observations', 'terminal-seed-aggregate'}
CASES = {f'accepted-case-{i:02d}-{kind}' for i in range(12) for kind in ('case', 'validation', 'metrics')}
DIAGNOSTIC_TAIL_BYTES = 8192
STAGED_EXECUTABLES = {
    'software/runtime/crypto': '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff',
    'software/runtime/node': 'd1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c',
    'software/runtime/native-validator': '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061',
    'native-codec': '8f724750bb4cc849e2e4bde26fc8da2b5bc7f9a7e4ffd09153ee1af15858d208',
}


def tail(raw):
    return {'bytes': len(raw), 'truncated': len(raw) > DIAGNOSTIC_TAIL_BYTES,
            'tail': raw[-DIAGNOSTIC_TAIL_BYTES:].decode('utf-8', errors='replace')}


class PublicCommandFailure(ValueError):
    def __init__(self, phase, result):
        super().__init__(phase + '-returncode-' + str(result.returncode))
        # No argv, environment, request bodies or unrestricted file trees.
        self.detail = {'phase': phase, 'returncode': result.returncode,
                       'stdout': tail(result.stdout), 'stderr': tail(result.stderr)}


def diagnostic_tail(path):
    """Bounded read from an exact public-output filename; never follow aliases."""
    path = Path(path).absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'diagnostic-path-symlink')
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'diagnostic-regular-single-link')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        attributes = lambda v: (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
        need(attributes(os.fstat(fd)) == attributes(before), 'diagnostic-before-first-byte')
        os.lseek(fd, max(0, before.st_size - DIAGNOSTIC_TAIL_BYTES), os.SEEK_SET)
        raw = os.read(fd, DIAGNOSTIC_TAIL_BYTES)
        need(attributes(os.fstat(fd)) == attributes(before) == attributes(path.stat()), 'diagnostic-file-changed')
    finally:
        os.close(fd)
    return {'bytes': before.st_size, 'truncated': before.st_size > len(raw),
            'tail': raw.decode('utf-8', errors='replace')}


def retained_diagnostics(output):
    """Select only known logs/reports from the already public-only replay."""
    names = ['replay/stdout.log', 'replay/stderr.log', 'replay/public/replayed/SDK-VERIFICATION.json',
             'probe-public/SDK-VERIFICATION.json']
    names += [f'replay/public/replayed/native-{i:04d}/native/{name}'
              for i in range(12) for name in ('native-validation.json', 'metrics.json')]
    result = {}
    for name in names:
        try:
            result[name] = diagnostic_tail(output / name)
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as error:
            result[name] = {'unavailable': type(error).__name__}
    return result


def diagnostic_probe(output, packet, closed):
    """Repeat only the failed existing SDK CLI for stderr, never acceptance.

    The frozen runtime intentionally discards nested subprocess stderr. This
    separate post-failure probe leaves that runtime and its output untouched.
    Only the same public staging mounts exist, in another closed namespace.
    """
    replay = output / 'replay'
    staged = closed.checked(str(replay / 'stage/software'))
    data = closed.checked(str(replay / 'stage/data'))
    public = closed.checked(str(replay / 'public'))
    if not (staged.is_dir() and data.is_dir() and public.is_dir()):
        return {'status': 'not-reached', 'financial_acceptance': False}
    generated = public / 'replayed'
    if (generated / 'SDK-VERIFICATION.json').exists():
        return {'status': 'SDK-report-already-exists', 'financial_acceptance': False}
    if not all((generated / (name + '.json')).is_file() for name in ('selection', 'descriptor', 'fetch')):
        return {'status': 'SDK-inputs-not-created', 'financial_acceptance': False}
    args = ['/work/runtime/node', '/work/poc/owner-private-lifecycle/chain/verify_bundle.mjs']
    for name in ('selection', 'descriptor', 'fetch'):
        args.extend(('/out/replayed/' + name + '.json', packet['inputs'][name]['sha256']))
    args.extend(('/data', '/diagnostic/SDK-VERIFICATION.json', '/work/sdk/kaspa'))
    destination = output / 'probe-public'
    destination.mkdir(mode=0o700)
    args_prefix = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv']
    for system in ('/usr', '/lib', '/lib64'):
        if Path(system).exists():
            args_prefix.extend(('--ro-bind', system, system))
    args_prefix.extend(('--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/home',
        '--ro-bind', str(staged), '/work', '--ro-bind', str(data), '/data',
        '--ro-bind', str(public), '/out', '--bind', str(destination), '/diagnostic',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8', '--chdir', '/work'))
    result = subprocess.run([*args_prefix, *args], stdin=subprocess.DEVNULL,
                            capture_output=True, env=CLEAN, timeout=600)
    return {'status': 'diagnostic-only', 'stage': 'SDK', 'returncode': result.returncode,
            'financial_acceptance': False, 'stdout': tail(result.stdout), 'stderr': tail(result.stderr)}


def loader_diagnostics(output):
    result = {}
    for name, pin in STAGED_EXECUTABLES.items():
        try:
            path = output / 'replay/stage' / name
            read(path, pin)  # Only the four already hash-selected public ELFs.
            process = subprocess.run(['/usr/bin/ldd', str(path)], stdin=subprocess.DEVNULL,
                                     capture_output=True, env=CLEAN, timeout=60)
            result[name] = {'returncode': process.returncode,
                           'stdout': tail(process.stdout), 'stderr': tail(process.stderr)}
        except FileNotFoundError:
            continue
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            result[name] = {'unavailable': type(error).__name__}
    return result


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def read(path, expected=None, size=None):
    """Single-link public bytes, with identity checked before and after opening."""
    path = Path(path).absolute()
    need('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), 'public-path')
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'regular-single-link-public-file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        identity = lambda v: (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
        need(identity(os.fstat(fd)) == identity(before), 'public-before-first-byte')
        with os.fdopen(os.dup(fd), 'rb') as source:
            raw = source.read()
        need(identity(os.fstat(fd)) == identity(before) == identity(path.stat()), 'public-file-changed')
    finally:
        os.close(fd)
    need((size is None or len(raw) == size) and
         (expected is None or hashlib.sha256(raw).hexdigest() == expected), 'whole-public-identity')
    return raw


def module(relative):
    raw = read(ROOT / relative, PINS[relative])
    result = importlib.util.module_from_spec(importlib.util.spec_from_loader('selected_public_' + Path(relative).stem, loader=None))
    result.__file__ = str(ROOT / relative)
    exec(compile(raw, result.__file__, 'exec'), result.__dict__)
    return result


def config(raw, closed):
    value = closed.parse(raw)
    need(type(value) is dict and value.get('schema') == 'kpx8-public-verification-config/v1'
         and type(value.get('enabled')) is bool, 'public-verification-config')
    if not value['enabled']:
        need(set(value) == {'schema', 'enabled', 'reason'} and type(value['reason']) is str, 'disabled-config')
        return value
    need(set(value) == {'schema', 'enabled', 'transport_selection', 'terminal_index'}, 'enabled-config-fields')
    for key, names in [('transport_selection', {'url', 'bytes', 'sha256'}), ('terminal_index', {'bytes', 'sha256'})]:
        row = value[key]
        need(type(row) is dict and set(row) == names, 'external-config-identity')
        closed.row({'path': key, 'bytes': row['bytes'], 'sha256': row['sha256']})
    need(type(value['transport_selection']['url']) is str
         and value['transport_selection']['url'].startswith(RELEASE)
         and '?' not in value['transport_selection']['url'] and '#' not in value['transport_selection']['url'], 'selected-release-URL')
    return value


def index(raw, selected, expected, closed):
    """Validate only object roles, complete identities and placements, not finance."""
    value = closed.parse(raw)
    need(set(value) == {'schema', 'domain_hex32', 'financial_profile_sha256', 'trial_id',
        'accepted_pool_transaction_ids', 'accepted_cases', 'checkpoint_sha256',
        'initial_R2_inventory_sha256', 'initial_R2_snapshot_changed', 'owner_client_associations_selected',
        'financial_verifier_or_consensus_claimed_by_packager', 'availability_claimed_by_manifest', 'objects'}, 'index-fields')
    need(value['schema'] == 'kpx8-terminal-public-evidence-index/v1'
         and value['domain_hex32'] == DOMAIN and value['financial_profile_sha256'] == PROFILE, 'index-profile')
    need(all(value[k] is False for k in ('initial_R2_snapshot_changed', 'owner_client_associations_selected',
         'financial_verifier_or_consensus_claimed_by_packager', 'availability_claimed_by_manifest')), 'index-limited-claims')
    need(len(raw) == expected['bytes'] and hashlib.sha256(raw).hexdigest() == expected['sha256'], 'external-index-identity')
    ids, cases = value['accepted_pool_transaction_ids'], value['accepted_cases']
    need(type(ids) is list and len(ids) == len(set(ids)) == 12
         and all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v) for v in ids)
         and type(cases) is list and len(cases) == 12, 'twelve-public-chain-cases')
    objects, placements = {}, set()
    for row in value['objects']:
        need(type(row) is dict and set(row) == {'id', 'kind', 'bytes', 'sha256', 'placement', 'release_filename', 'public_urls'}, 'index-object-fields')
        name = row['id']
        need(type(name) is str and name not in objects and (name in ROLES | CASES
             or re.fullmatch(r'terminal-prefix-page-\d{5}', name)), 'public-verification-role')
        closed.row({'path': row['placement'], 'bytes': row['bytes'], 'sha256': row['sha256']})
        need(row['placement'] not in placements, 'duplicate-placement')
        placements.add(row['placement']); objects[name] = row
    need(all(not any(str(parent) in placements for parent in Path(p).parents if str(parent) != '.')
             for p in placements), 'placement-file-directory-collision')
    required = ROLES | CASES
    need(required <= objects.keys() and any(k.startswith('terminal-prefix-page-') for k in objects), 'complete-verification-roles')
    for i, case in enumerate(cases):
        need(type(case) is dict and set(case) == {'transaction_id', 'kind', 'objects'}
             and case['transaction_id'] == ids[i]
             and case['kind'] == ('genesis' if i == 0 else 'batch' if i < 3 else 'exit')
             and case['objects'] == {k: f'accepted-case-{i:02d}-{k}' for k in ('case', 'validation', 'metrics')}, 'public-case-object-join')
    assets = {r['id']: r for r in selected['assets']}
    need(len(assets) == len(selected['assets']) and set(assets) == set(objects) | {'terminal-verification-manifest'}, 'exact-selected-index-closure')
    for name, row in objects.items():
        asset = assets[name]
        need((asset['bytes'], asset['sha256'], asset['kind']) == (row['bytes'], row['sha256'], row['kind'])
             and {r['url'] for r in asset['replicas']} == set(row['public_urls']), 'selection-index-whole-object-join')
    for name, (size, pin) in STATIC.items():
        need(objects[name]['sha256'] == pin and (size is None or objects[name]['bytes'] == size), 'fixed-replay-dependency')
    return value, objects


def command(phase, args):
    print('Public evidence: ' + phase, flush=True)
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, env=CLEAN)
    if result.returncode:
        raise PublicCommandFailure(phase, result)
    return result.stdout


def fetch(row, output):
    args = ['/usr/bin/python3', '-B', str(ROOT / 'poc/current-wrapper-runtime/transport/public_fetch.py'),
        '--url', row['url'], '--expected-bytes', str(row['bytes']), '--expected-sha256', row['sha256'], '--output', str(output)]
    for host in HOSTS:
        args.extend(('--allowed-host', host))
    command('small-bootstrap-object', args)


def compare_outputs(generated, objects):
    """Compare complete public bytes; a transaction ID alone omits witnesses."""
    for name, filename in [('terminal-history', 'HISTORY.json'), ('terminal-checkpoint', 'CHECKPOINT.json')]:
        read(generated / filename, objects[name]['sha256'], objects[name]['bytes'])
    for i in range(12):
        row = objects[f'accepted-case-{i:02d}-case']
        read(generated / f'native-{i:04d}/case.json', row['sha256'], row['bytes'])


def run(value, output, closed, report):
    need(not Path('/home/luke').exists() and not Path('/var/tmp/kpi-owner-private-lifecycle-01').exists(), 'fresh-non-Forge-host-required')
    output = closed.checked(str(output.absolute()))
    need(not output.exists(), 'fresh-verification-output')
    output.mkdir(parents=True, mode=0o755)
    report['fresh_output_created'] = True
    for name, pin in PINS.items():
        read(ROOT / name, pin)
    report['phase'] = 'namespace-smoke'
    command('namespace-smoke-before-download', ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
        '--clearenv', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '/usr/bin/true'])
    report['namespace_smoke_before_download'] = True
    report['phase'] = 'selected-public-download'
    fetch(value['transport_selection'], output / 'SELECTION.json')
    storage = module('poc/four-wallet-storage/restore.py')
    selected, providers = storage.selection(read(output / 'SELECTION.json'), value['transport_selection']['sha256'])
    need(selected['profile_reference_sha256'] == PROFILE and set(providers) == {'original-issuer', 'github-release'}
         and set(providers['github-release']['allowed_hosts']) == set(HOSTS), 'selected-public-provider-policy')
    for asset in selected['assets']:
        need(asset['replicas'] and all(r['provider_id'] == 'github-release' and r['url'].startswith(RELEASE)
             for r in asset['replicas']), 'GitHub-release-only-no-issuer')
    manifests = [r for r in selected['assets'] if r['id'] == 'terminal-verification-manifest']
    need(len(manifests) == 1 and manifests[0]['kind'] == 'other_public_metadata'
         and {k: manifests[0][k] for k in ('bytes', 'sha256')} == value['terminal_index'], 'selected-terminal-index')
    fetch({'url': manifests[0]['replicas'][0]['url'], **value['terminal_index']}, output / 'INDEX.json')
    terminal, objects = index(read(output / 'INDEX.json'), selected, value['terminal_index'], closed)
    total = sum(r['bytes'] for r in selected['assets'])
    report.update(selected_public_bytes=total, disk_available_bytes=shutil.disk_usage(output).free,
                  estimated_three_copy_bytes=3 * total + 3 * 159053643 + 52866973)
    # The estimate is observational, not an arbitrary trial-abort threshold.
    args = ['/usr/bin/python3', '-B', str(ROOT / 'poc/four-wallet-storage/restore.py'), '--selection', str(output / 'SELECTION.json'),
        '--selection-sha256', value['transport_selection']['sha256'], '--output', str(output / 'restored'), '--exclude-provider', 'original-issuer']
    for host in DENIED:
        args.extend(('--deny-host', host))
    command('all-pinned-public-objects', args)
    restored = closed.parse(read(output / 'restored/RESULT.json'))
    need(restored['status'] == 'ALL_SELECTED_BYTES_RESTORED', 'complete-byte-restore')
    rows = {r['asset_id']: r for r in restored['restored_objects']}
    layout = output / 'layout'
    for name, row in objects.items():
        source = rows[name]
        need(source['provider_id'] == 'github-release' and source['bytes'] == row['bytes'] and source['sha256'] == row['sha256'], 'actual-restored-object-join')
        closed.write(layout / row['placement'], read(output / 'restored' / closed.relative(source['relative_path']), row['sha256'], row['bytes']))
    placed = lambda name: layout / objects[name]['placement']
    packet = closed.packet(read(placed('terminal-replay-packet'), objects['terminal-replay-packet']['sha256']))
    need(packet['expected']['history_sha256'] == objects['terminal-history']['sha256']
         and packet['expected']['checkpoint_sha256'] == objects['terminal-checkpoint']['sha256'] == terminal['checkpoint_sha256'], 'index-packet-output-pins')
    report['phase'] = 'strict-unpack'
    command('strict-software-unpack', ['/usr/bin/python3', '-B', str(ROOT / 'poc/recovery-coldbuild/unpack_bundle.py'),
        str(placed('software-archive')), str(placed('software-members')), STATIC['software-archive'][1], str(STATIC['software-archive'][0]),
        STATIC['software-members'][1], STATIC['software-inventory'][1], str(output / 'software')])
    report['phase'] = 'unchanged-complete-financial-replay'
    try:
        command('unchanged-isolated-SDK-native-replay', ['/usr/bin/python3', '-B', str(placed('closed-replay-bootstrap')),
            '--software-root', str(output / 'software'), '--software-inventory', str(placed('software-inventory')),
            '--data-root', str(layout / 'data'), '--packet', str(placed('terminal-replay-packet')),
            '--packet-sha256', objects['terminal-replay-packet']['sha256'], '--codec', str(placed('native-codec')),
            '--output', str(output / 'replay'), '--exclude-private-directory', '/var/tmp/kpi-owner-private-lifecycle-01/private'])
    except PublicCommandFailure:
        try:
            report['diagnostic_probe'] = diagnostic_probe(output, packet, closed)
        except subprocess.TimeoutExpired as error:
            report['diagnostic_probe'] = {'status': 'timed-out', 'financial_acceptance': False,
                'stdout': tail(error.stdout or b''), 'stderr': tail(error.stderr or b'')}
        except (OSError, ValueError, KeyError, TypeError) as error:
            report['diagnostic_probe'] = {'unavailable': type(error).__name__, 'financial_acceptance': False}
        report['runtime_loader_diagnostics'] = loader_diagnostics(output)
        raise
    replay = json.loads(read(output / 'replay/RESULT.json'))
    need(replay['schema'] == 'kpx8-closed-public-replay-run/v1'
         and replay['result']['all_original_paths_absent'] is True and replay['result']['network_unshared'] is True
         and replay['result']['GPU_mounted'] is False and replay['result']['owner_backup_seed_witness_or_PK_mounted'] is False
         and replay['result']['all_native_Full_and_input_engines_executed'] is True, 'actual-closed-replay-report')
    generated = output / 'replay/public/replayed'
    compare_outputs(generated, objects)
    report.update(status='PASS', phase='complete', exact_native_case_files_matched=12,
        history_sha256=packet['expected']['history_sha256'], checkpoint_sha256=packet['expected']['checkpoint_sha256'],
        all_native_Full_and_input_engines_executed=True, original_paths_absent=True, financial_runtime_network_disabled=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--check-config', action='store_true')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    closed = module('poc/owner-private-lifecycle/recovery/replay_closed.py')
    value = config(read(args.config), closed)
    if args.check_config:
        print('enabled=' + str(value['enabled']).lower()); return
    need(args.execute and args.output is not None, 'explicit-execute-and-output-required')
    if not value['enabled']:
        print('Public evidence configuration is disabled: ' + value['reason']); return
    report = {'schema': 'kpx8-public-CI-terminal-verification/v1', 'status': 'INCOMPLETE', 'phase': 'preflight',
        'transport_selection_sha256': value['transport_selection']['sha256'], 'terminal_index_sha256': value['terminal_index']['sha256'],
        'trusted_source_pins': PINS, 'wrapper_sha256': hashlib.sha256(read(Path(__file__))).hexdigest(),
        'github_run_id': os.environ.get('GITHUB_RUN_ID'), 'github_source_commit': os.environ.get('GITHUB_SHA'),
        'financial_authorization_or_broadcast': False, 'offhost_seed_recovery_demonstrated': False,
        'privacy_or_sender_anonymity_qualified': False, 'independent_administration_or_retention_demonstrated': False,
        'independent_consensus_or_continuous_currentness': False}
    try:
        run(value, args.output, closed, report)
    except (OSError, ValueError, KeyError, TypeError) as error:
        report['failure'] = str(error) if type(error) is ValueError else type(error).__name__
        if isinstance(error, PublicCommandFailure):
            report['failure'] = str(error)
            report['failure_detail'] = error.detail
    if report.get('fresh_output_created') is True:
        if report['status'] != 'PASS':
            diagnostics = {'schema': 'kpx8-public-replay-failure-diagnostics/v1',
                'phase': report['phase'], 'failure_detail': report.get('failure_detail'),
                'diagnostic_probe': report.get('diagnostic_probe'),
                'runtime_loader_diagnostics': report.get('runtime_loader_diagnostics'),
                'public_output_tails': retained_diagnostics(args.output)}
            closed.write(args.output / 'DIAGNOSTICS.json', (json.dumps(diagnostics, sort_keys=True, indent=2) + '\n').encode(), 0o644)
        closed.write(args.output / 'RESULT.json', (json.dumps(report, sort_keys=True, indent=2) + '\n').encode(), 0o644)
    print('KAS_PUBLIC_REPLAY_RESULT=' + json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report['status'] == 'PASS' else 2)


if __name__ == '__main__':
    main()
