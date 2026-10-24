#!/usr/bin/env python3
"""Fresh mined-test-KAS acquisition. Default only stages; never a pool withdrawal."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path(__file__).absolute().parents[2]
LAUNCHER = 'poc/four-wallet-bootstrap/run_closed_signer.py'
LAUNCHER_SHA = '00d893e23d9c300b5afb86850346cc3a545000148be3567266f5948aa9b88f9c'
BASE_SHA = 'a4442e933608f8cca58943846a25fb9c06c03c5128ce1044504329cbffbfc100'
NAMES = ('ordinary_common.py', 'ordinary_worker.py', 'ordinary_sdk.mjs',
         'ordinary_rpc.mjs', 'ordinary_funding.py')


def need(value, category):
    if not value:
        raise ValueError(category)


def launcher(roots):
    """Protect the first source import using all eight metadata identities."""
    identities, directories = set(), []
    for root in roots:
        for role in 'ABCD':
            directory = Path(root).absolute() / 'owners' / role
            path = directory / 'backup.json'
            need(not any(p.is_symlink() for p in (path, *path.parents)), 'original-canonical-path')
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode), 'original-backup-metadata')
            identities.add((info.st_dev, info.st_ino)); directories.append(directory)
    need(len(roots) == 2 and len(identities) == 8, 'exact-two-trials-eight-originals')
    path = ROOT / LAUNCHER
    need(not any(path.is_relative_to(d) for d in directories)
         and not any(p.is_symlink() for p in (path, *path.parents)), 'public-launcher-path')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and (before.st_dev, before.st_ino) not in identities,
         'public-launcher-inode')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        names = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        attributes = lambda s: tuple(getattr(s, n) for n in names)
        need(attributes(opened) == attributes(before)
             and (opened.st_dev, opened.st_ino) not in identities, 'launcher-swapped-before-first-byte')
        with os.fdopen(os.dup(fd), 'rb') as source:
            raw = source.read()
        need(attributes(os.fstat(fd)) == attributes(before)
             and hashlib.sha256(raw).hexdigest() == LAUNCHER_SHA, 'selected-stable-launcher')
    finally:
        os.close(fd)
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('_ordinary_closed', loader=None))
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def load_common(raw):
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('_ordinary_policy', loader=None))
    module.__file__ = str(ROOT / 'poc/four-wallet-live/ordinary_common.py')
    sys.modules[module.__name__] = module
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def reserve(base, root, value):
    """One immutable intent per fresh constructor namespace, durable before ACK."""
    path = root / 'ordinary-funding-intent.json'
    base.write_new(path, base.encoded(value) + b'\n', 0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run(a):
    base = launcher(a.exclude_trial_directory)
    excluded = base.Exclusions(a.exclude_trial_directory)
    live = base.checked(a.live_trial_directory)
    need(live in [base.checked(p) for p in a.exclude_trial_directory], 'externally-selected-original-live-trial')
    need(stat.S_IMODE(live.stat().st_mode) == 0o700, 'original-trial-private-mode')
    intent = live / 'ordinary-funding-intent.json'
    need(a.operation in ('collect', 'reconcile') or not intent.exists(), 'used-trial-query-only-never-resubmit')
    original = excluded.original(live / 'owners/A/backup.json', 'A') if a.operation == 'sign' else None
    source_paths = [ROOT / 'poc/four-wallet-live' / name for name in NAMES]
    supplied = [(a.observation, a.observation_sha256), (a.case, a.case_sha256), (a.quote, a.quote_sha256)]
    public_paths = [a.source_freeze, a.profile, a.identity, a.software_root / 'SOFTWARE-BUNDLE.json',
                    *source_paths, *(path for path, _ in supplied if path is not None)]
    excluded.guard(public_paths)
    freeze = base.parse(excluded.read(a.source_freeze, a.source_freeze_sha256))
    need(freeze['schema'] == 'kpx6-ordinary-mined-funding-source/v1', 'externally-pinned-ordinary-source-freeze')
    expected_paths = {'poc/four-wallet-live/' + name for name in NAMES}
    need(type(freeze['files']) is list and len(freeze['files']) == len(NAMES)
         and {r['path'] for r in freeze['files']} == expected_paths, 'complete-five-file-source-closure')
    sources = {row['path']: row for row in freeze['files']}
    raw_sources = {}
    for path in source_paths:
        relative = path.relative_to(ROOT).as_posix()
        raw = excluded.read(path, sources[relative]['sha256'])
        need(len(raw) == sources[relative]['bytes'], 'source-freeze-length')
        raw_sources[path.name] = raw
    common = load_common(raw_sources['ordinary_common.py'])
    profile_raw = excluded.read(a.profile, common.PROFILE_SHA)
    identity_raw = excluded.read(a.identity, a.identity_sha256)
    chosen = common.selection(profile_raw, identity_raw, a.identity_sha256)
    inventory = base.parse(excluded.read(a.software_root / 'SOFTWARE-BUNDLE.json', BASE_SHA))
    inventory_rows = {row['path']: row for row in inventory['files']}
    rows = base.members()
    need(all(inventory_rows[relative]['sha256'] == pin for relative, _, pin, _ in rows),
         'fixed-base-inventory-source-runtime-SDK-join')
    public = [('profile.json', a.profile, common.PROFILE_SHA),
              ('identity.json', a.identity, a.identity_sha256)]
    for name in NAMES:
        public.append((name, ROOT / 'poc/four-wallet-live' / name,
                       sources['poc/four-wallet-live/' + name]['sha256']))
    for name, path, pin in [('observation.json', a.observation, a.observation_sha256),
                            ('case.json', a.case, a.case_sha256), ('quote.json', a.quote, a.quote_sha256)]:
        if path is not None:
            need(pin is not None, 'external-public-input-pin')
            public.append((name, path, base.sha(pin)))
    output, staged, inputs = base.stage(excluded, a.software_root, a.output, rows, public,
                                        a.exclude_trial_directory)
    for name in NAMES:
        staged.append((inputs / name, '/work/poc/four-wallet-live/' + name))
    client = output / 'client'; client.mkdir(mode=0o700)
    names = ['profile.json', 'identity.json']
    if a.operation != 'collect':
        need(a.observation is not None, 'selected-mature-source-observation-required')
        names.append('observation.json')
    if a.operation in ('sign', 'submit', 'reconcile'):
        need(a.case is not None and a.quote is not None, 'selected-case-and-own-quote-required')
        names += ['case.json', 'quote.json']
    command = base.sandbox(staged, inputs, names)
    if a.operation in ('quote', 'sign'):
        operation = a.operation
    elif a.operation == 'submit':
        operation = 'check'
    else:
        operation = None
    if operation:
        command += ['--bind', str(client), '/out']
        if original is not None:
            command += ['--ro-bind', str(original), '/owner/backup.json']
        command += ['--chdir', '/work/poc/four-wallet-live', '/usr/bin/python3', '-B',
            '/work/poc/four-wallet-live/ordinary_worker.py', operation, '--profile', '/profile.json',
            '--identity', '/identity.json', '--identity-sha256', a.identity_sha256,
            '--observation', '/observation.json', '--output', '/out/run']
        if operation in ('sign', 'check'):
            command += ['--case', '/case.json', '--quote', '/quote.json']
    base.write_new(output / 'PRIVATE-PLAN.json', base.encoded({'command': command,
        'publish_or_hash': False, 'one_original_A_backup_mount': original is not None}) + b'\n', 0o600)
    if not a.execute:
        return {'status': 'STAGED_ONLY_NOT_EXECUTED', 'original_backup_bytes_read_by_host': False}
    if operation:
        if original is not None:
            excluded.original(original, 'A')
        result = subprocess.run(command, capture_output=True, text=True, env=base.CLEAN)
        need(result.returncode == 0, 'closed-ordinary-quote-sign-or-Full-check-refused')
        reply = common.parse(result.stdout)
        if a.operation in ('quote', 'sign'):
            return reply
    request = {'action': a.operation, 'rpc_url': a.rpc, 'sdk_request': {
        'schema': 'kpx6-ordinary-coinbase-sdk/v1', 'operation': 'roundtrip',
        'network_id': common.NET, 'trial_id': chosen['trial_id'],
        'financial_profile_raw_utf8': profile_raw.decode(),
        'funding_identity_raw_utf8': identity_raw.decode(), 'funding_identity_sha256': a.identity_sha256}}
    case = None
    if a.operation != 'collect':
        case_raw = excluded.read(a.case, a.case_sha256)
        case = common.parse(case_raw)
        quote = common.parse(excluded.read(a.quote, a.quote_sha256))
        observed = common.parse(excluded.read(a.observation, a.observation_sha256))
        _, _, daa = common.observation(observed, chosen)
        common.validate_case(case, chosen, daa, quote['mining_mass'], signed=True)
        body, contexts = common.sdk_body(case)
        request['case_sha256'] = a.case_sha256
        request['sdk_request'].update({'transaction': body, 'contexts': contexts,
            'observed_daa_score': str(daa), 'reference_mining_mass': str(quote['mining_mass'])})
    need(type(a.rpc) is str and a.rpc.startswith(('wss://', 'ws://')), 'explicit-testnet-RPC-URL')
    if a.operation == 'reconcile':
        need(intent.exists(), 'once-intent-required-for-query-only-reconciliation')
        prior = common.parse(excluded.read_generated(intent))
        need(prior['case_sha256'] == a.case_sha256
             and prior['transaction_id'] == case['transaction']['id']
             and prior['funding_identity_sha256'] == a.identity_sha256, 'immutable-intent-query-join')
    network = base.sandbox(staged, inputs, ()) + ['--share-net']
    for path in ('/etc/resolv.conf', '/etc/hosts', '/etc/nsswitch.conf', '/etc/ssl/certs'):
        network += ['--ro-bind', path, path]
    network += ['/runtime/node', '--use-openssl-ca', '/work/poc/four-wallet-live/ordinary_rpc.mjs',
                '--sdk-dir', '/runtime/sdk']
    process = subprocess.Popen(network, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, env=base.CLEAN)
    try:
        process.stdin.write(common.encoded(request).decode() + '\n'); process.stdin.flush()
        first = common.parse(process.stdout.readline())
        if a.operation == 'submit':
            need(first == {'status': 'FRESH_INPUTS_CHECKED_AWAITING_DURABLE_INTENT',
                'transaction_id': case['transaction']['id'], 'case_sha256': a.case_sha256},
                'fresh-live-inputs-before-once-intent')
            reserve(base, live, {'schema': 'kpx6-ordinary-funding-once-intent/v1',
                'trial_id': chosen['trial_id'], 'financial_profile_sha256': common.PROFILE_SHA,
                'funding_identity_sha256': a.identity_sha256, 'case_sha256': a.case_sha256,
                'transaction_id': case['transaction']['id'], 'source_freeze_sha256': a.source_freeze_sha256,
                'case': case, 'never_resubmit': True})
            process.stdin.write(common.encoded({'intent_reserved': True, 'case_sha256': a.case_sha256,
                'transaction_id': case['transaction']['id']}).decode() + '\n'); process.stdin.flush()
            reply = common.parse(process.stdout.readline())
        else:
            reply = first
        process.stdin.close(); process.wait()
    finally:
        # Failed intent creation never sends ACK. An unknown send retains its
        # immutable intent; closing a broken controller grants no retry.
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
        process.stdout.close(); process.stderr.close()
    need(process.returncode == 0 or a.operation == 'submit', 'read-only-network-observation-incomplete')
    base.write_new(output / ('OBSERVATION.json' if a.operation == 'collect' else 'NETWORK-RESULTS.json'),
                   common.encoded(reply) + b'\n', 0o600)
    if a.operation == 'reconcile':
        need(reply['status'] == 'EXACT_ORDINARY_OUTPUTS_OBSERVED_AT_TRUSTED_NODE',
             'funding-outputs-not-yet-observed')
        common.validate_case(case, chosen, daa, quote['mining_mass'], signed=True)
        acquisition = {'schema': 'kpx6-ordinary-funding-acquisition-ledger/v1',
            'selected_coinbase_input_sum_sompi': sum(r['amount'] for r in case['entries']),
            'acquisition_fee_sompi': quote['mining_mass'] * 100,
            'ordinary_funding_output_sum_sompi': 2 * common.TARGET,
            'protected_own_refund_sompi': case['transaction']['outputs'][2]['value']
                if len(case['transaction']['outputs']) == 3 else 0,
            'useful_private_payment_principal_sompi_added_by_acquisition': 0,
            'exact_outputs_observed_at_trusted_node': True, 'full_accepted_history_proof': False}
        need(acquisition['selected_coinbase_input_sum_sompi'] ==
             acquisition['acquisition_fee_sompi'] + acquisition['ordinary_funding_output_sum_sompi']
             + acquisition['protected_own_refund_sompi'], 'acquisition-ledger-conservation')
        base.write_new(output / 'ACQUISITION.json', common.encoded(acquisition) + b'\n', 0o600)
    return {'status': reply.get('status', 'OBSERVED_MATURE_MINED_INPUTS'),
            'original_backup_bytes_read_by_host': False, 'no_resubmission': True}


if __name__ == '__main__':
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('collect', 'quote', 'sign', 'submit', 'reconcile'))
    for name in ('software-root', 'source-freeze', 'profile', 'identity', 'live-trial-directory', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('source-freeze-sha256', 'identity-sha256'):
        p.add_argument('--' + name, required=True)
    for name in ('observation', 'case', 'quote'):
        p.add_argument('--' + name, type=Path)
        p.add_argument('--' + name + '-sha256')
    p.add_argument('--exclude-trial-directory', type=Path, action='append', required=True)
    p.add_argument('--rpc')
    p.add_argument('--execute', action='store_true')
    try:
        print(json.dumps(run(p.parse_args()), sort_keys=True))
    except Exception:
        p.exit(1, 'ordinary funding incomplete; preserve any intent and use query-only reconciliation\n')
