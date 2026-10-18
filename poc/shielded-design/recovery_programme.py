#!/usr/bin/env python3
"""Execute the offline R08–R16 controls and retain a reproducible scope report.

Also verifies the earlier suite. Native/proof gates are always reported open.
Use an existing dependency environment; this command installs or fetches nothing.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

from recovery import reconstruct_public, restore_wallet
from recovery_format import SCOPE, read_json, write_private_json
from recovery_trials import checked


def test_ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from test_ids(item)
        else:
            yield item.id()


def shutdown_rehearsal(package, private, public):
    private.mkdir(mode=0o700)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    producer = private / 'producer'
    subprocess.run([sys.executable, '-O', str(package / 'recovery_fixture.py'), str(producer)],
                   env=env, capture_output=True, text=True, check=True)
    users = {}
    for name in ('alice', 'bob', 'carol'):
        workspace = private / name; workspace.mkdir(mode=0o700)
        users[name] = workspace
        write_private_json(workspace / 'backup.json', read_json(producer / (name + '-backup.json')))
    retained = private / 'retained'; retained.mkdir(mode=0o700)
    for name in ('archive.json', 'checkpoint.json'):
        write_private_json(retained / name, read_json(producer / name))
    producer.rename(private / 'unavailable-original')
    canaries = [read_json(workspace / 'backup.json')[key] for workspace in users.values()
                for key in ('spending_seed', 'incoming_secret')]
    calls = []

    def invoke(stage, prior, output, backup=None):
        trace = private / ('trace-' + str(len(calls)) + '.json')
        command = [sys.executable, '-O', str(package / 'offline_probe.py'), str(trace),
                   str(package / 'recovery_shutdown.py'), stage, '--archive', str(prior / 'archive.json'),
                   '--checkpoint', str(prior / 'checkpoint.json'), '--output', str(output)]
        if backup:
            command += ['--backup', str(backup)]
        run = subprocess.run(command, cwd=output.parent, env=env, capture_output=True, text=True)
        checked(run.returncode == 0 and not run.stderr, 'shutdown process failed')
        checked(not any(secret in run.stdout for secret in canaries), 'secret canary in stdout')
        checked(read_json(trace)['network_attempts'] == [], 'network attempt in shutdown process')
        calls.append({'stage': stage, 'network_attempts': 0, 'secret_canary_matches': 0})

    prior = retained
    for workspace in users.values():
        output = workspace / 'exit'
        invoke('exit-user', prior, output, workspace / 'backup.json')
        prior = output
    final = private / 'final'
    invoke('pay-all', prior, final)
    for workspace in users.values():
        invoke('audit-user', final, workspace / 'audit', workspace / 'backup.json')
    archive, checkpoint = (read_json(final / (name + '.json')) for name in ('archive', 'checkpoint'))
    state = reconstruct_public(archive, checkpoint)
    result = read_json(final / 'result.json')
    checked((result['reserve_sompi'], result['paid_user_principal_sompi'], result['paid_fee_sompi'], result['rent_paid_sompi']) ==
            (0, 1_999_999_000, 1_000, 200_000_000), 'shutdown literal ledger mismatch')
    checked(all(claim['paid'] for claim in state['claims'].values()) and all(fee['paid'] for fee in state['fees'].values()),
            'shutdown unpaid claim remains')
    for workspace in users.values():
        report = restore_wallet(archive, checkpoint, read_json(workspace / 'backup.json'))
        checked(all(report[key] == 0 for key in ('spendable_sompi', 'pending_deposit_sompi', 'unpaid_exit_sompi', 'unpaid_refund_sompi')),
                'shutdown user unresolved')
    public.mkdir(mode=0o700)
    for name, value in (('archive', archive), ('checkpoint', checkpoint)):
        raw = json.dumps(value, sort_keys=True)
        checked(not any(secret in raw for secret in canaries), 'secret canary in public archive')
        write_private_json(public / (name + '.json'), value)
    return {'producer_processes': 1, 'fresh_user_or_public_processes': len(calls), 'calls': calls,
            'aggregate_model_ledger': result, 'original_declared_path_unavailable': not producer.exists(),
            'one_backup_per_user_process': True, 'os_sandbox_or_independent_host': False,
            'native_shutdown_gate_passed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, help='new protected result directory')
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    private = args.output / 'private'; private.mkdir(mode=0o700)
    package = Path(__file__).resolve().parent
    suite = unittest.defaultTestLoader.discover(str(package), pattern='test_*.py')
    identities = list(test_ids(suite))
    log = io.StringIO()
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    write_private_json(private / 'test-log.json', {'log': log.getvalue()})
    failed = {test.id() for test, _ in result.failures + result.errors}
    skipped = {test.id() for test, _ in result.skipped}
    cases = {}
    for number in range(8, 17):
        case = 'R' + str(number).zfill(2)
        matches = [identity for identity in identities if re.search(r'\.test_r' + str(number).zfill(2) + '_', identity)]
        cases[case] = {'offline_checks': len(matches), 'passed': len(matches) - len(set(matches) & (failed | skipped)),
                       'skipped': len(set(matches) & skipped),
                       'full_proof_or_native_gate_passed': False,
                       'scope': 'offline_rehearsal_only' if number == 16 else 'model_controls_only' if number == 13 else 'offline_controls'}
    success = result.wasSuccessful() and not result.skipped and all(case['offline_checks'] > 0 for case in cases.values())
    shutdown = shutdown_rehearsal(package, private / 'shutdown', args.output / 'public-shutdown') if success else None
    report = {'scope': SCOPE, 'requested_cases': 'R08–R16', 'tests_run': result.testsRun,
              'test_failures': len(result.failures), 'test_errors': len(result.errors),
              'all_requested_offline_controls_passed': success, 'cases': cases, 'shutdown_rehearsal': shutdown,
              'real_zk_proofs': 0, 'native_payouts': 0, 'native_shutdown_gate_passed': False,
              'checkpoint_trust': 'separately trusted model horizon, not L1/fork-choice authentication',
              'source_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(package.glob('*.py'))}}
    write_private_json(args.output / 'report.json', report)
    print(json.dumps({'scope': SCOPE, 'tests_run': result.testsRun,
                      'offline_controls_passed': success, 'native_shutdown_gate_passed': False}, sort_keys=True))
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
