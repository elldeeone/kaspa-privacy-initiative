"""Actual pinned native Full/all-input verification over public cases."""
from pathlib import Path
import subprocess

from backend import bubble, write
from codec import parse_json, sha
from driver import produced
from public import need

VALIDATOR = Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/native-validator')
VALIDATOR_SHA = '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def native_full(runner, case_selector, output):
    case_raw = runner.ingress.read(*case_selector)
    case = parse_json(case_raw)
    runner.ingress.read(VALIDATOR, VALIDATOR_SHA)
    output = Path(output)
    need(not output.exists() and all(not output.absolute().is_relative_to(root)
         for root in runner.ingress.guard.directories), 'fresh-public-native-validation-output')
    output.mkdir(mode=0o700)
    source = output / 'case.json'
    write(source, case_raw)
    command = bubble() + ['--ro-bind', str(VALIDATOR), '/engine', '--ro-bind', str(source), '/case.json',
        '--bind', str(output), '/out', '--chdir', '/tmp', '/engine', 'validate-transaction', '/case.json', '/out/native']
    process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, env=CLEAN)
    need(process.returncode == 0, 'genuine-native-Full-process-refused')
    guard = runner.ingress.refresh()
    report_raw = produced(guard, output / 'native/native-validation.json')
    report = parse_json(report_raw)
    metrics_raw = produced(guard, output / 'native/metrics.json')
    metrics = parse_json(metrics_raw)
    need(report['isolation'] == 'PASS' and report['Full']['accepted'] is True
         and report['all_input_engines_accepted'] is True
         and len(report['per_input_ScriptEngine']) == len(case['transaction']['inputs'])
         and all(row['accepted'] is True for row in report['per_input_ScriptEngine']),
         'genuine-native-Full-and-every-input-engine-required')
    actual_fee = sum(row['amount'] for row in case['entries']) - sum(row['value'] for row in case['transaction']['outputs'])
    need(type(metrics['actual_fee_sompi']) is int and metrics['actual_fee_sompi'] == actual_fee
         and type(metrics['mining_mass']) is int and actual_fee == metrics['mining_mass'] * 100,
         'actual-native-Full-exact-reference-fee')
    return {'case_sha256': sha(case_raw), 'native_validation_sha256': sha(report_raw),
            'native_metrics_sha256': sha(metrics_raw), 'actual_fee_sompi': actual_fee,
            'Full_and_all_input_engines_accepted': True, 'accepted_chain_or_currentness': False}
