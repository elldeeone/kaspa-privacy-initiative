#!/usr/bin/env python3
"""Explicit first submission for one proven pre-intent refusal; never a retry.

Public incident evidence and metadata alone admit this fixed action. Private
STATE/PLAN/invoices stay untouched. The unchanged submitter owns both global
O_EXCL barriers and its fresh SDK/native/live-input checks and single RPC.
"""
from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import subprocess

import campaign
import launch_campaign
from support import checked, encoded, fields, need, parse, write_new

ROOT = Path('/var/tmp/kpi-local-private-payment-01/campaign/trial-02')
PRIVATE = campaign.PRIVATE / 'campaign-trial-02'
TRIAL = '8e9b72ce-ea5f-48e1-a385-ecb14ed4e6ea'
STAGE = 'action-0001'
TXID = '52759a70882cf763de38a289fb2683f5d8eb109b8f35c08d4bbaef6778b3a5c8'
CASE = {'path': str(ROOT / 'run/action-0001/native/public-output/CASE.json'),
        'sha256': 'a92f4c84cab943fbcc4b134512d36dd7566b69dd04ea27aa971b9fdf73b2c70a'}
REFUSAL = {'path': str(ROOT / 'run/action-0001/submission/INCOMPLETE.json'),
           'sha256': '54bee4fb997f41900b1740e8a8375e7cd2ffdfed4df6e8fb3c83fcf5dc16a048'}
CANDIDATE = {'path': str(ROOT / 'run/action-0001/submission/preflight/SDK-CANDIDATE.json'),
             'sha256': 'd7e6ef7aff72547fca403b01b0399f49abac8af8b1297b202ef7a4696a19eaa5'}
SUBMIT_SHA = '748c5e4c74c4d55553c521c19c7c10de00266d27f483b9f638f31cd61f28f968'
OLD_UNIT = 'local-payment-campaign-02.service'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'}


def no_attempt(value):
    expected = {'schema': 'kpxa-single-native-submission/v1', 'trial_id': TRIAL,
        'stage': STAGE, 'transaction_id': TXID, 'status': 'INCOMPLETE_QUERY_ONLY',
        'durable_intent_reserved': False, 'submission_attempted': False,
        'automatic_resubmission_permitted': False, 'confirmation_claimed': False,
        'stage_already_used': False, 'category': 'INTENT'}
    need(value == expected and all(value[name] is False for name in
         ('durable_intent_reserved', 'submission_attempted', 'automatic_resubmission_permitted',
          'confirmation_claimed', 'stage_already_used')), 'exact-pinned-pre-intent-no-attempt-refusal-required')


def same_candidate(value):
    need(value['schema'] == 'kpxa-public-submit-candidate/v1'
         and value['trial_id'] == TRIAL and value['stage'] == STAGE and value['mode'] == 'lifecycle'
         and value['case_sha256'] == CASE['sha256'] and value['transaction']['id'] == TXID
         and value['actual_native_Full_passed'] is True and value['broadcast_performed'] is False,
         'original-pre-intent-candidate-must-bind-exact-qualified-whole-CASE')


def absent_intents():
    """Metadata only: never open, hash, remove or replace any intent."""
    targets = (campaign.PRIVATE / 'submission-intents' / TRIAL / ('stage-' + STAGE + '.intent.json'),
               campaign.PRIVATE / 'submission-transactions' / ('tx-' + TXID + '.intent.json'))
    for target in targets:
        target = checked(target)
        try:
            target.lstat()
        except FileNotFoundError:
            continue
        raise ValueError('global-intent-already-exists-confirm-read-only-never-submit')
    return [str(target) for target in targets]


def stopped():
    probe = subprocess.run(['/usr/bin/systemctl', '--user', 'show', OLD_UNIT,
        '--property=ActiveState', '--property=MainPID'], capture_output=True, text=True,
        env=dict(CLEAN, XDG_RUNTIME_DIR='/run/user/' + str(os.getuid())))
    values = dict(line.split('=', 1) for line in probe.stdout.splitlines() if '=' in line)
    need(probe.returncode == 0 and values == {'MainPID': '0', 'ActiveState': 'inactive'},
         'original-query-only-unit-must-be-inactive-MainPID-zero')


def run(proposal_row, materialization_row, output, *, execute=False):
    p = launch_campaign.Producer()
    proposal = p.frozen_proposal(proposal_row)
    materialized = parse(p.read(materialization_row))
    need(materialized['schema'] == 'kpxa-campaign-materialization/v1'
         and materialized['proposal'] == proposal_row
         and materialized['caller_source'] == proposal['caller_source']
         and materialized['actual_download_and_inventory_and_finite_closures_verified'] is True,
         'corrected-reviewed-materialization-required')
    selection = parse(p.read(materialized['campaign_selection']))
    need(selection == dict(proposal['campaign_selection_template'],
                           cold=parse(p.read(materialized['cold_selector'])))
         and selection['trial_id'] == TRIAL
         and selection['scripts']['submit']['sha256'] == SUBMIT_SHA,
         'exact-incident-trial-and-unchanged-once-only-submitter')
    no_attempt(parse(p.read(REFUSAL)))
    same_candidate(parse(p.read(CANDIDATE)))
    case = parse(p.read(CASE))
    need(case['transaction']['id'] == TXID, 'same-already-qualified-whole-CASE-required')
    activation = parse(p.read(selection['activation']))
    expected_activation = {'path': '/var/tmp/kpi-local-private-payment-01/trials/local-pay-testnet-02/live-01/ACTIVATE-HANDOFF.json',
        'sha256': '29d6925fb33fe4ce0b51f08f0ae12d9095ff0d5ae1d78795514ab14b3ed718de'}
    need(selection['activation'] == expected_activation and activation['trial_id'] == TRIAL,
         'same-actual-confirmed-genesis')
    for name in ('submit', 'confirm'):
        p.read(selection['scripts'][name])
    p.read(selection['node'])
    stopped()
    missing = absent_intents()
    journal = campaign.submission_journal(PRIVATE)
    output = checked(output)
    need(output.is_relative_to(ROOT) and not output.exists(), 'fresh-public-first-submit-output')
    output.mkdir(mode=0o700)
    # Cooperate with the unchanged caller lock without reading any contents.
    lock = os.open(checked(PRIVATE / 'CALLER-LOCK'), os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stopped()
        absent_intents()
        argv = [selection['node']['path'], selection['scripts']['submit']['path'],
            '--mode', 'lifecycle', '--stage', STAGE, '--trial-id', TRIAL,
            '--case', CASE['path'], '--case-sha256', CASE['sha256'],
            '--output', str(output / 'submission'), '--journal', str(journal)]
        fetch = activation['selectors']['fetch.json']
        argv += ['--fetch', fetch['path'], '--fetch-sha256', fetch['sha256'],
                 '--bundle-directory', str(Path(fetch['path']).parent)]
        for name in ('selection', 'descriptor', 'assets', 'parameters', 'codec'):
            row = activation[name]
            p.read(row)
            argv += ['--' + name, row['path'], '--' + name + '-sha256', row['sha256']]
        if execute:
            argv.append('--execute')
        receipt = {'schema': 'kpxa-explicit-first-submit-invocation/v1',
            'trial_id': TRIAL, 'stage': STAGE, 'transaction_id': TXID, 'case': CASE,
            'pre_intent_refusal': REFUSAL, 'original_fixed_preflight_candidate': CANDIDATE,
            'global_intents_absent_metadata_only': missing,
            'unchanged_submitter': selection['scripts']['submit'], 'execute': execute,
            'private_state_plan_invoice_or_backup_read_or_mutated': False,
            'automatic_retry_or_resubmission_permitted': False}
        write_new(output / 'INVOCATION.json', encoded(receipt) + b'\n')
        # Exactly one child invocation; any unknown result remains query-only.
        process = subprocess.run(argv, capture_output=True, env=CLEAN)
        result = {'schema': 'kpxa-explicit-first-submit-result/v1', 'execute': execute,
            'returncode': process.returncode, 'submission_result_directory': str(output / 'submission'),
            'confirmation_claimed': False, 'private_inputs_read_or_mutated': False,
            'automatic_retry_or_resubmission_permitted': False}
        write_new(output / 'RESULT.json', encoded(result) + b'\n')
        return result
    finally:
        os.close(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('proposal', 'materialization'):
        parser.add_argument('--' + name, required=True)
        parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--execute', action='store_true')
    a = parser.parse_args()
    row = lambda name: {'path': getattr(a, name), 'sha256': getattr(a, name + '_sha256')}
    result = run(row('proposal'), row('materialization'), a.output, execute=a.execute)
    print(encoded(result).decode())
    raise SystemExit(result['returncode'])


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('first submission refused; retain state and reconcile read-only; never automatically retry')
