#!/usr/bin/env python3
"""Research-only new-profile GEN3 activation after complete native rehearsal.

Default writes a finite plan without network activity. --execute first reruns
the complete two-payment/nine-Exit offline native rehearsal, then mines only
testnet KAS, privately signs ordinary funding/GEN3 and confirms the exact whole
GEN3 CASE. It does not claim terminal testnet readiness or run private payments.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time

import funding
import genesis
import private_worker
import rehearsal_gate

HERE = Path(__file__).absolute().parent
need, checked, save, encoded, parse = funding.need, funding.checked, funding.save, private_worker.encoded, private_worker.parse


def ordinary_source(value, expected_script, trial_id):
    need(value['schema'] == 'kpb-ordinary-output-readback/v1'
         and value['status'] == 'EXACT_ORDINARY_OUTPUT_OBSERVED_DAA_DEPTH20'
         and value['trial_id'] == trial_id, 'new-profile-exact-ordinary-readback')
    output = value['output']
    genesis.fields(output, ('outpoint', 'amount_sompi', 'script_public_key', 'block_daa_score', 'is_coinbase', 'covenant_id'))
    from funding_worker import decimal_boundary
    amount, score = decimal_boundary(output['amount_sompi']), decimal_boundary(output['block_daa_score'])
    genesis.amount(amount)
    need(amount >= 2_100_000_000 and output['script_public_key'] == expected_script
         and output['is_coinbase'] is False and output['covenant_id'] is None, 'new-profile-own-ordinary-source')
    point = output['outpoint']; genesis.fields(point, ('transactionId', 'index'))
    genesis.hx(point['transactionId'], 32); genesis.uint(point['index'], 32)
    return {'outpoint': point, 'entry': {'amount': amount, 'scriptPublicKey': expected_script,
        'blockDaaScore': score, 'isCoinbase': False, 'covenantId': None}}


def run(args):
    import runpy
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    need(re.fullmatch('[a-z][a-z0-9-]{0,63}', args.label), 'fresh-new-profile-activation-label')
    value, original_parent, _ = funding.trial(args.trial, args.trial_sha256, read)
    identity = parse(read(checked(args.identity), args.identity_sha256))
    need(identity['schema'] == 'kpb-three-owner-funding-identity/v1' and identity['trial_id'] == value['trial_id']
         and identity['bootstrap_trial_sha256'] == args.trial_sha256
         and identity['component_profile_sha256'] == args.component_profile_sha256
         and identity['native_tail_sha256'] == args.tail_sha256
         and identity['financial_readiness'] is False, 'exact-new-profile-activation-funding-identity')
    selected = funding.component(args, read)
    need(identity['genesis_hash_hex'] == selected.identity[0].hex()
         and identity['pool_lineage_hex32'] == selected.identity[1].hex()
         and identity['profile_id_hex32'] == selected.identity[2].hex()
         and identity['domain_hex32'] == selected.identity[3].hex()
         and identity['service_policy_hex32'] == selected.identity[4].hex(), 'activation-one-exact-financial-profile')
    public = checked(args.output)
    private = checked(original_parent / 'activation-operations' / args.label)
    need(not public.exists() and not private.exists(), 'fresh-unused-activation-operation')
    public.mkdir(parents=True, mode=0o700); private.mkdir(parents=True, mode=0o700)
    network = HERE / 'funding_network.py'
    programs = [HERE / name for name in ('activate.py', 'funding.py', 'funding_worker.py', 'genesis.py',
        'rehearsal_gate.py', 'funding_network.py')]
    source = [{'path': str(path), 'sha256': hashlib.sha256(read(path)).hexdigest()} for path in programs]
    plan = {'schema': 'kpb-new-profile-research-activation-plan/v1', 'trial_id': value['trial_id'],
        'component_profile_sha256': args.component_profile_sha256, 'native_tail_sha256': args.tail_sha256,
        'funding_identity_sha256': args.identity_sha256, 'rehearsal_manifest_sha256': args.rehearsal_sha256,
        'source_members': source, 'ordered_steps': ['complete-native-rehearsal', 'birth-anchor',
            'three-own-testnet-miners', 'maturity-readback', 'three-own-consolidations-and-readbacks',
            'real-GEN3-proposal-three-Original-approvals-NativeFull', 'one-GEN3-submission', 'fresh-whole-CASE-confirmation'],
        'mining_funding_or_broadcast_executed': False, 'readiness_claimed': False,
        'private_payment_or_withdrawal_performed': False}
    save(public / 'PLAN.json', plan)
    if not args.execute:
        return {'status': 'NEW_PROFILE_RESEARCH_ACTIVATION_STAGED_NO_NETWORK', 'plan': str(public / 'PLAN.json')}
    need(args.rehearsal is not None and args.rehearsal_sha256 is not None,
         'complete-two-payment-nine-Exit-native-rehearsal-required-before-funding')
    # No caller-supplied PASS flag reaches the first network operation.
    rehearsal_gate.verify(args, read, args.rehearsal, args.rehearsal_sha256, public / 'actual-rehearsal-recheck')
    ordinal = 0
    launch_lock = threading.Lock()
    def pin(path): return hashlib.sha256(read(path)).hexdigest()
    def data(path): return parse(read(path))
    def call(script, arguments, *, failure_ok=False):
        nonlocal ordinal
        with launch_lock:
            ordinal += 1
            current = ordinal
            for row in source: read(Path(row['path']), row['sha256'])
            stdout = (private / ('step-' + str(current) + '.stdout')).open('xb')
            stderr = (private / ('step-' + str(current) + '.stderr')).open('xb')
        with stdout, stderr:
            result = subprocess.run(['/usr/bin/python3', '-B', str(script), *map(str, arguments)],
                env=funding.bootstrap.CLEAN, stdout=stdout, stderr=stderr)
        need(failure_ok or result.returncode == 0, 'activation-child-stage-incomplete')
        return result.returncode
    def net(operation, target, arguments=(), *, failure_ok=False):
        return call(network, [operation, '--identity', args.identity, '--identity-sha256', args.identity_sha256,
            '--output', target, '--fee-rate-sompi-per-mass', args.fee_rate_sompi_per_mass,
            *arguments, '--execute'], failure_ok=failure_ok)
    common = ['--trial', args.trial, '--trial-sha256', args.trial_sha256,
        '--component-profile', args.component_profile, '--component-profile-sha256', args.component_profile_sha256,
        '--tail', args.tail, '--tail-sha256', args.tail_sha256, '--fee-rate-sompi-per-mass', args.fee_rate_sompi_per_mass]
    def milestone(step, **metadata): print(json.dumps({'step': step, **metadata}), flush=True)
    milestone('complete-native-terminal-path-reexecuted')
    anchor = public / 'birth-anchor'
    net('anchor', anchor)
    anchor_file = anchor / 'RESULTS.json'
    milestone('testnet-birth-anchor-recorded')
    # Independent public mining jobs use the three distinct owner funding keys.
    # Concurrent stdout bookkeeping is separate from private owner-key work.
    def mine(i):
        net('mine', public / ('mine-' + str(i)), ['--owner-component', i,
            '--workers', args.mining_workers, '--target-sompi', args.target_sompi])
        milestone('own-testnet-reward-observed', owner_component=i)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as miners:
        list(miners.map(mine, range(3)))
    index = 0
    while True:
        observed = public / ('maturity-' + str(index))
        net('collect', observed, failure_ok=True)
        if (observed / 'RESULTS.json').exists() and data(observed / 'RESULTS.json')['status'] == 'MATURE_SOURCES_OBSERVED_PENDING_CONSOLIDATION': break
        index += 1; time.sleep(5)
    milestone('three-mature-own-testnet-sources-observed')
    ordinary, ordinary_fees = [], 0
    operation_tag = hashlib.sha256((value['trial_id'] + ':' + args.label).encode()).hexdigest()[:24]
    for i in range(3):
        observation = observed / ('OWNER-' + str(i) + '.json')
        consolidated = public / ('consolidation-' + str(i))
        call(HERE / 'funding.py', ['consolidate', *common, '--label', 'fund-' + operation_tag + '-consolidate-' + str(i),
            '--owner-component', i, '--observation', observation, '--observation-sha256', pin(observation),
            '--output', consolidated, '--execute'])
        case = consolidated / 'CASE.json'
        # The network operation itself reserves a durable one-use intent and
        # performs at most one submit. Uncertainty leads only to readback.
        submitted = public / ('submit-consolidation-' + str(i))
        net('submit-consolidation', submitted,
            ['--owner-component', i, '--case', case, '--case-sha256', pin(case)], failure_ok=True)
        need((submitted / 'RESULTS.json').exists() and data(submitted / 'RESULTS.json')['submission_attempted'] is True,
             'consolidation-not-submitted-no-readback-loop')
        attempt = 0
        while True:
            actual = public / ('ordinary-' + str(i) + '-' + str(attempt))
            net('reconcile-ordinary', actual, ['--owner-component', i, '--case', case,
                '--case-sha256', pin(case)], failure_ok=True)
            if (actual / 'RESULTS.json').exists() and data(actual / 'RESULTS.json')['status'] == 'EXACT_ORDINARY_OUTPUT_OBSERVED_DAA_DEPTH20': break
            attempt += 1; time.sleep(5)
        ordinary.append(ordinary_source(data(actual / 'RESULTS.json'), identity['owners'][i]['funding_spk_hex36'], value['trial_id']))
        ordinary_fees += data(consolidated / 'PUBLIC.json')['fee_sompi']
        milestone('own-ordinary-source-confirmed', owner_component=i)
    sources_path = public / 'ORDINARY-SOURCES.json'; sources_sha = save(sources_path, ordinary)
    proposal = public / 'genesis-proposal'
    call(HERE / 'funding.py', ['propose-genesis', *common, '--sources', sources_path,
        '--sources-sha256', sources_sha, '--output', proposal])
    unsigned = proposal / 'CASE.json'
    approvals = []
    for i in range(3):
        approval = public / ('genesis-approval-' + str(i))
        call(HERE / 'funding.py', ['approve-genesis', *common, '--label', 'fund-' + operation_tag + '-approve-' + str(i),
            '--owner-component', i, '--case', unsigned, '--case-sha256', pin(unsigned), '--output', approval, '--execute'])
        approvals.append(approval / 'PUBLIC.json')
    combined = public / 'genesis-combined'
    call(HERE / 'funding.py', ['combine-genesis', *common, '--case', unsigned, '--case-sha256', pin(unsigned),
        '--approvals', *approvals, '--approval-sha256', *[pin(path) for path in approvals], '--output', combined])
    case = combined / 'CASE.json'
    milestone('three-Original-GEN3-signatures-and-native-Full-passed')
    submitted = public / 'submit-genesis'
    net('submit-genesis', submitted, ['--case', case, '--case-sha256', pin(case),
        '--component-profile', args.component_profile, '--tail', args.tail], failure_ok=True)
    need((submitted / 'RESULTS.json').exists() and data(submitted / 'RESULTS.json')['submission_attempted'] is True,
         'genesis-not-submitted-no-readback-loop')
    index = 0
    while True:
        confirmed = public / ('confirm-genesis-' + str(index))
        net('confirm', confirmed, ['--case', case, '--case-sha256', pin(case), '--case-mode', 'genesis',
            '--component-profile', args.component_profile, '--tail', args.tail,
            '--anchor', anchor_file, '--anchor-sha256', pin(anchor_file)], failure_ok=True)
        if (confirmed / 'RESULTS.json').exists() and data(confirmed / 'RESULTS.json')['status'] == 'EXACT_CASE_IN_FRESH_PREFIX_AND_CURRENT_OUTPUT': break
        index += 1; time.sleep(5)
    result = {'schema': 'kpb-research-GEN3-activation-handoff/v1',
        'status': 'EXACT_NEW_GEN3_CONFIRMED_PRIVATE_PAYMENT_LIFECYCLE_PENDING', 'trial_id': value['trial_id'],
        'genesis_case': str(case), 'genesis_case_sha256': pin(case),
        'genesis_admission': str(combined / 'ADMISSION.json'), 'genesis_admission_sha256': pin(combined / 'ADMISSION.json'),
        'fresh_full_CASE_confirmation': str(confirmed / 'RESULTS.json'), 'confirmation_sha256': pin(confirmed / 'RESULTS.json'),
        'birth_anchor': str(anchor_file), 'birth_anchor_sha256': pin(anchor_file),
        'component_profile_sha256': args.component_profile_sha256, 'native_tail_sha256': args.tail_sha256,
        'pre_genesis_paid_fee_sompi': ordinary_fees, 'R1_R2_nine_exits_and_testnet_terminal_recovery_still_required': True,
        'financial_readiness_or_independent_consensus_proof': False}
    save(public / 'HANDOFF.json', result)
    milestone('new-profile-GEN3-confirmed-private-lifecycle-pending')
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('label', 'trial', 'trial-sha256', 'identity', 'identity-sha256', 'component-profile',
                 'component-profile-sha256', 'tail', 'tail-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--rehearsal'); parser.add_argument('--rehearsal-sha256')
    parser.add_argument('--fee-rate-sompi-per-mass', type=int, default=100)
    parser.add_argument('--mining-workers', type=int, default=4)
    parser.add_argument('--target-sompi', type=int, default=3_100_000_000)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    try: print(json.dumps(run(args), sort_keys=True))
    except BaseException as error:
        print(json.dumps({'status': 'NEW_PROFILE_ACTIVATION_INCOMPLETE_RECONCILE_READ_ONLY_NO_RESUBMIT',
                          'category': type(error).__name__}), flush=True)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
