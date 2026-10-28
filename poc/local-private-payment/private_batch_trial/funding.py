#!/usr/bin/env python3
"""Explicit new-profile public entry and isolated own-key funding operations.

The ``new`` command delegates the existing one-command unfunded bootstrap.
Other commands prepare a public identity/GEN3, isolate one new Original for
offline signing, or combine and actually NativeFull-check the signed CASE.
No command in this module mines, queries a node or broadcasts.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import time
import uuid

import genesis
import new_private_trial as bootstrap
import private_lifecycle
import private_worker
import wallet_profile as wallet

HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[2]
OLD = HERE.parent / 'bootstrap'
sys.path.insert(0, str(OLD))
from gn3_runtime import GENERIC, SDK_DIR, SDK_PINS, Runtime

PUBLIC = Path('/var/tmp/kpi-private-batch-funding-20261028')
need, read_private_metadata, save, checked = bootstrap.need, private_lifecycle.private_leaf, bootstrap.save, bootstrap.checked
parse, encoded = private_worker.parse, private_worker.encoded


def trial(path, pin, read):
    value = parse(read(checked(path), pin))
    need(value['schema'] == 'kpb-fresh-unfunded-private-original-trial/v1'
         and value['owner_count'] == 3 and value['controller_read_or_hashed_private_bodies'] is False
         and value['setup_mining_funding_broadcast_or_accepted_backing'] is False
         and value['domain_hex32'] == genesis.EXPECTED_IDENTITY[3].hex()
         and value['profile_id_hex32'] == genesis.EXPECTED_IDENTITY[2].hex(), 'funding-exact-new-unfunded-Original-trial')
    genesis.trial_uuid(value['trial_id'])
    private = checked(value['private_original_parent'])
    need(private.parent == bootstrap.PRIVATE and private.name == value['label'], 'funding-new-Original-parent')
    need(len(value['initial_public_files']) == 3, 'funding-three-public-initial-exports')
    initials = [parse(read(checked(path))) for path in value['initial_public_files']]
    for initial in initials:
        need(initial['schema'] == 'kpb-fresh-owner-initial-public/v1'
             and initial['domain_hex32'] == value['domain_hex32']
             and initial['profile_id_hex32'] == value['profile_id_hex32']
             and initial['original_backup_schema'] == private_worker.BACKUP_SCHEMA
             and initial['kdf_tag_ascii8'] == private_worker.KDF_TAG
             and initial['public_known_seed_used'] is False
             and type(initial['admission_sompi']) is int and initial['admission_sompi'] == genesis.ADMISSION,
             'funding-actual-new-20KAS-public-export')
    return value, private, initials


def component(args, read):
    profile = wallet.Profile(genesis.EXPECTED_IDENTITY[3], genesis.EXPECTED_IDENTITY[2])
    verifier = genesis.GenesisVerifier(profile, bootstrap.BINARY, bootstrap.BINARY_SHA,
        bootstrap.PARAMETERS / 'MANIFEST.json', bootstrap.MANIFEST_SHA, read_public=read)
    raw = read(checked(args.component_profile), args.component_profile_sha256)
    tail = read(checked(args.tail), args.tail_sha256)
    return genesis.Selection.from_component(raw, args.component_profile_sha256, tail, verifier)


def public_runtime(read):
    for _, (path, pin) in GENERIC.items(): read(path, pin)
    for name, pin in SDK_PINS.items(): read(SDK_DIR / name, pin)
    for name in ('sdk.mjs', 'gn3_runtime.py', 'gn3_common.py', 'paths.py'): read(OLD / name)
    return Runtime()


def initial_rows(initials):
    return [genesis.hx(value['output_hex520'], 520) for value in initials]


def prepare_identity(args, read):
    value, _, initials = trial(args.trial, args.trial_sha256, read)
    selected = component(args, read)
    genesis.encode_payload(selected, value['trial_id'], initial_rows(initials))
    runtime = public_runtime(read)
    owners = []
    for i, initial in enumerate(initials):
        script = genesis.hx(initial['funding_spk_hex36'], 36)
        address = runtime.address(script[3:35])
        owners.append({'owner_component': i, 'funding_spk_hex36': script.hex(), 'address': address['address']})
    need(len({row['funding_spk_hex36'] for row in owners}) == 3, 'funding-three-distinct-new-native-keys')
    result = {'schema': 'kpb-three-owner-funding-identity/v1', 'network_id': 'testnet-10',
        'genesis_hash_hex': selected.identity[0].hex(), 'trial_id': value['trial_id'], 'label': value['label'],
        'domain_hex32': selected.identity[3].hex(), 'profile_id_hex32': selected.identity[2].hex(),
        'pool_lineage_hex32': selected.identity[1].hex(), 'service_policy_hex32': selected.identity[4].hex(),
        'bootstrap_trial_sha256': args.trial_sha256, 'component_profile_sha256': args.component_profile_sha256,
        'native_tail_sha256': args.tail_sha256, 'owners': owners, 'financial_readiness': False}
    pin = save(checked(args.output), result)
    return {'status': 'NEW_PROFILE_UNFUNDED_FUNDING_IDENTITY_PREPARED', 'output': args.output,
            'sha256': pin, 'network_mining_funding_or_broadcast': False}


def source_members(shared, read):
    paths = [HERE / name for name in ('funding.py', 'funding_worker.py', 'genesis.py', 'output_verifier.py',
        'new_private_trial.py', 'private_lifecycle.py', 'component_run.py', 'private_worker.py', 'wallet_profile.py',
        'output_producer.py', 'owner_authority.mjs', 'wallet_history.py', 'exit_wire.py', 'consolidation_sdk.mjs')]
    paths += [OLD / name for name in ('gn3_runtime.py', 'gn3_common.py', 'paths.py', 'sdk.mjs')]
    paths += [HERE.parents[1] / 'future-recipient/v2/recipient.py', HERE.parent / 'integration/trees.py',
        HERE.parent / 'verification/wire.py', HERE.parent / 'chain/wire.mjs', HERE.parent / 'chain/public.mjs']
    rows = []
    for index, path in enumerate(paths):
        raw = read(path); save(shared / ('source-' + str(index)), raw)
        rows.append({'index': index, 'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
    return rows


def run_owner(args, read):
    need(re.fullmatch('[a-z][a-z0-9-]{0,63}', args.label), 'funding-fresh-operation-label')
    value, original_parent, initials = trial(args.trial, args.trial_sha256, read)
    need(type(args.owner_component) is int and args.owner_component in (0, 1, 2), 'funding-designated-one-owner')
    component_index = args.owner_component
    original = read_private_metadata(original_parent / ('owner-' + str(component_index)) / 'BACKUP.json')
    private = checked(original_parent / 'funding-operations' / args.label)
    public = checked(args.output)
    need(not private.exists() and not public.exists(), 'funding-fresh-isolated-operation-identity')
    private.mkdir(parents=True, mode=0o700); public.mkdir(parents=True, mode=0o700)
    shared = public / 'selected-public'; shared.mkdir(mode=0o700)
    own = private / 'owner'; own.mkdir(mode=0o700)
    sources = source_members(shared, read)
    runtimes = [(('/runtime/' + role), path, pin) for role, (path, pin) in GENERIC.items()]
    if args.operation == 'approve-genesis': runtimes.append(('/runtime/prover', bootstrap.BINARY, bootstrap.BINARY_SHA))
    runtime_rows = []
    mounts = []
    for alias, path, pin in runtimes:
        read(path, pin); mounts += ['--ro-bind', str(path), alias]
        runtime_rows.append({'path': alias, 'sha256': pin})
    for name, pin in SDK_PINS.items():
        read(SDK_DIR / name, pin); mounts += ['--ro-bind', str(SDK_DIR / name), '/runtime/sdk/' + name]
        runtime_rows.append({'path': '/runtime/sdk/' + name, 'sha256': pin})
    for source in sources:
        mounts += ['--ro-bind', str(shared / ('source-' + str(source['index']))), source['path']]
    initial_raw = read(checked(value['initial_public_files'][component_index]))
    initial_sha = save(shared / 'INITIAL-PUBLIC.json', initial_raw)
    config = {'trial_id': value['trial_id'], 'owner_component': component_index,
        'domain_hex32': value['domain_hex32'], 'profile_id_hex32': value['profile_id_hex32'],
        'initial_public_sha256': initial_sha, 'fee_rate_sompi_per_mass': args.fee_rate_sompi_per_mass,
        'js_leaf_map_sha256': bootstrap.LEAF_MAP_SHA, 'source_members': sources, 'runtime_members': runtime_rows}
    if args.operation == 'consolidate':
        raw = read(checked(args.observation), args.observation_sha256)
        save(shared / 'OBSERVATION.json', raw)
        config['observation_sha256'] = args.observation_sha256
        mounts += ['--ro-bind', str(shared / 'OBSERVATION.json'), '/inputs/OBSERVATION.json']
    else:
        selected = component(args, read)
        raw = read(checked(args.case), args.case_sha256)
        genesis.validate_case(parse(raw), selected, value['trial_id'])
        save(shared / 'CASE.json', raw)
        save(shared / 'COMPONENT-PROFILE.json', read(checked(args.component_profile), args.component_profile_sha256))
        save(shared / 'IMMUTABLE-TAIL.bin', read(checked(args.tail), args.tail_sha256))
        config.update(case_sha256=args.case_sha256, component_profile_sha256=args.component_profile_sha256,
            tail_sha256=args.tail_sha256, binary_sha256=bootstrap.BINARY_SHA,
            output_manifest_sha256=bootstrap.MANIFEST_SHA)
        mounts += ['--ro-bind', str(shared / 'CASE.json'), '/inputs/CASE.json',
            '--ro-bind', str(shared / 'COMPONENT-PROFILE.json'), '/component/PROFILE.json',
            '--ro-bind', str(shared / 'IMMUTABLE-TAIL.bin'), '/component/IMMUTABLE-TAIL.bin',
            '--ro-bind', str(bootstrap.PARAMETERS / 'MANIFEST.json'), '/parameters/OUTPUT-MANIFEST.json']
    config_path = private / 'CONFIG.json'
    private_worker.write(config_path, config)
    marker = shared / 'NAMESPACE.json'
    save(marker, {'schema': 'kpb-one-owner-namespace/v1', 'network': 'disabled',
                  'operation': args.operation, 'owner_slots': 1})
    argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', *mounts,
        '--ro-bind', str(original), '/original/BACKUP.json',
        '--ro-bind', str(shared / 'INITIAL-PUBLIC.json'), '/initial/PUBLIC.json',
        '--ro-bind', str(config_path), '/CONFIG.json', '--ro-bind', str(marker), '/NAMESPACE.json',
        '--ro-bind', str(bootstrap.JS_ROOT / 'node_modules'), '/runtime/js/node_modules',
        '--ro-bind', str(bootstrap.LEAF_MAP), '/runtime/JS-INSTALLED-LEAF-MAP.json',
        '--bind', str(own), '/owner', '--bind', str(public), '/out', '--chdir', '/owner',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC',
        '/usr/bin/python3', '-B', str(HERE / 'funding_worker.py'), args.operation]
    launch = {'schema': 'kpb-new-Original-funding-launch/v1', 'operation': args.operation,
        'trial_id': value['trial_id'], 'owner_component': component_index, 'source_members': sources,
        'runtime_members': runtime_rows, 'one_Original_only': True,
        'controller_private_Original_or_key_read': False, 'executed': False,
        'network_mining_funding_or_broadcast': False}
    if args.execute:
        read_private_metadata(original)
        with (own / 'WORKER-STDOUT.log').open('xb') as stdout, (own / 'WORKER-STDERR.log').open('xb') as stderr:
            result = subprocess.run(argv, stdout=stdout, stderr=stderr, env=bootstrap.CLEAN)
        need(result.returncode == 0, 'funding-isolated-new-Original-operation-incomplete')
        receipt = parse(read(public / 'PUBLIC.json'))
        expected_schema = 'kpb-own-ordinary-consolidation/v1' if args.operation == 'consolidate' else 'kpb-GEN3-owner-approval/v1'
        need(receipt['schema'] == expected_schema and receipt['trial_id'] == value['trial_id']
             and type(receipt['owner_component']) is int and receipt['owner_component'] == component_index
             and receipt['controller_private_Original_or_key_read'] is False and receipt['network_or_broadcast'] is False,
             'funding-exact-public-owner-result')
        launch['executed'] = True
    save(public / 'LAUNCH.json', launch)
    return {'status': 'NEW_ORIGINAL_FUNDING_OPERATION_' + ('EXECUTED' if args.execute else 'STAGED'),
            'operation': args.operation, 'public_output': str(public), 'network_or_broadcast': False}


def propose(args, read):
    value, _, initials = trial(args.trial, args.trial_sha256, read)
    selected = component(args, read)
    sources = parse(read(checked(args.sources), args.sources_sha256))
    need(type(sources) is list and len(sources) == 3, 'GEN3-three-ordinary-integer-sources')
    for i, source in enumerate(sources):
        genesis.fields(source, ('outpoint', 'entry'))
        need(source['entry']['scriptPublicKey'] == initials[i]['funding_spk_hex36'], 'GEN3-matching-designated-funding-key')
    runtime = public_runtime(read)
    out = checked(args.output); need(not out.exists(), 'GEN3-fresh-proposal-directory'); out.mkdir(parents=True, mode=0o700)
    fee, seen, index = 1, set(), 0
    while True:
        need(fee not in seen, 'GEN3-no-exact-entry-fee-fixed-point'); seen.add(fee)
        base = fee // 3; shares = [base, base, fee - 2 * base]
        changes = [sources[i]['entry']['amount'] - genesis.ADMISSION - shares[i] for i in range(3)]
        need(all(type(change) is int and change >= 0 for change in changes), 'GEN3-positive-funding-headroom')
        payload = genesis.encode_payload(selected, value['trial_id'], initial_rows(initials))
        _, state = genesis.records(payload, selected, value['trial_id'])
        case = {'transaction': {'version': 1, 'id': '00' * 32,
            'inputs': [{'previousOutpoint': copy.deepcopy(source['outpoint']), 'signatureScript': '41' + '00' * 64 + '01',
                'sequence': (1 << 64) - 1, 'computeBudget': 10} for source in sources],
            'outputs': [{'value': genesis.RESERVE, 'scriptPublicKey': genesis.exit_wire.state_spk(
                genesis.wallet_history.state_bytes(state, selected.identity[3]), selected.tail).hex(), 'covenant': None}]
                + [{'value': change, 'scriptPublicKey': initials[i]['funding_spk_hex36'], 'covenant': None}
                   for i, change in enumerate(changes) if change],
            'lockTime': 0, 'subnetworkId': '00' * 20, 'gas': 0, 'payload': payload.hex(), 'mass': 0},
            'entries': [copy.deepcopy(source['entry']) for source in sources]}
        case, metrics = runtime.normalize(case, out / ('quote-' + str(index)))
        required = genesis.amount(genesis.uint(metrics['mining_mass']) * genesis.amount(args.fee_rate_sompi_per_mass))
        if required == fee: break
        fee, index = required, index + 1
    admission = genesis.validate_case(case, selected, value['trial_id'], quoted_fee_sompi=fee)
    runtime.roundtrip(case)
    pin = save(out / 'CASE.json', case); save(out / 'ADMISSION.json', admission)
    return {'status': 'NEW_GEN3_UNSIGNED_PROPOSAL_PREPARED', 'case': str(out / 'CASE.json'),
            'case_sha256': pin, 'fee_sompi': fee, 'native_signatures_or_chain_acceptance': False}


def combine(args, read):
    value, _, _ = trial(args.trial, args.trial_sha256, read)
    selected = component(args, read)
    case = parse(read(checked(args.case), args.case_sha256))
    genesis.validate_case(case, selected, value['trial_id'])
    rate = genesis.amount(args.fee_rate_sompi_per_mass)
    expected = hashlib.sha256(b'KPBAGR01\0' + selected.component_sha + uuid.UUID(value['trial_id']).bytes
        + rate.to_bytes(8, 'little') + encoded(case)).hexdigest()
    need(len(args.approvals) == len(args.approval_sha256) == 3, 'GEN3-three-exact-owner-approvals')
    seen = set()
    for path, pin in zip(args.approvals, args.approval_sha256):
        approval = parse(read(checked(path), pin))
        slot = approval['owner_component']
        need(approval['schema'] == 'kpb-GEN3-owner-approval/v1' and type(slot) is int and slot in (0, 1, 2)
             and slot not in seen and approval['trial_id'] == value['trial_id']
             and approval['component_profile_sha256'] == args.component_profile_sha256
             and approval['unsigned_case_sha256'] == args.case_sha256
             and approval['unsigned_case_approval_sha256'] == expected
             and approval['own_Original_receipt_and_designated_key_rederived'] is True,
             'GEN3-real-own-Original-same-CASE-approval')
        signature = genesis.hx(approval['signature_script_hex66'], 66)
        need(signature[:1] == b'\x41' and signature[-1:] == b'\x01', 'GEN3-actual-ALL-script-frame')
        case['transaction']['inputs'][slot]['signatureScript'] = signature.hex(); seen.add(slot)
    runtime = public_runtime(read)
    out = checked(args.output); need(not out.exists(), 'GEN3-fresh-combined-directory'); out.mkdir(parents=True, mode=0o700)
    actual, metrics = runtime.normalize(case, out / 'normalized')
    need(actual == case, 'GEN3-signed-identity-and-storage-mass-unchanged')
    admission = genesis.validate_case(case, selected, value['trial_id'], signed=True,
        quoted_fee_sompi=genesis.uint(metrics['mining_mass']) * rate)
    runtime.roundtrip(case)
    runtime.validate(case, out / 'native-Full')
    pin = save(out / 'CASE.json', case)
    save(out / 'ADMISSION.json', admission)
    save(out / 'RESULT.json', {'schema': 'kpb-real-GEN3-signed-NativeFull/v1', 'trial_id': value['trial_id'],
        'case_sha256': pin, 'component_profile_sha256': args.component_profile_sha256,
        'all_three_Original_ALL_signatures_and_actual_native_Full': True,
        'SDK_lossless_roundtrip': True, 'genesis_reserve_sompi': genesis.RESERVE,
        'accepted_chain_funding_or_broadcast': False})
    return {'status': 'REAL_SIGNED_NEW_GEN3_NATIVE_FULL_PASSED', 'case': str(out / 'CASE.json'),
            'case_sha256': pin, 'accepted_chain_or_broadcast': False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('new', 'identity', 'consolidate', 'propose-genesis', 'approve-genesis', 'combine-genesis'))
    parser.add_argument('--label')
    for name in ('trial', 'trial-sha256', 'output', 'component-profile', 'component-profile-sha256',
        'tail', 'tail-sha256', 'observation', 'observation-sha256', 'case', 'case-sha256', 'sources', 'sources-sha256'):
        parser.add_argument('--' + name)
    parser.add_argument('--owner-component', type=int, choices=(0, 1, 2))
    parser.add_argument('--fee-rate-sompi-per-mass', type=int, default=100)
    parser.add_argument('--approvals', nargs=3); parser.add_argument('--approval-sha256', nargs=3)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    try:
        if args.operation == 'new': result = bootstrap.run(args)
        else:
            read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
            if args.operation == 'identity': result = prepare_identity(args, read)
            elif args.operation == 'propose-genesis': result = propose(args, read)
            elif args.operation == 'combine-genesis': result = combine(args, read)
            else: result = run_owner(args, read)
        print(json.dumps(result, sort_keys=True))
    except BaseException as error:
        print(json.dumps({'status': 'NEW_PROFILE_FUNDING_INCOMPLETE', 'category': type(error).__name__}), flush=True)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
