#!/usr/bin/env python3
"""Run new-profile Original-only owner operations without inspecting secrets.

This controller's only data inputs are public selections/status records. Each
worker gets one read-only Original and, for payment, one recipient invoice leaf
through an explicitly authenticated private namespace binding. No network or
broadcast entry exists. Only UNFUNDED_SUPPLIED_CONTEXT histories are admitted.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import time
import uuid

import component_run
import exit_wire
import new_private_trial as bootstrap
import private_worker
import wallet_history

HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[2]
PUBLIC = Path('/var/tmp/kpi-private-batch-lifecycle-20261028')
OWNER_AUX = ROOT / '.local/private-batch-owner-aux-binary-01/owner_aux'
OWNER_AUX_SHA = '065a10ebadf53c9be082301eaf2dc6e1935d85bf37d6aead3f8ed3a742ea5a4c'
EXIT_PARAMETERS = ROOT / '.local/private-batch-component-parameters/auth-exit-01'
EXIT_MANIFEST_SHA = 'bc41c97e06f07a06ee9ab2af59ef1ba8c5190a126dfb0eb120d586667aaddd8f'
REHEARSAL = ROOT / 'research/next-session/local-private-payment/private-batch-2026-10-28/UNFUNDED-REHEARSAL.json'
POOL_HEX = 'd68068e3eecfe9fe1b2fcc63026fe7a5268829efa37f4f64c2e7374798e94adf'
need, save, checked = bootstrap.need, bootstrap.save, bootstrap.checked
encoded, parse = private_worker.encoded, private_worker.parse


def private_leaf(path, size=None):
    """Metadata only: the controller never opens or hashes this leaf."""
    path = checked(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
         'private-single-owner-leaf-metadata')
    need(size is None or info.st_size == size, 'private-leaf-fixed-size-metadata')
    return path


def public_receipt(value, operation):
    need(type(value) is dict and value.get('schema') == 'kpb-original-lifecycle-operation/v1'
         and value.get('operation') == operation and value.get('scope') == wallet_history.SCOPE
         and value.get('private_original_or_witness_exported') is False
         and value.get('accepted_backing_or_native_settlement') is False, 'typed-owner-operation-receipt')
    exact = {'schema', 'operation', 'scope', 'private_original_or_witness_exported',
             'accepted_backing_or_native_settlement'}
    expected = {
        'invoice': {'authenticated_private_invoice_ready': True, 'invoice_exported_publicly': False},
        'pay': {'actual_output_proofs': 2, 'actual_restricted_intent_signature': True,
            'actual_signature_normalization': True, 'owner_private_auxiliary_values': 2_635_409,
            'original_seed_recovered_input': True, 'input_kind_exported': False,
            'creator_output_correspondence_exported': False},
        'exit': {'actual_AuthExit_proof': True, 'original_only_recovered_claim': True,
            'service_or_other_owner_dependency': False, 'candidate_exported': False},
        'scan': {'original_only_scan_complete': True, 'private_claims_exported': False},
    }[operation]
    exact |= set(expected)
    if operation == 'scan':
        exact.add('terminal_reconciled')
        exact.add('history_sha256')
        need(type(value.get('terminal_reconciled')) is bool, 'typed-terminal-reconciliation')
        need(type(value.get('history_sha256')) is str and re.fullmatch('[0-9a-f]{64}', value['history_sha256']),
             'typed-exact-public-scan-history-binding')
    need(set(value) == exact and all(type(value[key]) is type(expected_value) and value[key] == expected_value
         for key, expected_value in expected.items()), 'exact-owner-status-no-private-fields')
    return value


def source_selection(shared, read, operation):
    paths = [HERE / name for name in ('private_lifecycle.py', 'new_private_trial.py', 'component_run.py',
        'lifecycle_worker.py', 'wallet_history.py',
        'private_worker.py', 'wallet_profile.py', 'output_producer.py', 'output_verifier.py', 'owner_authority.mjs', 'exit_wire.py')]
    paths += [HERE.parent / 'private_batch/intent.py', HERE.parent / 'integration/trees.py',
        HERE.parent / 'verification/wire.py', HERE.parents[1] / 'future-recipient/v2/recipient.py']
    if operation == 'pay':
        paths += [HERE / 'privacy_owner.py', HERE / 'privacy_codec.py']
    rows = []
    for index, path in enumerate(paths):
        raw = read(path)
        save(shared / ('source-' + str(index)), raw)
        rows.append({'index': index, 'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
    return rows


def selected_runtime(read, operation):
    """Finite public dependencies, never a private package or arbitrary binary."""
    rows = [('/runtime/node', bootstrap.NODE, bootstrap.wallet.NODE_SHA256),
        ('/runtime/crypto', bootstrap.CRYPTO, bootstrap.wallet.CRYPTO_SHA256)]
    if operation != 'invoice':
        rows.append(('/runtime/prover', bootstrap.BINARY, bootstrap.BINARY_SHA))
    if operation == 'pay':
        rows.append(('/runtime/owner-aux', OWNER_AUX, OWNER_AUX_SHA))
    aliases = {'cpp0/private_authorization_cpp/private_authorization': '/generator/private_authorization',
        'cpp0/private_authorization_cpp/private_authorization.dat': '/generator/private_authorization.dat',
        'ordinary/private_authorization.r1cs': '/signature/ordinary.r1cs',
        'cpp0/private_authorization.r1cs': '/signature/cpp0.r1cs',
        'ordinary/private_authorization.sym': '/signature/ordinary.sym'}
    if operation in ('pay', 'exit'):
        rows += [(aliases[name], component_run.BUILD / name, pin) for name, pin in component_run.PINS.items()]
        freeze_path = ROOT / 'research/next-session/local-private-payment/source-checkpoint-2026-10-27/native-authority/SOURCE-FREEZE-02.json'
        freeze = parse(read(freeze_path, '9bded95d08ec2a372bd89b89d83b630155b1e095da7909b2696e423962320b71'))
        frozen = {row['path']: row['sha256'] for row in freeze['files']}
        for name in ('harness/worker.mjs', 'source-bridge/signature-component-adapter-selected.mjs'):
            path = component_run.AUTH / name
            read(path, frozen[name])
            rows.append(('/src/' + name, path, frozen[name]))
    for _, path, pin in rows:
        read(path, pin)
    return rows


def execute(slot, operation, original_parent, private, public, shared, config, runtimes, read, approved_fee,
            invoice=None, observed_route=None):
    own, out = private / ('owner-' + str(slot)), public / ('owner-' + str(slot))
    own.mkdir(mode=0o700); out.mkdir(mode=0o700)
    original = private_leaf(original_parent / ('owner-' + str(slot)) / 'BACKUP.json')
    selected = {**config, 'owner_component': slot}
    selected['approved_fee_sompi'] = approved_fee
    config_path, marker = own / 'CONFIG.json', shared / ('NAMESPACE-' + str(slot) + '.json')
    # This is a controller-created request, not an export. Persist it directly
    # to this owner's excluded directory; do not hash or reopen its body.
    private_worker.write(config_path, selected)
    save(marker, {'schema': 'kpb-one-owner-namespace/v1', 'network': 'disabled',
                  'operation': operation, 'owner_slots': 1})
    mounts = []
    for source in config['source_members']:
        mounts += ['--ro-bind', str(shared / ('source-' + str(source['index']))), source['path']]
    for alias, path, _ in runtimes:
        mounts += ['--ro-bind', str(path), alias]
    mounts += ['--ro-bind', str(bootstrap.JS_ROOT / 'node_modules'), '/runtime/js/node_modules',
        '--ro-bind', str(bootstrap.LEAF_MAP), '/runtime/JS-INSTALLED-LEAF-MAP.json']
    # The normalizer expects /src/node_modules; both names point only to the
    # same selected public JS closure, never another owner's filesystem.
    mounts += ['--ro-bind', str(bootstrap.JS_ROOT / 'node_modules'), '/src/node_modules']
    if operation != 'invoice':
        mounts += ['--ro-bind', str(bootstrap.PARAMETERS / 'MANIFEST.json'), '/parameters/MANIFEST.json',
                   '--ro-bind', str(shared / 'PUBLIC-HISTORY.json'), '/history/PUBLIC-HISTORY.json',
                   '--ro-bind', str(shared / 'IMMUTABLE-TAIL.bin'), '/policy/IMMUTABLE-TAIL.bin']
    if operation == 'pay':
        mounts += ['--ro-bind', str(private_leaf(invoice, 208)), '/invoice/INVOICE208.bin',
                   '--ro-bind', str(bootstrap.PARAMETERS / 'parameters.pk'), '/parameters/parameters.pk']
    if operation == 'exit':
        mounts += ['--ro-bind', str(EXIT_PARAMETERS / 'MANIFEST.json'), '/exit-parameters/MANIFEST.json',
            '--ro-bind', str(EXIT_PARAMETERS / 'parameters.pk'), '/exit-parameters/parameters.pk']
    argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', *mounts,
        '--ro-bind', str(original), '/original/BACKUP.json', '--ro-bind', str(config_path), '/CONFIG.json',
        '--ro-bind', str(marker), '/NAMESPACE.json', '--bind', str(own), '/owner', '--bind', str(out), '/out',
        '--chdir', '/owner', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
        '--setenv', 'TZ', 'UTC', '/usr/bin/python3', '-B', str(HERE / 'lifecycle_worker.py'), operation]
    if operation == 'pay':
        need(type(observed_route) is dict and observed_route['invoice_leaf_path'] == str(invoice)
             and any(argv[i:i + 3] == ['--ro-bind', str(invoice), '/invoice/INVOICE208.bin']
                     for i in range(len(argv) - 2)), 'observed-actual-authenticated-invoice-mount')
    launched = time.monotonic_ns()
    with (own / 'WORKER-STDOUT.log').open('xb') as stdout, (own / 'WORKER-STDERR.log').open('xb') as stderr:
        result = subprocess.run(argv, env=bootstrap.CLEAN, stdout=stdout, stderr=stderr)
    if observed_route is not None:
        # These are the actual namespace route/timings visible to the declared
        # dispatcher observer. Do not replace them with counts or infer a
        # route from owner truth. Retain attempted routes even on worker refusal.
        save(out / 'OBSERVED-INVOICE-ROUTE.json', {**observed_route,
            'launch_monotonic_ns': launched, 'complete_monotonic_ns': time.monotonic_ns(),
            'worker_returncode': result.returncode})
    need(result.returncode == 0, 'isolated-original-owner-operation-incomplete')
    receipt = public_receipt(parse(read(out / 'PUBLIC.json')), operation)
    if operation == 'scan':
        need(receipt['history_sha256'] == config['history_sha256'], 'actual-original-scan-selected-history')
    if operation == 'pay':
        import privacy_codec as codec
        commitment = codec.parse(read(out / 'PRIVACY-COMMITMENT.json'))
        codec.fields(commitment, ('schema', 'binding', 'owner_component', 'round',
                                  'salted_commitment_sha256', 'truth_or_identifiers_exported'))
        codec.need(commitment['schema'] == 'kpb-owner-truth-commitment/v1'
            and commitment['binding'] == config['privacy_binding'] and commitment['owner_component'] == slot
            and commitment['round'] == config['round'] and commitment['truth_or_identifiers_exported'] is False,
            'actual-owner-local-truth-commitment-only')
        codec.word(commitment['salted_commitment_sha256'])
    leaf = {'invoice': 'INVOICE208.bin', 'pay': 'OWNER-PRIVATE-INPUT.txt', 'exit': 'EXIT-CANDIDATE.json'}.get(operation)
    if leaf:
        private_leaf(own / leaf, 208 if operation == 'invoice' else None)
    return {'owner_component': slot, 'private_output_directory': str(own),
            'public_receipt': str(out / 'PUBLIC.json'), 'status': receipt}


def run(args):
    started = time.monotonic()
    need(re.fullmatch('[a-z][a-z0-9-]{0,63}', args.label), 'canonical-fresh-operation-label')
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    trial = parse(read(checked(args.bootstrap_trial), args.bootstrap_trial_sha256))
    need(trial['schema'] == 'kpb-fresh-unfunded-private-original-trial/v1'
         and trial['owner_count'] == 3 and trial['controller_read_or_hashed_private_bodies'] is False
         and trial['setup_mining_funding_broadcast_or_accepted_backing'] is False,
         'existing-explicit-new-profile-unfunded-Originals')
    original_parent = checked(trial['private_original_parent'])
    need(original_parent.parent == bootstrap.PRIVATE and original_parent.name == trial['label'],
         'exact-bootstrap-private-parent')
    descriptor = parse(read(bootstrap.PROFILE, bootstrap.PROFILE_SHA))
    rehearsal = parse(read(REHEARSAL))
    profile = descriptor['profile_descriptor']
    need(trial['domain_hex32'] == profile['domain_hex32']
         and trial['profile_id_hex32'] == descriptor['profile_id_hex32']
         and rehearsal['profile_id_hex32'] == descriptor['profile_id_hex32']
         and rehearsal['pool_lineage_hex32'] == POOL_HEX
         and rehearsal['domain_hex32'] == profile['domain_hex32']
         and rehearsal['chain_genesis_hex32'] == profile['chain_genesis_hex32']
         and rehearsal['service_policy_hex32'] == profile['service_policy_hex32'], 'one-exact-prospective-profile-pool')
    need(type(args.round) is int and args.round in (1, 2), 'matched-workload-round')
    fees = args.owner_fees_sompi
    need(type(fees) is list and len(fees) == 3 and all(type(fee) is int and 1 <= fee <= exit_wire.MAX for fee in fees),
         'three-explicit-exact-owner-approved-integer-fees')
    slots = list(range(3)) if args.owner_component is None else [args.owner_component]
    need(args.operation not in ('invoice', 'pay') or slots == [0, 1, 2], 'all-three-fixed-benchmark-owners')
    private, public = checked(original_parent / 'operations' / args.label), checked(PUBLIC / args.label)
    need(not private.exists() and not public.exists(), 'fresh-unused-owner-operation-identity')
    private.mkdir(parents=True, mode=0o700); public.mkdir(parents=True, mode=0o700)
    shared = public / 'selected-public'; shared.mkdir(mode=0o700)
    runtimes = selected_runtime(read, args.operation)
    config = {'domain_hex32': profile['domain_hex32'], 'profile_id_hex32': descriptor['profile_id_hex32'],
        'chain_hex32': profile['chain_genesis_hex32'], 'pool_hex32': POOL_HEX,
        'service_hex32': profile['service_policy_hex32'], 'binary_sha256': bootstrap.BINARY_SHA,
        'manifest_sha256': bootstrap.MANIFEST_SHA, 'exit_manifest_sha256': EXIT_MANIFEST_SHA,
        'js_leaf_map_sha256': bootstrap.LEAF_MAP_SHA, 'round': args.round,
        'source_members': source_selection(shared, read, args.operation),
        'runtime_members': [{'path': alias, 'sha256': pin} for alias, _, pin in runtimes]}
    invoices = None
    if args.operation != 'invoice':
        need(all((args.history, args.history_sha256, args.tail, args.tail_sha256)), 'exact-supplied-history-and-tail-required')
        raw = read(checked(args.history), args.history_sha256)
        history = parse(raw)
        need(history.get('schema') == 'kpb-private-batch-public-history/v1'
             and history.get('scope') == wallet_history.SCOPE, 'only-unfunded-supplied-history-controller')
        save(shared / 'PUBLIC-HISTORY.json', raw)
        save(shared / 'IMMUTABLE-TAIL.bin', read(checked(args.tail), args.tail_sha256))
        config.update(history_sha256=args.history_sha256, tail_sha256=args.tail_sha256)
    if args.operation == 'pay':
        import privacy_codec as codec
        need(args.privacy_binding is not None and args.privacy_binding_sha256 is not None,
             'prospectively-frozen-private-study-binding-required')
        bound = codec.binding(codec.parse(read(checked(args.privacy_binding), args.privacy_binding_sha256)))
        method = ROOT / 'research/next-session/local-private-payment/private-batch-2026-10-28/PRIVACY-METHOD-FREEZE.md'
        need(bound['trial_id'] == trial['trial_id'] and bound['method_sha256'] == hashlib.sha256(read(method)).hexdigest(),
             'same-Original-trial-and-frozen-privacy-method')
        config['privacy_binding'] = bound
        need(args.invoices is not None and args.invoices_sha256 is not None, 'authenticated-counterparty-invoice-manifest')
        invoices = parse(read(checked(args.invoices), args.invoices_sha256))
        need(invoices['schema'] == 'kpb-original-lifecycle-controller-result/v1'
             and invoices['operation'] == 'invoice' and invoices['bootstrap_trial_id'] == trial['trial_id']
             and invoices['round'] == args.round and [row['owner_component'] for row in invoices['owners']] == [0, 1, 2],
             'same-Original-owner-private-invoice-channel')
        for row in invoices['owners']:
            public_receipt(row['status'], 'invoice')
            parent = checked(row['private_output_directory'])
            need(parent.is_relative_to(original_parent / 'operations')
                 and parent.name == 'owner-' + str(row['owner_component']), 'same-trial-private-invoice-directory')
            private_leaf(parent / 'INVOICE208.bin', 208)
    selection = {'schema': 'kpb-original-lifecycle-selection/v1', 'scope': wallet_history.SCOPE,
        'operation_id': str(uuid.uuid4()), 'bootstrap_trial_id': trial['trial_id'], 'operation': args.operation,
        'source_members': config['source_members'], 'runtime_members': config['runtime_members'],
        'round': args.round, 'owner_components': slots, 'private_originals_read_by_controller': False,
        'creator_tuple_or_private_witness_public_exports': False, 'funded_or_broadcast_entry_available': False,
        'profile_sha256': bootstrap.PROFILE_SHA,
        'history_sha256': config.get('history_sha256'), 'tail_sha256': config.get('tail_sha256')}
    save(public / 'SELECTION.json', selection)
    def owner(slot):
        recipient = None if invoices is None else checked(invoices['owners'][(slot + args.round) % 3]['private_output_directory']) / 'INVOICE208.bin'
        route = None if invoices is None else {'schema': 'kpb-observed-invoice-route/v1', 'round': args.round,
            'source_owner_component': slot, 'target_owner_component': (slot + args.round) % 3,
            'invoice_leaf_path': str(recipient), 'source_operation_id': selection['operation_id'],
            'target_invoice_operation_id': invoices['operation_id']}
        return execute(slot, args.operation, original_parent, private, public, shared, config, runtimes, read,
                       fees[slot], recipient, route)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        owners = list(pool.map(owner, slots))
    result = {'schema': 'kpb-original-lifecycle-controller-result/v1', 'scope': wallet_history.SCOPE,
        'operation': args.operation, 'operation_id': selection['operation_id'], 'bootstrap_trial_id': trial['trial_id'],
        'round': args.round, 'owners': owners, 'controller_read_or_hashed_private_bodies': False,
        'native_settlement_or_privacy_qualification': False, 'wall_seconds': time.monotonic() - started}
    result_path = public / 'RESULT.json'
    result_sha = save(result_path, result)
    return {'status': 'ORIGINAL_ONLY_OWNER_OPERATIONS_COMPLETED', 'operation': args.operation,
            'owner_count': len(owners), 'result': str(result_path), 'result_sha256': result_sha}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('invoice', 'pay', 'scan', 'exit'))
    parser.add_argument('--label', required=True)
    parser.add_argument('--bootstrap-trial', required=True)
    parser.add_argument('--bootstrap-trial-sha256', required=True)
    parser.add_argument('--round', type=int, default=1)
    parser.add_argument('--owner-component', type=int, choices=(0, 1, 2))
    parser.add_argument('--owner-fees-sompi', type=int, nargs=3, required=True)
    parser.add_argument('--workers', type=int, choices=(1, 2, 3), default=3)
    for name in ('history', 'history-sha256', 'tail', 'tail-sha256', 'invoices', 'invoices-sha256',
                 'privacy-binding', 'privacy-binding-sha256'):
        parser.add_argument('--' + name)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args), sort_keys=True))
    except BaseException as error:
        print(json.dumps({'status': 'ORIGINAL_OWNER_OPERATION_INCOMPLETE', 'category': type(error).__name__}), flush=True)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
