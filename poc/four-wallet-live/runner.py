#!/usr/bin/env python3
"""Fixed public acquisition/reconciliation; never signs, proves or submits.

An RPC acknowledgment and a caller's JSON flags are never acceptance evidence.
Reconciliation executes the selected complete Full-page/native/financial replay
before recording correspondence with an immutable one-attempt intent. The host
and selected read-only software installation remain explicit trust premises.
"""
import argparse
import os
from pathlib import Path
import stat
import subprocess

from journal import Journal, NORMAL, STAGES
from ledger import complete
from live_contracts import authenticate_tree, module, public_runtime, stage_sdk
from owner_journal import OwnerJournal
from public import (ROOT, case_summary, checked, digest, encoded,
                    guard_public_paths, need, parse, read_public,
                    read_stable_public, sha, trial, write_new)

CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}


def fresh_output(path, trial_directory):
    path = checked(path)
    need(not path.exists() and not path.is_relative_to(ROOT)
         and not path.is_relative_to(checked(trial_directory) / 'owners'),
         'fresh-output-outside-code-and-private-owners')
    path.mkdir(parents=True, mode=0o700)
    return path


def identities(args):
    trial(args.trial_id)
    sha(args.financial_sha256)
    sha(args.descriptor_sha256)


def journal(args):
    identities(args)
    directory = checked(args.journal)
    # Read-only inspection must never silently create a new campaign identity.
    identity = parse(read_stable_public(directory / 'IDENTITY.json', args.trial_directory))
    need(identity.get('trial_id') == args.trial_id
         and identity.get('financial_profile_sha256') == args.financial_sha256
         and identity.get('descriptor_sha256') == args.descriptor_sha256,
         'existing-campaign-identity')
    return Journal(directory, args.trial_id, args.financial_sha256,
                   args.descriptor_sha256, trial_directory=args.trial_directory)


def owner_attempt(args):
    identities(args)
    directory = checked(args.owner_attempt)
    identity = parse(read_stable_public(directory / 'IDENTITY.json', args.trial_directory))
    need(identity.get('schema') == 'kpx6-four-wallet-owner-submit-attempt/v1'
         and identity.get('trial_id') == args.trial_id
         and identity.get('financial_profile_sha256') == args.financial_sha256
         and identity.get('descriptor_sha256') == args.descriptor_sha256,
         'existing-independent-owner-attempt')
    return OwnerJournal(directory, args.trial_id, args.financial_sha256,
        args.descriptor_sha256, trial_directory=args.trial_directory,
        previous_head=identity['previous_head'],
        prior_evidence_sha256=identity['prior_evidence_sha256'])


def stage_index(stage, cases):
    """Campaign labels constrain observation order, not consensus authority."""
    if stage == 'owner-exit':
        return None
    order = ('funding', 'fallback-01', 'fallback-02') if stage.startswith('fallback-') else NORMAL
    index = order.index(stage)
    need(index < len(cases), 'intended-stage-not-accepted')
    for number, case in enumerate(cases[:index + 1]):
        payload = bytes.fromhex(case['transaction']['payload'])
        if number == 0:
            need(len(payload) == 1080 and payload.startswith(b'KPX5GN02'), 'actual-GN2-stage')
        elif not stage.startswith('fallback-') and number == 1:
            need(len(payload) == 8108 and payload.startswith(b'KPX5VP01'), 'actual-two-child-settlement-stage')
        else:
            need(len(payload) == 2848 and payload.startswith(b'KPX4AU01'), 'actual-full-private-exit-stage')
    return index


def stage_pages(chain, fetched, fetch_sha256, bundle_directory, output, trial_directory):
    """Exclude every original backup inode before opening any retained page."""
    paths = chain.bundle_public_files(fetched, fetch_sha256, bundle_directory)
    guard_public_paths(paths, trial_directory)
    value = parse(fetched)
    rows = [*value['pages'], *value['current_view']['post_query_delta']['pages']]
    need(len(rows) == len(paths), 'complete-retained-page-list')
    destination = output / 'retained-public-pages'
    destination.mkdir(mode=0o700)
    for row, path in zip(rows, paths):
        raw = read_public(path, row['gzip_sha256'], trial_directory)
        need(len(raw) == row['gzip_bytes'], 'selected-page-exact-length')
        relative = checked(path).relative_to(checked(bundle_directory))
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, raw)
        target.chmod(0o400)
    return destination, value


def reconcile(args):
    identities(args)
    need((args.journal is None) != (args.owner_attempt is None), 'one-observation-journal')
    need((args.stage == 'owner-exit') == (args.owner_attempt is not None),
         'independent-owner-stage')
    guard_public_paths((args.financial_profile, args.descriptor, args.fetch, args.inventory),
                       args.trial_directory)
    source, assets, receipt = authenticate_tree(args.software_root, args.inventory,
        args.inventory_sha256, args.trial_directory)
    financial_raw = read_public(args.financial_profile, args.financial_sha256, args.trial_directory)
    descriptor_raw = read_public(args.descriptor, args.descriptor_sha256, args.trial_directory)
    fetched = read_public(args.fetch, args.fetch_sha256, args.trial_directory)
    profile, runtime, chain = public_runtime(source, assets, financial_raw, args.financial_sha256,
                                           args.trial_directory)
    descriptor = parse(descriptor_raw)
    need(descriptor['trial_id'] == args.trial_id
         and descriptor['financial_profile_sha256'] == args.financial_sha256,
         'descriptor-trial-and-financial-identity')
    campaign = journal(args) if args.journal is not None else None
    owner = owner_attempt(args) if args.owner_attempt is not None else None
    if campaign is not None:
        before = campaign.snapshot()
        need(args.stage in before['intents'] and args.stage not in before['receipts'],
             'unreconciled-immutable-intent-required')
        intended = before['intents'][args.stage]['summary']
    else:
        need(not (owner.directory / 'ACCEPTED.json').exists(), 'owner-observation-already-recorded')
        intended = parse(read_stable_public(owner.directory / 'INTENT.json', args.trial_directory))['summary']
    output = fresh_output(args.output, args.trial_directory)
    staged, bundle = stage_pages(chain, fetched, args.fetch_sha256,
                                args.bundle_directory, output, args.trial_directory)
    accepted = chain.replay_bundle(descriptor_raw, args.descriptor_sha256, fetched,
        args.fetch_sha256, profile, runtime, output / 'selected-accepted-replay',
        bundle_directory=staged,
        sdk_directory=stage_sdk(args.software_root, output / 'accepted-public-SDK', args.trial_directory))
    need(accepted['trial_id'] == args.trial_id
         and accepted['accepted_chain_backing_verified'] is True
         and accepted['currentness_verified'] is True,
         'selected-complete-accepted-replay-required')
    cases = [chain.native_case(row)[0] for row in bundle['transactions']]
    indices = [index for index, case in enumerate(cases)
               if case['transaction']['id'] == intended['transaction_id']]
    need(len(indices) == 1, 'immutable-intent-present-exactly-once-in-accepted-prefix')
    index = indices[0]
    if campaign is not None:
        need(stage_index(args.stage, cases) == index, 'accepted-stage-position')
        # A reorg cannot silently replace the campaign's already recorded
        # financial history. Same-ID valid budget/witness variants are allowed.
        recorded = campaign.accepted_cases()
        need(len(recorded) == index, 'accepted-campaign-predecessor-count')
        for (_, old), actual in zip(recorded, cases[:index]):
            a, b = case_summary(old), case_summary(actual)
            need(a['transaction_id'] == b['transaction_id']
                 and a['financial_projection_sha256'] == b['financial_projection_sha256'],
                 'accepted-campaign-predecessor-financial-history')
    else:
        need(index > 0 and len(bytes.fromhex(cases[index]['transaction']['payload'])) == 2848
             and cases[index]['transaction']['payload'].startswith(b'KPX4AU01'.hex())
             and case_summary(cases[index])['input_outpoints'] == [owner.identity['previous_head']],
             'accepted-independent-full-exit-from-observed-head')
    actual, contexts = chain.native_case(bundle['transactions'][index])
    summary = case_summary(actual)
    need(summary['financial_projection_sha256'] == intended['financial_projection_sha256'],
         'accepted-intended-financial-effects')
    body, metrics = runtime.normalize(actual['transaction'], contexts, output / 'actual-intent-normalize')
    need(body == actual['transaction'], 'actual-intent-complete-native-ID-mass')
    runtime.sdk(body, contexts)
    native, checked_metrics = runtime.validate(body, contexts, output / 'actual-intent-Full')
    need(native['all_input_engines_accepted'] is True and metrics == checked_metrics
         and metrics['actual_fee_sompi'] == summary['fee_sompi'], 'actual-intent-native-engines-fee')
    # Never recompute an own-preparation reference-rate quote here: budgets and
    # witnesses are unsigned by V1 txid and historical Native-valid variants
    # must not strand the original backup's recovery.
    if campaign is not None:
        initial = accepted['entry']
        if index == 0:
            point, reserve = initial['founding_outpoint'], initial['reserve_sompi']
        else:
            prefix = runtime.replay_cases(initial['snapshot'], initial['founding_outpoint'],
                initial['reserve_sompi'], cases[1:index + 1], output / 'actual-intent-prefix')
            point, reserve = prefix['point'], prefix['reserve']
        result = campaign.record_accepted(args.stage, actual, evidence_sha256=args.fetch_sha256,
            new_head=point, remaining_reserve_sompi=reserve, native_metrics=metrics)
    else:
        result = owner.record_accepted(actual, args.fetch_sha256, metrics)
    exported = {'schema': 'kpx6-four-wallet-public-reconciliation/v1',
        'status': 'ACTUAL_ACCEPTED_PREFIX_RECONCILED', 'trial_id': args.trial_id,
        'stage': args.stage, 'financial_profile_sha256': args.financial_sha256,
        'descriptor_sha256': args.descriptor_sha256, 'fetch_sha256': args.fetch_sha256,
        'transaction_id': summary['transaction_id'],
        'intent_case_sha256': result['intent_case_sha256'],
        'accepted_case_sha256': result['accepted_case_sha256'],
        'byte_correspondence': result['byte_correspondence'],
        'actual_native_metrics': metrics,
        'accepted_prefix_transaction_count': len(cases),
        'current_remaining_reserve_sompi': accepted['reserve'],
        'payout_count': len(accepted['payouts']),
        'observation_checkpoint': accepted['observation_checkpoint'],
        'currentness_scope': accepted['currentness_scope'],
        'selected_public_software_receipt': receipt,
        'independent_consensus_verified': False, 'spend_authorized': False,
        'workflow_readiness_or_privacy_qualification': False,
        'backup_key_witness_or_parameter_blob_read': False,
        'submission_attempted': False}
    write_new(output / 'RECONCILED.json', exported)
    return exported


def selected_network(args):
    """Invoke only two fixed read-only Node entry points; never a caller command."""
    names = [args.financial_profile, args.inventory]
    if args.op == 'fetch':
        names.append(args.descriptor)
    guard_public_paths(names, args.trial_directory)
    source, assets, receipt = authenticate_tree(args.software_root, args.inventory,
        args.inventory_sha256, args.trial_directory)
    raw = read_public(args.financial_profile, args.financial_sha256, args.trial_directory)
    profile = module(source / 'poc/four-wallet-profile/selection.py',
        '_kpx6_live_network_selected_financial').load(raw, args.financial_sha256)
    inventory = parse(read_public(args.inventory, args.inventory_sha256, args.trial_directory))
    members = {row['path']: row for row in inventory['files']}
    required = {'runtime/node', *(f'runtime-sdk/{name}' for name in ('kaspa.js', 'kaspa_bg.wasm', 'package.json')),
                'runtime-source/poc/four-wallet-chain/anchor.mjs',
                'runtime-source/poc/four-wallet-chain/fetch.mjs'}
    need(required <= members.keys(), 'selected-network-fixed-entrypoint-and-SDK-closure')
    node = assets / 'node'
    info = node.stat()
    need(stat.S_IMODE(info.st_mode) == 0o500 and not os.access(node, os.W_OK)
         and info.st_size == profile.executables['node']['bytes']
         and digest(read_stable_public(node, args.trial_directory)) == profile.executables['node']['sha256'],
         'selected-readonly-network-node')
    output = fresh_output(args.output, args.trial_directory)
    inputs = output / 'inputs'
    inputs.mkdir(mode=0o700)
    selected_profile = inputs / 'financial-profile.json'
    write_new(selected_profile, raw)
    selected_profile.chmod(0o400)
    sdk_names = ('kaspa.js', 'kaspa_bg.wasm', 'package.json')
    sdk_root = checked(args.software_root) / 'runtime-sdk'
    guard_public_paths([sdk_root / name for name in sdk_names], args.trial_directory)
    sdk_owned = output / 'public-sdk'
    sdk_owned.mkdir(mode=0o700)
    for name in sdk_names:
        selected = members['runtime-sdk/' + name]
        sdk_bytes = read_public(sdk_root / name, selected['sha256'], args.trial_directory)
        need(len(sdk_bytes) == selected['bytes'], 'selected-network-SDK-length')
        write_new(sdk_owned / name, sdk_bytes)
        (sdk_owned / name).chmod(0o400)
    command = [str(node), '--use-openssl-ca', str(source / 'poc/four-wallet-chain' / (args.op + '.mjs')),
               str(selected_profile), args.financial_sha256]
    if args.op == 'fetch':
        descriptor_raw = read_public(args.descriptor, args.descriptor_sha256, args.trial_directory)
        selected_descriptor = inputs / 'descriptor.json'
        write_new(selected_descriptor, descriptor_raw)
        selected_descriptor.chmod(0o400)
        command.extend((str(selected_descriptor), args.descriptor_sha256))
        destination = output / 'acquisition'
        result_file = destination / 'fetch.json'
    else:
        destination = output / 'anchor.json'
        result_file = destination
    command.extend((str(destination), '--sdk-dir', str(sdk_owned)))
    for endpoint in args.rpc:
        command.extend(('--rpc', endpoint))
    process = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, env=dict(CLEAN), check=False)
    need(process.returncode == 0 and result_file.is_file(), 'selected-public-network-acquisition-incomplete')
    result_raw = read_stable_public(result_file, args.trial_directory)
    value = parse(result_raw)
    need(value['financial_profile_sha256'] == args.financial_sha256,
         'fresh-acquisition-financial-identity')
    result = {'schema': 'kpx6-four-wallet-fixed-public-acquisition/v1',
        'status': 'FETCHED_PENDING_REPLAY' if args.op == 'fetch' else 'RECENT_ANCHOR_OBSERVED',
        'operation': args.op, 'result_sha256': digest(result_raw),
        'selected_public_software_receipt': receipt,
        'accepted_or_spend_authorized_or_ready': False,
        'private_backup_key_or_parameter_blob_read': False, 'submission_attempted': False}
    write_new(output / 'PUBLIC-ACQUISITION.json', result)
    return result


def inspect(args):
    campaign = journal(args)
    if args.op == 'arithmetic':
        result = complete(campaign.accepted_cases())
        output = fresh_output(args.output, args.trial_directory)
        write_new(output / 'ARITHMETIC.json', result)
        return result
    value = campaign.snapshot()
    return {'status': 'ONE_ATTEMPT_JOURNAL_COUNTS_ONLY',
        'intent_count': len(value['intents']), 'recorded_accepted_count': len(value['receipts']),
        'unreconciled_intent_count': len(set(value['intents']) - set(value['receipts'])),
        'journal_is_consensus_or_spend_authority': False,
        'workflow_readiness_or_privacy_qualification': False}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest='op', required=True)
    for op in ('anchor', 'fetch', 'reconcile', 'snapshot', 'arithmetic'):
        sub = commands.add_parser(op)
        sub.add_argument('--trial-directory', required=True, type=Path)
        sub.add_argument('--financial-sha256', required=True)
        if op not in ('snapshot',):
            sub.add_argument('--output', required=True, type=Path)
        if op in ('anchor', 'fetch', 'reconcile'):
            for name in ('financial-profile', 'software-root', 'inventory'):
                sub.add_argument('--' + name, required=True, type=Path)
            sub.add_argument('--inventory-sha256', required=True)
        if op != 'anchor':
            sub.add_argument('--descriptor-sha256', required=True)
        if op in ('fetch', 'reconcile'):
            sub.add_argument('--descriptor', required=True, type=Path)
        if op in ('snapshot', 'arithmetic', 'reconcile'):
            sub.add_argument('--trial-id', required=True)
            sub.add_argument('--journal', required=op != 'reconcile', type=Path)
        if op == 'reconcile':
            sub.add_argument('--owner-attempt', type=Path)
            sub.add_argument('--stage', required=True, choices=sorted(STAGES | {'owner-exit'}))
            sub.add_argument('--fetch', required=True, type=Path)
            sub.add_argument('--fetch-sha256', required=True)
            sub.add_argument('--bundle-directory', required=True, type=Path)
        if op in ('anchor', 'fetch'):
            sub.add_argument('--rpc', action='append', default=[])
    return p


if __name__ == '__main__':
    p = parser()
    try:
        args = p.parse_args()
        result = reconcile(args) if args.op == 'reconcile' else (
            selected_network(args) if args.op in ('anchor', 'fetch') else inspect(args))
        # No raw controller paths, opaque owner mapping, subprocess argv/logs,
        # note commitments, nullifiers or backup-derived data enter stdout.
        keys = ('status', 'intent_count', 'recorded_accepted_count',
                'unreconciled_intent_count', 'payout_count', 'current_remaining_reserve_sompi')
        print(encoded({key: result[key] for key in keys if key in result}).decode())
    except (ValueError, OSError, KeyError, TypeError, IndexError, AttributeError, subprocess.SubprocessError):
        p.exit(2, 'four-wallet public operation incomplete; retained intent never resubmitted\n')
