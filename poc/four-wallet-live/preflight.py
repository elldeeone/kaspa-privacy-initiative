#!/usr/bin/env python3
"""Fixed public Native/financial/current-prefix checks; no backup or PK read."""
import argparse
import copy
from pathlib import Path

from live_contracts import authenticate_tree, public_runtime, stage_sdk
from public import (case_summary, checked, digest, encoded, guard_public_paths,
                    need, parse, read_public, read_stable_public, write_new)


def run(args):
    need(args.fee_rate == 100, 'selected-campaign-reference-rate100')
    names = ['financial_profile', 'descriptor', 'case', 'inventory']
    if args.stage != 'funding':
        need(args.fetch is not None and args.bundle_directory is not None,
             'accepted-prefix-required-before-W-spend')
        names.append('fetch')
    guard_public_paths([getattr(args, name) for name in names], args.trial_directory)
    source, assets, receipt = authenticate_tree(args.software_root, args.inventory,
        args.inventory_sha256, args.trial_directory)
    financial_raw = read_public(args.financial_profile, args.financial_sha256, args.trial_directory)
    descriptor_raw = read_public(args.descriptor, args.descriptor_sha256, args.trial_directory)
    case_raw = read_public(args.case, args.case_sha256, args.trial_directory)
    profile, runtime, chain = public_runtime(source, assets, financial_raw, args.financial_sha256,
                                           args.trial_directory)
    d, case = parse(descriptor_raw), parse(case_raw)
    summary = case_summary(case)
    need(d['trial_id'] == args.trial_id and d['financial_profile_sha256'] == args.financial_sha256,
         'descriptor-trial-and-profile')
    output = checked(args.output)
    need(not output.exists() and not output.is_relative_to(source)
         and not output.is_relative_to(checked(args.trial_directory) / 'owners'),
         'fresh-public-preflight-output')
    output.mkdir(parents=True, mode=0o700)
    if args.stage == 'funding':
        sys_path = str(source / 'poc/four-wallet-bootstrap')
        import sys
        sys.path.insert(0, sys_path)
        from gn2 import EntrySelection, validate_genesis
        initial = validate_genesis(case, EntrySelection(profile.profile_sha256,
            profile.domain, profile.w_tail), args.trial_id, signed=True)
        need(initial['founding_outpoint'] == d['founding_outpoint']
             and initial['redeem_hex'] == d['initial_redeem_hex']
             and digest(bytes.fromhex(initial['redeem_hex'])) == d['initial_redeem_sha256'],
             'GN2-candidate-descriptor')
        previous, remaining = None, initial['reserve_sompi']
        evidence, prospective = None, {'point': initial['founding_outpoint'], 'reserve': remaining}
    else:
        fetched = read_public(args.fetch, args.fetch_sha256, args.trial_directory)
        page_paths = chain.bundle_public_files(fetched, args.fetch_sha256, args.bundle_directory)
        guard_public_paths(page_paths, args.trial_directory)
        # As in the owner launcher, never give the Node verifier mutable input
        # paths after a metadata-only check. Copy exact selected public bytes
        # into this fresh owned tree first; all four backup aliases remain
        # forbidden before every original page open/read.
        bundle = parse(fetched)
        staged_bundle = output / 'retained-public-pages'
        staged_bundle.mkdir(mode=0o700)
        page_rows = [*bundle['pages'], *bundle['current_view']['post_query_delta']['pages']]
        need(len(page_rows) == len(page_paths), 'complete-public-page-staging')
        for row, path in zip(page_rows, page_paths):
            raw = read_public(path, row['gzip_sha256'], args.trial_directory)
            need(len(raw) == row['gzip_bytes'], 'exact-public-page-length')
            relative = checked(path).relative_to(checked(args.bundle_directory))
            target = staged_bundle / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            write_new(target, raw); target.chmod(0o400)
        base = chain.replay_bundle(descriptor_raw, args.descriptor_sha256,
            fetched, args.fetch_sha256, profile, runtime, output / 'accepted-prefix',
            bundle_directory=staged_bundle,
            sdk_directory=stage_sdk(args.software_root, output / 'accepted-public-SDK', args.trial_directory))
        previous = base['point']
        need(previous is not None and summary['input_outpoints'] == [previous],
             'candidate-spends-fresh-accepted-head')
        current = base['head_context']; entry = case['entries'][0]
        need(entry == {'amount': int(current['amount_sompi']),
            'scriptPublicKey': current['script_public_key'],
            'blockDaaScore': int(current['block_daa_score']),
            'isCoinbase': False, 'covenantId': None}, 'exact-accepted-input-context')
        candidate_payload = bytes.fromhex(case['transaction']['payload'])
        if args.stage == 'settlement':
            need(not base['operations'] and candidate_payload.startswith(b'KPX5VP01'),
                 'settlement-from-original-funded-state')
        else:
            need(len(candidate_payload) == 2848 and candidate_payload.startswith(b'KPX4AU01'),
                 'one-full-private-noappend-exit')
        accepted_cases = [chain.native_case(row)[0] for row in bundle['transactions']]
        initial = base['entry']
        prospective = runtime.replay_cases(initial['snapshot'], initial['founding_outpoint'],
            initial['reserve_sompi'], accepted_cases[1:] + [case], output / 'prospective-public-replay')
        remaining, evidence = prospective['reserve'], args.fetch_sha256
    body, metrics = runtime.normalize(case['transaction'],
        [{'amount_sompi': str(row['amount']), 'script_public_key': row['scriptPublicKey'],
          'block_daa_score': str(row['blockDaaScore']), 'is_coinbase': False, 'covenant_id': None}
         for row in case['entries']], output / 'candidate-normalize')
    need(body == case['transaction'], 'exact-official-candidate-ID-and-storage-mass')
    contexts = [{'amount_sompi': str(row['amount']), 'script_public_key': row['scriptPublicKey'],
                 'block_daa_score': str(row['blockDaaScore']), 'is_coinbase': False, 'covenant_id': None}
                for row in case['entries']]
    runtime.sdk(body, contexts)
    native, checked_metrics = runtime.validate(body, contexts, output / 'candidate-Full')
    need(metrics == checked_metrics and native['all_input_engines_accepted'] is True
         and metrics['actual_fee_sompi'] == summary['fee_sompi'], 'actual-native-fee-and-engines')
    # New preparations retain our explicit reference-rate quote. Accepted
    # reconciliation never applies this rule to a valid unsigned-budget variant.
    need(summary['fee_sompi'] == args.fee_rate * metrics['mining_mass'],
         'new-campaign-exact-quote')
    if args.stage == 'funding':
        need(all(row['computeBudget'] == 10 for row in body['inputs']), 'new-GN2-budgets')
    else:
        budget = profile.aggregate_budget if args.stage == 'settlement' else profile.private_budget
        need(body['inputs'][0]['computeBudget'] == budget, 'new-selected-W-budget')
    result = {'schema': 'kpx6-four-wallet-public-submit-preflight/v1',
        'trial_id': args.trial_id, 'stage': args.stage,
        'financial_profile_sha256': args.financial_sha256,
        'descriptor_sha256': args.descriptor_sha256, 'summary': summary,
        'previous_head': previous, 'prior_evidence_sha256': evidence,
        'prospective_remaining_reserve_sompi': remaining,
        'prospective_head': prospective['point'], 'actual_native_metrics': metrics,
        'selected_public_software_receipt': receipt,
        'candidate_is_accepted_or_spend_authorized': False,
        'immediate_live_input_requery_required': True,
        'PK_backup_key_or_witness_read': False}
    write_new(output / 'PREFLIGHT.json', result)
    rpc_body = copy.deepcopy(body)
    for item in rpc_body['inputs']:
        item['sequence'] = str(item['sequence'])
    for item in rpc_body['outputs']:
        item['value'] = str(item['value'])
    for name in ('lockTime', 'gas'):
        rpc_body[name] = str(rpc_body[name])
    rpc_body['storageMass'] = str(rpc_body.pop('mass'))
    sdk_candidate = {'schema': 'kpx6-four-wallet-public-SDK-candidate/v1',
        'network_id': 'testnet-10',
        'genesis_hash_hex': 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
        'financial_profile_sha256': args.financial_sha256,
        'descriptor_sha256': args.descriptor_sha256, 'trial_id': args.trial_id,
        'stage': args.stage, 'case_file_sha256': args.case_sha256,
        'preflight_result_sha256': digest(read_stable_public(output / 'PREFLIGHT.json', args.trial_directory)),
        'canonical_case_sha256': summary['case_sha256'],
        'financial_projection_sha256': summary['financial_projection_sha256'],
        'transaction': rpc_body, 'contexts': contexts,
        'previous_head': previous, 'prior_evidence_sha256': evidence,
        'prospective_remaining_reserve_sompi': str(remaining),
        'prospective_head': prospective['point'], 'fee_rate': str(args.fee_rate),
        'submitting_or_accepted': False}
    write_new(output / 'SDK-CANDIDATE.json', sdk_candidate)
    return result


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stage', required=True, choices=('funding', 'settlement', 'owner-exit',
        'exit-01', 'exit-02', 'exit-03', 'exit-04', 'fallback-01', 'fallback-02'))
    for name in ('trial-directory', 'financial-profile', 'descriptor', 'case', 'inventory',
                 'software-root', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('trial-id', 'financial-sha256', 'descriptor-sha256', 'case-sha256', 'inventory-sha256'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--fetch', type=Path); p.add_argument('--fetch-sha256')
    p.add_argument('--bundle-directory', type=Path)
    p.add_argument('--fee-rate', type=int, default=100)
    return p


if __name__ == '__main__':
    p = parser()
    try:
        value = run(p.parse_args())
        print(encoded({'status': 'PUBLIC_PREFLIGHT_COMPLETE_NOT_SUBMITTED',
            'transaction_id': value['summary']['transaction_id']}).decode())
    except (ValueError, OSError, KeyError, TypeError):
        p.exit(2, 'four-wallet public preflight incomplete\n')
