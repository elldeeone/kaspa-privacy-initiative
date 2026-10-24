#!/usr/bin/env python3
"""One original compound backup and selected public data; no broadcast API."""
import argparse
from pathlib import Path

from compat import ROOT, core, payment, source_paths
from contracts import (FINANCIAL_SOURCE, CHAIN_SOURCE, backup_source_paths,
                       financial, genesis_source_paths, own_backup)
import no_append
from paths import checked, guard, need
from preparation import finish_sender, pending_receipt, prepare_sender
from pricing import evaluate
from runtime import Runtime
from source import actual_daa, input_paths, page_paths, replay_source
from worker import Worker, parameter_manifest

OPS = ('recover', 'preflight-pending', 'prepare-payment', 'prepare-full-cashout')
OWN_SOURCES = ('compat', 'contracts', 'local_source', 'no_append', 'owner', 'paths',
               'preparation', 'pricing', 'replay', 'runtime', 'source', 'worker')
CHAIN_SOURCES = ('chain_replay.py', 'selection.mjs', 'wire.mjs', 'json.mjs',
                 'acquire.mjs', 'verify_bundle.mjs')
SDK_DIR = Path('/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa')


def public_paths(args):
    paths = [args.financial_profile, *input_paths(args), FINANCIAL_SOURCE,
        *source_paths(), *backup_source_paths(), *genesis_source_paths(),
        ROOT / 'poc/future-recipient/v2/recipient.py',
        ROOT / 'poc/private-cashout-trial/sdk.mjs',
        *[Path(__file__).parent / (name + '.py') for name in OWN_SOURCES],
        *[Path(args.runtime_root) / role for role in ('prover', 'node', 'native-validator', 'crypto')],
        *[SDK_DIR / name for name in ('kaspa.js', 'kaspa_bg.wasm', 'package.json')]]
    if args.source_kind == 'accepted':
        paths.extend(ROOT / 'poc/four-wallet-chain' / name for name in CHAIN_SOURCES)
    for name in ('request', 'virtual_prefix', 'manifest', 'pk'):
        value = getattr(args, name)
        if value is not None:
            paths.append(value)
    return paths


def selected_public(path, expected):
    p = core().primitives
    raw = checked(path).read_bytes()
    core().history.hexbytes(expected, 32)
    p.need(p.h(raw).hex() == expected, 'external-public-byte-pin')
    return raw


def records(args, profile):
    p = core().primitives
    data = p.parse(selected_public(args.virtual_prefix, args.virtual_prefix_sha256))
    p.need(type(data) is dict and set(data) == {'schema', 'financial_profile_sha256', 'record_hex4048'}
           and data['schema'] == 'kpx6-four-wallet-proposed-prefix/v1'
           and data['financial_profile_sha256'] == profile.profile_sha256
           and type(data['record_hex4048']) is list and len(data['record_hex4048']) <= 2,
           'strict-proposed-virtual-prefix')
    return tuple(core().history.hexbytes(row, 4048) for row in data['record_hex4048'])


def ordinary_change_control(backup, runtime, replayed):
    pub = (b'\0\0\x20' + runtime.crypto.xonly(backup.funding_key) + b'\xac').hex()
    changes = [row['ordinary_change_sompi'] for row in replayed['entry']['contributions']
               if row['source_script_public_key'] == pub and row['ordinary_change_sompi'] > 0]
    return {'ordinary_funding_change_key_control_match_count': len(changes),
            'ordinary_funding_change_sompi': sum(changes),
            'ordinary_change_current_UTXO_or_spendability_claimed': False}


def run(args):
    need(args.op in OPS and args.source_kind in ('local', 'accepted'), 'selected-owner-operation')
    heavy = args.op in ('prepare-payment', 'prepare-full-cashout')
    need((args.pk is not None) == heavy and (args.manifest is not None) == heavy,
         'PK-and-manifest-only-for-proof-generation')
    need(not heavy or args.execute is True, 'root-scheduled-proof-release-required')
    need(type(args.workers) is int and 1 <= args.workers <= 14, 'selected-worker-count')
    need(type(args.fee_rate) is int and 0 < args.fee_rate < 1 << 64, 'selected-fee-rate')
    requested = args.op in ('prepare-payment', 'preflight-pending')
    need((args.request is not None) == requested and (args.virtual_prefix is not None) == requested,
         'request-and-proposed-prefix-for-selected-operation')
    if args.op == 'prepare-payment':
        need(type(args.ordinal) is int and args.ordinal in (0, 1), 'selected-child-ordinal')
    if args.op == 'prepare-full-cashout':
        need(type(args.minimum_payout_sompi) is int and args.minimum_payout_sompi >= 10_000_000,
             'explicit-owner-minimum-payout')
    if args.source_kind == 'local':
        need(args.history is not None and args.history_sha256 is not None,
             'selected-unfunded-local-history')
    else:
        need(all(getattr(args, name) is not None for name in
                 ('descriptor', 'descriptor_sha256', 'fetch', 'fetch_sha256', 'bundle_directory')),
             'selected-accepted-network-evidence')
    backup_path, output = guard(args.backup, public_paths(args), args.output)
    backup_info = backup_path.stat()
    pages = page_paths(args, (backup_info.st_dev, backup_info.st_ino))
    # Reusable complete page metadata was guarded before any page is read.
    need(type(pages) is tuple, 'reusable-public-page-exclusion-pass')
    for path in args.must_be_absent:
        need(not checked(path).exists(), 'original-operator-or-other-owner-path-visible')
    selected = financial(checked(args.financial_profile).read_bytes(), args.financial_sha256)
    runtime = Runtime(selected, args.runtime_root)
    if heavy:
        parameter_manifest(checked(args.manifest).read_bytes(), selected)
    output.mkdir(parents=True, mode=0o700)
    replayed = replay_source(args, selected, runtime, output / 'public-replay')
    request, proposed = None, ()
    if requested:
        request = payment().Request.parse(selected_public(args.request, args.request_sha256), selected.domain)
        proposed = records(args, selected)
    sizing = None
    if args.op == 'prepare-payment':
        sizing = evaluate(runtime, replayed['snapshot'], replayed['point'], replayed['reserve'],
            actual_daa(replayed, runtime), output / 'PRIVATE-sizing',
            net_principal_sompi=request.net_principal_sompi, rate=args.fee_rate)
    worker = None
    try:
        if heavy:
            worker = Worker(runtime, args.pk, output / 'proof', args.workers)
            core().native_runtime.save(output / 'PARAMETERS-READY.json', worker.ready())
        # FIRST existing original-backup byte read. Proof generation has
        # authenticated the entire selected PK and checked VK/READY above.
        backup = own_backup(backup_path.read_bytes(), selected.domain, replayed['trial_id'])
        c = core(); p = c.primitives
        wallet = c.receiver.module().Receiver(backup.seed, selected.domain, runtime.crypto)
        recovered = c.receiver.recover(wallet, replayed['snapshot'],
                                        replayed['snapshot'].state(selected.domain))
        current = no_append.available(recovered)
        summary = {'schema': 'kpx6-four-wallet-own-result/v1', 'op': args.op,
            'financial_profile_sha256': selected.profile_sha256,
            'public_source_kind': args.source_kind,
            'recognized_historical_receipt_count': len(recovered.owned),
            'recognized_spent_receipt_count': sum(row.spent for row in recovered.owned),
            'recognized_unspent_claim_count_before': len(current),
            **no_append.controlled_payouts(backup.seed, wallet, recovered,
                replayed['anchor_point'], replayed['payouts']),
            **ordinary_change_control(backup, runtime, replayed),
            'public_network_evidence_consistency_validated':
                replayed.get('network_evidence_consistency_validated', False),
            'currentness_scope': replayed.get('currentness_scope', 'UNFUNDED_SUPPLIED_CONTEXTS_ONLY'),
            'spend_authorized_or_submitted_by_this_owner_process': False,
            'root_seed_funding_key_witness_openings_owned_positions_or_backup_hash_exported': False}
        if args.op == 'prepare-payment':
            prepared = prepare_sender(runtime, replayed, proposed, args.ordinal,
                                       wallet, request, sizing, output / 'PRIVATE-payment')
            proof = worker.prove(prepared.prepared.candidate, quoted=prepared.quote_context)
            _, _, metrics = finish_sender(runtime, prepared, proof, output)
            summary.update({'genuine_compact_P0_child_proof_verified': True,
                'whole_PK_VK_READY_before_original_backup': True,
                'fee_sompi': prepared.prepared.candidate.fee,
                'reserve_after_sompi': prepared.prepared.candidate.reserve_after,
                'requested_net_sompi': request.net_principal_sompi,
                'explicit_exit_credit_sompi': request.recipient_exit_credit_sompi,
                'official_virtual_body_metrics': metrics,
                'actual_settlement_or_native_chain_acceptance_claimed': False})
        elif args.op == 'preflight-pending':
            pending = pending_receipt(runtime, replayed, proposed, wallet, request, output)
            c.native_runtime.save(output / 'PENDING-RECEIPT-CHECK.json', pending)
            summary.update({'pending_recipient_check_passed': True,
                            'pending_check_grants_no_native_or_settlement_authority': True})
        elif args.op == 'prepare-full-cashout':
            p.need(len(current) == 1, 'one-own-current-claim-in-four-wallet-campaign')
            daa = actual_daa(replayed, runtime)
            material = no_append.prepare(backup.seed, wallet, replayed['snapshot'], recovered,
                (current[0],), replayed['point'], replayed['anchor_point'], replayed['reserve'],
                expected_domain=selected.domain)
            candidate, quote = runtime.quote_material(material, output / 'PRIVATE-quotes',
                                                       args.fee_rate, daa=daa)
            p.need(candidate.payout >= p.amount(args.minimum_payout_sompi),
                   'owner-minimum-net-payout-after-actual-fee')
            proof = worker.prove(candidate, quoted=quote)
            body, contexts, native, metrics = runtime.finalize(candidate, replayed['point'],
                replayed['reserve'], selected.vk, selected.vk, proof, quote,
                output / 'prepared', daa=daa)
            after = c.receiver.recover(wallet, material.after, material.after.state(selected.domain))
            p.need(not no_append.available(after), 'all-own-four-wallet-claims-consumed')
            summary.update({'transaction_id': body['id'],
                'proof_sha256': p.h(proof).hex(), 'authorization_sha256': p.h(candidate.auth).hex(),
                'quote_id': quote['quote_id'], 'consumed_same_backup_claim_count': 1,
                'recognized_unspent_claim_count_after': 0, 'native_payout_sompi': candidate.payout,
                'minimum_payout_sompi': args.minimum_payout_sompi,
                'fee_sompi': candidate.fee, 'reserve_after_sompi': candidate.reserve_after,
                'whole_PK_VK_READY_before_original_backup': True,
                'native_Full_all_input_engines': native['all_input_engines_accepted'] is True,
                'actual_selected_body_metrics': metrics})
        c.native_runtime.save(output / 'RESULTS.json', summary)
        return summary
    finally:
        if worker is not None:
            worker.close()


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('op', choices=OPS)
    for name in ('financial-profile', 'runtime-root', 'backup', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--financial-sha256', required=True)
    parser.add_argument('--source-kind', choices=('local', 'accepted'), required=True)
    for name in ('history', 'descriptor', 'fetch', 'bundle-directory', 'manifest', 'pk',
                 'request', 'virtual-prefix'):
        parser.add_argument('--' + name, type=Path)
    for name in ('history', 'descriptor', 'fetch', 'request', 'virtual-prefix'):
        parser.add_argument('--' + name + '-sha256')
    parser.add_argument('--ordinal', type=int, choices=(0, 1))
    parser.add_argument('--minimum-payout-sompi', type=int)
    parser.add_argument('--fee-rate', type=int, default=100)
    parser.add_argument('--workers', type=int, default=14)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--must-be-absent', type=Path, action='append', default=[])
    return parser.parse_args()


if __name__ == '__main__':
    import json
    try:
        print(json.dumps(run(arguments()), sort_keys=True))
    except Exception:
        print(json.dumps({'error': 'own-operation-incomplete',
                          'spend_authorized_or_submitted': False}))
        raise SystemExit(1)
