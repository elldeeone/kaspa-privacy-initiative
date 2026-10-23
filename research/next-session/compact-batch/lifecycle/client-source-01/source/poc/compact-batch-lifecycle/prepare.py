#!/usr/bin/env python3
"""Controller prepares only synthetic ordinary GN and public owner selections.

No private owner backup is read here. The separately controlled synthetic
ordinary-source key signs one ordinary funding transaction. Individual owner
proofs are produced later by owner.py with empty-FD PK authentication first.
All output (including public-format history) stays outside Git by default.
"""
import argparse
import hashlib
import json
from pathlib import Path
import secrets

import history
from native_runtime import DOMAIN, GENESIS, ROOT, Runtime, context, encoded, p2sh, public_case, save, tx
from owner import minimum_shape_fee
from primitives import NOTE_FLOOR, fixed, need, parse
import receiver


def manifests(compact_path, wide_path):
    values, digests = [], []
    for role, path in [('compact2', compact_path), ('wide32', wide_path)]:
        raw = receiver.no_symlinks(path).read_bytes()
        value = parse(raw)
        need(value['schema'] == 'kpx4-public-proving-parameters/v1' and value['role'] == role
             and value['domain_hex32'] == DOMAIN.hex() and value['genesis_hash_hex'] == GENESIS,
             'fresh-matched-role-manifest')
        values.append(value)
        digests.append(hashlib.sha256(raw).hexdigest())
    need(values[0]['compiled_build_identity_sha256'] == values[1]['compiled_build_identity_sha256'],
         'same-reviewed-build-two-relations')
    return values, digests


def new(identity, compact_manifest, wide_manifest, prover, prover_sha, output, rate=100):
    identity, output = receiver.no_symlinks(identity), receiver.no_symlinks(output)
    need(not identity.is_relative_to(ROOT) and not output.is_relative_to(ROOT) and not output.exists(),
         'fresh-main-controller-output-outside-Git')
    plan = parse((identity / 'PRIVATE-PLAN.json').read_bytes())
    need(plan['schema'] == 'kpx4-compact-batch-private-owner-plan/v1'
         and plan['domain_hex32'] == DOMAIN.hex() and plan['publish_or_hash'] is False,
         'new-local-private-owner-plan')
    values, hashes = manifests(compact_manifest, wide_manifest)
    compact, wide = (history.hexbytes(value['vk_hex328'], 328) for value in values)
    runtime, crypto, v2 = Runtime(), receiver.Crypto(), receiver.module()
    output.mkdir(parents=True, mode=0o700)
    payer_invoice = v2.Invoice.parse(history.hexbytes(plan['payer']['public_invoice_hex208'], 208))
    # Length/shape are public; source compute mass is checked again by each
    # owner's actual official quote before a private witness is serialized.
    dummy = v2.Receipt.for_invoice(payer_invoice, NOTE_FLOOR, secrets.token_bytes(32))
    test_cipher = crypto.seal(payer_invoice.delivery_pk, dummy.encode())
    _, template_redeem, _ = runtime.genesis(dummy.note_bytes(), test_cipher, compact, wide)
    exit_fee = minimum_shape_fee(2, len(template_redeem), rate)
    wide_fee = minimum_shape_fee(32, len(template_redeem), rate)
    useful_each = 1_000_000_000
    gross = useful_each + exit_fee
    initial_reserve = 32 * gross + wide_fee
    note = v2.Receipt.for_invoice(payer_invoice, initial_reserve, secrets.token_bytes(32))
    cipher = crypto.seal(payer_invoice.delivery_pk, note.encode())
    snapshot, redeem, payload = runtime.genesis(note.note_bytes(), cipher, compact, wide)
    source_spk = plan['funding_spk_hex']
    source = {'transactionId': hashlib.sha256(b'LOCAL_DO_NOT_FUND_ORDINARY_SOURCE\0' + DOMAIN
                    + bytes.fromhex(source_spk)).hexdigest(), 'index': 0}
    ordinary_change = 10_000_000_000
    fee, attempt = 1, 0
    while True:
        source_amount = initial_reserve + ordinary_change + fee
        entry = {'amount_sompi': str(source_amount), 'script_public_key': source_spk,
                 'block_daa_score': '0', 'is_coinbase': False, 'covenant_id': None}
        body = tx(source, [(initial_reserve, p2sh(redeem)), (ordinary_change, source_spk)],
                  payload, bytes(66), 10)
        body, metrics = runtime.normalize(body, [entry], output / f'entry-quote-{attempt:04d}')
        required = rate * metrics['mining_mass']
        if required == fee:
            break
        fee, attempt = required, attempt + 1
    signed = runtime.sdk(body, [entry], history.hexbytes(plan['funding_secret_hex32'], 32))
    signed, actual_metrics = runtime.normalize(signed, [entry], output / 'entry-final-normalized')
    need(actual_metrics['actual_fee_sompi'] == fee and rate * actual_metrics['mining_mass'] == fee,
         'ordinary-entry-official-exact-fee')
    runtime.sdk(signed, [entry])
    report, checked_metrics = runtime.validate(signed, [entry], output / 'entry-full')
    need(checked_metrics == actual_metrics, 'ordinary-entry-mass-conformance')
    founding = {'transactionId': signed['id'], 'index': 0}
    selected = {'schema': 'kpx4-compact-batch-descriptor/v1', 'network_id': 'testnet-10',
        'genesis_hash_hex': GENESIS, 'domain_hex32': DOMAIN.hex(), 'founding_outpoint': founding,
        'birth_start_hash': '00' * 32, 'initial_redeem_hex': redeem.hex(),
        'compact_vk_hex328': compact.hex(), 'wide_vk_hex328': wide.hex(),
        'immutable_policy_sha256': hashlib.sha256(redeem[114:]).hexdigest(),
        'compact_public_params_manifest_sha256': hashes[0],
        'wide_public_params_manifest_sha256': hashes[1]}
    descriptor_sha = hashlib.sha256(encoded(selected)).hexdigest()
    history.descriptor(encoded(selected), descriptor_sha)
    history.validate_genesis(signed, entry, selected, runtime, compact, wide)
    records = [{'transaction': signed, 'entries': public_case(signed, [entry])['entries']}]
    public_history = {'schema': 'kpx4-compact-batch-history/v1',
        'classification': 'SYNTHETIC_NATIVE_VALID_CONTEXTS_NOT_ACCEPTED',
        'descriptor_sha256': descriptor_sha, 'records': records}
    save(output / 'descriptor.json', selected)
    save(output / 'history-0000.json', public_history)
    for ordinal, role in enumerate(('compact2', 'wide32')):
        save(output / (role + '-client-selection.json'), {
            'schema': 'kpx4-compact-batch-owner-selection/v1', 'role': role,
            'domain_hex32': DOMAIN.hex(), 'descriptor_sha256': descriptor_sha,
            'parameter_manifest_sha256': hashes[ordinal], 'vk_sha256': values[ordinal]['vk_sha256'],
            'compiled_build_identity_sha256': values[ordinal]['compiled_build_identity_sha256'],
            'prover_sha256': prover_sha})
    # This controller-only plan is not mounted into any owner process. Its
    # sparse/private ownership join and paths are never published or hashed.
    save(output / 'PRIVATE-CONTROLLER.json', {'schema': 'kpx4-local-batch-controller/v1',
        'publish_or_hash': False, 'payer_backup': plan['payer']['backup'],
        'receiver_backups': [row['backup'] for row in plan['receivers']],
        'public_invoices': str(identity / 'PUBLIC-INVOICES.json'), 'prover': str(prover),
        'gross_recipient_sompi': gross, 'useful_each_sompi': useful_each,
        'wide_fee_expected_sompi': wide_fee, 'compact_continuing_fee_sompi': exit_fee,
        'compact_terminal_fee_sompi': minimum_shape_fee(0, len(redeem), rate),
        'source_sompi': source_amount, 'ordinary_change_sompi': ordinary_change,
        'entry_fee_sompi': fee, 'funding_source': source, 'founding': founding})
    for name, value in [('founding-transaction.json', signed), ('founding-context.json', [entry]),
                        ('founding-native.json', report), ('founding-metrics.json', actual_metrics)]:
        save(output / name, value)
    return {'classification': 'LOCAL_SYNTHETIC_NATIVE_GN_NOT_ACCEPTED_OR_FUNDED',
        'native_ordinary_GN_Full_all_engines': True, 'source_sompi': source_amount,
        'initial_reserve_sompi': initial_reserve, 'ordinary_change_sompi': ordinary_change,
        'entry_fee_sompi': fee, 'receiver_gross_sompi': gross,
        'wide_fee_planning_sompi': wide_fee, 'compact_exit_fee_planning_sompi': exit_fee,
        'descriptor_sha256': descriptor_sha, 'software_recipient_count_not_humans': 32,
        'old_seed_or_private_owner_backup_read': False, 'funding_network_or_broadcast': False}


def append(history_path, selected_output, output):
    """Link one already verified selected owner result into private history."""
    current = parse(Path(history_path).read_bytes())
    prepared = Path(selected_output) / 'prepared'
    body = parse((prepared / 'transaction.json').read_bytes())
    case = parse((prepared / 'validation-case.json').read_bytes())
    report = parse((prepared / 'native-validation.json').read_bytes())
    need(case['transaction'] == body and report['Full']['accepted'] is True
         and report['all_input_engines_accepted'] is True, 'selected-owner-native-Full-required')
    previous = current['records'][-1]['transaction']
    need(body['inputs'][0]['previousOutpoint'] == {'transactionId': previous['id'], 'index': 0}
         and case['entries'][0]['amount'] == previous['outputs'][0]['value']
         and case['entries'][0]['scriptPublicKey'] == previous['outputs'][0]['scriptPublicKey'],
         'selected-owner-exact-predecessor-context')
    current['records'].append(case)
    save(Path(output), current)
    return {'history_record_count': len(current['records']), 'transaction_id': body['id'],
            'accepted_chain_or_currentness_claimed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    initialize = sub.add_parser('init')
    for name in ('identity', 'compact-manifest', 'wide-manifest', 'prover', 'output'):
        initialize.add_argument('--' + name, type=Path, required=True)
    initialize.add_argument('--prover-sha', required=True)
    add = sub.add_parser('append')
    for name in ('history', 'owner-output', 'output'):
        add.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if args.operation == 'init':
        result = new(args.identity, args.compact_manifest, args.wide_manifest,
                     args.prover, args.prover_sha, args.output)
    else:
        result = append(args.history, args.owner_output, args.output)
    print(json.dumps(result, sort_keys=True))
