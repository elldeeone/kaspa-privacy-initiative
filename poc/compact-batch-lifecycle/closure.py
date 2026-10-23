#!/usr/bin/env python3
"""Read-only financial closure of the supplied-context 32-recipient experiment.

Reads selected public-format history/body/case/report/metrics and public proving
reports only. Never opens a controller plan, backup, private witness or PK. No
native/SDK/proof/network API is invoked. Recorded execution reports are trusted
experiment evidence, not self-authenticating acceptance/currentness authority.
"""
import argparse
from decimal import Decimal, localcontext
from fractions import Fraction
import hashlib
import json
from pathlib import Path

import history
from native_runtime import DOMAIN, encoded, quote_id
from primitives import MAX, h, need, parse
from receiver import no_symlinks

COUNT = 32
USEFUL_EACH = 1_000_000_000
COMMON_BYTES = 23575


def read(path):
    return parse(no_symlinks(path).read_bytes())


def recorded_metrics(case, report, metrics, rate):
    """Exact selected-case arithmetic; caller separately authenticates execution."""
    rows = history.contexts(case)
    body = case['transaction']
    history.hexbytes(body['id'], 32)
    history.common(body)
    need(type(rate) is int and rate > 0, 'reference-fee-rate')
    fees = int(rows[0]['amount_sompi']) - sum(row['value'] for row in body['outputs'])
    need(type(metrics) is dict and type(metrics['mining_mass']) is int and metrics['mining_mass'] > 0
         and type(metrics['actual_fee_sompi']) is int and type(metrics['storage_mass']) is int
         and body['mass'] == metrics['storage_mass']
         and fees == metrics['actual_fee_sompi'] == rate * metrics['mining_mass']
         and fees > 0, 'exact-recorded-minimum-fee-and-storage')
    need(report['isolation'] == 'PASS' and report['Full']['accepted'] is True
         and report['Full']['fee_sompi'] == fees and report['all_input_engines_accepted'] is True
         and len(report['per_input_ScriptEngine']) == len(body['inputs'])
         and all(row['accepted'] is True for row in report['per_input_ScriptEngine']),
         'recorded-native-Full-all-engines-required')
    need(case['entries'][0]['blockDaaScore'] == 0, 'supplied-contexts-have-explicit-synthetic-zero-DAA')
    return rows, fees


def accounting(source, ordinary_change, entry_fee, private_fees, payouts, useful_each):
    need(useful_each == USEFUL_EACH and len(private_fees) == COUNT + 1
         and len(payouts) == COUNT, 'fixed-economic-intent-and-complete-drain-count')
    need(all(type(v) is int and 0 < v <= MAX for v in [source, ordinary_change, entry_fee, *private_fees, *payouts]),
         'positive-bounded-financial-values')
    continuing_fees = private_fees[1:-1]
    need(len(set(continuing_fees)) == 1 and payouts[:-1] == [useful_each] * (COUNT - 1),
         'all31-useful-withdrawals-and-common-gross-credit')
    need(private_fees[-1] < continuing_fees[0], 'terminal-minimum-fee-credit-surplus')
    refund = continuing_fees[0] - private_fees[-1]
    need(payouts[-1] == useful_each + refund, 'terminal-surplus-refunded-not-donated')
    gross = useful_each + continuing_fees[0]
    need(all(payout + fee == gross for payout, fee in zip(payouts, private_fees[1:])),
         'same-gross-recipient-claims')
    fees, native = entry_fee + sum(private_fees), sum(payouts)
    useful = COUNT * useful_each
    need(source == ordinary_change + native + fees, 'whole-source-exact-reconciliation-no-tail')
    ratio = Fraction(100 * fees, useful)
    with localcontext() as context:
        context.prec = 40
        decimal = format(Decimal(ratio.numerator) / Decimal(ratio.denominator), 'f')
    return {'source_sompi': source, 'ordinary_change_sompi': ordinary_change,
        'useful_payment_count': COUNT, 'useful_each_sompi': useful_each, 'useful_payment_total_sompi': useful,
        'gross_recipient_claim_sompi': gross, 'native_payout_total_sompi': native,
        'terminal_credit_refund_sompi': refund, 'all_entry_and_private_fees_sompi': fees,
        'fee_percent_exact': [ratio.numerator, ratio.denominator], 'fee_percent_decimal': decimal,
        'refund_gross_note_credit_and_ordinary_change_counted_as_useful': False}


class PublicPolicy:
    """Pure reconstruction of the externally pinned immutable program tail."""
    def __init__(self, descriptor, compact, wide):
        redeem = history.hexbytes(descriptor['initial_redeem_hex'])
        need(len(redeem) == COMMON_BYTES and redeem[:2] == b'\x4c\x70'
             and redeem[114:].count(compact) == 1 and redeem[114:].count(wide) == 1,
             'actual-complete23575-program-and-two-role-key-operands')
        self.tail = redeem[114:]

    def emit(self, state, compact, wide):
        need(len(state) == 112, 'state-width')
        return b'\x4c\x70' + state + self.tail


def selected_owner(directory):
    """Finite reads only; raw diagnostics and private plans are deliberately absent."""
    base = no_symlinks(directory)
    result = read(base / 'RESULTS.json')
    body = read(base / 'prepared/transaction.json')
    contexts = read(base / 'prepared/supplied-context.json')
    case = read(base / 'prepared/validation-case.json')
    native = read(base / 'prepared/native-validation.json')
    metrics = read(base / 'prepared/metrics.json')
    proof_report = read(base / 'proof/report.json')
    need(case['transaction'] == body and history.contexts(case) == contexts,
         'selected-executed-case-body-and-context-identity')
    return {'result': result, 'case': case, 'report': native, 'metrics': metrics, 'proof_report': proof_report}


def close(args):
    descriptor, compact, wide = history.descriptor(no_symlinks(args.descriptor).read_bytes(), args.descriptor_sha256)
    manifests = {}
    for role, path, vk in [('compact2', args.compact_manifest, compact), ('wide32', args.wide_manifest, wide)]:
        raw = no_symlinks(path).read_bytes()
        manifest = parse(raw)
        field = 'compact_public_params_manifest_sha256' if role == 'compact2' else 'wide_public_params_manifest_sha256'
        need(manifest['schema'] == 'kpx4-public-proving-parameters/v1' and manifest['role'] == role
             and manifest['domain_hex32'] == DOMAIN.hex() and manifest['output_arity'] == (2 if role == 'compact2' else 32)
             and hashlib.sha256(raw).hexdigest() == descriptor[field]
             and history.hexbytes(manifest['vk_hex328'], 328) == vk and manifest['vk_sha256'] == h(vk).hex(),
             'externally-pinned-role-manifests-and-VKs')
        manifests[role] = manifest
    need(manifests['compact2']['compiled_build_identity_sha256'] == manifests['wide32']['compiled_build_identity_sha256'],
         'same-reviewed-build-independent-role-relations')
    data = read(args.history)
    need(set(data) == {'schema', 'classification', 'descriptor_sha256', 'records'}
         and data['schema'] == 'kpx4-compact-batch-history/v1'
         and data['classification'] == 'SYNTHETIC_NATIVE_VALID_CONTEXTS_NOT_ACCEPTED'
         and data['descriptor_sha256'] == args.descriptor_sha256 and len(data['records']) == 34,
         'complete34-record-supplied-context-history')
    selected = [selected_owner(path) for path in args.owner_output]
    indexed = {row['case']['transaction']['id']: row for row in selected}
    need(len(selected) == len(indexed) == 33, 'all33-distinct-selected-owner-results')
    records = data['records']
    need(len({record['transaction']['id'] for record in records}) == 34, 'all34-history-body-IDs-distinct')
    policy = PublicPolicy(descriptor, compact, wide)
    first = records[0]
    entries, entry_fee = recorded_metrics(first, read(args.founding_native), read(args.founding_metrics), args.fee_rate)
    snapshot, reserve, redeem = history.validate_genesis(first['transaction'], entries[0], descriptor, policy, compact, wide)
    source = int(entries[0]['amount_sompi'])
    need(len(first['transaction']['outputs']) == 2, 'one-direct-entry-with-explicit-ordinary-change')
    ordinary_change = first['transaction']['outputs'][1]['value']
    previous = {'transactionId': first['transaction']['id'], 'index': 0}
    fees, payouts, safe = [], [], []
    modes = []
    for ordinal, case in enumerate(records[1:]):
        body = case['transaction']
        need(body['id'] in indexed and indexed[body['id']]['case'] == case, 'history-matches-exact-selected-owner-case')
        item = indexed[body['id']]
        contexts, fee = recorded_metrics(case, item['report'], item['metrics'], args.fee_rate)
        auth = history.hexbytes(body['payload'])[:528]
        frame = history.hexbytes(body['inputs'][0]['signatureScript'])
        role = 'wide32' if ordinal == 0 else 'compact2'
        mode = 32 if ordinal == 0 else 0 if ordinal == 32 else 2
        proof = frame[68:196]
        need(len(proof) == 128 and len(frame[199:]) == COMMON_BYTES and auth[300] == mode,
             'actual-private-budget-mode-frame-and-program-size')
        result, proof_report, manifest = item['result'], item['proof_report'], manifests[role]
        need(result['schema'] == 'kpx4-compact-batch-owner-result/v1'
             and proof_report['schema'] == 'kpx4-own-prover-public-report/v1'
             and result['classification'] == 'SUPPLIED_SYNTHETIC_CONTEXTS_NOT_ACCEPTED_OR_CURRENT'
             and result['role'] == proof_report['role'] == role and result['mode'] == mode
             and result['transaction_id'] == body['id']
             and proof_report['genuine_Groth16_verified'] is True
             and result['proof_sha256'] == proof_report['proof_sha256'] == h(proof).hex()
             and result['authorization_sha256'] == proof_report['authorization_sha256'] == h(auth).hex()
             and result['prover_authenticated_whole_PK_before_own_backup_read'] is True
             and result['recognized_current_claim_count_before'] == 1
             and result['native_Full_all_engines_with_supplied_contexts'] is True
             and proof_report['vk_sha256'] == manifest['vk_sha256']
             and proof_report['compiled_build_identity_sha256'] == manifest['compiled_build_identity_sha256']
             and proof_report['parameter_manifest_sha256'] == descriptor[
                 'wide_public_params_manifest_sha256' if role == 'wide32' else 'compact_public_params_manifest_sha256'],
             'selected-role-proof-effect-parameter-and-one-backup-records')
        need(result['quote_id'] == quote_id(body, contexts, args.fee_rate)
             and result['fee_sompi'] == fee
             and result['native_payout_sompi'] == int.from_bytes(auth[484:492], 'little')
             and result['reserve_after_sompi'] == int.from_bytes(auth[476:484], 'little'),
             'independently-reproduced-proof-normalized-quote-and-effects')
        snapshot, reserve, redeem = history.advance(snapshot, reserve, previous, redeem, body,
            contexts[0], policy, compact, wide)
        need(reserve == result['reserve_after_sompi'], 'exact-replayed-reserve')
        previous = {'transactionId': body['id'], 'index': 0} if reserve else None
        modes.append(mode)
        fees.append(fee)
        if ordinal:
            payouts.append(result['native_payout_sompi'])
        else:
            need(result['native_payout_sompi'] == 0, 'wide-P0-not-useful-native-payment')
        safe.append({'sequence': ordinal + 1, 'role': role, 'mode': mode,
            'selected_case_matches_history_and_quote_reproduced': True,
            'proof_sha256': h(proof).hex(), 'authorization_sha256': h(auth).hex(),
            'fee_sompi': fee, 'native_payout_sompi': result['native_payout_sompi'], 'reserve_after_sompi': reserve})
    need(reserve == 0 and previous is None and modes == [32] + [2] * 31 + [0]
         and snapshot.cm_cursor == 126 and len(snapshot.deliveries) == 95 and len(snapshot.nullifiers) == 67,
         'complete-independent-drain-and-sparse-counts')
    outcome = accounting(source, ordinary_change, entry_fee, fees, payouts, args.useful_each)
    return {'schema': 'kpx4-supplied-batch-financial-closure/v1',
        'classification': 'GENUINE_RECORDED_PROOFS_NATIVE_SUPPLIED_CONTEXTS_ONLY',
        'domain_hex32': DOMAIN.hex(), 'reference_fee_rate': args.fee_rate, **outcome,
        'history_record_count': 34, 'recorded_genuine_owner_proofs': 33, 'recorded_full_native_bodies': 34,
        'all33_quote_IDs_reproduced_from_selected_public_bodies_and_contexts': True,
        'whole_common_program_bytes': COMMON_BYTES, 'all_private_compute_budgets': 1600,
        'CM_cursor_after': snapshot.cm_cursor, 'delivery_record_count': len(snapshot.deliveries),
        'NF_count_after': len(snapshot.nullifiers), 'terminal_reserve_sompi': 0,
        'direct_ordinary_source_inputs': 1, 'separate_funding_preparation_transactions_in_this_fixture': 0,
        'new_native_SDK_G16_setup_network_or_PK_execution_by_collector': False,
        'accepted_backing_currentness_privacy_fee_production_or32human_qualification': False,
        'private_inputs_or_witness_hashes_backup_paths_owner_maps_exported': False,
        'selected_public_effects': safe}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('history', 'descriptor', 'compact-manifest', 'wide-manifest', 'founding-native', 'founding-metrics', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--descriptor-sha256', required=True)
    parser.add_argument('--owner-output', type=Path, action='append', required=True)
    parser.add_argument('--useful-each', type=int, default=USEFUL_EACH)
    parser.add_argument('--fee-rate', type=int, default=100)
    args = parser.parse_args()
    try:
        value = close(args)
        output = no_symlinks(args.output)
        need(not output.exists(), 'fresh-sanitized-closure-output')
        with output.open('xb') as file:
            file.write(encoded(value) + b'\n')
        print(json.dumps({key: value[key] for key in ('history_record_count', 'recorded_genuine_owner_proofs',
            'all_entry_and_private_fees_sompi', 'useful_payment_total_sompi', 'terminal_credit_refund_sompi', 'fee_percent_decimal')}))
    except (ValueError, KeyError, TypeError, OSError):
        raise SystemExit('compact batch financial closure refused') from None
