#!/usr/bin/env python3
"""Derive owner-free observer input from selected final public HISTORY/CASEs.

This checks byte/accounting consistency. Accepted-chain/native/proof authority
comes from the separately selected public final-accounting process, not a flag
or a new verification claim made by this adapter.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import types
import uuid

OBSERVER_SHA256 = 'f861537240593dfda94fccd499ab802f2f3bbe23a52d6d4c4219e81b97d60641'
MAX = 2_870_000_000_000_000_000


def need(value, code):
    if not value:
        raise ValueError(code)


def parse(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate-public-JSON-key'); value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite-JSON')))


def fields(value, names, code):
    need(type(value) is dict and set(value) == set(names), code)


def integer(value, maximum=MAX):
    need(type(value) is int and 0 <= value <= maximum, 'canonical-integer-sompi-or-index')
    return value


def hx(value, width=None):
    need(type(value) is str and len(value) % 2 == 0
         and re.fullmatch('[0-9a-f]*', value) is not None
         and (width is None or len(value) == width * 2), 'canonical-public-hex')
    return bytes.fromhex(value)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def point(transaction, index=0):
    return hx(transaction['id'], 32) + integer(index, (1 << 32) - 1).to_bytes(4, 'little')


def case_fee(case):
    transaction = case['transaction']
    need(len(case['entries']) == len(transaction['inputs']) and case['entries'], 'complete-actual-input-context')
    result = sum(integer(row['amount']) for row in case['entries'])
    result -= sum(integer(row['value']) for row in transaction['outputs'])
    need(0 < result <= MAX, 'positive-exact-CASE-fee')
    return result


def case_projection(case):
    """Independent fixed native-effect serialization, without invoking a codec."""
    transaction = case['transaction']
    need(transaction['version'] == 1 and type(transaction['version']) is int
         and len(transaction['inputs']) == len(case['entries']) == 1, 'one-canonical-reserve-input')
    item, entry = transaction['inputs'][0], case['entries'][0]
    previous = item['previousOutpoint']
    outpoint = hx(previous['transactionId'], 32) + integer(previous['index'], (1 << 32) - 1).to_bytes(4, 'little')
    need(integer(item['sequence'], (1 << 64) - 1) == (1 << 64) - 1, 'fixed-native-sequence')
    input_spk = hx(entry['scriptPublicKey'])
    need(len(input_spk) == 37, 'reserve-input-SPK-width')
    outputs = transaction['outputs']
    need(type(outputs) is list and len(outputs) in (1, 2), 'canonical-native-output-count')
    prefix = (b'KPXAFX01' + struct.pack('<HH', 1, 1) + outpoint + struct.pack('<Q', item['sequence'])
              + struct.pack('<QH', integer(entry['amount']), len(input_spk)) + input_spk
              + struct.pack('<H', len(outputs)))
    for output in outputs:
        script = hx(output['scriptPublicKey'])
        need(len(script) in (36, 37) and output.get('covenant') is None, 'canonical-native-output')
        prefix += struct.pack('<QH', integer(output['value']), len(script)) + script + b'\0'
    need(integer(transaction['lockTime'], (1 << 64) - 1) == 0
         and hx(transaction['subnetworkId'], 20) == bytes(20)
         and integer(transaction['gas'], (1 << 64) - 1) == 0, 'fixed-native-tail-fields')
    payload = hx(transaction['payload'])
    return prefix + bytes(36) + struct.pack('<I', len(payload)) + payload


def prefix_root(leaves, depth, tag, empty, wire):
    """Complete public prefix root; no private membership or proof query."""
    nodes, default = dict(enumerate(leaves)), empty
    for _ in range(depth):
        nodes = {parent: wire.sha(tag, nodes.get(parent * 2, default), nodes.get(parent * 2 + 1, default))
                 for parent in {index // 2 for index in nodes}}
        default = wire.sha(tag, default, default)
    return nodes.get(0, default)


def genesis_native_layout(case, first, genesis_fee, reserve_script):
    """Separate verified reserve0 from ordinary change; change is never note credit."""
    transaction, entries = case['transaction'], case['entries']
    outputs = transaction['outputs']
    need(type(outputs) is list and 1 <= len(outputs) <= 4 and len(entries) == 3,
         'GEN3-native-reserve-and-at-most-three-changes')
    need(outputs[0]['value'] == first['reserve_sompi']
         and first['outpoint_hex36'] == point(transaction).hex()
         and hx(outputs[0]['scriptPublicKey'], 37) == hx(reserve_script, 37),
         'actual-GEN3-reserve-outpoint-and-next-input-policy')
    scripts = [hx(entry['scriptPublicKey'], 36) for entry in entries]
    need(len(set(scripts)) == 3 and all(s[:3] == b'\x00\x00\x20' and s[-1:] == b'\xac' for s in scripts),
         'GEN3-distinct-ordinary-funding-P2PK-scripts')
    for output in outputs:
        fields(output, ('value', 'scriptPublicKey', 'covenant'), 'GEN3-native-output-fields')
        need(integer(output['value']) > 0 and output['covenant'] is None,
             'GEN3-positive-native-output-without-covenant')
    changes, last = [0, 0, 0], -1
    for output in outputs[1:]:
        script = hx(output['scriptPublicKey'], 36)
        need(script in scripts, 'GEN3-no-foreign-or-reserve-change')
        owner = scripts.index(script)
        need(owner > last, 'GEN3-change-order-or-duplicate')
        changes[owner], last = output['value'], owner
    fee = integer(genesis_fee)
    need(case_fee(case) == fee, 'GEN3-exact-full-CASE-fee')
    shares = [fee // 3, fee // 3, fee - 2 * (fee // 3)]
    for entry, change, share in zip(entries, changes, shares):
        need(integer(entry['amount']) == integer(first['deposit_sompi']) + change + share,
             'GEN3-exact-deposit-own-change-and-fee-share')
    return changes


def genesis_state(first, genesis_rows, wire):
    # These existing root checks are unchanged; isolation makes their controls explicit.
    initial = wire.parse_state(hx(first['state_hex112'], 112))
    need(initial.cm_count == 3 and initial.nf_count == 1, 'GEN3-state-counts')
    cm_root = prefix_root([row[:32] for row in genesis_rows], 16, b'KPX1CMN\0', wire.CM_EMPTY, wire)
    nf_root = prefix_root([wire.nf_leaf(bytes(32), bytes(32), 0)], 17, b'KPX1NFN\0', wire.NF_EMPTY, wire)
    need(initial.raw == wire.encode_state(cm_root, 3, nf_root, 1), 'complete-public-GEN3-CM-prefix-and-NF-sentinel')
    return initial


def derive(history, accounting, cases, wire, observer):
    fields(history, ('schema', 'domain_hex32', 'genesis', 'transitions', 'head'), 'public-history-fields')
    need(history['schema'] == 'kpxa-local-private-history/v1'
         and history['domain_hex32'] == wire.DOMAIN.hex(), 'selected-new-domain-history')
    need(accounting['schema'] == 'kpxa-independent-public-final-accounting/v1'
         and accounting['status'] == 'ACTUAL_TERMINAL_NATIVE_ACCOUNTING_PASS'
         and accounting['accepted_pool_transactions'] == 16 and accounting['ordinary_funding_transactions'] == 3
         and accounting['unique_confirmed_actions'] == 15 and accounting['private_payments'] == 6
         and accounting['direct_exit152_actions'] == 9 and accounting['terminal_reserve_sompi'] == 0
         and accounting['terminal_cm_count'] == 15 and accounting['terminal_nf_count'] == 16,
         'selected-terminal-accounting-profile')
    for key, expected in {'accepted_pool_transactions': 16, 'ordinary_funding_transactions': 3,
        'unique_confirmed_actions': 15, 'private_payments': 6, 'direct_exit152_actions': 9,
        'terminal_reserve_sompi': 0, 'terminal_cm_count': 15, 'terminal_nf_count': 16}.items():
        need(type(accounting[key]) is int and accounting[key] == expected, 'canonical-final-accounting-counts')
    for key in ('ordinary_pre_genesis_fee_sompi', 'genesis_fee_sompi', 'private_payment_fee_sompi',
                'direct_exit_fee_sompi', 'native_payout_sum_sompi'):
        integer(accounting[key])
    rows = accounting['actual_native_Full_reports']
    need(type(rows) is list and len(rows) == len(cases) == 19, 'exact-nineteen-selected-whole-CASEs')
    ids, fees = set(), []
    for index, (row, case) in enumerate(zip(rows, cases)):
        fields(row, ('kind', 'index', 'transaction_id', 'case_path', 'case_sha256', 'fee_sompi', 'metrics'),
               'public-CASE-selection-fields')
        group, number = ('ordinary', index) if index < 3 else ('pool', index - 3)
        need(row['kind'] == group and type(row['index']) is int and row['index'] == number,
             'fixed-ordinary-and-causal-pool-CASE-order')
        txid = hx(case['transaction']['id'], 32)
        need(txid != bytes(32) and row['transaction_id'] == txid.hex() and txid not in ids,
             'nineteen-distinct-selected-transaction-IDs')
        ids.add(txid)
        actual = case_fee(case)
        need(type(row['fee_sompi']) is int and actual == row['fee_sompi']
             and type(row['metrics']['actual_fee_sompi']) is int
             and actual == row['metrics']['actual_fee_sompi'], 'independent-native-CASE-fee-agreement')
        fees.append(actual)
    need(sum(fees[:3]) == accounting['ordinary_pre_genesis_fee_sompi']
         and fees[3] == accounting['genesis_fee_sompi'], 'external-funding-and-GEN3-fees-separated')
    first = history['genesis']
    fields(first, ('state_hex112', 'reserve_sompi', 'outpoint_hex36', 'outputs_hex520', 'deposit_sompi'),
           'public-GEN3-history-fields')
    need(type(first['outputs_hex520']) is list and len(first['outputs_hex520']) == 3
         and type(first['deposit_sompi']) is int and first['deposit_sompi'] == 2_000_000_000
         and type(first['reserve_sompi']) is int and first['reserve_sompi'] == 6_000_000_000,
         'three-public-twenty-KAS-note-values')
    genesis_rows = [hx(row, 520) for row in first['outputs_hex520']]
    for row in genesis_rows: wire.parse_output(row)
    genesis_case = cases[3]; genesis_tx = genesis_case['transaction']
    need(len(genesis_tx['inputs']) == len(genesis_case['entries']) == 3, 'three-ordinary-GEN3-inputs')
    for ordinary, item, entry in zip(cases[:3], genesis_tx['inputs'], genesis_case['entries']):
        previous = item['previousOutpoint']
        fields(previous, ('transactionId', 'index'), 'GEN3-previous-outpoint-fields')
        previous_id, previous_index = hx(previous['transactionId'], 32), integer(previous['index'], (1 << 32) - 1)
        need(len(ordinary['transaction']['outputs']) == 1
             and previous_id.hex() == ordinary['transaction']['id'] and previous_index == 0,
             'public-ordinary-to-GEN3-outpoint-lineage')
        output = ordinary['transaction']['outputs'][0]
        need(entry['amount'] == output['value'] and entry['scriptPublicKey'] == output['scriptPublicKey'],
             'public-GEN3-populated-ordinary-entry')
    payload = hx(genesis_tx['payload'])
    need(len(payload) == 1648 and payload[:8] == b'KPXAGN01' and payload[40:72] == wire.DOMAIN
         and payload[88:] == b''.join(genesis_rows), 'actual-GEN3-payload-equals-history-output-tuples')
    need(type(accounting['trial_id']) is str and payload[72:88] == uuid.UUID(accounting['trial_id']).bytes,
         'same-public-GEN3-trial-UUID')
    genesis_native_layout(genesis_case, first, fees[3], cases[4]['entries'][0]['scriptPublicKey'])
    initial = genesis_state(first, genesis_rows, wire)
    value = {'schema': observer.SCHEMA, 'terminal': True, 'terminal_reserve_sompi': 0,
        'genesis': [{'cm_hex32': row[:32].hex(), 'position': i, 'value_sompi': first['deposit_sompi']}
                    for i, row in enumerate(genesis_rows)], 'payments': [], 'exits': []}
    current_point, current_state, reserve = point(genesis_tx), initial.raw, first['reserve_sompi']
    current_spk, cm_position = hx(genesis_tx['outputs'][0]['scriptPublicKey']), 3
    transitions = history['transitions']
    need(type(transitions) is list and len(transitions) == 15, 'exact-final-fifteen-history-actions')
    payout_sum, payment_fee_sum, exit_fee_sum = 0, 0, 0
    payouts = accounting['native_payouts']; need(type(payouts) is list and len(payouts) == 9, 'nine-accounted-public-payouts')
    for index, (transition, case) in enumerate(zip(transitions, cases[4:])):
        payment = index < 6
        fields(transition, ('kind', 'projection_hex', 'successor_outpoint_hex36') if payment else
               ('kind', 'projection_hex', 'successor_outpoint_hex36', 'proof_hex128'), 'public-transition-fields')
        need(transition['kind'] == ('payment' if payment else 'exit'), 'accepted-six-payments-then-nine-exits')
        raw = hx(transition['projection_hex'])
        need(case_projection(case) == raw, 'actual-whole-CASE-native-effects-equal-history-projection')
        if payment:
            wire.validate_public(raw); projection = wire.parse_projection(raw)
        else:
            wire.validate_exit_public(raw); projection = wire.parse_exit_projection(raw)
            witness = hx(case['transaction']['inputs'][0]['signatureScript'])
            need(witness[:2] == b'\x4c\x80' and witness[2:130] == hx(transition['proof_hex128'], 128),
                 'actual-direct-Exit-proof-equals-public-history')
        body = projection.body
        need(body.point == current_point and body.old_state.raw == current_state and body.old_reserve == reserve
             and projection.input_spk == current_spk and case['entries'][0]['amount'] == reserve,
             'unbroken-current-native-reserve-and-public-state-lineage')
        need(body.fee == fees[index + 4], 'actual-CASE-fee-is-observed-action-fee')
        item = {'action_id_hex32': body.action_id.hex(), 'event_index': index,
                'nf_hex32': (body.spends[0].nf if payment else body.nf).hex(), 'fee_sompi': body.fee}
        if payment:
            item['outputs'] = [{'cm_hex32': output.cm.hex(), 'position': cm_position + slot}
                               for slot, output in enumerate(body.outputs)]
            value['payments'].append(item); cm_position += 2; payment_fee_sum += body.fee
        else:
            item['payout_sompi'] = body.payout; value['exits'].append(item)
            payout_sum += body.payout; exit_fee_sum += body.fee
            observed = payouts[index - 6]
            fields(observed, ('outpoint_hex36', 'payout_sompi', 'script_public_key', 'fee_sompi'), 'public-payout-fields')
            integer(observed['payout_sompi']); integer(observed['fee_sompi'])
            need(observed['outpoint_hex36'] == point(case['transaction'], len(case['transaction']['outputs']) - 1).hex()
                 and observed['payout_sompi'] == body.payout and observed['fee_sompi'] == body.fee
                 and hx(observed['script_public_key']) == body.payout_spk, 'selected-exact-public-native-payout-join')
        reserve, current_state = body.new_reserve, body.new_state.raw
        current_point = point(case['transaction']) if reserve else None
        need(transition['successor_outpoint_hex36'] == (None if current_point is None else current_point.hex()),
             'actual-successor-point-equals-history')
        if reserve:
            current_spk = hx(case['transaction']['outputs'][0]['scriptPublicKey'])
    head = {'state_hex112': current_state.hex(), 'reserve_sompi': reserve,
            'outpoint_hex36': None if current_point is None else current_point.hex()}
    final_state = wire.parse_state(current_state)
    fields(history['head'], ('state_hex112', 'reserve_sompi', 'outpoint_hex36'), 'canonical-final-head-fields')
    need(type(history['head']['reserve_sompi']) is int and head == history['head'] and reserve == 0 and current_point is None
         and final_state.cm_count == cm_position == 15 and final_state.nf_count == 16,
         'same-final-zero-reserve-CM15-NF16-history-head')
    need(payment_fee_sum == accounting['private_payment_fee_sompi']
         and exit_fee_sum == accounting['direct_exit_fee_sompi']
         and payout_sum == accounting['native_payout_sum_sompi']
         and payment_fee_sum + exit_fee_sum + payout_sum == 6_000_000_000,
         'full-note-exit-and-payment-fee-accounting')
    observer.validate_ledger(value)
    return value


def selected_module(name, raw, path):
    module = types.ModuleType(name); module.__file__ = str(path); sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def main():
    import argparse
    import runpy
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('history', 'accounting', 'wire', 'observer'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--provenance', type=Path, required=True)
    args = parser.parse_args()
    need(args.observer_sha256 == OBSERVER_SHA256, 'same-frozen-observer-input-schema')
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    raw = {name: read(str(getattr(args, name)), getattr(args, name + '_sha256'))
           for name in ('history', 'accounting', 'wire', 'observer')}
    history, accounting = parse(raw['history']), parse(raw['accounting'])
    need(accounting['history_sha256'] == hashlib.sha256(raw['history']).hexdigest(), 'accounting-selected-same-history-bytes')
    reports = accounting['actual_native_Full_reports']
    case_raw = [read(row['case_path'], row['case_sha256']) for row in reports]
    cases = [parse(value) for value in case_raw]
    wire = selected_module('_kpxa_economic_adapter_wire', raw['wire'], args.wire)
    observer = selected_module('_kpxa_frozen_public_observer', raw['observer'], args.observer)
    value = derive(history, accounting, cases, wire, observer)
    output_raw = encoded(value)
    provenance = {'schema': 'kpxa-public-economic-ledger-provenance/v1',
        'classification': 'PUBLIC_BYTE_AND_ACCOUNTING_DERIVATION_FROM_EXTERNALLY_SELECTED_FINAL_EVIDENCE',
        'public_ledger_sha256': hashlib.sha256(output_raw).hexdigest(),
        'history_sha256': hashlib.sha256(raw['history']).hexdigest(),
        'accounting_sha256': hashlib.sha256(raw['accounting']).hexdigest(),
        'wire_source_sha256': hashlib.sha256(raw['wire']).hexdigest(),
        'frozen_observer_source_sha256': hashlib.sha256(raw['observer']).hexdigest(),
        'selected_public_whole_CASE_sha256': [hashlib.sha256(case).hexdigest() for case in case_raw],
        'owner_mapping_private_plan_or_truth_input': False,
        'external_funding_and_genesis_fees_in_private_note_equation': False,
        'chain_native_or_proof_authority_independently_established_by_adapter': False}
    with args.output.open('xb') as out: out.write(output_raw)
    with args.provenance.open('xb') as out: out.write(encoded(provenance))
    print(json.dumps({'status': 'PUBLIC_ECONOMIC_LEDGER_DERIVED', 'public_ledger': str(args.output),
                     'sha256': provenance['public_ledger_sha256']}))


if __name__ == '__main__':
    main()
