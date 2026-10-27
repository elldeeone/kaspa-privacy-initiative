"""Synthetic byte fixtures only: no genuine proofs, chain data or owner inputs."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import unittest

import economic_ledger_adapter as adapter
import economic_linkage as observer
from test_economic_linkage import symmetric_public_fixture


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); sys.modules[name] = value; spec.loader.exec_module(value)
    return value


ROOT = Path(__file__).resolve().parents[1]
wire = module('_kpxa_adapter_toy_wire', ROOT / 'verification/wire.py')
trees = module('_kpxa_adapter_toy_trees', ROOT / 'integration/trees.py')


def toy_transaction(txid, inputs, outputs, payload=b''):
    return {'version': 1, 'id': txid, 'inputs': inputs, 'outputs': outputs, 'payload': payload.hex(),
            'lockTime': 0, 'subnetworkId': bytes(20).hex(), 'gas': 0, 'mass': 0}


def output(value, script):
    return {'value': value, 'scriptPublicKey': script.hex(), 'covenant': None}


def entry(value, script):
    return {'amount': value, 'scriptPublicKey': script.hex(), 'blockDaaScore': 0,
            'isCoinbase': False, 'covenantId': None}


def input_at(point, proof=bytes(128)):
    return {'previousOutpoint': {'transactionId': point[:32].hex(), 'index': int.from_bytes(point[32:], 'little')},
            'signatureScript': (b'\x4c\x80' + proof + b'PUBLIC SYNTHETIC UNUSED TAIL').hex(),
            'sequence': (1 << 64) - 1, 'computeBudget': 1}


def row(cm, label):
    cf = (wire.sha(label) * 9)[:264]
    return wire.build_output(bytes.fromhex(cm), b'\x21' * 64, cf, wire.sha(b'NOT A PROOF/' + label) * 4)


def synthetic_final():
    """Fake G16/Full status is fixture data, never financial acceptance evidence."""
    expected = symmetric_public_fixture(); tail = b'PUBLIC SYNTHETIC POLICY'
    genesis_rows = [row(g['cm_hex32'], b'genesis-' + bytes([i])) for i, g in enumerate(expected['genesis'])]
    state = trees.PublicState([r[:32] for r in genesis_rows])
    ordinary = []
    for i, fee in enumerate((7, 11, 13)):
        spk = b'\0\0\x20' + wire.sha(b'ordinary-public-destination/' + bytes([i])) + b'\xac'
        tx = toy_transaction(wire.sha(b'ordinary-public-ID/' + bytes([i])).hex(),
            [input_at(wire.sha(b'ordinary-public-source/' + bytes([i])) + bytes(4))], [output(2_000_000_010, spk)])
        ordinary.append({'transaction': tx, 'entries': [entry(2_000_000_010 + fee, spk)]})
    genesis_inputs = [input_at(adapter.point(case['transaction'])) for case in ordinary]
    genesis_entries = [entry(case['transaction']['outputs'][0]['value'],
                             bytes.fromhex(case['transaction']['outputs'][0]['scriptPublicKey'])) for case in ordinary]
    payload = b'KPXAGN01' + wire.sha(b'PUBLIC SYNTHETIC PROFILE') + wire.DOMAIN + b'\x11' * 16 + b''.join(genesis_rows)
    genesis_tx = toy_transaction(wire.sha(b'PUBLIC SYNTHETIC GENESIS ID').hex(), genesis_inputs,
        [output(6_000_000_000, wire.state_spk(state.state(), tail))], payload)
    genesis_case = {'transaction': genesis_tx, 'entries': genesis_entries}
    current_point, reserve = adapter.point(genesis_tx), 6_000_000_000
    first = {'state_hex112': state.state().hex(), 'reserve_sompi': reserve, 'outpoint_hex36': current_point.hex(),
             'outputs_hex520': [r.hex() for r in genesis_rows], 'deposit_sompi': 2_000_000_000}
    history = {'schema': 'kpxa-local-private-history/v1', 'domain_hex32': wire.DOMAIN.hex(),
               'genesis': first, 'transitions': [], 'head': None}
    pool, native_payouts = [genesis_case], []
    for i in range(15):
        payment = i < 6
        event = expected['payments'][i] if payment else expected['exits'][i - 6]
        old = state.state(); following = state.copy(); nf = bytes.fromhex(event['nf_hex32'])
        witness = following.insert(nf)
        if payment:
            rows = [row(o['cm_hex32'], b'payment-' + bytes([i, slot])) for slot, o in enumerate(event['outputs'])]
            paths = [following.append(r[:32]) for r in rows]
            remaining = reserve - event['fee_sompi']
            core = wire.build_body_core(action_id=bytes.fromhex(event['action_id_hex32']), point=current_point,
                old_state=old, new_state=following.state(), old_reserve=reserve, new_reserve=remaining,
                fee=event['fee_sompi'], delta=bytes(32), nf=nf, cv=b'\x31' * 64, outputs=rows,
                nf_witness=witness, cm_paths=paths)
            raw = wire.build_projection(core + wire.sha(b'PUBLIC SYNTHETIC SPEND/' + bytes([i])) * 4, tail)
            decoded = wire.parse_projection(raw); outputs = [output(remaining, decoded.output_spk)]
            proof = b'\x71' * 128
        else:
            remaining = reserve - event['payout_sompi'] - event['fee_sompi']
            payout_spk = b'\0\0\x20' + wire.sha(b'PUBLIC SYNTHETIC PAYOUT/' + bytes([i])) + b'\xac'
            body = wire.build_exit_body(action_id=bytes.fromhex(event['action_id_hex32']), point=current_point,
                old_state=old, new_state=following.state(), old_reserve=reserve, new_reserve=remaining,
                fee=event['fee_sompi'], payout=event['payout_sompi'], payout_spk=payout_spk, nf=nf, nf_witness=witness)
            raw = wire.build_exit_projection(body, tail); decoded = wire.parse_exit_projection(raw)
            outputs = [output(value, script) for value, script in decoded.outputs]
            proof = wire.sha(b'PUBLIC SYNTHETIC EXIT PROOF/' + bytes([i])) * 4
        tx = toy_transaction(wire.sha(b'PUBLIC SYNTHETIC TRANSITION ID/' + bytes([i])).hex(),
            [input_at(current_point, proof)], outputs, decoded.body.raw)
        case = {'transaction': tx, 'entries': [entry(reserve, decoded.input_spk)]}
        pool.append(case)
        current_point = adapter.point(tx) if remaining else None
        transition = {'kind': 'payment' if payment else 'exit', 'projection_hex': raw.hex(),
                      'successor_outpoint_hex36': None if current_point is None else current_point.hex()}
        if not payment:
            transition['proof_hex128'] = proof.hex()
            native_payouts.append({'outpoint_hex36': adapter.point(tx, len(outputs) - 1).hex(),
                'payout_sompi': event['payout_sompi'], 'fee_sompi': event['fee_sompi'],
                'script_public_key': decoded.body.payout_spk.hex()})
        history['transitions'].append(transition)
        state, reserve = following, remaining
    history['head'] = {'state_hex112': state.state().hex(), 'reserve_sompi': reserve, 'outpoint_hex36': None}
    cases = ordinary + pool; reports = []
    for i, case in enumerate(cases):
        fee = adapter.case_fee(case); group, index = ('ordinary', i) if i < 3 else ('pool', i - 3)
        reports.append({'kind': group, 'index': index, 'transaction_id': case['transaction']['id'],
            'case_path': '/PUBLIC-SYNTHETIC/%s-%02d-CASE.json' % (group, index),
            'case_sha256': wire.sha(adapter.encoded(case)).hex(), 'fee_sompi': fee,
            'metrics': {'actual_fee_sompi': fee}})
    accounting = {'schema': 'kpxa-independent-public-final-accounting/v1',
        'trial_id': '11111111-1111-1111-1111-111111111111',
        'status': 'ACTUAL_TERMINAL_NATIVE_ACCOUNTING_PASS', 'accepted_pool_transactions': 16,
        'ordinary_funding_transactions': 3, 'unique_confirmed_actions': 15, 'private_payments': 6,
        'direct_exit152_actions': 9, 'terminal_reserve_sompi': 0, 'terminal_cm_count': 15, 'terminal_nf_count': 16,
        'ordinary_pre_genesis_fee_sompi': 31, 'genesis_fee_sompi': 30, 'actual_native_Full_reports': reports,
        'native_payouts': native_payouts, 'private_payment_fee_sompi': 6000, 'direct_exit_fee_sompi': 9000,
        'native_payout_sum_sompi': sum(e['payout_sompi'] for e in expected['exits']),
        'history_sha256': wire.sha(adapter.encoded(history)).hex()}
    return history, accounting, cases, expected


class PublicAdapterControls(unittest.TestCase):
    def setUp(self):
        self.history, self.accounting, self.cases, self.expected = synthetic_final()

    def test_public_projection_fee_and_position_derivation(self):
        result = adapter.derive(self.history, self.accounting, self.cases, wire, observer)
        self.assertEqual(result, self.expected)
        self.assertEqual([o['position'] for p in result['payments'] for o in p['outputs']], list(range(3, 15)))
        self.assertEqual(sum(e['payout_sompi'] + e['fee_sompi'] for e in result['exits'])
                         + sum(p['fee_sompi'] for p in result['payments']), 6_000_000_000)
        self.assertEqual(set(result), {'schema', 'terminal', 'terminal_reserve_sompi', 'genesis', 'payments', 'exits'})

    def test_fee_payload_order_and_extra_private_fields_reject(self):
        for mutation in ('case-fee', 'report-fee', 'payload', 'order', 'exit-proof', 'private-field', 'head-bool', 'count-bool'):
            history, accounting, cases = deepcopy((self.history, self.accounting, self.cases))
            if mutation == 'case-fee': cases[4]['entries'][0]['amount'] += 1
            elif mutation == 'report-fee': accounting['actual_native_Full_reports'][4]['fee_sompi'] += 1
            elif mutation == 'payload':
                raw = bytearray.fromhex(cases[4]['transaction']['payload']); raw[48] ^= 1
                cases[4]['transaction']['payload'] = raw.hex()
            elif mutation == 'order': history['transitions'][0], history['transitions'][1] = history['transitions'][1], history['transitions'][0]
            elif mutation == 'exit-proof': history['transitions'][6]['proof_hex128'] = bytes(128).hex()
            elif mutation == 'private-field': history['transitions'][0]['owner_mapping'] = 'FORBIDDEN TOY FIELD'
            elif mutation == 'head-bool': history['head']['reserve_sompi'] = False
            else: accounting['terminal_reserve_sompi'] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                adapter.derive(history, accounting, cases, wire, observer)

    def test_genesis_root_and_ordinary_source_lineage_reject(self):
        history, accounting, cases = deepcopy((self.history, self.accounting, self.cases))
        raw = bytearray.fromhex(history['genesis']['outputs_hex520'][0]); raw[0] ^= 1
        history['genesis']['outputs_hex520'][0] = raw.hex()
        payload = bytearray.fromhex(cases[3]['transaction']['payload']); payload[88:608] = raw
        cases[3]['transaction']['payload'] = payload.hex()
        with self.assertRaisesRegex(ValueError, 'complete-public-GEN3'):
            adapter.derive(history, accounting, cases, wire, observer)
        history, accounting, cases = deepcopy((self.history, self.accounting, self.cases))
        cases[3]['transaction']['inputs'][0]['previousOutpoint']['transactionId'] = wire.sha(b'different public source').hex()
        with self.assertRaisesRegex(ValueError, 'ordinary-to-GEN3'):
            adapter.derive(history, accounting, cases, wire, observer)

    def test_fixed_native_prefix_fields_and_integer_types_reject(self):
        for key, value in [('lockTime', 1), ('gas', 1), ('subnetworkId', '01' * 20), ('version', True)]:
            case = deepcopy(self.cases[4]); case['transaction'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): adapter.case_projection(case)
        case = deepcopy(self.cases[4]); case['entries'][0]['amount'] = float(case['entries'][0]['amount'])
        with self.assertRaises(ValueError): adapter.case_fee(case)

    def test_public_trial_UUID_and_accounting_sompi_are_exact(self):
        for bad_index in (False, 0.0):
            cases = deepcopy(self.cases); cases[3]['transaction']['inputs'][0]['previousOutpoint']['index'] = bad_index
            with self.subTest(GEN3_index_type=type(bad_index)), self.assertRaises(ValueError):
                adapter.derive(self.history, self.accounting, cases, wire, observer)
        for key in ('ordinary_pre_genesis_fee_sompi', 'genesis_fee_sompi', 'private_payment_fee_sompi',
                    'direct_exit_fee_sompi', 'native_payout_sum_sompi'):
            accounting = deepcopy(self.accounting); accounting[key] = float(accounting[key])
            with self.subTest(field=key), self.assertRaises(ValueError):
                adapter.derive(self.history, accounting, self.cases, wire, observer)
        for key in ('payout_sompi', 'fee_sompi'):
            accounting = deepcopy(self.accounting)
            accounting['native_payouts'][0][key] = float(accounting['native_payouts'][0][key])
            with self.subTest(payout_field=key), self.assertRaises(ValueError):
                adapter.derive(self.history, accounting, self.cases, wire, observer)
        accounting = deepcopy(self.accounting); accounting['trial_id'] = '22222222-2222-2222-2222-222222222222'
        with self.assertRaisesRegex(ValueError, 'trial-UUID'):
            adapter.derive(self.history, accounting, self.cases, wire, observer)


if __name__ == '__main__':
    unittest.main()
