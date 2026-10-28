"""Public model boundaries; no SDK, proof validity, chain or private run claim."""
import copy
import hashlib
import unittest

import accepted_head_relation as relation
import exit_wire
import genesis
import test_genesis as model
import wallet_history


def output_row(index):
    ciphertext = bytes([index]) * 264
    return (hashlib.sha256(b'PUBLIC HEAD MODEL CM' + bytes([index])).digest() + model.CV
            + ciphertext + hashlib.sha256(ciphertext).digest() + bytes([index]) * 128)


ADDED = tuple(output_row(i) for i in range(41, 47))
PROOF = bytes([67]) * 128


class ModelVerifier:
    def verify(self, row):
        return row in model.ROWS + ADDED


def selected():
    value = model.selection()
    return genesis.Selection(value.component_sha, value.identity, value.tail, ModelVerifier(), value.initial_cv)


def native_case(kind, context, body, outputs, label):
    redeem = b'\x4c\x70' + context.state() + model.TAIL
    script = b'\x4c\x80' + PROOF + b'\x4d' + len(redeem).to_bytes(2, 'little') + redeem
    return {'transaction': {'version': 1, 'id': hashlib.sha256(label).hexdigest(),
        'inputs': [{'previousOutpoint': {'transactionId': context.point[:32].hex(),
                                      'index': int.from_bytes(context.point[32:], 'little')},
                    'signatureScript': script.hex(), 'sequence': (1 << 64) - 1, 'computeBudget': 1800}],
        'outputs': [{'value': amount, 'scriptPublicKey': spk.hex(), 'covenant': None} for amount, spk in outputs],
        'lockTime': 0, 'subnetworkId': '00' * 20, 'gas': 0, 'payload': body.hex(), 'mass': 0},
        'entries': [{'amount': context.reserve, 'scriptPublicKey': exit_wire.state_spk(context.state(), model.TAIL).hex(),
                     'blockDaaScore': 123, 'isCoinbase': False, 'covenantId': None}]}


def vector():
    origin = model.case()
    state = wallet_history.trees.PublicState([row[:32] for row in model.ROWS])
    context = wallet_history.context(genesis.EXPECTED_IDENTITY,
        bytes.fromhex(origin['transaction']['id']) + bytes(4), state, genesis.RESERVE)
    following = state.copy()
    nfs = [i.to_bytes(32, 'little') for i in (1, 2, 3)]
    witnesses = [following.insert(nf) for nf in nfs]
    paths = [following.append(row[:32]) for row in ADDED]
    reserve, fee = 5_979_000_000, 21_000_000
    body = (b'KPBAEF01' + context.encode() + following.cm.root() + following.nf.root()
        + len(following.cms).to_bytes(4, 'little') + len(following.entries).to_bytes(4, 'little')
        + reserve.to_bytes(8, 'little') + fee.to_bytes(8, 'little') + bytes(32)
        + b''.join(nf + model.CV for nf in nfs) + b''.join(ADDED)
        + b''.join(witnesses) + b''.join(paths) + bytes([99]) * 128)
    payment = native_case('payment', context, body,
        [(reserve, exit_wire.state_spk(wallet_history.state_bytes(following, context.domain), model.TAIL))],
        b'PUBLIC MODEL PAYMENT ID')
    next_context = wallet_history.context(genesis.EXPECTED_IDENTITY,
        bytes.fromhex(payment['transaction']['id']) + bytes(4), following, reserve)
    final = following.copy()
    nf = (4).to_bytes(32, 'little')
    witness = final.insert(nf)
    body = exit_wire.body(next_context, bytes([71]) * 32, final.nf.root(), len(final.entries),
        reserve - 200_000_000, 1_000_000, 199_000_000,
        b'\0\0\x20' + bytes([72]) * 32 + b'\xac', nf, witness)
    exit_case = native_case('exit', next_context, body,
        [(reserve - 200_000_000, exit_wire.state_spk(exit_wire.parse_body(body).next_state(), model.TAIL)),
         (199_000_000, b'\0\0\x20' + bytes([72]) * 32 + b'\xac')], b'PUBLIC MODEL EXIT ID')
    return origin, [{'kind': 'payment', 'case': payment}, {'kind': 'exit', 'case': exit_case}], final


def verify_model(kind, case, projection, proof):
    # This explicit public model never claims real proof/native/SDK acceptance.
    return (projection is None and proof is None) if kind == 'genesis' else proof == PROOF


def replay(origin=None, events=None, verify=verify_model, fee=3_000_000):
    initial, transitions, _ = vector()
    return relation.replay_relation(initial if origin is None else origin, selected(), model.TRIAL,
                                   fee, transitions if events is None else events, verify)


class AcceptedHeadRelationControls(unittest.TestCase):
    def test_GEN3_only_export_has_three_CMs_and_NF_sentinel(self):
        result = replay(events=[])
        self.assertEqual(set(result), {'context_hex', 'commitments_hex32', 'nullifiers'})
        context = exit_wire.HeadContext.parse(bytes.fromhex(result['context_hex']))
        self.assertEqual((context.cm_count, context.nf_count, context.reserve), (3, 1, 6_000_000_000))
        self.assertEqual(result['commitments_hex32'], [row[:32].hex() for row in model.ROWS])
        self.assertEqual(result['nullifiers'], [{'value_hex32': '00' * 32, 'successor_hex32': '00' * 32, 'successor_index': 0}])

    def test_whole_CASE_ordered_payment_Exit_export_exact_tree_and_context(self):
        _, events, expected = vector()
        calls = []
        def verify(kind, case, projection, proof):
            calls.append(kind)
            return verify_model(kind, case, projection, proof)
        result = replay(verify=verify)
        context = exit_wire.HeadContext.parse(bytes.fromhex(result['context_hex']))
        self.assertEqual(calls, ['genesis', 'payment', 'exit'])
        self.assertEqual(context.point.hex(), events[-1]['case']['transaction']['id'] + '00000000')
        self.assertEqual((context.cm_count, context.nf_count, context.reserve), (9, 5, 5_779_000_000))
        self.assertEqual((context.cm_root, context.nf_root), (expected.cm.root(), expected.nf.root()))
        self.assertEqual(result['nullifiers'], [{'value_hex32': v.hex(), 'successor_hex32': s.hex(), 'successor_index': i}
                                               for v, s, i in expected.entries])

    def test_actual_verification_callback_required_for_every_CASE(self):
        for verdict in (False, 1, {'accepted': True}, None):
            with self.assertRaises(ValueError):
                replay(verify=lambda *_: verdict)
        for refused_kind in ('genesis', 'payment', 'exit'):
            with self.assertRaises(ValueError):
                replay(verify=lambda kind, *_: kind != refused_kind)
        with self.assertRaises(ValueError):
            replay(verify={'accepted': True})
        for mutate_kind in ('genesis', 'payment', 'exit'):
            def mutate(kind, case, projection, proof):
                if kind == mutate_kind:
                    case['transaction']['id'] = 'ab' * 32
                return verify_model(kind, case, projection, proof)
            with self.assertRaisesRegex(ValueError, 'mutated-CASE'):
                replay(verify=mutate)

    def test_callback_detached_alias_cannot_replace_verified_outpoint(self):
        _, events, _ = vector()
        expected_id = events[0]['case']['transaction']['id']
        def detach(kind, case, projection, proof):
            if kind == 'payment':
                detached = case['transaction']
                case['transaction'] = copy.deepcopy(detached)
                detached['id'] = 'ef' * 32
            return verify_model(kind, case, projection, proof)
        result = replay(events=events[:1], verify=detach)
        context = exit_wire.HeadContext.parse(bytes.fromhex(result['context_hex']))
        self.assertEqual(context.point.hex(), expected_id + '00000000')

    def test_GEN3_value_CV_funding_ALL_and_quote_checks_are_reexecuted(self):
        for mutation in ('CV', 'subsidy', 'reserve', 'sighash', 'ordinary'):
            initial = model.case()
            if mutation == 'CV':
                raw = bytearray.fromhex(initial['transaction']['payload']); raw[120] ^= 1
                initial['transaction']['payload'] = raw.hex()
            if mutation == 'subsidy':
                initial['transaction']['outputs'][1]['value'] += 1
                initial['transaction']['outputs'][2]['value'] -= 1
            if mutation == 'reserve': initial['transaction']['outputs'][0]['value'] += 1
            if mutation == 'sighash': initial['transaction']['inputs'][0]['signatureScript'] = '41' + '00' * 64 + '02'
            if mutation == 'ordinary': initial['entries'][0]['isCoinbase'] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): replay(origin=initial)
        with self.assertRaises(ValueError): replay(fee=3_000_001)

    def test_reordered_replayed_extra_flag_or_wrong_lane_CASEs_refuse(self):
        _, events, _ = vector()
        for changed in (events[::-1], [events[0], events[0]], [{**events[0], 'accepted': True}]):
            with self.assertRaises(ValueError): replay(events=changed)
        changed = copy.deepcopy(events)
        raw = bytearray.fromhex(changed[0]['case']['transaction']['payload']); raw[40] ^= 1
        changed[0]['case']['transaction']['payload'] = raw.hex()
        with self.assertRaises(ValueError): replay(events=changed)

    def test_actual_witness_proof_policy_and_native_effects_are_bound(self):
        for mutation in ('proof', 'redeem', 'extra-selector', 'output', 'NF-witness'):
            _, changed, _ = vector()
            case = changed[0]['case']
            if mutation in ('proof', 'redeem', 'extra-selector'):
                raw = bytearray.fromhex(case['transaction']['inputs'][0]['signatureScript'])
                if mutation == 'proof': raw[2] ^= 1
                if mutation == 'redeem': raw[-1] ^= 1
                if mutation == 'extra-selector': raw += b'\x51'
                case['transaction']['inputs'][0]['signatureScript'] = raw.hex()
            if mutation == 'output': case['transaction']['outputs'][0]['value'] += 1
            if mutation == 'NF-witness':
                raw = bytearray.fromhex(case['transaction']['payload']); raw[3812 + 72] ^= 1
                case['transaction']['payload'] = raw.hex()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): replay(events=changed)

    def test_noncanonical_integer_aliases_refuse(self):
        for field, value in (('lockTime', False), ('gas', False), ('mass', '0')):
            _, changed, _ = vector(); changed[0]['case']['transaction'][field] = value
            with self.assertRaises(ValueError): replay(events=changed)
        for value in (True, '1800', 65536):
            _, changed, _ = vector(); changed[0]['case']['transaction']['inputs'][0]['computeBudget'] = value
            with self.assertRaises(ValueError): replay(events=changed)

    def test_terminal_state_does_not_export_a_fake_live_head(self):
        origin = model.case()
        state = wallet_history.trees.PublicState([row[:32] for row in model.ROWS])
        context = wallet_history.context(genesis.EXPECTED_IDENTITY,
            bytes.fromhex(origin['transaction']['id']) + bytes(4), state, genesis.RESERVE)
        nf = (9).to_bytes(32, 'little'); witness = state.insert(nf)
        raw = exit_wire.body(context, bytes([81]) * 32, state.nf.root(), len(state.entries), 0,
            1_000_000, genesis.RESERVE - 1_000_000, b'\0\0\x20' + bytes([82]) * 32 + b'\xac', nf, witness)
        terminal = native_case('exit', context, raw,
            [(genesis.RESERVE - 1_000_000, b'\0\0\x20' + bytes([82]) * 32 + b'\xac')], b'PUBLIC TERMINAL MODEL ID')
        with self.assertRaisesRegex(ValueError, 'live-head'):
            replay(events=[{'kind': 'exit', 'case': terminal}])


if __name__ == '__main__':
    unittest.main()
