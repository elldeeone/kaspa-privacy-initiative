"""Synthetic public history controls, deliberately not real financial proofs."""
from copy import deepcopy
import struct
import unittest

from construction.codec import canonical_json
import public
from trees import sha


def fixture():
    records = []
    for index in range(3):
        note = sha(b'public owner', bytes([index])) + sha(b'public incoming', bytes([index]))
        note += (2_000_000_000).to_bytes(8, 'little') + bytes([index + 1]) * 96
        cf = bytes([index + 1]) * 264
        records.append(note + sha(b'KPX1NOT\0', public.DOMAIN, note) + cf + sha(cf))
    history = public.genesis(records, sha(b'public founding point').hex() + '00000000')
    roster = [sha(b'public participant', bytes([index])).hex() for index in range(3)]
    return history, roster


def batch_projection(history, round_number, roster):
    context = public.premix_context(history, sha(b'public profile').hex(), 30_000_000, '75')
    session = {'schema': 'kpx8-private-construction-session/v1',
        'session_id': sha(b'public session nonce', bytes([round_number])).hex(),
        'domain_hex': public.DOMAIN.hex(), 'prior_state_digest': sha(bytes.fromhex(history['head']['state_hex112'])).hex(),
        'circuit_profile_sha256': sha(b'public profile').hex(),
        'public_effects_context_sha256': sha(canonical_json(context)).hex(),
        'roster': roster, 'program_source_sha256': sha(b'public program').hex(),
        'tuple_bytes': 520, 'outputs_per_party': 2, 'mpc_prime': str(public.Q)}
    inputs = [((round_number * 3 + i + 1).to_bytes(32, 'little'), bytes([i + 1]) * 64) for i in range(3)]
    rows = []
    for index in range(6):
        cf = bytes([10 * round_number + index + 1]) * 264
        rows.append(sha(b'round CM', bytes([round_number, index])) + bytes([index + 1]) * 64
                    + cf + sha(cf) + bytes(128))
    body = public.body_core(history, inputs, rows, bytes(32), sha(canonical_json(session)).hex(), roster, 30_000_000)
    parsed = public.load_wire().parse_body(body)
    tail = b'\x75'
    wire = public.load_wire()
    before = wire.state_spk(parsed.old_state.raw, tail)
    after = wire.state_spk(parsed.new_state.raw, tail)
    prefix = (b'KPX8FX01' + struct.pack('<2H', 1, 1) + parsed.point + bytes([255]) * 8
        + parsed.old_reserve.to_bytes(8, 'little') + struct.pack('<H', 37) + before + struct.pack('<H', 1)
        + parsed.new_reserve.to_bytes(8, 'little') + struct.pack('<H', 37) + after + bytes(37)
        + len(body).to_bytes(4, 'little'))
    projection = prefix + body
    wire.validate_public(projection)
    return {'kind': 'batch', 'session': session, 'projection_hex': projection.hex(),
            'successor_outpoint_hex36': sha(b'round transaction', bytes([round_number])).hex() + '00000000'}


def exit_projection(history, index, gross):
    wire = public.load_wire()
    spk = b'\0\0\x20' + sha(b'public payout', bytes([index])) + b'\xac'
    body = public.exit_body(history, (100 + index).to_bytes(32, 'little'), spk, gross,
                            1_000_000, sha(b'exit session', bytes([index])).hex())
    parsed = wire.parse_exit_body(body)
    outputs = []
    if parsed.new_reserve:
        outputs.append((parsed.new_reserve, wire.state_spk(parsed.new_state.raw, b'\x75')))
    outputs.append((parsed.payout, spk))
    prefix = (b'KPX8FX01' + struct.pack('<2H', 1, 1) + parsed.point + bytes([255]) * 8
        + parsed.old_reserve.to_bytes(8, 'little') + struct.pack('<H', 37)
        + wire.state_spk(parsed.old_state.raw, b'\x75') + struct.pack('<H', len(outputs)))
    prefix += b''.join(value.to_bytes(8, 'little') + struct.pack('<H', len(script)) + script + b'\0'
                       for value, script in outputs)
    prefix += bytes(36) + len(body).to_bytes(4, 'little')
    projection = prefix + body
    wire.validate_exit_public(projection)
    return {'kind': 'exit', 'projection_hex': projection.hex(), 'proof_hex128': '00' * 128,
            'successor_outpoint_hex36': None if not parsed.new_reserve else
                sha(b'exit transaction', bytes([index])).hex() + '00000000'}


class HistoryTests(unittest.TestCase):
    def test_two_rounds_then_nine_exits_reconstruct_exactly(self):
        history, roster = fixture()
        for number in range(2):
            history = public.extend(history, batch_projection(history, number, roster))
        state, head = public.reconstruct(history)
        self.assertEqual((len(state.cms), len(state.nfs)), (15, 6))
        for index in range(9):
            gross = 600_000_000 if index != 8 else history['head']['reserve_sompi']
            history = public.extend(history, exit_projection(history, index, gross))
        state, head = public.reconstruct(history)
        self.assertEqual((head['reserve_sompi'], head['outpoint_hex36']), (0, None))
        self.assertEqual((len(state.cms), len(state.nfs)), (15, 15))

    def test_wrong_founding_record_root_or_reserve_rejected(self):
        history, _ = fixture()
        for key, value in (('state_hex112', '00' * 112), ('reserve_sompi', 1)):
            changed = deepcopy(history)
            changed['genesis'][key] = value
            with self.assertRaises(ValueError):
                public.reconstruct(changed)
        changed = deepcopy(history)
        changed['genesis']['records_hex496'][0] = '00' * 496
        with self.assertRaises(ValueError):
            public.reconstruct(changed)

    def test_stale_head_session_and_corrupted_path_rejected(self):
        history, roster = fixture()
        transition = batch_projection(history, 0, roster)
        final = public.extend(history, transition)
        for key in ('head', 'session', 'path'):
            changed = deepcopy(final)
            if key == 'head':
                changed['head'] = deepcopy(history['head'])
            elif key == 'session':
                changed['transitions'][0]['session']['session_id'] = 'aa' * 32
            else:
                raw = bytearray.fromhex(changed['transitions'][0]['projection_hex'])
                raw[193 + 3844 + 72] ^= 1
                changed['transitions'][0]['projection_hex'] = raw.hex()
            with self.assertRaises(ValueError):
                public.reconstruct(changed)

    def test_public_prepare_context_does_not_disclose_input_note(self):
        history, _ = fixture()
        context = public.premix_context(history, sha(b'profile').hex(), 30_000_001, '75')
        self.assertEqual(context['fee_shares_sompi'], [10_000_000, 10_000_000, 10_000_001])
        self.assertNotIn('initial_cms_hex32', context)
        self.assertNotIn('input_cm_hex32', context)
        self.assertNotIn('position', context)

    def test_original_NF_reuse_and_underfunded_exit_rejected(self):
        history, roster = fixture()
        history = public.extend(history, batch_projection(history, 0, roster))
        with self.assertRaises(ValueError):
            public.exit_body(history, (1).to_bytes(32, 'little'), b'\0\0\x20' + sha(b'payout') + b'\xac',
                             100_000_000, 1_000_000, sha(b'session').hex())
        with self.assertRaises(ValueError):
            exit_projection(history, 0, history['head']['reserve_sompi'] + 1)

    def test_spend_attachment_preserves_effects_but_output_proof_changes_them(self):
        history, roster = fixture()
        projection = bytes.fromhex(batch_projection(history, 0, roster)['projection_hex'])
        wire = public.load_wire()
        changed = public.attach_spend_proofs(projection, [bytes([i + 1]) * 128 for i in range(3)])
        self.assertEqual(wire.effects_digest(projection), wire.effects_digest(changed))
        corrupted = bytearray(projection)
        corrupted[193 + 724 + 392] ^= 1
        self.assertNotEqual(wire.effects_digest(projection), wire.effects_digest(bytes(corrupted)))


if __name__ == '__main__':
    unittest.main()
