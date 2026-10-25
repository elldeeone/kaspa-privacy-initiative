"""Public structural negatives; these tests deliberately use invalid G16 bytes."""
import hashlib
import json
from pathlib import Path
import random
import struct
import unittest

import reference
import wire


def replace(raw, at, value):
    return raw[:at] + value + raw[at + len(value):]


class PublicCodecTests(unittest.TestCase):
    def setUp(self):
        self.fixture = reference.payment_fixture()
        self.raw = self.fixture['projection']

    def invalid_body(self, at, value):
        with self.assertRaises(wire.WireError):
            wire.parse_body(replace(self.fixture['body'], at, value))

    def test_frozen_spec_and_independent_reference_bytes(self):
        spec = json.loads((Path(__file__).resolve().parents[1] / 'SPEC.json').read_text())
        self.assertEqual(wire.sha(spec['domain_preimage_utf8_no_newline'].encode()), wire.DOMAIN)
        self.assertEqual((len(self.fixture['core']), len(self.fixture['body']), len(self.raw)), (3756, 3884, 4077))
        built = wire.build_body_core(**{key: self.fixture[key] for key in (
            'action_id', 'point', 'old_state', 'new_state', 'old_reserve', 'new_reserve',
            'fee', 'delta', 'nf', 'cv', 'outputs', 'nf_witness', 'cm_paths')})
        self.assertEqual(built, self.fixture['core'])
        self.assertEqual(wire.build_projection(self.fixture['body'], self.fixture['tail']), self.raw)
        result = wire.validate_public(self.raw)
        for key in ('g16_verified', 'curve_and_global_balance_verified', 'native_VM_executed',
                    'accepted_backing_or_currentness'):
            self.assertIs(result[key], False)
        self.assertEqual(wire.effects_digest(self.raw), hashlib.sha256(
            b'KPXAEF01' + self.fixture['prefix'] + self.fixture['core']).digest())
        self.assertEqual(len(wire.spend_statement(self.raw)), 200)
        self.assertEqual(len(wire.output_statement(self.fixture['outputs'][0])), 168)
        self.assertEqual(wire.journal(self.raw, bytes(32)), b'KPXAJR01' + wire.DOMAIN + bytes(32) + wire.sha(self.raw))

    def test_exact_width_type_tags_domain_and_reserved(self):
        for bad in (self.raw[:-1], self.raw + b'\0', bytearray(self.raw), self.raw.hex(), None):
            with self.subTest(type=type(bad)):
                with self.assertRaises(wire.WireError):
                    wire.parse_projection(bad)
        for at, value in [(0, b'KPX8PB01'), (8, struct.pack('<4H', 1, 3, 6, 0)),
                          (16, bytes(32)), (48, bytes(32)), (80, b'\1'), (112, bytes(32)),
                          (148, b'KPX8ST01'), (156, bytes(32)), (268, b'KPX8ST01')]:
            with self.subTest(at=at):
                self.invalid_body(at, value)
        for at in (0, 8, 48, 64, 103, 113, 152, 153, 189):
            changed = replace(self.raw, at, bytes([self.raw[at] ^ 1]))
            with self.assertRaises(wire.WireError):
                wire.parse_projection(changed)

    def test_delta_and_integer_boundaries(self):
        for value in (0, wire.Q - 1):
            wire.parse_body(replace(self.fixture['body'], 404, value.to_bytes(32, 'little')))
        self.invalid_body(404, wire.Q.to_bytes(32, 'little'))
        self.invalid_body(404, b'\xff' * 32)
        for reserve, remaining, fee in [(wire.NOTE_FLOOR + 1, wire.NOTE_FLOOR, 1),
                                        (wire.MAX_VALUE, wire.MAX_VALUE - 1, 1)]:
            body = replace(self.fixture['body'], 260, struct.pack('<Q', reserve))
            body = replace(body, 380, struct.pack('<QQQ', remaining, fee, 0))
            wire.parse_body(body)
        for at, value in [(260, wire.NOTE_FLOOR - 1), (260, wire.MAX_VALUE + 1),
                          (380, 0), (388, 0), (396, 1)]:
            self.invalid_body(at, struct.pack('<Q', value))
        params = {key: self.fixture[key] for key in ('action_id', 'point', 'old_state', 'new_state',
            'old_reserve', 'new_reserve', 'fee', 'delta', 'nf', 'cv', 'outputs', 'nf_witness', 'cm_paths')}
        for bad in (True, 1.0, -1, wire.MAX_VALUE + 1):
            with self.assertRaises(wire.WireError):
                wire.build_body_core(**{**params, 'fee': bad})

    def test_counts_capacity_and_forbidden_components(self):
        for at in (220, 256, 340, 376):
            self.invalid_body(at, bytes(4))
        for old_cm, old_nf, valid in [(65534, 131071, True), (65535, 1, False),
                                      (65536, 1, False), (1, 131072, False)]:
            body = self.fixture['body']
            for at, value in [(220, old_cm), (256, old_nf), (340, old_cm + 2), (376, old_nf + 1)]:
                body = replace(body, at, struct.pack('<I', value))
            if valid:
                wire.parse_body(body)
            else:
                with self.assertRaises(wire.WireError):
                    wire.parse_body(body)
        for empty in (wire.ZERO, wire.CM_EMPTY):
            self.invalid_body(532, empty)
        self.invalid_body(1052, self.fixture['outputs'][0])
        self.invalid_body(436, wire.ZERO)
        self.invalid_body(532 + 360, bytes(32))
        with self.assertRaises(wire.WireError):
            wire.insert_nf(bytes(32), 131072, self.fixture['nf'], self.fixture['nf_witness'])

    def test_effects_bind_outputs_paths_policy_and_exclude_only_spend_proof(self):
        effect = wire.effects_digest(self.raw)
        changed = wire.attach_spend_proof(self.raw, b'\x21' * 128)
        self.assertEqual(wire.effects_digest(changed), effect)
        self.assertNotEqual(wire.sha(changed), wire.sha(self.raw))
        for body_at in (48, 404, 532 + 392):
            at = wire.PREFIX_LEN + body_at
            changed = replace(self.raw, at, bytes([self.raw[at] ^ 1]))
            self.assertNotEqual(wire.effects_digest(changed), effect)
        for body_at in (1572 + 72, 1572 + 616, 2732, 3244):
            at = wire.PREFIX_LEN + body_at
            changed = replace(self.raw, at, bytes([self.raw[at] ^ 1]))
            self.assertNotEqual(wire.effects_digest(changed), effect)
            with self.assertRaises(wire.WireError):
                wire.validate_public(changed)
        changed = replace(self.raw, 70, bytes([self.raw[70] ^ 1]))
        self.assertNotEqual(wire.effects_digest(changed), effect)
        with self.assertRaises(wire.WireError):
            wire.require_current_head(changed, self.fixture['old_state'], self.fixture['point'],
                                      self.fixture['old_reserve'], self.fixture['tail'])

    def test_exact_current_head_stale_cross_domain_and_replay(self):
        f = self.fixture
        wire.require_current_head(self.raw, f['old_state'], f['point'], f['old_reserve'], f['tail'])
        for state, point, reserve, tail in [(f['new_state'], f['point'], f['old_reserve'], f['tail']),
            (f['old_state'], b'\x21' * 36, f['old_reserve'], f['tail']),
            (f['old_state'], f['point'], f['old_reserve'] - 1, f['tail']),
            (f['old_state'], f['point'], f['old_reserve'], b'different-policy')]:
            with self.assertRaises(wire.WireError):
                wire.require_current_head(self.raw, state, point, reserve, tail)
        with self.assertRaises(ValueError):
            f['following'].insert(f['nf'])
        with self.assertRaises(ValueError):
            f['following'].transition('batch', [f['nf']], [row[:32] for row in f['outputs']],
                                      f['old_state'], f['new_state'])
        with self.assertRaises(ValueError):
            f['initial'].state(bytes(32), b'KPXAST01')

    def test_independent_random_public_tree_transitions_and_atomic_failures(self):
        rng = random.Random(6601)
        state = reference.PublicState([wire.sha(b'public genesis')])
        for round_number in range(48):
            old, old_root, old_count = state.state(), state.nf.root(), len(state.entries)
            nf = rng.getrandbits(256).to_bytes(32, 'little')
            witness = state.insert(nf)
            self.assertEqual(wire.insert_nf(old_root, old_count, nf, witness), state.nf.root())
            for index in range(2):
                cm = wire.sha(struct.pack('<II', round_number, index))
                before, position = state.cm.root(), len(state.cms)
                path = state.append(cm)
                self.assertEqual(wire.fold(wire.CM_EMPTY, position, path, b'KPX1CMN\0', 16), before)
                self.assertEqual(wire.fold(cm, position, path, b'KPX1CMN\0', 16), state.cm.root())
            before = state.state()
            with self.assertRaises(ValueError):
                state.transition('batch', [wire.sha(b'next' + old)], [wire.sha(b'a' + old), wire.sha(b'b' + old)],
                                 old, bytes(112))
            self.assertEqual(state.state(), before)

    def test_complete_tree_capacity_and_invalid_indices(self):
        cms = [wire.sha(struct.pack('<I', i)) for i in range(1 << 16)]
        state = reference.PublicState(cms)
        before = len(state.cms)
        with self.assertRaises(ValueError):
            state.append(wire.sha(b'past capacity'))
        self.assertEqual(len(state.cms), before)
        for index in (-1, 1 << 16, True):
            with self.assertRaises(ValueError):
                state.cm.path(index)

    def test_historical_repeated_CM_at_distinct_positions_replays(self):
        first = self.fixture
        state = first['following'].copy()
        old = state.state()
        nf = wire.sha(b'second public payment NF')
        witness = state.insert(nf)
        rows = [first['outputs'][0], reference.output(b'second-payment-other-output')]
        paths = [state.append(row[:32]) for row in rows]
        core = wire.build_body_core(action_id=wire.sha(b'second public action'),
            point=wire.sha(b'second public head') + bytes(4), old_state=old, new_state=state.state(),
            old_reserve=first['new_reserve'], new_reserve=first['new_reserve'] - first['fee'],
            fee=first['fee'], delta=bytes(32), nf=nf, cv=first['cv'], outputs=rows,
            nf_witness=witness, cm_paths=paths)
        projection = wire.build_projection(core + bytes(128), first['tail'])
        wire.validate_public(projection)
        self.assertEqual((len(first['following'].cms), len(state.cms)), (3, 5))
        self.assertEqual(state.cms[1], state.cms[3])
        self.assertNotEqual(state.cm.path(1), state.cm.path(3))
        rebuilt = reference.PublicState(state.cms, state.nfs)
        self.assertEqual(rebuilt.state(), state.state())
        following, witnesses, appends = first['following'].transition('batch', [nf],
            [row[:32] for row in rows], old, state.state())
        self.assertEqual((following.state(), witnesses, appends), (state.state(), [witness], paths))
        with self.assertRaises(ValueError):
            first['following'].transition('batch', [nf], [rows[0][:32], rows[0][:32]], old, state.state())

    def test_continuing_and_terminal_exit_reference_and_negatives(self):
        for terminal in (False, True):
            f = reference.exit_fixture(terminal)
            raw = f['projection']
            self.assertEqual(len(raw), 1632 + (192 if terminal else 240))
            body = wire.build_exit_body(**{key: f[key] for key in ('action_id', 'point', 'old_state',
                'new_state', 'old_reserve', 'new_reserve', 'fee', 'payout', 'payout_spk', 'nf', 'nf_witness')})
            self.assertEqual(body, f['body'])
            self.assertEqual(wire.build_exit_projection(body, f['tail']), raw)
            wire.require_current_exit_head(raw, f['old_state'], f['point'], f['old_reserve'], f['tail'])
            statement = wire.exit_statement(raw)
            self.assertEqual(len(statement), 152)
            self.assertEqual(statement[:40], b'KPXAEX01' + wire.DOMAIN)
            self.assertFalse(wire.validate_exit_public(raw)['g16_verified'])
            for body_at in (0, 16, 48, 80, 112, 148, 268, 388, 396, 404, 440, 472 + 72):
                at = len(f['prefix']) + body_at
                changed = replace(raw, at, bytes([raw[at] ^ 1]))
                if body_at == 48:
                    # A different nonzero action is structurally well-formed;
                    # the genuine Exit proof must bind its changed effects.
                    self.assertNotEqual(wire.exit_effects_digest(changed), wire.exit_effects_digest(raw))
                elif body_at == 112:
                    with self.assertRaises(wire.WireError):
                        wire.require_current_exit_head(changed, f['old_state'], f['point'], f['old_reserve'], f['tail'])
                else:
                    with self.assertRaises(wire.WireError):
                        wire.validate_exit_public(changed)
            with self.assertRaises(wire.WireError):
                wire.require_current_exit_head(raw, f['new_state'], f['point'], f['old_reserve'], f['tail'])


if __name__ == '__main__':
    unittest.main()
