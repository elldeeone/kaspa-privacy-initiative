"""Independent path/effects controls; synthetic bytes are not genuine proofs."""
import unittest

import public as assembly
from trees import PublicState, sha


def fixture():
    cms = [sha(b'PUBLIC GENESIS', bytes([i])) for i in range(3)]
    initial = assembly.genesis(cms, 3_000_000_000)
    inputs = [(i.to_bytes(32, 'little'), bytes([i]) * 64) for i in (7, 3, 11)]
    rows = []
    for i in range(6):
        cf = bytes([i + 1]) * 264
        rows.append(sha(b'PUBLIC OUTPUT', bytes([i])) + bytes([i + 1]) * 64
                    + cf + sha(cf) + bytes(128))
    roster = [sha(b'PUBLIC PARTICIPANT', bytes([i])).hex() for i in range(3)]
    body = assembly.body_core(initial, inputs, rows, bytes(32), sha(b'PUBLIC SESSION').hex(),
                              roster, sha(b'KPX7 unfunded prototype context') + bytes(4), 30_000_000)
    spk = b'\0\0\xaa\x20' + sha(b'FRAME ONLY, NOT A NATIVE TEMPLATE') + b'\x87'
    return initial, inputs, rows, assembly.project(body, spk, spk)


class PublicAssemblyTests(unittest.TestCase):
    def test_genesis_prefix_and_all_paths(self):
        initial, _, _, projection = fixture()
        old = assembly.wire.parse_projection(projection).body.old_state
        self.assertEqual((old.cm_count, old.nf_count), (3, 1))
        for i, cm in enumerate(initial['initial_cm_hex32']):
            self.assertEqual(assembly.wire.fold(bytes.fromhex(cm), i,
                bytes.fromhex(initial['membership_path_hex512'][i]), b'KPX1CMN\0', 16), old.cm_root)
        changed = dict(initial, state_hex112='00' * 112)
        with self.assertRaises(ValueError):
            assembly.parse_genesis(changed)

    def test_independent_indexed_NF_builder_matches_consumer_in_unsorted_order(self):
        initial, inputs, _, _ = fixture()
        state = PublicState([bytes.fromhex(cm) for cm in initial['initial_cm_hex32']])
        for nf, _ in inputs:
            root, count = state.nf.root(), len(state.entries)
            witness = state.insert(nf)
            self.assertEqual(assembly.wire.insert_nf(root, count, nf, witness), state.nf.root())
        self.assertEqual([int.from_bytes(entry[0], 'little') for entry in state.entries], [0, 7, 3, 11])
        self.assertEqual(state.entries[0][1], (3).to_bytes(32, 'little'))
        with self.assertRaises(ValueError):
            state.insert(inputs[0][0])

    def test_all_sequential_root_transitions_validate(self):
        _, _, _, projection = fixture()
        checked = assembly.wire.validate_public(projection)
        new = assembly.wire.parse_projection(projection).body.new_state
        self.assertEqual((new.cm_count, new.nf_count), (9, 4))
        self.assertTrue(checked['public_frame_and_transition_validated'])
        self.assertFalse(checked['g16_verified'])
        self.assertFalse(checked['accepted_backing_or_currentness'])
        for offset in (193 + 3844 + 72, 193 + 7324):
            changed = bytearray(projection); changed[offset] ^= 1
            with self.assertRaises(ValueError):
                assembly.wire.validate_public(bytes(changed))

    def test_effects_exclude_only_Spend_witness_not_Output_proof(self):
        _, _, _, projection = fixture()
        old = assembly.wire.effects_digest(projection)
        authorized = assembly.attach_spend_proofs(projection, [bytes([i + 1]) * 128 for i in range(3)])
        self.assertEqual(old, assembly.wire.effects_digest(authorized))
        self.assertNotEqual(sha(projection), sha(authorized))
        changed = bytearray(projection); changed[193 + 724 + 392] ^= 1
        self.assertNotEqual(old, assembly.wire.effects_digest(bytes(changed)))
        # No claim that these deliberately zero/changed proof fixtures verify.
        self.assertFalse(assembly.wire.validate_public(bytes(changed))['g16_verified'])

    def test_duplicate_original_NF_and_output_are_rejected(self):
        initial, inputs, rows, _ = fixture()
        roster = [sha(bytes([i])).hex() for i in range(3)]
        args = (bytes(32), sha(b'session').hex(), roster, sha(b'point') + bytes(4), 30_000_000)
        with self.assertRaises(ValueError):
            assembly.body_core(initial, [inputs[0], inputs[0], inputs[2]], rows, *args)
        with self.assertRaises(ValueError):
            assembly.body_core(initial, inputs, rows[:5] + [rows[0]], *args)

    def test_point_fee_cipher_and_scalar_boundaries(self):
        initial, inputs, rows, _ = fixture()
        roster = [sha(bytes([i])).hex() for i in range(3)]
        with self.assertRaises(ValueError):
            assembly.body_core(initial, inputs, rows, assembly.Q.to_bytes(32, 'little'),
                               sha(b'session').hex(), roster, sha(b'point') + bytes(4), 1)
        with self.assertRaises(ValueError):
            assembly.body_core(initial, inputs, rows, bytes(32), sha(b'session').hex(),
                               roster, sha(b'point') + bytes(4), 3_000_000_000)
        changed = bytearray(rows[0]); changed[96] ^= 1
        with self.assertRaises(ValueError):
            assembly.body_core(initial, inputs, [bytes(changed)] + rows[1:], bytes(32),
                               sha(b'session').hex(), roster, sha(b'point') + bytes(4), 1)


if __name__ == '__main__':
    unittest.main()
