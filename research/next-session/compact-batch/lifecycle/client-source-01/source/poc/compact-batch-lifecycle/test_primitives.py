import unittest

from primitives import (CM_MAX, ZERO, Delivery, NFEntry, Snapshot, SparseTree,
                        dummy_nf, fold_path, h, insert_nf, note_cm, real_nf, u32)
from synthetic import DOMAIN, fixture, note, box


class SparseStateControls(unittest.TestCase):
    def test_wide_start_keeps_empty_physical_gap(self):
        witness, summary = fixture('gap-control', 32)
        auth = bytes.fromhex(witness['auth_hex528'])
        self.assertEqual(summary['CM_start'], 32)
        self.assertEqual(summary['physical_CM_cursor_after'], 64)
        self.assertEqual(summary['delivered_record_count'], 33)
        self.assertEqual(int.from_bytes(auth[304:308], 'little'), 32)

    def test_sparse_membership_cannot_be_renumbered(self):
        leaves = {0: h(b'first'), 32: h(b'receiver'), 63: h(b'last')}
        tree = SparseTree(16, leaves, b'KPX1CMN\0', h(b'KPX1CME\0'))
        self.assertEqual(fold_path(leaves[32], 32, tree.path(32), tree.tag), tree.root)
        self.assertNotEqual(fold_path(leaves[32], 1, tree.path(32), tree.tag), tree.root)
        self.assertNotEqual(real_nf(DOMAIN, h(b'key'), leaves[32], 32),
                            real_nf(DOMAIN, h(b'key'), leaves[32], 1))

    def test_empty_gap_is_not_a_zero_note_commitment(self):
        self.assertNotEqual(h(b'KPX1CME\0'), note_cm(DOMAIN, bytes(168)))

    def test_terminal_has_no_appended_leaf(self):
        witness, summary = fixture('terminal-control', 0)
        auth = bytes.fromhex(witness['auth_hex528'])
        self.assertEqual(summary['physical_CM_cursor_after'], 1)
        self.assertEqual(summary['delivered_record_count'], 1)
        self.assertEqual(auth[268:332], bytes(64))
        self.assertEqual(auth[116:148], auth[404:436])

    def test_replay_duplicate_nullifier_is_rejected(self):
        snapshot = Snapshot(1, (Delivery(0, h(b'initial'), bytes(264)),),
                            (NFEntry(ZERO, ZERO, 0),))
        after, proof = insert_nf(snapshot, h(b'nf'))
        self.assertEqual(len(proof), 1160)
        with self.assertRaisesRegex(ValueError, 'spent-or-zero-NF'):
            insert_nf(after, h(b'nf'))

    def test_indexed_nf_order_uses_little_endian_integer(self):
        snapshot = Snapshot(1, (Delivery(0, h(b'initial'), bytes(264)),),
                            (NFEntry(ZERO, ZERO, 0),))
        a, _ = insert_nf(snapshot, bytes([255]) + bytes(31))
        b, _ = insert_nf(a, bytes([0, 1]) + bytes(30))
        self.assertEqual(b.nullifiers[0].next_value, bytes([255]) + bytes(31))
        self.assertEqual(b.nullifiers[1].next_index, 2)

    def test_unreachable_nf_entry_is_rejected(self):
        snapshot = Snapshot(1, (Delivery(0, h(b'initial'), bytes(264)),),
                            (NFEntry(ZERO, ZERO, 0), NFEntry(h(b'hidden'), ZERO, 0)))
        with self.assertRaisesRegex(ValueError, 'nf-unreachable'):
            snapshot.verify()

    def test_cm_capacity_not_rounded_past_u16_cursor(self):
        snapshot = Snapshot(CM_MAX, (Delivery(0, h(b'initial'), bytes(264)),),
                            (NFEntry(ZERO, ZERO, 0),))
        with self.assertRaisesRegex(ValueError, 'cm-append-capacity'):
            snapshot.append(DOMAIN, [bytes(168), bytes(168)], [bytes(264), bytes(264)])

    def test_full_bounded_batch_cursor_and_nullifier_counts(self):
        source = note('cursor-ledger/source', 40_000_000_000)[0]
        snapshot = Snapshot(1, (Delivery(0, note_cm(DOMAIN, source), box('initial', 0)),),
                            (NFEntry(ZERO, ZERO, 0),))
        for offset in range(2):
            snapshot, _ = insert_nf(snapshot, h(b'initial-NF', u32(offset)))
        notes = [note(f'cursor-ledger/output/{i}', 1_000_000_000)[0] for i in range(32)]
        snapshot, _, _ = snapshot.append(DOMAIN, notes, [box('wide', i) for i in range(32)])
        for ordinal in range(32):
            for slot in range(2):
                snapshot, _ = insert_nf(snapshot, h(b'exit-NF', u32(ordinal), bytes([slot])))
            if ordinal < 31:
                dummies = [bytes(72) + h(b'zero-note-rho', u32(ordinal), bytes([slot])) + bytes(64)
                           for slot in range(2)]
                snapshot, _, _ = snapshot.append(DOMAIN, dummies, [box('exit', 2 * ordinal + i) for i in range(2)])
        self.assertEqual(snapshot.cm_cursor, 126)
        self.assertEqual(len(snapshot.deliveries), 95)
        self.assertEqual(len(snapshot.nullifiers), 67)
        self.assertTrue(all(record.position not in range(1, 32) for record in snapshot.deliveries))


if __name__ == '__main__':
    unittest.main()
