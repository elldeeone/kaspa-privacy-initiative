"""Public integer/absence/terminal boundaries; no proving or native VM."""
from dataclasses import replace
import sys
import unittest

from fixtures import ROOT, given_head, install
from policy import Head, ZERO, insert_public, number
from wire import Invalid


class PublicBoundaryControls(unittest.TestCase):
    def test_external_head_has_exact_integer_point_and_reserve(self):
        _, cases = install()
        head = given_head(cases['wide'])
        for values in ({'index': False}, {'index': -1}, {'reserve': True}, {'reserve': 0},
                       {'transaction_id': head.transaction_id.upper()}, {'scope': True}):
            with self.assertRaises(Invalid):
                replace(head, **values)

    def test_strict_LE256_interval_against_existing_public_tree_implementation(self):
        # Established public tree implementation is an independent oracle for
        # this small cross-endian boundary. No note opening or crypto proof.
        sys.path.insert(0, str(ROOT / 'poc/compact-batch-lifecycle'))
        from primitives import Delivery, NFEntry, Snapshot, insert_nf
        hi, low = (256).to_bytes(32, 'little'), (255).to_bytes(32, 'little')
        self.assertGreater(low, hi)
        self.assertLess(number(low), number(hi))
        snapshot = Snapshot(1, (Delivery(0, b'c' * 32, b'd' * 264),),
            (NFEntry(ZERO, hi, 1), NFEntry(hi, ZERO, 0))).verify()
        following, witness = insert_nf(snapshot, low)
        actual = insert_public(snapshot.roots()[1].root, 2, low, witness)
        self.assertEqual(actual, following.roots()[1].root)
        with self.assertRaises(Invalid):
            insert_public(snapshot.roots()[1].root, 2, hi, witness)
        changed = bytearray(witness); changed[616] ^= 1
        with self.assertRaises(Invalid):
            insert_public(snapshot.roots()[1].root, 2, low, bytes(changed))

    def test_currentness_cannot_be_supplied_by_a_boolean(self):
        policy, cases = install()
        head = given_head(cases['wide'])
        with self.assertRaisesRegex(Invalid, 'accepted_current_head_authority_unavailable'):
            policy.apply(cases['wide'], head, 'wide32', require_live=True)
        with self.assertRaisesRegex(Invalid, 'external_starting_head_required'):
            policy.apply(cases['wide'], replace(head, scope='ACCEPTED_TRUE'), 'wide32')


if __name__ == '__main__':
    unittest.main()
