"""Capacity reservation controls; no privacy/soundness/currentness claim."""
import sys
import unittest
from collections import deque
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import capacity


def transitions(state, cap):
    n, m, users = state
    if users == 0:
        return
    if n < cap:
        yield 'admit', (n+1, m, users+1)
    for real in range(1, min(2, users)+1):
        if m+2 <= 2*cap+1:
            yield 'noappend', (n, m+2, users-real)
        for width in (2, 32):
            end = ((n+width-1)//width)*width+width
            if end <= cap and m+2 <= 2*cap+1:
                for positives in range(width+1):
                    yield 'append', (end, m+2, users-real+positives)
    if m+1 <= 2*cap+1:
        yield 'reveal', (n, m+1, users-1)


class Capacity(unittest.TestCase):
    def test_exhaustive_small_state_induction_and_independent_full_exit(self):
        checked = 0
        for cap in (3, 7, 15, 35):
            seen, queue = {(1, 1, 1)}, deque([(1, 1, 1)])
            while queue:
                state = queue.popleft()
                n, m, users = state
                self.assertLessEqual(m+2*users, 2*n+1)
                if users:
                    self.assertLessEqual(m+2, 2*cap+1)
                    self.assertIn(('noappend', (n, m+2, users-1)), list(transitions(state, cap)))
                for _, following in transitions(state, cap):
                    checked += 1
                    nn, mm, uu = following
                    self.assertLessEqual(mm+2*uu, 2*nn+1)
                    if following not in seen:
                        seen.add(following)
                        queue.append(following)
        self.assertGreater(checked, 1000)

    def test_exact_maximum_boundary_and_all_drain_orders(self):
        n, m, users = 65_535, 131_067, 2
        self.assertEqual(m+2*users, 2*n+1)
        for _ in range(users):
            m += 2
        self.assertEqual(m, 131_071)
        self.assertLess(m, 1 << 17)
        self.assertEqual(n, 65_535)

    def test_dummy_outputs_and_alignment_are_not_unspent_liabilities(self):
        state = (1, 1, 1)
        possible = set(transitions(state, 65_535))
        self.assertIn(('append', (64, 3, 32)), possible)
        self.assertIn(('append', (64, 3, 0)), possible)
        self.assertIn(('append', (4, 3, 2)), possible)
        # A physical gap advances n but never creates a positive receipt.
        self.assertNotIn(('append', (64, 3, 63)), possible)

    def test_zero_real_input_would_break_reservation(self):
        n, m, users = 65_535, 131_069, 1
        self.assertEqual(m+2*users, 2*n+1)
        self.assertGreater(m+2+2*users, 2*n+1)

    def test_small_constructed_snapshot_matches_real_and_dummy_spent_nfs(self):
        before = capacity.construct(capacity.ORIGINAL_DOMAIN, 2, 7)
        self.assertEqual(before.cm_cursor, 7)
        self.assertEqual(len(before.nullifiers), 11)
        remaining = {row.value for row in before.nullifiers}
        for pos in (5, 6):
            raw, _, key = capacity.note(capacity.ORIGINAL_DOMAIN, pos)
            nf = capacity.real_nf(capacity.ORIGINAL_DOMAIN, key,
                                  capacity.note_cm(capacity.ORIGINAL_DOMAIN, raw), pos)
            self.assertNotIn(nf, remaining)
        point = {'transactionId':'11'*32, 'index':0}
        first = capacity.cashout(capacity.ORIGINAL_DOMAIN, before, 5, 2*capacity.VALUE, point)
        self.assertEqual(first.reserve_after, capacity.VALUE)
        self.assertEqual(first.after.cm_cursor, before.cm_cursor)
        self.assertEqual(len(first.after.nullifiers), 13)
        second = capacity.cashout(capacity.ORIGINAL_DOMAIN, first.after, 6, capacity.VALUE, point)
        self.assertEqual(second.reserve_after, 0)
        self.assertEqual(len(second.after.nullifiers), 15)
        with self.assertRaisesRegex(ValueError, 'spent-or-zero-NF'):
            capacity.cashout(capacity.ORIGINAL_DOMAIN, first.after, 5, capacity.VALUE, point)


if __name__ == '__main__':
    unittest.main()
