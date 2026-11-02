"""Controls for the actual-reserve observer and synthetic common-reserve model."""

import unittest

import reserve_lineage_privacy as observer


INITIAL = (("A", 10), ("B", 10))
TERMINAL = (("A", 6), ("B", 8), ("M", 2), ("M", 3), ("S", 1))
H1 = (("A", "M", 4), ("B", "M", 2), ("M", "S", 1))
H2 = (("A", "M", 3), ("A", "S", 1), ("B", "M", 2))


class ReserveLineageTests(unittest.TestCase):
    def setUp(self):
        self.executions = observer.provenance_executions(INITIAL, [value for _, value in TERMINAL])
        self.known = [
            (history, notes) for history, notes in self.executions
            if sorted((owner, value) for owner, value, _ in notes) == sorted(TERMINAL)
        ]

    def test_corrected_known_owner_histories_remain_exactly_two(self):
        self.assertEqual({observer.gross(H1), observer.gross(H2)}, set(observer.histories(self.known)))

    def test_both_histories_have_the_same_terminal_funding_origins(self):
        signatures = {}
        for history, notes in self.known:
            signatures.setdefault(observer.gross(history), set()).add(tuple(notes))
        expected = tuple(sorted((("A", 6, "A"), ("B", 8, "B"), ("M", 2, "B"), ("M", 3, "A"), ("S", 1, "A"))))
        self.assertEqual(signatures[observer.gross(H1)], {expected})
        self.assertEqual(signatures[observer.gross(H2)], {expected})

    def test_reserve_lineage_cannot_choose_between_direct_payment_histories(self):
        observed = {("A", 6): "A", ("B", 8): "B", ("M", 2): "B", ("M", 3): "A", ("S", 1): "A"}
        compatible = [
            history for history, notes in self.known
            if all(observed[(owner, value)] == origin for owner, value, origin in notes)
        ]
        self.assertEqual({observer.gross(H1), observer.gross(H2)}, {observer.gross(item) for item in compatible})

    def test_known_owner_balances_reveal_b_to_m_and_constrain_a_to_m(self):
        histories = observer.histories(self.known)
        self.assertTrue(all(("B", "M", 2) in history for history in histories))
        self.assertEqual({3, 4}, {value for history in histories for a, b, value in history if (a, b) == ("A", "M")})

    def test_s_participant_view_uses_only_own_facts_and_retains_four_histories(self):
        own_terminal = [1]
        own_facts = observer.own_facts(observer.gross(H2), "S")
        candidates = [
            (history, notes) for history, notes in self.executions
            if sorted(value for owner, value, _ in notes if owner == "S") == own_terminal
            and observer.own_facts(observer.gross(history), "S") == own_facts
        ]
        self.assertEqual(4, len(observer.histories(candidates)))
        self.assertIn(observer.gross(H2), observer.histories(candidates))

    def test_common_reserve_preserves_immediate_full_drain(self):
        balance = 20
        for exit_value in (6, 8, 3, 2, 1):
            self.assertGreaterEqual(balance, exit_value)
            balance -= exit_value
        self.assertEqual(0, balance)
        self.assertEqual({"A", "B"}, {origin for origin, _ in INITIAL})

    def test_sparse_known_owner_control_stays_unique(self):
        sequences = observer.correction.legacy.enumerate_sequences(
            (("A", "B"),), lambda notes: tuple(sorted(notes)) == (("A", 6), ("B", 4)),
            steps=1, initial=(("A", 10),),
        )
        self.assertEqual({(("A", "B", 4),)}, {observer.gross(item) for item in sequences})


if __name__ == "__main__":
    unittest.main()
