"""Distinguish an optional timing model from the independent exit relation."""
import unittest

from scheduled_payout_observer import ScheduledModel, timing_graph_valid
from two_input_privacy_tests import fixture


class EscapeControl(unittest.TestCase):
    def test_immediate_change_exit_is_valid_outside_normal_timer_model(self):
        # 9 -> (6,2); Q takes 2+1 fee from 6, leaving 3. Immediately withdraw
        # that change for 2+1 fee, then the unaffected 2 for 1+1 fee.
        data = fixture(9, [(1, 0, 0, 1), (1, 0, 2, 3),
                           (2, 0, 2, 5), (2, 0, 1, 5)])
        for i, event in enumerate(data["events"]):
            event["minute"] = 2 * i
        graph = {0: (0,), 1: (1,), 2: (3,), 3: (2,)}
        ordinary = ScheduledModel(data, timed=False, payout=2, floor=1, payout_floor=1)
        self.assertTrue(ordinary.integer.check(fixed=graph))
        self.assertFalse(timing_graph_valid(data, graph, 2, 1, 1))
        # A normal-timer observer must flag this out-of-model history rather
        # than reporting an empty candidate set as privacy or a locked note.
        timed = ScheduledModel(data, timed=True, payout=2, floor=1, payout_floor=1)
        self.assertIsNone(timed.ask())


if __name__ == "__main__":
    unittest.main()
