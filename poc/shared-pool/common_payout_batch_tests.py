"""Compare batch queries with independent exhaustive integer enumeration."""
import itertools
import unittest

from common_payout_batch_observer import BatchModel
from common_payout_tests import enumerate_small, sample
from participant_privacy_observer import prefix_view
from participant_privacy_view import project


class BatchControls(unittest.TestCase):
    def test_all_inputs_and_origins_against_integer_oracle(self):
        data, plan = sample()
        for end in (3, 6):
            prefix = dict(data, events=data["events"][:end+1])
            for participant in (None, 0, 1):
                view = prefix_view(data, project(plan, participant, "0"*64), end) if participant is not None else None
                states = enumerate_small(prefix, view)
                model = BatchModel(prefix, view, payout=2, floor=1, payout_floor=1)
                for target in model.integer.select:
                    expected = {h[target] for _, _, h, _ in states}
                    allowed = [c for size in (1, 2) for c in itertools.combinations(
                        range(prefix["events"][target]["anchor_count"]), size)]
                    self.assertEqual(set(model.candidates(target, allowed)), expected)
                    # Exercise a fully cached repeat and an empty allowed set.
                    self.assertEqual(set(model.candidates(target, allowed)), expected)
                    self.assertEqual(model.candidates(target, []), [])
                for target in (2, 3, *range(4, end+1)):
                    expected = {origins[h[target][0]] for _, _, h, origins in states}
                    self.assertEqual(set(model.candidates(target, (-1, 0, 1), True)), expected)


if __name__ == "__main__":
    unittest.main()
