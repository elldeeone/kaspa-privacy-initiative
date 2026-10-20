"""Oracle parity plus preservation of real two-input private payments."""
import sys
import unittest

import common_payout_batch_observer as original

# Match the runner's two explicit module mounts without editing either source.
sys.modules["common_payout_batch_impl"] = original
import common_payout_propagating_observer as propagating
import common_payout_batch_tests as batch_tests
from two_input_privacy_tests import fixture

assert batch_tests.BatchModel is propagating.BatchModel


class PropagatingControls(batch_tests.BatchControls):
    def test_two_input_normal_payment_is_preserved(self):
        data = fixture(14, [(1, 0, 0, 1), (0, 8, 0, 0), (1, 0, 0, 5),
                            (1, 0, 2, 7), (2, 0, 7, 9), (2, 0, 7, 9)])
        model = propagating.BatchModel(data, payout=2, floor=1, payout_floor=1)
        graph = {0: (0,), 2: (1, 3), 3: (5,), 4: (2,), 5: (7,)}
        self.assertTrue(model.integer.check(fixed=graph))
        self.assertTrue(model.check(2, combo=(1, 3)))


if __name__ == "__main__":
    unittest.main()
