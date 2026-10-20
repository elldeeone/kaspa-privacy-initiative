"""Direct integer-search parity with the independent enumeration oracle."""
import sys
import unittest

import common_payout_batch_observer as original

sys.modules["common_payout_batch_impl"] = original
import common_payout_integer_observer as integer
import common_payout_batch_tests as batch_tests
from two_input_privacy_tests import fixture

assert batch_tests.BatchModel is integer.BatchModel


class IntegerControls(batch_tests.BatchControls):
    def test_two_input_normal_payment_is_preserved(self):
        data = fixture(14, [(1, 0, 0, 1), (0, 8, 0, 0), (1, 0, 0, 5),
                            (1, 0, 2, 7), (2, 0, 7, 9), (2, 0, 7, 9)])
        model = integer.BatchModel(data, payout=2, floor=1, payout_floor=1)
        self.assertTrue(model.check(2, combo=(1, 3)))


if __name__ == "__main__":
    unittest.main()
