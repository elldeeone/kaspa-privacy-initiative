"""Supplementary second-pass coverage of H16 partial-change ownership.

Added during observation, before scoring; no observer or frozen input changes.
Only hand-constructed tiny ledgers are used.
"""
import unittest

from participant_privacy_observer import ParticipantModel, ParticipantZ3Model, ParticipantExactModel
from participant_privacy_tests import DIGEST, enumerate_view, sample
from participant_privacy_view import project
from two_input_privacy_tests import fixture

CLASSES = (ParticipantModel, ParticipantZ3Model, ParticipantExactModel)


class PartialOwnershipControls(unittest.TestCase):
    def test_partial_retained_value_ownership_is_conditional(self):
        # Another client can withdraw and pay a private recipient in slot 0.
        # This prototype treats that slot as the withdrawing wallet's change.
        data = fixture(8, [(1, 0, 2, 1)])
        view = dict(schema="kpi-h16-participant-view-v1", public_sha256=DIGEST,
                    receipts=[dict(position=1, value=5)], authored=[])
        for profile in ("records", "wallet"):
            oracle = enumerate_view(data, view, profile)[0]
            for cls in CLASSES:
                model = cls(data, view, profile, 1, 1)
                self.assertEqual(set(model.candidates(0)), oracle)
                self.assertEqual(model.check(), profile == "records")

    def test_real_partial_record_and_zero_change_against_oracle(self):
        data, plan = sample()
        data = fixture(11, [(1, 0, 0, 1), (0, 6, 0, 0), (1, 0, 0, 5),
                            (1, 0, 0, 7), (1, 0, 1, 9)])
        plan["steps"].append(dict(inputs=[7], owners=[2, 2], values=[2, 0],
                                  depositor=None, mode=1, count_before=9))
        plan["drains"] = []
        view = project(plan, 2, DIGEST)
        zero_data = fixture(6, [(1, 0, 0, 1), (1, 0, 1, 3)])
        zero_view = dict(
            schema="kpi-h16-participant-view-v1", public_sha256=DIGEST,
            receipts=[dict(position=p, value=v) for p, v in [(0, 6), (1, 2), (2, 3)]],
            authored=[
                dict(event=0, inputs=[0], outputs=[
                    dict(position=1, value=2, recipient=0), dict(position=2, value=3, recipient=0)]),
                dict(event=1, inputs=[1], outputs=[
                    dict(position=3, value=0, recipient=None), dict(position=4, value=0, recipient=None)]),
            ])
        for data, view in [(data, view), (zero_data, zero_view)]:
            for profile in ("records", "wallet"):
                oracle = enumerate_view(data, view, profile)
                for cls in CLASSES:
                    model = cls(data, view, profile, 1, 1)
                    self.assertTrue(model.check())
                    for target, expected in oracle.items():
                        self.assertEqual(set(model.candidates(target)), expected)


if __name__ == "__main__":
    unittest.main()
