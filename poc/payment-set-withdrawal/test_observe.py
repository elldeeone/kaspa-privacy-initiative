import copy
from pathlib import Path
import unittest
import observe

PUBLIC = Path(__file__).resolve().parents[2] / "research/payment-set-withdrawal-2026-11-05/run"


class ObserverControls(unittest.TestCase):
    def fixture(self):
        return observe.read(PUBLIC / "candidate.json")

    def test_real_candidate_and_participant(self):
        self.assertEqual(observe.predict(self.fixture())["assignmentCount"], 6)
        self.assertEqual(observe.predict(observe.read(PUBLIC / "one-participant.json"))["assignmentCount"], 2)

    def test_actual_original_exit_destinations_are_identifying(self):
        baseline = observe.read(PUBLIC / "baseline.json")
        # Even without the identified-registration control, the original real
        # EXIT proofs expose the map. Do not silently remove these in a wrapper.
        baseline.pop("identifiedOutputRegistrations")
        self.assertEqual(observe.predict(baseline)["assignmentCount"], 1)

    def test_all_declared_failure_controls(self):
        for name in ("all-but-one", "known-payout-owners", "echoed-origin", "leaked-issuance-randomizer", "legacy-public-exits"):
            self.assertEqual(observe.predict(observe.read(PUBLIC / f"{name}.json"))["assignmentCount"], 1, name)

    def test_metadata_is_never_silently_removed(self):
        for field in ("top", "history", "operation", "statement", "delivery", "issue", "redeem", "native"):
            v = self.fixture()
            target = {"top": v, "history": v["walletHistory"], "operation": v["walletHistory"]["operations"][0], "statement": v["walletHistory"]["operations"][0]["statement"], "delivery": v["walletHistory"]["operations"][0]["deliveries"][0], "issue": v["events"][0], "redeem": v["events"][3], "native": v["native"]}[field]
            target["unexpectedOwnerMarker"] = "owner-1"
            with self.assertRaisesRegex(ValueError, "unreviewed"):
                observe.predict(v)

    def test_relabel_and_redemption_order_invariance(self):
        v = self.fixture()
        v["owners"] = ["x", "y", "z"]
        for owner, e in zip(v["owners"], v["events"][:3]):
            e["owner"] = owner
        v["events"][3:] = reversed(v["events"][3:])
        self.assertEqual(observe.predict(v)["assignmentCount"], 6)

    def test_contradictions_cannot_be_scored_as_privacy(self):
        v = self.fixture()
        key = v["events"][3]["recipientKey"]
        v["explicitOwnerLinks"] = [{"owner": o, "recipientKey": key} for o in v["owners"][:2]]
        with self.assertRaisesRegex(ValueError, "contradictory"):
            observe.predict(v)

    def test_unequal_actual_outputs_refuse(self):
        v = self.fixture()
        v["native"]["outputs"][0]["valueSompi"] -= 1
        with self.assertRaisesRegex(ValueError, "actual native outputs"):
            observe.predict(v)

    def test_typed_amounts(self):
        for amount in (True, 1.0, 0, -1, 2**63):
            v = self.fixture()
            v["denominationSompi"] = amount
            with self.assertRaisesRegex(ValueError, "integer sompi"):
                observe.predict(v)

    def test_spent_claim_cannot_enter_the_view(self):
        v = self.fixture()
        v["walletHistory"]["priorSpentNullifiers"].append(v["native"]["activePublicClaims"][0])
        with self.assertRaisesRegex(ValueError, "already spent"):
            observe.predict(v)


if __name__ == "__main__":
    unittest.main()
