"""Independent-validator controls using an explicitly public development seed.

No private attempt, retained artifact, or fresh experiment seed is opened.
The model supplies fixtures; only working_balance_trial.validate_bundle decides
whether the independently reconstructed arithmetic and obligations agree.
"""
import copy
import unittest

import working_balance_model as model
from working_balance_trial import validate_bundle

PUBLIC_DEVELOPMENT_SEED = bytes(range(32))


class ValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = model.generate(PUBLIC_DEVELOPMENT_SEED)
        # This fixed public case contains a bridge and actual urgent operations.
        cls.base = cls.fixtures["sparse-independent"]["partial"]
        cls.pay = next(i for i, row in enumerate(cls.base["truth"]["events"]) if row["kind"] == "pay")
        cls.bridge = next(i for i, row in enumerate(cls.base["public"]["events"]) if row["bridge"])
        cls.urgent = next(i for i, row in enumerate(cls.base["truth"]["events"]) if row["phase"] == "urgent")

    def validate(self, bundle):
        return validate_bundle(bundle["public"], bundle["directory"], bundle["truth"], bundle["cost"])

    def rejected(self, mutate):
        bundle = copy.deepcopy(self.base)
        mutate(bundle)
        with self.assertRaises((ValueError, KeyError, TypeError, IndexError)):
            self.validate(bundle)

    def test_all_eight_public_development_bundles(self):
        for cell, arms in self.fixtures.items():
            for arm, bundle in arms.items():
                with self.subTest(cell=cell, arm=arm):
                    original = copy.deepcopy(bundle)
                    checked = self.validate(bundle)
                    self.assertTrue(checked["complete"])
                    self.assertEqual(checked["payment_obligations"], 64)
                    self.assertEqual(checked["cash_obligations"], 32)
                    self.assertEqual(checked["initial_admissions"], 32)
                    self.assertEqual(checked["final_private_reserve"], 0)
                    self.assertEqual(checked["initial_injected_sompi"],
                                     checked["final_external_sompi"] + checked["pool_fees_sompi"]
                                     + checked["bridge_fees_sompi"])
                    self.assertEqual(bundle, original, "validator must not mutate its evidence")

    def test_conservation_spending_and_obligations_reject_corruption(self):
        p, b, u = self.pay, self.bridge, self.urgent
        mutations = {
            "reserve inflation": lambda x: x["public"]["events"][p].__setitem__("reserve", x["public"]["events"][p]["reserve"]+1),
            "private output inflation": lambda x: x["truth"]["events"][p]["outputs"][1].__setitem__("value", x["truth"]["events"][p]["outputs"][1]["value"]+1),
            "wrong owner": lambda x: x["truth"]["events"][p].__setitem__("owner", 31),
            "duplicate private input": lambda x: x["truth"]["events"][p]["inputs"].append(x["truth"]["events"][p]["inputs"][0]),
            "future private input": lambda x: x["truth"]["events"][p].__setitem__("inputs", [len(x["public"]["commitments"])-2]),
            "nullifier replay": lambda x: x["public"]["events"][p]["nullifiers"].__setitem__(1, x["public"]["events"][p]["nullifiers"][0]),
            "stale anchor": lambda x: x["public"]["events"][p].__setitem__("anchor_count", 0),
            "unbacked reentry": lambda x: x["public"]["events"][b].__setitem__("bridge", None),
            "native source replay": lambda x: x["public"]["events"][b]["bridge"]["sources"].append(copy.deepcopy(x["public"]["events"][b]["bridge"]["sources"][0])),
            "native source wrong value": lambda x: x["public"]["events"][b]["bridge"]["sources"][0].__setitem__("value", x["public"]["events"][b]["bridge"]["sources"][0]["value"]+1),
            "native source missing": lambda x: x["public"]["events"][b]["bridge"]["sources"].pop(),
            "wrong bridge fee": lambda x: x["public"]["events"][b]["bridge"].__setitem__("fee", 0),
            "earmarked native change stolen": lambda x: x["public"]["events"][b]["bridge"].__setitem__("change", x["public"]["events"][b]["bridge"]["change"]-1),
            "native change ref replay": lambda x: x["public"]["events"][b]["bridge"].__setitem__("change_ref", x["public"]["events"][b]["bridge"]["sources"][0]["ref"]),
            "wrong cash attribution": lambda x: x["truth"]["cash_audit"][0].__setitem__("owner", (x["truth"]["cash_audit"][0]["owner"]+1)%32),
            "false cash completion": lambda x: x["truth"]["cash_audit"][0].__setitem__("complete", False),
            "omitted urgent request": lambda x: x["truth"]["events"][u].__setitem__("request", None),
            "duplicate economic obligation": lambda x: x["truth"]["plan"]["payments"][1].__setitem__("obligation", 0),
            "independent owner not permutation": lambda x: x["truth"]["plan"]["cash_requests"][1].__setitem__("owner", x["truth"]["plan"]["cash_requests"][0]["owner"]),
            "wrong initial funding directory": lambda x: x["directory"]["initial_funding_owners"].__setitem__(x["public"]["events"][0]["funding_group"], 1),
            "false fee cost aggregate": lambda x: x["cost"].__setitem__("pool_fees", x["cost"]["pool_fees"]-1),
            "false final external value": lambda x: x["truth"]["final"]["external_values"].__setitem__(0, x["truth"]["final"]["external_values"][0]+1),
            "incomplete drainage": lambda x: (x["public"]["events"].pop(), x["truth"]["events"].pop()),
            "unrequested public metadata": lambda x: x["public"]["events"][p].__setitem__("owner", 0),
        }
        for name, mutate in mutations.items():
            with self.subTest(corruption=name):
                self.rejected(mutate)

    def test_previously_spent_same_owner_note_rejected(self):
        spent_by_owner = {}
        for i, record in enumerate(self.base["truth"]["events"]):
            owner = record["owner"]
            if record["kind"] == "pay" and owner in spent_by_owner:
                old = spent_by_owner[owner]
                self.rejected(lambda x: x["truth"]["events"][i].__setitem__("inputs", [old]))
                return
            for position in record["inputs"]:
                spent_by_owner[owner] = position
        self.fail("public fixture must exercise a prior same-owner spend")

    def test_boolean_and_noninteger_values_rejected(self):
        mutations = {
            "boolean event ordinal": lambda x: x["public"]["events"][0].__setitem__("event", False),
            "boolean owner": lambda x: x["truth"]["events"][0].__setitem__("owner", False),
            "boolean zero note": lambda x: x["truth"]["events"][0]["outputs"][1].__setitem__("value", False),
            "boolean obligation": lambda x: x["truth"]["plan"]["payments"][0].__setitem__("obligation", False),
            "negative amount": lambda x: x["truth"]["events"][self.pay]["outputs"][0].__setitem__("value", -1),
            "float amount": lambda x: x["truth"]["events"][self.pay]["outputs"][0].__setitem__("value", 1.5),
            "string amount": lambda x: x["truth"]["events"][self.pay]["outputs"][0].__setitem__("value", "1000000000"),
            "over-range amount": lambda x: x["truth"]["events"][self.pay]["outputs"][0].__setitem__("value", 2_900_000_000_000_000_001),
        }
        for name, mutate in mutations.items():
            with self.subTest(corruption=name):
                self.rejected(mutate)


if __name__ == "__main__":
    unittest.main()
