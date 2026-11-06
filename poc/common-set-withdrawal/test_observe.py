import copy
import hashlib
import unittest

import observe


def fixture():
    owners = ["a", "b", "c"]
    keys = [bytes([i]).hex() * 32 for i in (1, 2, 3)]
    claims = [bytes([i]).hex() * 32 for i in (4, 5, 6)]
    issuer = b"public observer-test placeholder DER; no crypto claim"
    fingerprint = hashlib.sha256(observe.MODE + issuer).hexdigest()
    round_id = bytes([7]) * 32
    amount = 1_000_000_000
    events = [{"kind": "issue", "owner": o, "claim": c} for o, c in zip(owners, claims)]
    for i, key in enumerate(keys):
        msg = observe.TAG + round_id + bytes.fromhex(fingerprint) + amount.to_bytes(8, "little") + bytes.fromhex(key)
        events.append({"kind": "redeem", "recipientKey": key, "valueSompi": amount, "message": msg.hex(), "randomizer": bytes([8+i]).hex()*32})
    return {"schema": "common-set-observation-v1", "mode": observe.MODE.decode(), "issuerDer": issuer.hex(), "issuerFingerprint": fingerprint, "round": round_id.hex(), "denominationSompi": amount, "owners": owners, "events": events, "explicitOwnerLinks": [], "native": {"version": 1, "subnetwork": "00"*20, "lockTime": 0, "gas": 0, "payload": "", "inputs": [{"transactionId": "00"*32, "index": 0, "sequence": 0, "computeBudget":4800,"sigOpCount":None,"signatureScript": "public-placeholder"}], "outputs": [{"scriptPublicKey": "000020"+k+"ac", "valueSompi": amount,"covenant":None} for k in keys], "activePublicClaims": claims, "policyRedeemScript": "public-placeholder"}}


class ObserverControls(unittest.TestCase):
    def test_candidate_counts_real_output_ownership(self):
        result = observe.predict(fixture())
        self.assertEqual(result["assignmentCount"], 6)
        self.assertEqual(result["uniquelyAttributedOutputs"], 0)

    def test_participant_and_elimination(self):
        view = fixture()
        keys = [e["recipientKey"] for e in view["events"] if e["kind"] == "redeem"]
        view["explicitOwnerLinks"] = [{"owner": "a", "recipientKey": keys[0]}]
        self.assertEqual(observe.predict(view)["assignmentCount"], 2)
        view["explicitOwnerLinks"].append({"owner": "b", "recipientKey": keys[1]})
        self.assertEqual(observe.predict(view)["assignmentCount"], 1)

    def test_echoed_origins_collapse_all_mappings(self):
        view = fixture()
        for owner, e in zip(view["owners"], view["events"][3:]):
            e["owner"] = owner
        self.assertEqual(observe.predict(view)["assignmentCount"], 1)

    def test_leaked_client_randomizers_collapse_mappings(self):
        view = fixture()
        for issue, redeem in zip(view["events"][:3], view["events"][3:]):
            issue["leakedRandomizer"] = redeem["randomizer"]
        self.assertEqual(observe.predict(view)["assignmentCount"], 1)

    def test_legacy_public_exits_remain_observable(self):
        view = fixture()
        view["previouslyPublishedIndividualExits"] = [{"owner": o, "recipientKey": e["recipientKey"]} for o, e in zip(view["owners"], view["events"][3:])]
        self.assertEqual(observe.predict(view)["assignmentCount"], 1)

    def test_rename_and_output_event_order_invariance(self):
        view = fixture()
        expected = observe.predict(view)["assignmentCount"]
        view["owners"] = ["z", "y", "x"]
        for name, issue in zip(view["owners"], view["events"][:3]):
            issue["owner"] = name
        view["events"][3:] = reversed(view["events"][3:])
        view["native"]["outputs"].reverse()
        self.assertEqual(observe.predict(view)["assignmentCount"], expected)

    def test_unknown_metadata_is_never_silently_removed(self):
        for path in ("top", "issue", "redeem", "native"):
            view = fixture()
            where = {"top": view, "issue": view["events"][0], "redeem": view["events"][3], "native": view["native"]}[path]
            where["unexpectedIdentityMarker"] = "a"
            with self.assertRaisesRegex(ValueError, "unreviewed"):
                observe.predict(view)

    def test_contradiction_cannot_be_scored_as_privacy(self):
        view = fixture()
        key = view["events"][3]["recipientKey"]
        view["explicitOwnerLinks"] = [{"owner": "a", "recipientKey": key}, {"owner": "b", "recipientKey": key}]
        with self.assertRaisesRegex(ValueError, "contradictory"):
            observe.predict(view)

    def test_native_and_registration_sets_must_match(self):
        view = fixture()
        view["native"]["outputs"][0]["valueSompi"] -= 1
        with self.assertRaisesRegex(ValueError, "actual native outputs"):
            observe.predict(view)

    def test_interleaved_issuance_redemption_rejects(self):
        view = fixture()
        view["events"][1], view["events"][3] = view["events"][3], view["events"][1]
        with self.assertRaisesRegex(ValueError, "barrier"):
            observe.predict(view)

    def test_float_and_bool_amounts_reject(self):
        for value in (True, 1.0, -1, 0, 2**63):
            view = fixture()
            view["denominationSompi"] = value
            with self.assertRaisesRegex(ValueError, "integer sompi"):
                observe.predict(view)


if __name__ == "__main__":
    unittest.main()
