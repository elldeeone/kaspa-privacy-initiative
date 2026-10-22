#!/usr/bin/env python3
"""Controls of NEW public extraction; never import a frozen privacy observer."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import public_native_observation as o

# This fixed expectation is the canonical descriptor derived from the three
# already-public, hash-pinned rehearsal artifacts; it is not taken from test input.
EXPECTED_DESCRIPTOR = "d02c36cd87db7bfd43f6f85a425539a90f8f39224a20ac5ef860ae0f54be3a8b"


def mutate_hex(container, key, offset, delta=1):
    value = bytearray.fromhex(container[key])
    value[offset] ^= delta
    container[key] = value.hex()


def pointer(value, path):
    for key in path.split("/")[1:]:
        value = value[int(key)] if type(value) is list else value[key]
    return value


class PublicObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = o.load_public_rehearsal()
        cls.full = o.extract(cls.raw, 13, EXPECTED_DESCRIPTOR)

    def fresh(self):
        return copy.deepcopy(self.raw)

    def extract(self, raw, count=13):
        return o.extract(raw, count, EXPECTED_DESCRIPTOR)

    def rejected(self, raw, reason, count=13):
        with self.assertRaisesRegex(o.ObservationError, reason):
            self.extract(raw, count)

    def test_all_actual_witness_bytes_regenerated_and_full_drain(self):
        self.assertEqual(len(self.full["records"]), 13)
        self.assertEqual([sum(r["mode"] == mode for r in self.full["records"]) for mode in range(3)], [3, 4, 6])
        self.assertEqual(self.full["accounting"]["admitted_sompi"], "3600000000")
        self.assertEqual(self.full["accounting"]["paid_sompi"], "5080000000")
        self.assertEqual(self.full["accounting"]["pool_fees_sompi"], "520000000")
        self.assertEqual(self.full["accounting"]["remaining_reserve_sompi"], "0")
        for record in self.full["records"]:
            witness = record["settlement_witness"]
            self.assertTrue(witness["exact_match"])
            self.assertEqual(witness["supplied_sha256"], witness["independently_regenerated_sha256"])
        self.assertTrue(any(r["anchor_count"] < r["commitment_count_before"] for r in self.full["records"] if r["mode"] != 0))
        self.assertTrue(any(r["mode"] == 1 and int(r["payout_sompi"]) > 0 for r in self.full["records"]))

    def test_every_prefix_uses_only_available_public_history(self):
        for count in range(14):
            with self.subTest(count=count):
                selected = o.select_prefix(self.raw, count)
                result = self.extract(self.raw, count)
                self.assertEqual(result, self.extract(selected, count))
                self.assertEqual(result["records"], self.full["records"][:count])
                self.assertEqual(result["prefix_operations"], count)
                self.assertEqual(result["initial"]["commitment_count"], 1)
                self.assertEqual(result["validation"]["covenant_script_continuity_checked"], count > 0)

    def test_future_bytes_and_unselected_parent_cannot_change_prefix(self):
        for count in (0, 1, 5, 12):
            with self.subTest(count=count):
                bad = self.fresh()
                for index in range(count + 1, len(bad["lineage"])):
                    bad["lineage"][index] = {"id": "future poison", "payload": {"private_owner": "must not read"}}
                bad["parents"].extend([{"id": "unused future", "inputs": "poison"}, {"id": []}])
                self.assertEqual(self.extract(bad, count), self.extract(self.raw, count))

    def test_every_source_region_round_trips_in_selected_snapshot(self):
        selected = o.select_prefix(self.raw, 13)
        regions = 0
        for record in self.full["records"]:
            for ref in record["source_regions"]:
                data = bytes.fromhex(pointer(selected, ref["pointer"]))
                observed = data[ref["byte_start"]:ref["byte_end_exclusive"]]
                self.assertEqual(len(observed), ref["bytes"])
                self.assertEqual(o.sha(observed).hex(), ref["sha256"])
                regions += 1
        self.assertEqual(regions, 91)
        for funding in self.full["funding_outputs"]:
            source = pointer(selected, funding["source_pointer"])
            self.assertEqual(source["value"], funding["value_sompi"])
            self.assertEqual(source["scriptPublicKey"], funding["script_public_key"])

    def test_claimed_projection_cannot_inject_facts_or_upgrade_verification(self):
        o.validate_observation(self.full, self.raw, EXPECTED_DESCRIPTOR)
        for mutate in (
            lambda x: x["validation"].update(native_vm_verified=True),
            lambda x: x["validation"].update(native_vm_verified=0),
            lambda x: x["records"][0].update(mode=True),
            lambda x: x["records"][0].update(ordinal=False),
            lambda x: x["records"][0].update(ordinal=0.0),
            lambda x: x["records"][0].update(owner=3),
            lambda x: x["records"][0].update(fee_sompi="1"),
            lambda x: x["provenance"].update(selected_public_input_sha256="00" * 32),
            lambda x: x.update(private_truth={}),
        ):
            bad = copy.deepcopy(self.full)
            mutate(bad)
            with self.assertRaisesRegex(o.ObservationError, "differs from regenerated public bytes"):
                o.validate_observation(bad, self.raw, EXPECTED_DESCRIPTOR)
        bad = copy.deepcopy(self.full)
        bad["records"][0]["ordinal"] = float("nan")
        with self.assertRaisesRegex(o.ObservationError, "not canonical JSON"):
            o.validate_observation(bad, self.raw, EXPECTED_DESCRIPTOR)

    def test_each_settlement_witness_region_tamper_rejected(self):
        # Anchor, both indexed-nullifier predecessors/paths, commitment paths,
        # history append and final byte; no supplied sibling is trusted.
        for offset in (0, 512, 584, 1128, 1672, 1744, 2288, 2832, 3344, 3856, 4367):
            with self.subTest(offset=offset):
                bad = self.fresh()
                mutate_hex(bad["lineage"][1], "payload", 860 + offset)
                self.rejected(bad, "recomputed public settlement witness mismatch")

    def test_wrong_successor_and_old_state_root_rejected(self):
        bad = self.fresh()
        mutate_hex(bad["lineage"][1], "payload", 755 + 9)
        self.rejected(bad, "recomputed successor public state mismatch")
        bad = self.fresh()
        mutate_hex(bad["lineage"][1]["inputs"][0], "signatureScript", 133 + 36 + 9)
        self.rejected(bad, "recomputed old public state mismatch")

    def test_stale_unknown_anchor_and_replayed_nullifier_rejected(self):
        bad = self.fresh()
        payload = bytearray.fromhex(bad["lineage"][5]["payload"])
        payload[8 + 40:8 + 44] = (99).to_bytes(4, "little")
        bad["lineage"][5]["payload"] = payload.hex()
        self.rejected(bad, "historical anchor")
        bad = self.fresh()
        payload = bytearray.fromhex(bad["lineage"][5]["payload"])
        previous = bytes.fromhex(bad["lineage"][1]["payload"])
        payload[8 + 76:8 + 108] = previous[8 + 76:8 + 108]
        bad["lineage"][5]["payload"] = payload.hex()
        self.rejected(bad, "nullifier spent/zero")
        bad = self.fresh()
        payload = bytearray.fromhex(bad["lineage"][1]["payload"])
        payload[212] = 3
        bad["lineage"][1]["payload"] = payload.hex()
        self.rejected(bad, "mode/input shape")

    def test_parent_future_dependency_and_repeated_funding_source_rejected(self):
        bad = self.fresh()
        bad["parents"][0]["inputs"][0]["previousOutpoint"] = dict(transactionId=bad["lineage"][-1]["id"], index=0)
        self.rejected(bad, "future pool transaction")
        bad = self.fresh()
        first_admission = bad["lineage"][2]["inputs"][1]["previousOutpoint"]
        bad["lineage"][3]["inputs"][1]["previousOutpoint"] = copy.deepcopy(first_admission)
        self.rejected(bad, "native input reused across public graph")

    def test_auth_ciphertext_and_payout_mutations_rejected(self):
        for offset, reason in ((8 + 8, "authorization domain"),
                               (385, "ciphertext binding"),
                               (8 + 213, "native output accounting"),
                               (8 + 76, "recomputed public settlement witness mismatch")):
            with self.subTest(offset=offset):
                bad = self.fresh()
                mutate_hex(bad["lineage"][1], "payload", offset)
                self.rejected(bad, reason)
        bad = self.fresh()
        payout_index = next(i + 1 for i, r in enumerate(self.full["records"]) if int(r["payout_sompi"]) > 0)
        bad["lineage"][payout_index]["outputs"][-1]["value"] = str(int(bad["lineage"][payout_index]["outputs"][-1]["value"]) + 1)
        self.rejected(bad, "native output accounting")

    def test_script_and_reserve_outpoint_tampering_rejected(self):
        bad = self.fresh()
        mutate_hex(bad["lineage"][1]["inputs"][0], "signatureScript", 133 + 200)
        self.rejected(bad, "reserve script binding")
        bad = self.fresh()
        bad["lineage"][1]["inputs"][0]["previousOutpoint"]["index"] = 1
        self.rejected(bad, "reserve ancestry")
        bad = self.fresh()
        mutate_hex(bad["lineage"][1]["outputs"][0], "scriptPublicKey", 5)
        self.rejected(bad, "successor reserve/script binding")

    def test_selected_parent_amount_script_and_absence(self):
        admission = next(tx for tx in self.raw["lineage"][1:] if bytes.fromhex(tx["payload"])[212] == 0)
        selected_index = admission["inputs"][1]["previousOutpoint"]["index"]
        for key in ("value", "scriptPublicKey"):
            bad = self.fresh()
            output = bad["parents"][0]["outputs"][selected_index]
            if key == "value":
                output[key] = str(int(output[key]) + 1)
            else:
                mutate_hex(output, key, 5)
            self.rejected(bad, "actual funding binding")
        bad = self.fresh()
        bad["parents"] = []
        self.rejected(bad, "missing selected funding parent")

    def test_duplicate_transactions_sources_and_unknown_fields_rejected(self):
        bad = self.fresh()
        bad["parents"].append(copy.deepcopy(bad["parents"][0]))
        self.rejected(bad, "duplicate selected funding parent")
        bad = self.fresh()
        bad["lineage"][2]["id"] = bad["lineage"][1]["id"]
        self.rejected(bad, "duplicate native transaction identity")
        bad = self.fresh()
        bad["parents"][0]["inputs"].append(copy.deepcopy(bad["parents"][0]["inputs"][0]))
        self.rejected(bad, "duplicate transaction input")
        bad = self.fresh()
        bad["lineage"][1]["owner"] = 1
        self.rejected(bad, "native transaction: fields")
        bad = self.fresh()
        bad["truth"] = {}
        self.rejected(bad, "public input: fields")

    def test_descriptor_is_checked_against_independent_expectation(self):
        bad = self.fresh()
        bad["descriptor"]["initial_value_sompi"] = "2000000001"
        self.rejected(bad, "descriptor differs from trusted expectation")
        with self.assertRaisesRegex(o.ObservationError, "trusted expectation"):
            o.extract(self.raw, 13, "00" * 32)
        bad = self.fresh()
        mutate_hex(bad, "vk_hex", 1)
        self.rejected(bad, "VK identity")

    def test_integer_sompi_boundaries_and_no_coercion(self):
        for value in (False, True, 1.0, -1, o.MAX_SOMPI + 1, "1"):
            with self.subTest(value=value):
                with self.assertRaises(o.ObservationError):
                    o.Sompi(value)
        for value in ("01", "+1", "1.0", "-1", " 1", "١", str(o.MAX_SOMPI + 1), 1):
            with self.subTest(value=value):
                with self.assertRaises(o.ObservationError):
                    o.Sompi.parse(value)
        for value in (0, 1, 2**53 + 1, o.MAX_SOMPI):
            self.assertEqual(o.Sompi.parse(str(value)).value, value)
            self.assertEqual(o.Sompi.little_endian(value.to_bytes(8, "little")).value, value)

    def test_missing_ancestry_and_unverified_crypto_are_never_promoted(self):
        flags = self.full["validation"]
        for flag in ("transaction_id_recomputed", "native_vm_verified", "groth16_verified",
                     "funding_parent_spends_verified", "chain_acceptance_verified", "canonical_covenant_code_verified"):
            self.assertIs(flags[flag], False)
        self.assertTrue(self.full["omissions"]["funding_parent_input_ancestry"])
        self.assertEqual(self.full["known_funding_parent_inputs"], [])
        for row in self.full["records"]:
            self.assertIsNone(row["timestamp"])
            self.assertIsNone(row["request_minute"])
            self.assertIsNone(row["owner"])

    def test_proof_tamper_observable_but_requires_native_verification(self):
        bad = self.fresh()
        mutate_hex(bad["lineage"][1]["inputs"][0], "signatureScript", 2)
        result = self.extract(bad)
        self.assertNotEqual(result["records"][0]["proof_sha256"], self.full["records"][0]["proof_sha256"])
        self.assertFalse(result["validation"]["groth16_verified"])
        self.assertFalse(result["validation"]["native_vm_verified"])
        self.assertNotEqual(result["provenance"]["selected_public_input_sha256"],
                            self.full["provenance"]["selected_public_input_sha256"])

    def test_transaction_id_tamper_is_explicit_native_hash_gap(self):
        bad = self.fresh()
        bad["parents"][0]["inputs"][0]["signatureScript"] = "00"
        result = self.extract(bad)
        self.assertFalse(result["validation"]["transaction_id_recomputed"])
        self.assertFalse(result["validation"]["funding_parent_spends_verified"])

    def test_duplicate_json_keys_fail_before_any_projection(self):
        with self.assertRaisesRegex(o.ObservationError, "JSON duplicate key"):
            o.unique_json('{"x":1,"x":2}')

    def test_pinned_source_drift_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            for relative, _ in o.FIXTURE_PINS.values():
                target = base / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((o.HERE / relative).read_bytes())
            target = base / o.FIXTURE_PINS["descriptor"][0]
            target.write_bytes(target.read_bytes() + b" ")
            with self.assertRaisesRegex(o.ObservationError, "public fixture pin mismatch"):
                o.load_public_rehearsal(base)
            target.unlink()
            target.symlink_to(o.HERE / o.FIXTURE_PINS["descriptor"][0])
            with self.assertRaisesRegex(o.ObservationError, "missing/nonregular"):
                o.load_public_rehearsal(base)


if __name__ == "__main__":
    unittest.main(verbosity=2)
