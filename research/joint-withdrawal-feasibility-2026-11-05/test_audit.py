"""Controls against false unlinkability and false owner attribution."""
import itertools
import tempfile
import unittest
from pathlib import Path

import audit


class ExposureControls(unittest.TestCase):
    def setUp(self):
        _, tx = audit.transaction(audit.ARCHIVE, "publish-06-accepted.json")
        self.payload = bytes.fromhex(tx["payload"])
        self.request = audit.decode_exit(self.payload)
        self.output = {
            "scriptPublicKey": self.request["scriptPublicKey"],
            "value": self.request["nativeOutputSompi"],
        }

    def test_equal_amounts_do_not_hide_distinct_public_scripts(self):
        requests = []
        outputs = []
        for i in range(3):
            request = dict(self.request, intentId=str(i), scriptPublicKey=str(i))
            requests.append(request)
            outputs.append(dict(self.output, scriptPublicKey=str(i)))
        for permutation in itertools.permutations(outputs):
            linked = audit.match_outputs(requests, permutation)
            self.assertEqual({r["intentId"]: permutation[linked[r["intentId"]]]["scriptPublicKey"] for r in requests}, {str(i): str(i) for i in range(3)})

    def test_matching_needs_no_owner_names_or_event_tags(self):
        # Only request ID, public script and value are supplied. The routine has
        # no owner, service-origin, transaction-label or payout-tag input.
        request = {k: self.request[k] for k in ("intentId", "scriptPublicKey", "nativeOutputSompi")}
        self.assertEqual(audit.match_outputs([request], [self.output]), {request["intentId"]: 0})

    def test_all_truncated_prefixes_and_trailing_data_reject(self):
        for end in range(len(self.payload)):
            with self.assertRaises(ValueError):
                audit.decode_exit(self.payload[:end])
        with self.assertRaises(ValueError):
            audit.decode_exit(self.payload + b"\x00")

    def test_substituting_public_key_or_destination_rejects(self):
        for offset in (-1, len(audit.OP_TAG) + 4 + 330):
            mutated = bytearray(self.payload)
            mutated[offset] ^= 1
            with self.assertRaisesRegex(ValueError, "key/destination"):
                audit.decode_exit(bytes(mutated))

    def test_duplicate_or_missing_script_cannot_be_scored_as_linkage(self):
        for outputs in ([], [self.output, self.output], [dict(self.output, scriptPublicKey="other")]):
            with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
                audit.match_outputs([self.request], outputs)

    def test_wrong_amount_or_rent_rejects_even_with_right_script(self):
        with self.assertRaisesRegex(ValueError, "amount/rent"):
            audit.match_outputs([self.request], [dict(self.output, value=self.output["value"] - 1)])

    def test_reuse_of_one_output_cannot_satisfy_two_requests(self):
        second = dict(self.request, intentId="second")
        with self.assertRaisesRegex(ValueError, "reused output"):
            audit.match_outputs([self.request, second], [self.output])

    def test_integer_sompi_rejects_bool_float_negative_and_overflow(self):
        for invalid in (True, 1.0, -1, 0, 1 << 63):
            with self.assertRaises(ValueError):
                audit.amount(invalid)
        self.assertEqual(audit.amount((1 << 63) - 1), (1 << 63) - 1)

    def test_duplicate_json_keys_and_changed_manifest_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ARCHIVE-MANIFEST.json"
            path.write_text('{"entries":{},"entries":{}}')
            with self.assertRaisesRegex(ValueError, "duplicate JSON"):
                audit.read(path)
            with self.assertRaisesRegex(ValueError, "manifest changed"):
                audit.verify_archive(Path(directory))

    def test_report_carries_negative_scope_and_separates_owner_knowledge(self):
        report = audit.audit()
        self.assertEqual(report["publicRequestToPayoutLinks"], 5)
        self.assertEqual(report["linksWithoutPermissionOrPayoutPayloadTags"], 5)
        self.assertEqual(report["ownersKnownOnlyWithSuppliedMapping"], 5)
        self.assertEqual(report["outputPermutationsChecked"], 120)
        self.assertFalse(report["conditionalCompleteLifecycleComparisonRun"])
        self.assertFalse(report["newCandidateNativeValidationRun"])


if __name__ == "__main__":
    unittest.main()
