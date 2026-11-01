#!/usr/bin/env python3
"""Controls for the immutable selected-parent 10x6 table contract."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import privacy_measurement_selected_parent_artifact_table as table


class SelectedParentArtifactTableControls(unittest.TestCase):
    def test_current_report_is_exactly_all_sixty_missing(self):
        contract = table.load()
        table.validate(contract)
        report = table.missing_report(contract)
        recorded = json.loads(
            table.MISSING_REPORT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(recorded, report)
        self.assertEqual(report["missing_count"], 60)
        self.assertFalse(report["complete"])
        self.assertFalse(report["production_table_selected"])
        self.assertFalse(report["selected_launcher_callsite"])
        self.assertFalse(report["configured"])
        expected_fields = [row[0] for row in table.FIELD_ROWS]
        self.assertEqual(len(report["missing"]), 10)
        for index, component in enumerate(report["missing"], 1):
            self.assertEqual(component["component"], index)
            self.assertEqual(component["fields"], expected_fields)
        with self.assertRaisesRegex(ValueError, "missing-entries"):
            table.require_complete(contract, check_files=False)

    def test_missing_entries_cannot_be_marked_selected_or_configured(self):
        for key in (
                "production_table_selected", "selected_launcher_callsite",
                "configured"):
            changed = deepcopy(table.load())
            changed["status"][key] = True
            with self.subTest(key=key), self.assertRaisesRegex(
                    ValueError, "missing-status"):
                table.validate(changed)

    def test_one_exact_source_owned_entry_reduces_only_its_slot(self):
        contract = deepcopy(table.load())
        with tempfile.TemporaryDirectory(
                prefix="kpb-selected-artifact-contract-") as directory:
            root = Path(directory).resolve()
            artifact = root / "financial-source.kpb"
            artifact.write_bytes(b"source-owned-artifact-control")
            origin = contract["components"][0]["origin_contracts"][0]
            origin_path = table.HERE.parents[2] / origin
            self.assertTrue(origin_path.is_file())
            contract["selected_snapshot_root"] = str(root)
            contract["artifacts"] = [{
                "component": 1,
                "field": 1,
                "path": str(artifact),
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "origin_contract": origin,
                "origin_contract_sha256": hashlib.sha256(
                    origin_path.read_bytes()).hexdigest(),
                "final_executable": False,
            }]
            table.validate(contract, check_files=True)
            report = table.missing_report(contract)
            self.assertEqual(report["missing_count"], 59)
            self.assertEqual(report["missing"][0]["fields"], [
                "build", "runtime", "assets", "pinned-executable",
                "launcher",
            ])

    def test_duplicate_slots_wrong_owner_and_symlink_refuse(self):
        base = deepcopy(table.load())
        with tempfile.TemporaryDirectory(
                prefix="kpb-selected-artifact-hostile-") as directory:
            root = Path(directory).resolve()
            artifact = root / "artifact"
            artifact.write_bytes(b"artifact")
            link = root / "link"
            link.symlink_to(artifact)
            origin = base["components"][0]["origin_contracts"][0]
            origin_path = table.HERE.parents[2] / origin
            row = {
                "component": 1,
                "field": 1,
                "path": str(artifact),
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "origin_contract": origin,
                "origin_contract_sha256": hashlib.sha256(
                    origin_path.read_bytes()).hexdigest(),
                "final_executable": False,
            }
            duplicate = deepcopy(base)
            duplicate["selected_snapshot_root"] = str(root)
            duplicate["artifacts"] = [row, deepcopy(row)]
            with self.assertRaisesRegex(ValueError, "artifact-slot"):
                table.validate(duplicate)

            wrong_owner = deepcopy(base)
            wrong_owner["selected_snapshot_root"] = str(root)
            wrong_row = deepcopy(row)
            wrong_row["origin_contract"] = base["components"][1][
                "origin_contracts"][0]
            wrong_owner["artifacts"] = [wrong_row]
            with self.assertRaisesRegex(ValueError, "artifact-origin-owner"):
                table.validate(wrong_owner)

            symlink = deepcopy(base)
            symlink["selected_snapshot_root"] = str(root)
            symlink_row = deepcopy(row)
            symlink_row["path"] = str(link)
            symlink["artifacts"] = [symlink_row]
            with self.assertRaisesRegex(ValueError, "artifact-(path|regular)"):
                table.validate(symlink, check_files=True)


if __name__ == "__main__":
    unittest.main()
