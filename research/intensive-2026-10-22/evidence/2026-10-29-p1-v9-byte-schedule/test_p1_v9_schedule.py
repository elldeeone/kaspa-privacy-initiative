#!/usr/bin/env python3
"""Hostile controls for the non-authorizing P1 v9 schedule receipt."""

import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "p1_v9_schedule", HERE / "verify_p1_v9_schedule.py")
schedule = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(schedule)


class P1V9ScheduleControls(unittest.TestCase):
    def setUp(self):
        self.receipt = schedule.load_receipt()

    def verify(self, receipt):
        schedule.verify_receipt(
            receipt, check_sources=False, check_trace=False)

    def test_frozen_receipt_and_current_source_trace_pins_recompute(self):
        schedule.verify_receipt(
            self.receipt, check_sources=True, check_trace=True)

    def test_top_level_deletion_extra_and_authorizing_flip_refuse(self):
        deleted = copy.deepcopy(self.receipt)
        del deleted["missing_bound_reasons"]
        extra = copy.deepcopy(self.receipt)
        extra["caller_claimed_bound"] = 1
        authorizing = copy.deepcopy(self.receipt)
        authorizing["authorizing"] = True
        authorizing["fd23_bound"] = 123
        for candidate in (deleted, extra, authorizing):
            with self.subTest(keys=sorted(candidate)), \
                 self.assertRaises(schedule.ReceiptError):
                self.verify(candidate)

    def test_scalar_count_width_order_and_H_mutations_refuse(self):
        count = copy.deepcopy(self.receipt)
        count["scalar_sites"][11]["calls"] += 1
        width = copy.deepcopy(self.receipt)
        width["scalar_sites"][13]["widths"][0] -= 1
        order = copy.deepcopy(self.receipt)
        order["scalar_sites"][11], order["scalar_sites"][12] = \
            order["scalar_sites"][12], order["scalar_sites"][11]
        symbolic = copy.deepcopy(self.receipt)
        symbolic["scalar_sites"][14]["per_H"]["wire_bytes"] -= 1
        for candidate in (count, width, order, symbolic):
            with self.assertRaises(schedule.ReceiptError):
                self.verify(candidate)

    def test_base_formula_lane_and_source_pin_mutations_refuse(self):
        formula = copy.deepcopy(self.receipt)
        formula["symbolic_totals"]["base_no_fork_hidden"] = \
            "19861945317 + 57408*H"
        lane = copy.deepcopy(self.receipt)
        lane["fixed_non_scalar_lanes"]["mac_and_group"]["payloads"][0] = 31
        source = copy.deepcopy(self.receipt)
        first = next(iter(source["source_pins"]["files"]))
        source["source_pins"]["files"][first] = "00" * 32
        with self.assertRaises(schedule.ReceiptError):
            self.verify(formula)
        with self.assertRaises(schedule.ReceiptError):
            self.verify(lane)
        with self.assertRaises(schedule.ReceiptError):
            schedule.verify_receipt(
                source, check_sources=True, check_trace=False)

    def test_site_schema_schedule_and_compensating_histogram_refuse(self):
        renamed = copy.deepcopy(self.receipt)
        renamed["scalar_sites"][0]["name"] = "owner-ddnnt-random-v-copy"
        schedule_text = copy.deepcopy(self.receipt)
        schedule_text["scalar_sites"][0]["width_schedule"] = \
            "[4096]*1929+[1681]*3"
        extra = copy.deepcopy(self.receipt)
        extra["scalar_sites"][13]["caller_asserted_exact"] = True

        compensated = copy.deepcopy(self.receipt)
        row = compensated["scalar_sites"][7]
        row["width_histogram"]["33"] -= 1
        row["width_histogram"]["34"] += 1
        metrics = schedule.histogram_metrics(row["width_histogram"])
        row.update(metrics)
        row["width_histogram_sha256"] = schedule.histogram_digest(
            row["width_histogram"])
        row["ordered_width_sha256"] = "11" * 32

        for candidate in (renamed, schedule_text, extra, compensated):
            with self.assertRaises(schedule.ReceiptError):
                self.verify(candidate)

    def test_source_path_and_missing_boundary_text_mutations_refuse(self):
        source_path = copy.deepcopy(self.receipt)
        removed = next(iter(source_path["source_pins"]["files"]))
        del source_path["source_pins"]["files"][removed]
        boundary = copy.deepcopy(self.receipt)
        boundary["missing_bound_reasons"][2] = \
            "peer traffic is probably bounded"
        for candidate in (source_path, boundary):
            with self.assertRaises(schedule.ReceiptError):
                self.verify(candidate)

    def test_histogram_truncation_duplicate_reorder_and_summary_refuse(self):
        original = schedule.HISTOGRAM.read_text(encoding="ascii").splitlines()
        variants = [
            original[:-1],
            original + [original[-1]],
            [original[0], original[2], original[1], *original[3:]],
            [original[0].replace("calls=324024", "calls=324025"),
             *original[1:]],
        ]
        for lines in variants:
            with self.subTest(first=lines[0]):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "histogram.txt"
                    path.write_text("\n".join(lines) + "\n", encoding="ascii")
                    with self.assertRaises(schedule.ReceiptError):
                        schedule.parse_site11(path)


if __name__ == "__main__":
    unittest.main()
