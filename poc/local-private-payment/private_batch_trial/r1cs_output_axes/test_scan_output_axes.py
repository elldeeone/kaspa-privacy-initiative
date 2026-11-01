#!/usr/bin/env python3
"""Tiny injected hostile controls for the Output-axis admission scanner."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import time
import unittest

import scan_output_axes as scan


def make_raw(axis: int, coefficient: int = 1, column: int = 1) -> bytes:
    return (
        scan.MAGIC + struct.pack("<Q", axis) + scan.FIELD_BYTES +
        struct.pack("<QQQ", 1, 1, 1) + struct.pack("<Q", 1) +
        coefficient.to_bytes(32, "little") + struct.pack("<Q", column)
    )


def make_pin(raw: bytes, compressed: bytes) -> dict:
    return {
        "compressed_bytes": len(compressed),
        "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
        "raw_bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "terms": 1,
        "maximum_row_terms": 1,
    }


class OutputAxesScannerControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kpb-output-axis-scan-")
        self.root = Path(self.temporary.name)
        self.original = (
            scan.INSTANCES, scan.WITNESSES, scan.VARIABLES, scan.CONSTRAINTS)
        scan.INSTANCES = 1
        scan.WITNESSES = 1
        scan.VARIABLES = 2
        scan.CONSTRAINTS = 1

    def tearDown(self):
        (scan.INSTANCES, scan.WITNESSES, scan.VARIABLES,
         scan.CONSTRAINTS) = self.original
        self.temporary.cleanup()

    def source(self, name: str, body: bytes) -> scan.Pinned:
        path = self.root / name
        path.write_bytes(body)
        return scan.Pinned(path, name)

    def test_exact_tiny_axis_round_trip(self):
        raw = make_raw(0)
        compressed = gzip.compress(raw, compresslevel=1, mtime=0)
        fingerprint = hashlib.sha256(
            scan.DOMAIN + struct.pack("<QQQ", 1, 1, 1))
        source = self.source("exact.gz", compressed)
        try:
            receipt = scan.scan_axis(source, make_pin(raw, compressed), 0, fingerprint)
            self.assertEqual(receipt["terms"], 1)
            expected = hashlib.sha256(
                scan.DOMAIN + struct.pack("<QQQ", 1, 1, 1) +
                struct.pack("<Q", 1) + raw[-40:]
            ).hexdigest()
            self.assertEqual(fingerprint.hexdigest(), expected)
        finally:
            source.close()

    def test_crc_failure_after_compressed_pin_is_rejected(self):
        raw = make_raw(0)
        compressed = bytearray(gzip.compress(raw, compresslevel=1, mtime=0))
        compressed[-1] ^= 1
        source = self.source("crc.gz", compressed)
        try:
            with self.assertRaisesRegex(scan.Reject, "gzip-crc"):
                scan.scan_axis(source, make_pin(raw, compressed), 0,
                               hashlib.sha256())
        finally:
            source.close()

    def test_trailing_member_after_compressed_pin_is_rejected(self):
        raw = make_raw(0)
        compressed = (gzip.compress(raw, compresslevel=1, mtime=0) +
                      gzip.compress(b"second", mtime=0))
        source = self.source("trailing.gz", compressed)
        try:
            with self.assertRaisesRegex(scan.Reject, "gzip-trailing-member"):
                scan.scan_axis(source, make_pin(raw, compressed), 0,
                               hashlib.sha256())
        finally:
            source.close()

    def test_chunk_cursor_many_small_reads_are_exact_and_bounded(self):
        eight = b"12345678"
        forty = bytes(range(40))
        repetitions = 5_000
        raw = (eight + forty) * repetitions
        compressed = gzip.compress(raw, compresslevel=1, mtime=0)
        source = self.source("cursor.gz", compressed)
        try:
            cursor = scan.Gzip(source, make_pin(raw, compressed), 0)
            started = time.monotonic()
            for _ in range(repetitions):
                self.assertEqual(cursor.exact(8), eight)
                self.assertEqual(cursor.exact(40), forty)
            cursor.finish()
            self.assertLess(time.monotonic() - started, 5.0)
        finally:
            source.close()

    def test_zero_and_out_of_range_terms_are_rejected(self):
        for label, raw, pattern in (
            ("zero", make_raw(0, coefficient=0), "zero"),
            ("column", make_raw(0, column=2), "column"),
        ):
            compressed = gzip.compress(raw, compresslevel=1, mtime=0)
            source = self.source(f"{label}.gz", compressed)
            try:
                with self.assertRaisesRegex(scan.Reject, pattern):
                    scan.scan_axis(source, make_pin(raw, compressed), 0,
                                   hashlib.sha256())
            finally:
                source.close()

    def test_receipt_reuse_is_rejected_and_original_preserved(self):
        path = self.root / "RECEIPT.json"
        receipt = {"schema": "test", "status": "PASS"}
        scan.write_receipt(path, receipt)
        before = path.read_bytes()
        with self.assertRaises(FileExistsError):
            scan.write_receipt(path, receipt)
        self.assertEqual(path.read_bytes(), before)

    def test_current_source_closure_verifies(self):
        closure = json.loads((scan.HERE / "source_closure.json").read_text())
        manifest = {
            "source_closure_manifest_sha256": hashlib.sha256(
                (scan.HERE / "source_closure.json").read_bytes()).hexdigest(),
            "source_closure_identity": closure["closure_identity"],
        }
        scan.verify_source_closure(manifest)


if __name__ == "__main__":
    unittest.main()
