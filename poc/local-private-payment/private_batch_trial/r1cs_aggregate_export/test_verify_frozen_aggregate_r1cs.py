#!/usr/bin/env python3
"""Tiny injected controls for the production-only aggregate verifier."""

from __future__ import annotations

from dataclasses import replace
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import time
import unittest

import verify_frozen_aggregate_r1cs as verify


PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617
PRIME_BYTES = PRIME.to_bytes(32, "little")
ROWS = (
    (((3, 1),), ((4, 1),), ((5, 1),)),
    (((0, 3), (1, 2), (5, 1)), ((0, 1),), ((0, 10), (2, 2))),
    (((1, 1), (3, PRIME - 1)), ((2, 1), (4, PRIME - 1)),
     ((0, 9), (5, 1))),
)


def sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def pinned(path: Path, code: str = "test-input") -> verify.PinnedFd:
    raw = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        return verify.PinnedFd(raw, code)
    finally:
        os.close(raw)


def build_axes(root: Path) -> tuple[tuple[Path, Path, Path], verify.Contract]:
    paths = []
    pins = []
    fingerprint = hashlib.sha256(
        verify.FINGERPRINT_DOMAIN + struct.pack("<QQQ", 3, 3, 3))
    for axis, label in enumerate(("A.r1cs.bin.gz", "B.r1cs.bin.gz", "C.r1cs.bin.gz")):
        raw = bytearray(
            verify.AXIS_MAGIC + struct.pack("<Q", axis) + PRIME_BYTES +
            struct.pack("<QQQ", 3, 3, 3)
        )
        maximum = 0
        terms = 0
        for row in ROWS:
            linear_combination = row[axis]
            maximum = max(maximum, len(linear_combination))
            terms += len(linear_combination)
            encoded_count = struct.pack("<Q", len(linear_combination))
            raw.extend(encoded_count)
            fingerprint.update(encoded_count)
            for wire, coefficient in linear_combination:
                encoded = coefficient.to_bytes(32, "little") + struct.pack("<Q", wire)
                raw.extend(encoded)
                fingerprint.update(encoded)
        compressed = gzip.compress(bytes(raw), compresslevel=1, mtime=0)
        path = root / label
        path.write_bytes(compressed)
        paths.append(path)
        pins.append(verify.AxisPin(
            axis=axis,
            label=label,
            compressed_bytes=len(compressed),
            compressed_sha256=sha256(compressed),
            raw_bytes=len(raw),
            raw_sha256=sha256(raw),
            terms=terms,
            maximum_row_terms=maximum,
        ))
    contract = verify.Contract(
        plan_sha256="11" * 32,
        exporter_source_sha256="22" * 32,
        cargo_toml_sha256="33" * 32,
        cargo_lock_sha256="44" * 32,
        rust_toolchain_sha256="55" * 32,
        verifier_source_sha256="66" * 32,
        verifier_python_path="/test/python",
        verifier_python_sha256="77" * 32,
        verifier_python_version=(3, 14, 4, "final", 0),
        verifier_zlib_version="1.3.1",
        scanner_receipt_sha256="88" * 32,
        scanner_binary_sha256="99" * 32,
        frozen_manifest_sha256="aa" * 32,
        frozen_source_sha256="bb" * 32,
        field=PRIME_BYTES,
        instances=3,
        witnesses=3,
        variables=6,
        constraints=3,
        public_outputs=0,
        public_inputs=2,
        private_inputs=3,
        labels=6,
        axes=tuple(pins),
        matrix_fingerprint=fingerprint.hexdigest(),
        constraint_section_bytes=576,
        wire_map_bytes=48,
        output_bytes=736,
    )
    verify.validate_contract(contract)
    return tuple(paths), contract


def build_r1cs(contract: verify.Contract) -> bytes:
    output = bytearray()
    output.extend(b"r1cs" + struct.pack("<II", 1, 3))
    output.extend(struct.pack("<IQI", 1, 64, 32))
    output.extend(contract.field)
    output.extend(struct.pack(
        "<IIIIQI", contract.variables, contract.public_outputs,
        contract.public_inputs, contract.private_inputs, contract.labels,
        contract.constraints))
    output.extend(struct.pack("<IQ", 2, contract.constraint_section_bytes))
    for row in ROWS:
        for linear_combination in row:
            output.extend(struct.pack("<I", len(linear_combination)))
            for wire, coefficient in linear_combination:
                output.extend(struct.pack("<I", wire))
                output.extend(coefficient.to_bytes(32, "little"))
    output.extend(struct.pack("<IQ", 3, contract.wire_map_bytes))
    for wire in range(contract.variables):
        output.extend(struct.pack("<Q", wire))
    assert len(output) == contract.output_bytes
    return bytes(output)


def axis_sources(paths: tuple[Path, Path, Path]):
    return tuple(pinned(path, f"axis-{axis}") for axis, path in enumerate(paths))


def export_receipt(contract: verify.Contract, output_sha256: str,
                   exporter_binary_sha256: str,
                   exporter_binary_identity: os.stat_result) -> dict:
    return {
        "schema": "kpb-frozen-aggregate-r1cs-export-receipt/v1",
        "status": "PASS",
        "classification": "PRODUCTION_SIZED_R1CS_CONVERSION_ONLY_NO_SETUP_OR_CEREMONY",
        "plan_sha256": contract.plan_sha256,
        "exporter_source_sha256": contract.exporter_source_sha256,
        "exporter_binary_sha256": exporter_binary_sha256,
        "exporter_binary_descriptor_identity":
            verify.identity_json(exporter_binary_identity),
        "cargo_toml_sha256": contract.cargo_toml_sha256,
        "cargo_lock_sha256": contract.cargo_lock_sha256,
        "rust_toolchain_sha256": contract.rust_toolchain_sha256,
        "expected_verifier_source_sha256": contract.verifier_source_sha256,
        "expected_verifier_python_sha256": contract.verifier_python_sha256,
        "admission_receipt_sha256": contract.scanner_receipt_sha256,
        "canonical_r1cs_fingerprint": contract.matrix_fingerprint,
        "output": {
            "file": verify.OUTPUT_NAME,
            "bytes": contract.output_bytes,
            "sha256": output_sha256,
            "section_order": [1, 2, 3],
            "constraint_section_bytes": contract.constraint_section_bytes,
            "identity_wire_map_bytes": contract.wire_map_bytes,
            "mode": "0600",
        },
        "independent_verifier_passed": False,
        "r1cs_full_aggregate_exported": True,
        "zkey_generated": False,
        "setup_executed": False,
        "phase1_executed": False,
        "phase2_executed": False,
        "ceremony_executed": False,
    }


class ProductionVerifierControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kpb-aggregate-verifier-")
        self.root = Path(self.temporary.name)
        self.axes, self.contract = build_axes(self.root)
        self.output = self.root / "aggregate.r1cs"
        self.output.write_bytes(build_r1cs(self.contract))

    def tearDown(self):
        self.temporary.cleanup()

    def verify_output(self, contract=None, output=None):
        contract = self.contract if contract is None else contract
        output = self.output if output is None else output
        body = output.read_bytes()
        verify.preflight_axes(contract, axis_sources(self.axes))
        verify.verify_output(contract, axis_sources(self.axes), pinned(output, "r1cs"),
                             sha256(body))

    def test_tiny_injected_round_trip(self):
        self.verify_output()

    def test_wrong_constraint_section_is_rejected(self):
        body = bytearray(self.output.read_bytes())
        body[88:92] = struct.pack("<I", 9)
        self.output.write_bytes(body)
        with self.assertRaisesRegex(verify.Reject, "r1cs-constraint-section"):
            self.verify_output()

    def test_wrong_identity_map_is_rejected(self):
        body = bytearray(self.output.read_bytes())
        body[688:696] = struct.pack("<Q", 9)
        self.output.write_bytes(body)
        with self.assertRaisesRegex(verify.Reject, "r1cs-map-substitution"):
            self.verify_output()

    def test_output_coefficient_substitution_is_rejected(self):
        body = bytearray(self.output.read_bytes())
        body[108] ^= 1
        self.output.write_bytes(body)
        with self.assertRaisesRegex(verify.Reject, "r1cs-term-substitution"):
            self.verify_output()

    def test_pass_one_pass_two_input_mutation_is_rejected(self):
        verify.preflight_axes(self.contract, axis_sources(self.axes))
        changed = bytearray(self.axes[0].read_bytes())
        changed[20] ^= 1
        self.axes[0].write_bytes(changed)
        with self.assertRaisesRegex(verify.Reject, "compressed-identity-pin"):
            verify.verify_output(
                self.contract, axis_sources(self.axes), pinned(self.output, "r1cs"),
                sha256(self.output.read_bytes()))

    def test_crc_failure_after_compressed_pin_is_rejected(self):
        changed = bytearray(self.axes[0].read_bytes())
        changed[-1] ^= 1
        self.axes[0].write_bytes(changed)
        changed_pin = replace(
            self.contract.axes[0],
            compressed_sha256=sha256(changed),
        )
        contract = replace(
            self.contract,
            axes=(changed_pin, self.contract.axes[1], self.contract.axes[2]),
        )
        with self.assertRaisesRegex(verify.Reject, "gzip-crc-or-stream"):
            verify.preflight_axes(contract, axis_sources(self.axes))

    def test_trailing_gzip_member_after_compressed_pin_is_rejected(self):
        changed = self.axes[0].read_bytes() + gzip.compress(b"second", mtime=0)
        self.axes[0].write_bytes(changed)
        changed_pin = replace(
            self.contract.axes[0],
            compressed_bytes=len(changed),
            compressed_sha256=sha256(changed),
        )
        contract = replace(
            self.contract,
            axes=(changed_pin, self.contract.axes[1], self.contract.axes[2]),
        )
        with self.assertRaisesRegex(verify.Reject, "gzip-trailing-or-second-member"):
            verify.preflight_axes(contract, axis_sources(self.axes))

    def test_chunk_cursor_many_small_reads_are_exact_and_bounded(self):
        eight = b"12345678"
        forty = bytes(range(40))
        repetitions = 5_000
        raw = (eight + forty) * repetitions
        compressed = gzip.compress(raw, compresslevel=1, mtime=0)
        path = self.root / "cursor.gz"
        path.write_bytes(compressed)
        pin = verify.AxisPin(
            axis=0,
            label="cursor.gz",
            compressed_bytes=len(compressed),
            compressed_sha256=sha256(compressed),
            raw_bytes=len(raw),
            raw_sha256=sha256(raw),
            terms=0,
            maximum_row_terms=0,
        )
        started = time.monotonic()
        cursor = verify.SingleMember(pinned(path, "cursor"), pin)
        for _ in range(repetitions):
            self.assertEqual(cursor.read_exact(8), eight)
            self.assertEqual(cursor.read_exact(40), forty)
        cursor.finish()
        self.assertLess(time.monotonic() - started, 5.0)

    def test_overflow_geometry_is_rejected(self):
        with self.assertRaisesRegex(verify.Reject, "contract-u32"):
            verify.validate_contract(replace(self.contract, constraints=1 << 40))

    def test_exporter_source_substitution_in_receipt_is_rejected(self):
        binary = self.root / "exporter"
        binary.write_bytes(b"binary")
        binary_hash = sha256(binary.read_bytes())
        binary_source = pinned(binary, "binary")
        receipt = export_receipt(
            self.contract, sha256(self.output.read_bytes()), binary_hash,
            binary_source.identity)
        receipt["exporter_source_sha256"] = "00" * 32
        receipt_path = self.root / "receipt.json"
        receipt_path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(verify.Reject, "export-receipt-binding"):
            verify.validate_export_receipt(
                self.contract, pinned(receipt_path, "receipt"), binary_hash,
                binary_source.identity)
        binary_source.close()

    def test_verifier_source_and_interpreter_substitution_are_rejected(self):
        production = verify.load_production_contract()
        with self.assertRaisesRegex(verify.Reject, "material-identity"):
            verify.validate_materials(replace(
                production, verifier_source_sha256="00" * 32))
        with self.assertRaisesRegex(verify.Reject, "verifier-interpreter-identity"):
            verify.validate_materials(replace(
                production, verifier_python_sha256="00" * 32))

    def test_verifier_receipt_reuse_is_rejected_and_original_preserved(self):
        directory_fd = os.open(self.root, os.O_RDONLY | os.O_CLOEXEC)
        try:
            receipt = {"schema": "test", "status": "PASS"}
            verify.atomic_receipt(directory_fd, receipt)
            path = self.root / verify.VERIFY_RECEIPT_NAME
            before = path.read_bytes()
            with self.assertRaisesRegex(verify.Reject, "verify-receipt-publish"):
                verify.atomic_receipt(directory_fd, receipt)
            self.assertEqual(path.read_bytes(), before)
        finally:
            os.close(directory_fd)


if __name__ == "__main__":
    unittest.main()
