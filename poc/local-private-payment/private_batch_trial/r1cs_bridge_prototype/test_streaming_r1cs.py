#!/usr/bin/env python3
"""Hostile controls for the synthetic-only bounded streaming exporter."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[3]
EXPORTER = HERE / "target" / "release" / "stream_tiny_r1cs"
VERIFIER = HERE / "verify_streamed_r1cs.py"
EXPECTED_R1CS_SHA256 = "786364162a371e862488ed92dbb12e36670024c9fbb8c3acc1391f4c2bce33ab"
EXPECTED_GZIP_SHA256 = "2ba6fd35db5f0b5561e56b97124a08b067464b795e8e08278367f23dc539d549"
PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_axes(root: Path) -> tuple[Path, Path, Path]:
    rows = (
        (((3, 1),), ((4, 1),), ((5, 1),)),
        (((0, 3), (1, 2), (5, 1)), ((0, 1),), ((0, 10), (2, 2))),
        (((1, 1), (3, PRIME - 1)), ((2, 1), (4, PRIME - 1)),
         ((0, 9), (5, 1))),
    )
    result = []
    for axis, name in enumerate(("A.r1cs.bin.gz", "B.r1cs.bin.gz", "C.r1cs.bin.gz")):
        raw = bytearray(
            b"KPI_R1CS_AXIS_V1"
            + struct.pack("<Q", axis)
            + PRIME.to_bytes(32, "little")
            + struct.pack("<QQQ", 3, 3, 3)
        )
        for row in rows:
            linear_combination = row[axis]
            raw.extend(struct.pack("<Q", len(linear_combination)))
            for wire, coefficient in linear_combination:
                raw.extend(coefficient.to_bytes(32, "little"))
                raw.extend(struct.pack("<Q", wire))
        compressed = subprocess.run(
            ["/usr/bin/gzip", "-1", "-n", "-c"],
            input=raw,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        path = root / name
        path.write_bytes(compressed)
        result.append(path)
    return tuple(result)


class StreamingR1csControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(
            ["cargo", "build", "--release", "--locked", "--offline",
             "--bin", "stream_tiny_r1cs"],
            cwd=HERE,
            check=True,
            capture_output=True,
            text=True,
        )
        cls.directory = tempfile.TemporaryDirectory(prefix="kpb-streaming-r1cs-")
        cls.root = Path(cls.directory.name)
        cls.inputs = cls.root / "inputs"
        cls.inputs.mkdir()
        cls.axes = fixture_axes(cls.inputs)
        if sha256(Path("/usr/bin/gzip")) != EXPECTED_GZIP_SHA256:
            raise AssertionError("pinned gzip binary changed")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def output(self, name: str) -> Path:
        path = self.root / name
        path.mkdir()
        return path

    def export(self, output: Path, axes=None):
        selected = self.axes if axes is None else axes
        return subprocess.run(
            [EXPORTER, *selected, output], capture_output=True, text=True)

    def verify(self, output: Path, exporter=EXPORTER):
        return subprocess.run(
            ["python3", VERIFIER, *self.axes, output / "tiny.r1cs", exporter,
             output / "EXPORT-RECEIPT.json", output / "VERIFY-RECEIPT.json"],
            capture_output=True,
            text=True,
        )

    def verify_with_script(self, output: Path, verifier: Path):
        return subprocess.run(
            ["python3", verifier, *self.axes, output / "tiny.r1cs", EXPORTER,
             output / "EXPORT-RECEIPT.json", output / "VERIFY-RECEIPT.json"],
            capture_output=True,
            text=True,
        )

    def test_exact_export_and_independent_round_trip(self):
        output = self.output("positive")
        exported = self.export(output)
        self.assertEqual(exported.returncode, 0, exported.stderr)
        self.assertEqual({path.name for path in output.iterdir()},
                         {"tiny.r1cs", "EXPORT-RECEIPT.json"})
        self.assertEqual((output / "tiny.r1cs").stat().st_size, 736)
        self.assertEqual(sha256(output / "tiny.r1cs"), EXPECTED_R1CS_SHA256)
        self.assertEqual(stat.S_IMODE((output / "tiny.r1cs").stat().st_mode), 0o600)
        self.assertEqual(
            stat.S_IMODE((output / "EXPORT-RECEIPT.json").stat().st_mode), 0o600)
        verified = self.verify(output)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual({path.name for path in output.iterdir()},
                         {"tiny.r1cs", "EXPORT-RECEIPT.json", "VERIFY-RECEIPT.json"})
        receipt = json.loads((output / "VERIFY-RECEIPT.json").read_text())
        self.assertEqual(
            stat.S_IMODE((output / "VERIFY-RECEIPT.json").stat().st_mode), 0o600)
        self.assertTrue(receipt["output"]["every_input_row_term_equal"])
        self.assertFalse(receipt["setup_executed"])
        self.assertFalse(receipt["aggregate_full_export_authorized"])

    def test_swapped_axis_is_rejected_before_output(self):
        output = self.output("swapped-axis")
        result = self.export(output, (self.axes[1], self.axes[0], self.axes[2]))
        self.assertEqual(result.returncode, 2)
        self.assertIn("compressed-size-pin", result.stderr)
        self.assertEqual(list(output.iterdir()), [])

    def test_changed_compressed_input_is_rejected_before_output(self):
        inputs = self.root / "changed-inputs"
        shutil.copytree(self.inputs, inputs)
        changed = bytearray((inputs / "A.r1cs.bin.gz").read_bytes())
        changed[20] ^= 1
        (inputs / "A.r1cs.bin.gz").write_bytes(changed)
        output = self.output("changed-input")
        axes = tuple(inputs / path.name for path in self.axes)
        result = self.export(output, axes)
        self.assertEqual(result.returncode, 2)
        self.assertIn("compressed-identity-pin", result.stderr)
        self.assertEqual(list(output.iterdir()), [])

    def test_partial_gzip_is_rejected_before_output(self):
        inputs = self.root / "partial-inputs"
        shutil.copytree(self.inputs, inputs)
        source = inputs / "C.r1cs.bin.gz"
        source.write_bytes(source.read_bytes()[:-1])
        output = self.output("partial-input")
        axes = tuple(inputs / path.name for path in self.axes)
        result = self.export(output, axes)
        self.assertEqual(result.returncode, 2)
        self.assertIn("compressed-size-pin", result.stderr)
        self.assertEqual(list(output.iterdir()), [])

    def test_nonempty_output_directory_is_rejected_without_changes(self):
        output = self.output("nonempty")
        marker = output / "unexpected-observer-descriptor"
        marker.write_bytes(b"preserve")
        result = self.export(output)
        self.assertEqual(result.returncode, 2)
        self.assertIn("output-directory-not-empty", result.stderr)
        self.assertEqual(marker.read_bytes(), b"preserve")

    def test_symlink_output_directory_is_rejected_without_target_changes(self):
        target = self.output("symlink-output-target")
        alias = self.root / "symlink-output-alias"
        alias.symlink_to(target, target_is_directory=True)
        result = self.export(alias)
        self.assertEqual(result.returncode, 2)
        self.assertIn("not a directory", result.stderr)
        self.assertEqual(list(target.iterdir()), [])

    def test_export_reuse_is_rejected_and_outputs_are_unchanged(self):
        output = self.output("reuse-export")
        self.assertEqual(self.export(output).returncode, 0)
        before = {path.name: sha256(path) for path in output.iterdir()}
        repeated = self.export(output)
        self.assertEqual(repeated.returncode, 2)
        self.assertIn("output-directory-not-empty", repeated.stderr)
        self.assertEqual(before, {path.name: sha256(path) for path in output.iterdir()})

    def test_corrupted_output_is_rejected_without_verifier_receipt(self):
        output = self.output("corrupt-output")
        self.assertEqual(self.export(output).returncode, 0)
        body = bytearray((output / "tiny.r1cs").read_bytes())
        body[120] ^= 1
        (output / "tiny.r1cs").write_bytes(body)
        result = self.verify(output)
        self.assertEqual(result.returncode, 2)
        self.assertIn("r1cs-identity", result.stderr)
        self.assertFalse((output / "VERIFY-RECEIPT.json").exists())

    def test_partial_output_is_rejected_without_verifier_receipt(self):
        output = self.output("partial-output")
        self.assertEqual(self.export(output).returncode, 0)
        body = (output / "tiny.r1cs").read_bytes()
        (output / "tiny.r1cs").write_bytes(body[:-1])
        result = self.verify(output)
        self.assertEqual(result.returncode, 2)
        self.assertIn("r1cs-identity", result.stderr)
        self.assertFalse((output / "VERIFY-RECEIPT.json").exists())

    def test_wrong_exporter_binary_is_rejected(self):
        output = self.output("wrong-binary")
        self.assertEqual(self.export(output).returncode, 0)
        result = self.verify(output, Path("/bin/true"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("export-receipt-binding", result.stderr)
        self.assertFalse((output / "VERIFY-RECEIPT.json").exists())

    def test_substituted_export_receipt_is_rejected(self):
        output = self.output("wrong-receipt")
        self.assertEqual(self.export(output).returncode, 0)
        receipt_path = output / "EXPORT-RECEIPT.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["plan_sha256"] = "00" * 32
        receipt_path.write_text(json.dumps(receipt))
        result = self.verify(output)
        self.assertEqual(result.returncode, 2)
        self.assertIn("export-receipt-binding", result.stderr)
        self.assertFalse((output / "VERIFY-RECEIPT.json").exists())

    def test_substituted_input_pin_in_export_receipt_is_rejected(self):
        output = self.output("wrong-receipt-input-pin")
        self.assertEqual(self.export(output).returncode, 0)
        receipt_path = output / "EXPORT-RECEIPT.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["axes"][0]["raw_sha256"] = "00" * 32
        receipt_path.write_text(json.dumps(receipt))
        result = self.verify(output)
        self.assertEqual(result.returncode, 2)
        self.assertIn("export-receipt-input-pins", result.stderr)
        self.assertFalse((output / "VERIFY-RECEIPT.json").exists())

    def test_wrong_plan_file_is_rejected_without_verifier_receipt(self):
        output = self.output("wrong-plan")
        self.assertEqual(self.export(output).returncode, 0)
        verifier_directory = self.root / "wrong-plan-verifier"
        verifier_directory.mkdir()
        verifier = verifier_directory / VERIFIER.name
        shutil.copy2(VERIFIER, verifier)
        plan = json.loads((HERE / "tiny_stream_plan.json").read_text())
        plan["setup_authorized"] = True
        (verifier_directory / "tiny_stream_plan.json").write_text(json.dumps(plan))
        result = self.verify_with_script(output, verifier)
        self.assertEqual(result.returncode, 2)
        self.assertIn("plan-identity", result.stderr)
        self.assertFalse((output / "VERIFY-RECEIPT.json").exists())

    def test_extra_output_blocks_verification(self):
        output = self.output("extra-output")
        self.assertEqual(self.export(output).returncode, 0)
        (output / "contact.sock").write_bytes(b"not-a-socket-but-still-extra")
        result = self.verify(output)
        self.assertEqual(result.returncode, 2)
        self.assertIn("verification-directory-contents", result.stderr)
        self.assertFalse((output / "VERIFY-RECEIPT.json").exists())

    def test_symlink_output_directory_blocks_verification(self):
        output = self.output("verify-symlink-target")
        self.assertEqual(self.export(output).returncode, 0)
        alias = self.root / "verify-symlink-alias"
        alias.symlink_to(output, target_is_directory=True)
        result = self.verify(alias)
        self.assertEqual(result.returncode, 2)
        self.assertIn("verification-directory-not-real", result.stderr)
        self.assertFalse((output / "VERIFY-RECEIPT.json").exists())

    def test_verifier_receipt_reuse_is_rejected_and_preserved(self):
        output = self.output("reuse-verifier")
        self.assertEqual(self.export(output).returncode, 0)
        self.assertEqual(self.verify(output).returncode, 0)
        receipt = output / "VERIFY-RECEIPT.json"
        before = sha256(receipt)
        repeated = self.verify(output)
        self.assertEqual(repeated.returncode, 2)
        self.assertIn("verification-directory-contents", repeated.stderr)
        self.assertEqual(sha256(receipt), before)

    def test_full_aggregate_artifacts_cannot_select_tiny_export(self):
        root = WORKSPACE / ".local/private-batch-current-matrix-equivalence-20261029-01/artifact"
        if not root.is_dir():
            self.skipTest("retained full aggregate axes unavailable")
        output = self.output("full-aggregate-refused")
        axes = tuple(root / name for name in
                     ("A.r1cs.bin.gz", "B.r1cs.bin.gz", "C.r1cs.bin.gz"))
        result = self.export(output, axes)
        self.assertEqual(result.returncode, 2)
        self.assertIn("compressed-size-pin", result.stderr)
        self.assertEqual(list(output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
