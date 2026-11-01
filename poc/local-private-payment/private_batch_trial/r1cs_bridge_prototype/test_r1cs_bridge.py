#!/usr/bin/env python3
"""Hostile controls for the isolated throwaway R1CS format bridge."""

from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
EXPORTER = HERE / "target" / "debug" / "kpb-r1cs-bridge-prototype"
VERIFIER = HERE / "verify_r1cs.py"
EXPECTED_SHA256 = "786364162a371e862488ed92dbb12e36670024c9fbb8c3acc1391f4c2bce33ab"
PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def unpack_sections(body: bytes):
    if body[:4] != b"r1cs" or struct.unpack_from("<II", body, 4) != (1, 3):
        raise AssertionError("unexpected base fixture")
    at = 12
    sections = []
    for _ in range(3):
        kind, size = struct.unpack_from("<IQ", body, at)
        at += 12
        sections.append((kind, body[at:at + size]))
        at += size
    if at != len(body):
        raise AssertionError("unexpected base trailing data")
    return sections


def pack_sections(sections) -> bytes:
    result = bytearray(b"r1cs" + struct.pack("<II", 1, len(sections)))
    for kind, section in sections:
        result.extend(struct.pack("<IQ", kind, len(section)))
        result.extend(section)
    return bytes(result)


def split_rows(section: bytes):
    at = 0
    rows = []
    for _ in range(3):
        start = at
        for _ in range(3):
            count = struct.unpack_from("<I", section, at)[0]
            at += 4 + count * 36
        rows.append(section[start:at])
    if at != len(section):
        raise AssertionError("unexpected constraint trailing data")
    return rows


def split_axes(row: bytes):
    at = 0
    axes = []
    for _ in range(3):
        start = at
        count = struct.unpack_from("<I", row, at)[0]
        at += 4 + count * 36
        axes.append(row[start:at])
    if at != len(row):
        raise AssertionError("unexpected row trailing data")
    return axes


class R1csBridgeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(
            ["cargo", "build", "--locked", "--offline"], cwd=HERE,
            check=True, capture_output=True, text=True)
        cls.directory = tempfile.TemporaryDirectory(
            prefix="kpb-r1cs-bridge-prototype-")
        cls.root = Path(cls.directory.name)
        cls.fixture = cls.root / "fixture.r1cs"
        subprocess.run([EXPORTER, cls.fixture], check=True,
                       capture_output=True, text=True)
        cls.body = cls.fixture.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def verify(self, path: Path):
        return subprocess.run(
            ["python3", VERIFIER, path], capture_output=True, text=True)

    def mutated(self, name: str, constraint_body: bytes) -> Path:
        sections = unpack_sections(self.body)
        self.assertEqual([kind for kind, _ in sections], [1, 2, 3])
        sections[1] = (2, constraint_body)
        return self.repacked(name, sections)

    def repacked(self, name: str, sections) -> Path:
        path = self.root / name
        path.write_bytes(pack_sections(sections))
        return path

    def test_exact_export_is_deterministic_and_round_trips(self):
        second = self.root / "second.r1cs"
        subprocess.run([EXPORTER, second], check=True,
                       capture_output=True, text=True)
        self.assertEqual(self.body, second.read_bytes())
        self.assertEqual(hashlib.sha256(self.body).hexdigest(), EXPECTED_SHA256)
        result = self.verify(self.fixture)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"all_rows_satisfied": true', result.stdout)
        self.assertIn('"setup_executed": false', result.stdout)

    def test_reordered_rows_are_rejected(self):
        rows = split_rows(unpack_sections(self.body)[1][1])
        path = self.mutated("row-reorder.r1cs", rows[1] + rows[0] + rows[2])
        result = self.verify(path)
        self.assertEqual(result.returncode, 2)
        self.assertIn("matrix mismatch at row 0", result.stderr)

    def test_explicit_zero_coefficient_is_rejected(self):
        rows = split_rows(unpack_sections(self.body)[1][1])
        axes = split_axes(rows[0])
        old_a = axes[0]
        zero_term = struct.pack("<I", 1) + bytes(32)
        axes[0] = struct.pack("<I", 2) + zero_term + old_a[4:]
        rows[0] = b"".join(axes)
        path = self.mutated("explicit-zero.r1cs", b"".join(rows))
        result = self.verify(path)
        self.assertEqual(result.returncode, 2)
        self.assertIn("explicit zero coefficient at row 0 A", result.stderr)

    def test_changed_coefficient_is_rejected(self):
        rows = split_rows(unpack_sections(self.body)[1][1])
        changed = bytearray(rows[0])
        changed[8:40] = (2).to_bytes(32, "little")
        rows[0] = bytes(changed)
        path = self.mutated("coefficient.r1cs", b"".join(rows))
        result = self.verify(path)
        self.assertEqual(result.returncode, 2)
        self.assertIn("matrix mismatch at row 0", result.stderr)

    def test_noncanonical_coefficient_encoding_is_rejected(self):
        rows = split_rows(unpack_sections(self.body)[1][1])
        changed = bytearray(rows[0])
        changed[8:40] = PRIME.to_bytes(32, "little")
        rows[0] = bytes(changed)
        path = self.mutated("noncanonical-coefficient.r1cs", b"".join(rows))
        result = self.verify(path)
        self.assertEqual(result.returncode, 2)
        self.assertIn("noncanonical coefficient at row 0 A", result.stderr)

    def test_same_shape_satisfied_matrix_substitution_is_rejected(self):
        rows = split_rows(unpack_sections(self.body)[1][1])
        axes = split_axes(rows[0])
        # x*y and y*x are equally satisfied under the fixture assignment. The
        # exact matrix identity must still reject this foreign relation.
        rows[0] = axes[1] + axes[0] + axes[2]
        path = self.mutated("matrix-substitution.r1cs", b"".join(rows))
        result = self.verify(path)
        self.assertEqual(result.returncode, 2)
        self.assertIn("matrix mismatch at row 0", result.stderr)

    def test_field_modulus_substitution_is_rejected(self):
        sections = unpack_sections(self.body)
        header = bytearray(sections[0][1])
        header[4:36] = (PRIME - 1).to_bytes(32, "little")
        sections[0] = (1, bytes(header))
        result = self.verify(self.repacked("field-substitution.r1cs", sections))
        self.assertEqual(result.returncode, 2)
        self.assertIn("wrong BN254 scalar modulus", result.stderr)

    def test_variable_count_substitution_is_rejected(self):
        sections = unpack_sections(self.body)
        header = bytearray(sections[0][1])
        struct.pack_into("<I", header, 48, 2)  # nPrvInputs: 3 -> 2.
        sections[0] = (1, bytes(header))
        result = self.verify(self.repacked("count-substitution.r1cs", sections))
        self.assertEqual(result.returncode, 2)
        self.assertIn("header/count substitution", result.stderr)


if __name__ == "__main__":
    unittest.main()
