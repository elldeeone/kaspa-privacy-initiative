#!/usr/bin/env python3
"""Independent exact verifier for the throwaway Arkworks R1CS fixture."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys


PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617
FIELD_BYTES = 32
EXPECTED_HEADER = {
    "wires": 6,
    "public_outputs": 0,
    "public_inputs": 2,
    "private_inputs": 3,
    "labels": 6,
    "constraints": 3,
}
ASSIGNMENT = (1, 7, 11, 3, 5, 15)
NEG_ONE = PRIME - 1
EXPECTED_CONSTRAINTS = (
    (
        ((3, 1),),
        ((4, 1),),
        ((5, 1),),
    ),
    (
        ((0, 3), (1, 2), (5, 1)),
        ((0, 1),),
        ((0, 10), (2, 2)),
    ),
    (
        ((1, 1), (3, NEG_ONE)),
        ((2, 1), (4, NEG_ONE)),
        ((0, 9), (5, 1)),
    ),
)

# Patched after the exporter is built once; this binds the exact deterministic
# section order and bytes in addition to the semantic matrix checks above.
EXPECTED_SHA256 = "786364162a371e862488ed92dbb12e36670024c9fbb8c3acc1391f4c2bce33ab"


class R1csError(ValueError):
    pass


class Cursor:
    def __init__(self, body: bytes, label: str):
        self.body = body
        self.label = label
        self.at = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.at + size > len(self.body):
            raise R1csError(f"truncated {self.label}")
        result = self.body[self.at:self.at + size]
        self.at += size
        return result

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def finish(self) -> None:
        if self.at != len(self.body):
            raise R1csError(f"trailing bytes in {self.label}")


def parse_sections(body: bytes) -> dict[int, bytes]:
    cursor = Cursor(body, "R1CS container")
    if cursor.take(4) != b"r1cs":
        raise R1csError("wrong magic")
    if cursor.u32() != 1:
        raise R1csError("wrong R1CS version")
    if cursor.u32() != 3:
        raise R1csError("wrong section count")
    sections: dict[int, bytes] = {}
    order = []
    for _ in range(3):
        kind = cursor.u32()
        size = cursor.u64()
        if kind in sections:
            raise R1csError("duplicate section")
        order.append(kind)
        sections[kind] = cursor.take(size)
    cursor.finish()
    if order != [1, 2, 3]:
        raise R1csError("noncanonical section order")
    return sections


def parse_header(body: bytes) -> dict[str, int]:
    cursor = Cursor(body, "header section")
    if cursor.u32() != FIELD_BYTES:
        raise R1csError("wrong field width")
    modulus = int.from_bytes(cursor.take(FIELD_BYTES), "little")
    if modulus != PRIME:
        raise R1csError("wrong BN254 scalar modulus")
    header = {
        "wires": cursor.u32(),
        "public_outputs": cursor.u32(),
        "public_inputs": cursor.u32(),
        "private_inputs": cursor.u32(),
        "labels": cursor.u64(),
        "constraints": cursor.u32(),
    }
    cursor.finish()
    if header != EXPECTED_HEADER:
        raise R1csError(f"header/count substitution: {header}")
    return header


def parse_constraints(body: bytes, header: dict[str, int]):
    cursor = Cursor(body, "constraint section")
    rows = []
    for row_index in range(header["constraints"]):
        axes = []
        for axis in "ABC":
            count = cursor.u32()
            if count > header["wires"]:
                raise R1csError(f"impossible term count at row {row_index} {axis}")
            terms = []
            previous_wire = -1
            for _ in range(count):
                wire = cursor.u32()
                coefficient = int.from_bytes(cursor.take(FIELD_BYTES), "little")
                if wire >= header["wires"]:
                    raise R1csError(f"wire out of range at row {row_index} {axis}")
                if wire <= previous_wire:
                    raise R1csError(f"duplicate or reordered term at row {row_index} {axis}")
                if coefficient == 0:
                    raise R1csError(f"explicit zero coefficient at row {row_index} {axis}")
                if coefficient >= PRIME:
                    raise R1csError(f"noncanonical coefficient at row {row_index} {axis}")
                previous_wire = wire
                terms.append((wire, coefficient))
            axes.append(tuple(terms))
        rows.append(tuple(axes))
    cursor.finish()
    return tuple(rows)


def parse_wire_map(body: bytes, wires: int) -> tuple[int, ...]:
    cursor = Cursor(body, "wire map section")
    result = tuple(cursor.u64() for _ in range(wires))
    cursor.finish()
    if result != tuple(range(wires)):
        raise R1csError("wire/label substitution")
    return result


def evaluate(terms: tuple[tuple[int, int], ...]) -> int:
    return sum(coefficient * ASSIGNMENT[wire]
               for wire, coefficient in terms) % PRIME


def verify(path: Path) -> dict:
    if path.is_symlink():
        raise R1csError("symlinked fixture refused")
    body = path.read_bytes()
    sections = parse_sections(body)
    header = parse_header(sections[1])
    constraints = parse_constraints(sections[2], header)
    parse_wire_map(sections[3], header["wires"])
    if constraints != EXPECTED_CONSTRAINTS:
        for index, (actual, expected) in enumerate(
                zip(constraints, EXPECTED_CONSTRAINTS, strict=True)):
            if actual != expected:
                raise R1csError(f"matrix mismatch at row {index}")
        raise R1csError("matrix mismatch")
    for index, (a, b, c) in enumerate(constraints):
        if (evaluate(a) * evaluate(b) - evaluate(c)) % PRIME:
            raise R1csError(f"unsatisfied row {index}")
    identity = hashlib.sha256(body).hexdigest()
    if identity != EXPECTED_SHA256:
        raise R1csError("exact fixture identity mismatch")
    return {
        "schema": "kpb-r1cs-bridge-roundtrip/v1",
        "sha256": identity,
        "field_modulus": str(PRIME),
        "field_bytes": FIELD_BYTES,
        "section_order": [1, 2, 3],
        "wire_order": ["ONE", "INSTANCE[0]", "INSTANCE[1]",
                       "WITNESS[0]", "WITNESS[1]", "WITNESS[2]"],
        "row_order": [0, 1, 2],
        **header,
        "all_rows_satisfied": True,
        "setup_executed": False,
    }


def main() -> None:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} FILE.r1cs", file=sys.stderr)
        raise SystemExit(2)
    try:
        result = verify(Path(sys.argv[1]))
    except (OSError, R1csError) as error:
        print(f"R1CS_BRIDGE_REJECT: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
