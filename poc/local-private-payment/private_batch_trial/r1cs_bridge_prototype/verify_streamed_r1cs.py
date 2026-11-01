#!/usr/bin/env python3
"""Independent streaming verifier for the synthetic gzip-to-R1CS export."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import zlib


HERE = Path(__file__).resolve().parent
PLAN_PATH = HERE / "tiny_stream_plan.json"
PLAN_SHA256 = "bce9352152cb1d92c0a4232da1973c569216bcb38d0a37fb8019adf6fe0fd424"
SOURCE_SHA256 = "9e6fb041bc7d4aa3a1a675e05b8ab45e6565667ac5f9cf59869f335e4911ec4b"
MATRIX_FINGERPRINT = "898baeab8bcddddc17845cf8b4956db569b253f0d551e7b9ddce0a53661812db"
OUTPUT_SHA256 = "786364162a371e862488ed92dbb12e36670024c9fbb8c3acc1391f4c2bce33ab"
PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617
PRIME_BYTES = PRIME.to_bytes(32, "little")
MAGIC = b"KPI_R1CS_AXIS_V1"
INSTANCES = 3
WITNESSES = 3
VARIABLES = 6
CONSTRAINTS = 3
CONSTRAINT_SECTION_BYTES = 576
WIRE_MAP_BYTES = 48
OUTPUT_BYTES = 736
VERIFY_RECEIPT_NAME = "VERIFY-RECEIPT.json"
AXES = (
    {
        "file": "A.r1cs.bin.gz",
        "compressed_bytes": 117,
        "compressed_sha256": "9d26dbff4cb5775beeb53fbafcb1c74adc8d978a05ea268e9f0dc2ac4dba3c12",
        "raw_bytes": 344,
        "raw_sha256": "c41c813f980e515c0dcde491aeba85d846c2e8a36860771f5fd93533d4a5fc36",
        "terms": 6,
    },
    {
        "file": "B.r1cs.bin.gz",
        "compressed_bytes": 105,
        "compressed_sha256": "7d8d8106d9a161fb15961dd996bb23af26a0d4fb22ab4326b326d7cb27db5d78",
        "raw_bytes": 264,
        "raw_sha256": "5c15bbb6eecaa9ed8fc5fc8ff917cdbe491471141e4139852c768c59aab0a3ba",
        "terms": 4,
    },
    {
        "file": "C.r1cs.bin.gz",
        "compressed_bytes": 114,
        "compressed_sha256": "f84cda321e84e645498491dd20ec315866d6e42a47116e2ddc6fd21871b94360",
        "raw_bytes": 304,
        "raw_sha256": "02d51205dc70056d8d4bad364b75167b020e41339204cba92b482b9c55f4b344",
        "terms": 5,
    },
)


class Reject(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def require(value: bool, code: str, detail: str = "") -> None:
    if not value:
        raise Reject(code, detail)


def digest_bytes(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def digest_path(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(65536):
            result.update(chunk)
    return result.hexdigest()


def stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


class PinnedInput:
    def __init__(self, path: Path, axis: int):
        self.path = path
        self.axis = axis
        self.pin = AXES[axis]
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            self.fd = os.open(path, flags)
        except OSError as error:
            raise Reject("input-open", f"axis={axis} {error}") from error
        before = os.fstat(self.fd)
        require(stat.S_ISREG(before.st_mode), "input-not-regular", f"axis={axis}")
        require(before.st_size == self.pin["compressed_bytes"],
                "compressed-size-pin", f"axis={axis} actual={before.st_size}")
        compressed = hashlib.sha256()
        total = 0
        while chunk := os.read(self.fd, 65536):
            total += len(chunk)
            compressed.update(chunk)
        require(total == self.pin["compressed_bytes"] and
                compressed.hexdigest() == self.pin["compressed_sha256"],
                "compressed-identity-pin", f"axis={axis}")
        after = os.fstat(self.fd)
        require(stat_identity(before) == stat_identity(after),
                "input-changed-during-pin", f"axis={axis}")
        self.identity = stat_identity(before)
        os.lseek(self.fd, 0, os.SEEK_SET)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class SingleMember:
    """Bounded one-member gzip decoder preserving trailing compressed bytes."""

    def __init__(self, pinned: PinnedInput):
        self.pinned = pinned
        self.inflate = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self.pending = b""
        self.output = bytearray()
        self.ended = False
        self.raw_hash = hashlib.sha256()
        self.raw_bytes = 0

    def _pump(self, maximum: int = 65536) -> None:
        while not self.output and not self.ended:
            source = self.pending
            self.pending = b""
            if not source:
                source = os.read(self.pinned.fd, 65536)
                if not source:
                    require(self.inflate.eof, "gzip-truncated",
                            f"axis={self.pinned.axis}")
                    self.ended = True
                    break
            try:
                decoded = self.inflate.decompress(source, maximum)
            except zlib.error as error:
                raise Reject("gzip-crc-or-stream",
                             f"axis={self.pinned.axis} {error}") from error
            if self.inflate.unconsumed_tail:
                self.pending = self.inflate.unconsumed_tail
            self.output.extend(decoded)
            if self.inflate.eof:
                trailing = self.inflate.unused_data + self.pending
                self.pending = b""
                if not trailing:
                    trailing = os.read(self.pinned.fd, 1)
                require(not trailing, "gzip-trailing-or-second-member",
                        f"axis={self.pinned.axis} prefix={trailing[:16].hex()}")
                self.ended = True

    def read_exact(self, size: int) -> bytes:
        while len(self.output) < size:
            self._pump(max(65536, size - len(self.output)))
            if self.ended and len(self.output) < size:
                raise Reject("raw-truncated", f"axis={self.pinned.axis}")
        result = bytes(self.output[:size])
        del self.output[:size]
        self.raw_hash.update(result)
        self.raw_bytes += size
        return result

    def finish(self) -> None:
        while not self.ended:
            self._pump(1)
            if self.output:
                raise Reject("raw-trailing", f"axis={self.pinned.axis}")
        require(not self.output, "raw-trailing", f"axis={self.pinned.axis}")
        pin = self.pinned.pin
        require(self.raw_bytes == pin["raw_bytes"] and
                self.raw_hash.hexdigest() == pin["raw_sha256"],
                "raw-identity-pin", f"axis={self.pinned.axis}")
        require(stat_identity(os.fstat(self.pinned.fd)) == self.pinned.identity,
                "input-changed-during-scan", f"axis={self.pinned.axis}")
        self.pinned.close()


class AxisCursor:
    def __init__(self, pinned: PinnedInput):
        self.axis = pinned.axis
        self.pin = pinned.pin
        self.raw = SingleMember(pinned)
        require(self.raw.read_exact(16) == MAGIC, "axis-magic", f"axis={self.axis}")
        require(self.u64() == self.axis, "axis-number", f"axis={self.axis}")
        require(self.raw.read_exact(32) == PRIME_BYTES,
                "field-modulus", f"axis={self.axis}")
        require((self.u64(), self.u64(), self.u64()) ==
                (INSTANCES, WITNESSES, CONSTRAINTS),
                "axis-shape", f"axis={self.axis}")
        self.rows = 0
        self.terms = 0
        self.remaining = 0
        self.previous: int | None = None

    def u64(self) -> int:
        return struct.unpack("<Q", self.raw.read_exact(8))[0]

    def start_row(self, row: int) -> tuple[int, bytes]:
        require(row == self.rows and self.remaining == 0,
                "row-state", f"axis={self.axis} row={row}")
        encoded = self.raw.read_exact(8)
        count = struct.unpack("<Q", encoded)[0]
        require(count <= 0xFFFFFFFF, "row-term-count-u32",
                f"axis={self.axis} row={row} count={count}")
        self.rows += 1
        self.terms += count
        self.remaining = count
        self.previous = None
        return count, encoded

    def next_term(self, row: int, term: int) -> tuple[int, bytes, bytes]:
        require(self.remaining > 0, "term-state",
                f"axis={self.axis} row={row} term={term}")
        encoded = self.raw.read_exact(40)
        coefficient = encoded[:32]
        column = struct.unpack("<Q", encoded[32:])[0]
        require(any(coefficient), "zero-coefficient",
                f"axis={self.axis} row={row} term={term} column={column}")
        require(int.from_bytes(coefficient, "little") < PRIME,
                "noncanonical-coefficient",
                f"axis={self.axis} row={row} term={term} column={column}")
        require(column < VARIABLES and column <= 0xFFFFFFFF,
                "column-out-of-range",
                f"axis={self.axis} row={row} term={term} column={column}")
        require(self.previous is None or column > self.previous,
                "duplicate-or-reordered-column",
                f"axis={self.axis} row={row} term={term} "
                f"previous={self.previous} column={column}")
        self.previous = column
        self.remaining -= 1
        return column, coefficient, encoded

    def finish(self) -> None:
        require(self.rows == CONSTRAINTS and self.remaining == 0 and
                self.terms == self.pin["terms"],
                "axis-row-or-term-total", f"axis={self.axis}")
        self.raw.finish()


def open_all_pinned(paths: tuple[Path, Path, Path]) -> list[PinnedInput]:
    result = []
    try:
        for axis, path in enumerate(paths):
            result.append(PinnedInput(path, axis))
        return result
    except Exception:
        for value in result:
            value.close()
        raise


def preflight_axes(paths: tuple[Path, Path, Path]) -> None:
    pinned = open_all_pinned(paths)
    fingerprint = hashlib.sha256(
        b"KPINAS/R1CS/v1\0" + struct.pack("<QQQ", INSTANCES, WITNESSES, CONSTRAINTS))
    for source in pinned:
        cursor = AxisCursor(source)
        for row in range(CONSTRAINTS):
            count, encoded_count = cursor.start_row(row)
            fingerprint.update(encoded_count)
            for term in range(count):
                _, _, encoded = cursor.next_term(row, term)
                fingerprint.update(encoded)
        cursor.finish()
    require(fingerprint.hexdigest() == MATRIX_FINGERPRINT,
            "matrix-fingerprint", fingerprint.hexdigest())


class FileCursor:
    def __init__(self, path: Path):
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            self.fd = os.open(path, flags)
        except OSError as error:
            raise Reject("r1cs-open", str(error)) from error
        metadata = os.fstat(self.fd)
        require(stat.S_ISREG(metadata.st_mode), "r1cs-not-regular")
        require(metadata.st_size == OUTPUT_BYTES, "r1cs-size", str(metadata.st_size))
        self.identity = stat_identity(metadata)
        self.offset = 0

    def take(self, size: int) -> bytes:
        chunks = []
        remaining = size
        while remaining:
            chunk = os.read(self.fd, remaining)
            require(bool(chunk), "r1cs-truncated", f"offset={self.offset}")
            chunks.append(chunk)
            remaining -= len(chunk)
        self.offset += size
        return b"".join(chunks)

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def finish(self) -> None:
        require(not os.read(self.fd, 1), "r1cs-trailing")
        require(stat_identity(os.fstat(self.fd)) == self.identity,
                "r1cs-changed-during-verify")
        os.close(self.fd)
        self.fd = -1


def verify_output(paths: tuple[Path, Path, Path], r1cs_path: Path) -> None:
    require(r1cs_path.stat().st_size == OUTPUT_BYTES and
            digest_path(r1cs_path) == OUTPUT_SHA256,
            "r1cs-identity")
    pinned = open_all_pinned(paths)
    axes = [AxisCursor(source) for source in pinned]
    output = FileCursor(r1cs_path)
    require(output.take(4) == b"r1cs" and output.u32() == 1 and output.u32() == 3,
            "r1cs-container")
    require(output.u32() == 1 and output.u64() == 64, "r1cs-header-section")
    require(output.u32() == 32 and output.take(32) == PRIME_BYTES,
            "r1cs-field")
    header = (output.u32(), output.u32(), output.u32(), output.u32(),
              output.u64(), output.u32())
    require(header == (VARIABLES, 0, 2, 3, VARIABLES, CONSTRAINTS),
            "r1cs-header", repr(header))
    require(output.u32() == 2 and output.u64() == CONSTRAINT_SECTION_BYTES,
            "r1cs-constraint-section")
    section_start = output.offset
    for row in range(CONSTRAINTS):
        for axis, source in enumerate(axes):
            expected_count, _ = source.start_row(row)
            actual_count = output.u32()
            require(actual_count == expected_count, "r1cs-term-count",
                    f"row={row} axis={axis}")
            previous = None
            for term in range(actual_count):
                wire = output.u32()
                coefficient = output.take(32)
                expected_wire, expected_coefficient, _ = source.next_term(row, term)
                require(wire == expected_wire and coefficient == expected_coefficient,
                        "r1cs-term-substitution",
                        f"row={row} axis={axis} term={term}")
                require(previous is None or wire > previous,
                        "r1cs-term-order", f"row={row} axis={axis} term={term}")
                previous = wire
    require(output.offset - section_start == CONSTRAINT_SECTION_BYTES,
            "r1cs-constraint-section-size")
    for source in axes:
        source.finish()
    require(output.u32() == 3 and output.u64() == WIRE_MAP_BYTES,
            "r1cs-map-section")
    for wire in range(VARIABLES):
        require(output.u64() == wire, "r1cs-map-substitution", f"wire={wire}")
    output.finish()


def load_json_exact(path: Path, code: str) -> tuple[dict, str]:
    body = path.read_bytes()
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Reject(code, str(error)) from error
    require(isinstance(value, dict), code, "not an object")
    return value, digest_bytes(body)


def verify_export_receipt(receipt_path: Path, exporter_binary: Path) -> tuple[str, str]:
    receipt, receipt_sha256 = load_json_exact(receipt_path, "export-receipt-json")
    binary_sha256 = digest_path(exporter_binary)
    require(receipt.get("schema") == "kpb-tiny-stream-r1cs-export-receipt/v1" and
            receipt.get("status") == "PASS" and
            receipt.get("classification") ==
            "SYNTHETIC_FORMAT_BRIDGE_ONLY_NO_SETUP_OR_CEREMONY",
            "export-receipt-schema")
    require(receipt.get("plan_sha256") == PLAN_SHA256 and
            receipt.get("fixture_source_sha256") == SOURCE_SHA256 and
            receipt.get("exporter_binary_sha256") == binary_sha256 and
            receipt.get("canonical_r1cs_fingerprint") == MATRIX_FINGERPRINT,
            "export-receipt-binding")
    expected_axes = [
        {
            "axis": axis,
            "file_label": pin["file"],
            "compressed_bytes": pin["compressed_bytes"],
            "compressed_sha256": pin["compressed_sha256"],
            "raw_bytes": pin["raw_bytes"],
            "raw_sha256": pin["raw_sha256"],
            "terms": pin["terms"],
            "maximum_row_terms": (3, 2, 2)[axis],
        }
        for axis, pin in enumerate(AXES)
    ]
    require(receipt.get("axes") == expected_axes, "export-receipt-input-pins")
    require(receipt.get("passes") == {
        "complete_admission_before_output": True,
        "second_pass_all_input_pins_and_eof_rechecked": True,
        "coefficients_canonical_nonzero": True,
        "columns_strictly_increasing_unique_and_in_range": True,
    }, "export-receipt-passes")
    output = receipt.get("output", {})
    require(output.get("file") == "tiny.r1cs" and
            output.get("bytes") == OUTPUT_BYTES and
            output.get("sha256") == OUTPUT_SHA256 and
            output.get("section_order") == [1, 2, 3] and
            output.get("constraint_section_bytes") == CONSTRAINT_SECTION_BYTES and
            output.get("identity_wire_map_bytes") == WIRE_MAP_BYTES,
            "export-receipt-output")
    require(receipt.get("independent_verifier_passed") is False and
            receipt.get("aggregate_full_export_authorized") is False and
            receipt.get("r1cs_full_aggregate_exported") is False and
            receipt.get("zkey_generated") is False and
            receipt.get("setup_executed") is False and
            receipt.get("phase1_executed") is False and
            receipt.get("phase2_executed") is False and
            receipt.get("ceremony_executed") is False,
            "export-receipt-authority")
    return receipt_sha256, binary_sha256


def atomic_create_receipt(path: Path, receipt: dict) -> None:
    require(path.name == VERIFY_RECEIPT_NAME, "verify-receipt-name")
    partial = path.with_name(f".{VERIFY_RECEIPT_NAME}.partial")
    encoded = json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n"
    try:
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC |
                 getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(partial, flags, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.link(partial, path)
        partial.unlink()
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError as error:
        raise Reject("verify-receipt-create-new", str(error)) from error


def verify(
    axes: tuple[Path, Path, Path],
    r1cs_path: Path,
    exporter_binary: Path,
    export_receipt: Path,
    verify_receipt: Path,
) -> dict:
    try:
        output_directory = r1cs_path.parent.lstat()
    except OSError as error:
        raise Reject("verification-directory", str(error)) from error
    require(stat.S_ISDIR(output_directory.st_mode),
            "verification-directory-not-real")
    require(verify_receipt.parent == r1cs_path.parent,
            "verify-receipt-directory")
    require(r1cs_path.name == "tiny.r1cs" and
            export_receipt.parent == r1cs_path.parent and
            export_receipt.name == "EXPORT-RECEIPT.json",
            "verified-output-names")
    directory_entries = {entry.name for entry in r1cs_path.parent.iterdir()}
    require(directory_entries == {"tiny.r1cs", "EXPORT-RECEIPT.json"},
            "verification-directory-contents", repr(sorted(directory_entries)))
    plan_body = PLAN_PATH.read_bytes()
    require(digest_bytes(plan_body) == PLAN_SHA256, "plan-identity")
    plan = json.loads(plan_body)
    require(plan["aggregate_full_export_authorized"] is False and
            plan["setup_authorized"] is False and
            plan["zkey_authorized"] is False and
            plan["phase1_authorized"] is False and
            plan["phase2_authorized"] is False and
            plan["ceremony_authorized"] is False,
            "plan-authority")
    export_receipt_sha256, exporter_binary_sha256 = verify_export_receipt(
        export_receipt, exporter_binary)
    preflight_axes(axes)
    verify_output(axes, r1cs_path)
    verifier_source_sha256 = digest_path(Path(__file__).resolve())
    receipt = {
        "schema": "kpb-tiny-stream-r1cs-verification-receipt/v1",
        "status": "PASS",
        "classification": "INDEPENDENT_SYNTHETIC_STREAM_VERIFICATION_NO_SETUP_OR_CEREMONY",
        "plan_sha256": PLAN_SHA256,
        "fixture_source_sha256": SOURCE_SHA256,
        "exporter_binary_sha256": exporter_binary_sha256,
        "export_receipt_sha256": export_receipt_sha256,
        "verifier_source_sha256": verifier_source_sha256,
        "canonical_r1cs_fingerprint": MATRIX_FINGERPRINT,
        "output": {
            "file": r1cs_path.name,
            "bytes": OUTPUT_BYTES,
            "sha256": OUTPUT_SHA256,
            "every_input_row_term_equal": True,
            "exact_section_sizes_and_eof": True,
            "identity_wire_map": True,
        },
        "aggregate_full_export_authorized": False,
        "r1cs_full_aggregate_exported": False,
        "zkey_generated": False,
        "setup_executed": False,
        "phase1_executed": False,
        "phase2_executed": False,
        "ceremony_executed": False,
    }
    atomic_create_receipt(verify_receipt, receipt)
    return receipt


def main() -> None:
    if len(sys.argv) != 8:
        print(
            "usage: verify_streamed_r1cs.py A.gz B.gz C.gz tiny.r1cs "
            "EXPORTER-BINARY EXPORT-RECEIPT.json VERIFY-RECEIPT.json",
            file=sys.stderr,
        )
        raise SystemExit(2)
    try:
        result = verify(
            (Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])),
            Path(sys.argv[4]),
            Path(sys.argv[5]),
            Path(sys.argv[6]),
            Path(sys.argv[7]),
        )
    except (OSError, Reject, KeyError, TypeError, ValueError) as error:
        print(f"STREAM_R1CS_VERIFY_REJECT: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    print(json.dumps({
        "schema": "kpb-tiny-stream-r1cs-verification-status/v1",
        "status": result["status"],
        "setup_executed": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
