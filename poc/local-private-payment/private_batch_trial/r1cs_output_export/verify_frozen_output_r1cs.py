#!/usr/bin/env python3
"""Independent descriptor-only verifier for the frozen output R1CS export."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import struct
import sys
import zlib


HERE = Path(__file__).resolve().parent
PLAN_PATH = HERE / "output_export_plan.json"
CARGO_TOML_PATH = HERE / "Cargo.toml"
CARGO_LOCK_PATH = HERE / "Cargo.lock"
RUST_TOOLCHAIN_PATH = HERE / "rust-toolchain.toml"
OUTPUT_NAME = "output.r1cs"
EXPORT_RECEIPT_NAME = "EXPORT-RECEIPT.json"
VERIFY_RECEIPT_NAME = "VERIFY-RECEIPT.json"
VERIFY_PARTIAL_NAME = ".VERIFY-RECEIPT.json.partial"
AXIS_MAGIC = b"KPI_R1CS_AXIS_V1"
FINGERPRINT_DOMAIN = b"KPINAS/R1CS/v1\0"


class Reject(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def require(value: bool, code: str, detail: str = "") -> None:
    if not value:
        raise Reject(code, detail)


def sha256_bytes(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        stat.S_IMODE(value.st_mode),
        value.st_uid,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def identity_json(value: os.stat_result) -> dict:
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "bytes": value.st_size,
        "mode": f"{stat.S_IMODE(value.st_mode):04o}",
        "owner_uid": value.st_uid,
        "mtime_seconds": value.st_mtime_ns // 1_000_000_000,
        "mtime_nanoseconds": value.st_mtime_ns % 1_000_000_000,
        "ctime_seconds": value.st_ctime_ns // 1_000_000_000,
        "ctime_nanoseconds": value.st_ctime_ns % 1_000_000_000,
    }


def hash_fd(fd: int, code: str) -> tuple[int, str, os.stat_result]:
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode), code, "not a regular file")
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while chunk := os.read(fd, 65536):
        total += len(chunk)
        digest.update(chunk)
    after = os.fstat(fd)
    require(stat_identity(before) == stat_identity(after), code, "identity changed")
    require(total == before.st_size, code, "short read")
    os.lseek(fd, 0, os.SEEK_SET)
    return total, digest.hexdigest(), before


def read_small_fd(fd: int, maximum: int, code: str) -> tuple[bytes, os.stat_result]:
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode), code, "not a regular file")
    require(before.st_size <= maximum, code, f"too large: {before.st_size}")
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    total = 0
    while chunk := os.read(fd, min(65536, maximum + 1 - total)):
        total += len(chunk)
        require(total <= maximum, code, "too large")
        chunks.append(chunk)
    after = os.fstat(fd)
    require(stat_identity(before) == stat_identity(after), code, "identity changed")
    body = b"".join(chunks)
    require(len(body) == before.st_size, code, "short read")
    os.lseek(fd, 0, os.SEEK_SET)
    return body, before


def read_regular_path(path: Path, maximum: int, code: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise Reject(code, str(error)) from error
    try:
        return read_small_fd(fd, maximum, code)[0]
    finally:
        os.close(fd)


@dataclass(frozen=True)
class AxisPin:
    axis: int
    label: str
    compressed_bytes: int
    compressed_sha256: str
    raw_bytes: int
    raw_sha256: str
    terms: int
    maximum_row_terms: int


@dataclass(frozen=True)
class Contract:
    plan_sha256: str
    exporter_source_sha256: str
    cargo_toml_sha256: str
    cargo_lock_sha256: str
    rust_toolchain_sha256: str
    verifier_source_sha256: str
    verifier_python_path: str
    verifier_python_sha256: str
    verifier_python_version: tuple
    verifier_zlib_version: str
    scanner_receipt_sha256: str
    generator_source_sha256: str
    generator_binary_sha256: str
    selected_axes_manifest_sha256: str
    selected_historical_source_sha256: str
    current_source_closure_manifest_sha256: str
    current_source_closure_identity: str
    current_build_dep_info_sha256: str
    current_build_dep_info_local_source_identity: str
    scanner_source_sha256: str
    field: bytes
    instances: int
    witnesses: int
    variables: int
    constraints: int
    public_outputs: int
    public_inputs: int
    private_inputs: int
    labels: int
    axes: tuple[AxisPin, AxisPin, AxisPin]
    matrix_fingerprint: str
    constraint_section_bytes: int
    wire_map_bytes: int
    output_bytes: int


def parse_contract(plan_body: bytes) -> Contract:
    try:
        plan = json.loads(plan_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Reject("plan-json", str(error)) from error
    require(plan.get("schema") == "kpb-frozen-output-r1cs-export-plan/v1" and
            plan.get("classification") ==
            "PRODUCTION_SIZED_R1CS_CONVERSION_ONLY_NO_SETUP_OR_CEREMONY" and
            plan.get("materials_pending") is False,
            "plan-schema")
    for field in ("setup_authorized", "zkey_authorized", "phase1_authorized",
                  "phase2_authorized", "ceremony_authorized"):
        require(plan.get(field) is False, "plan-authority", field)
    materials = plan["materials"]
    geometry = plan["geometry"]
    layout = plan["standard_r1cs_v1"]
    verifier = plan["verifier_runtime"]
    axes = tuple(
        AxisPin(
            axis=index,
            label=value["file_label"],
            compressed_bytes=value["compressed_bytes"],
            compressed_sha256=value["compressed_sha256"],
            raw_bytes=value["raw_bytes"],
            raw_sha256=value["raw_sha256"],
            terms=value["terms"],
            maximum_row_terms=value["maximum_row_terms"],
        )
        for index, value in enumerate(plan["axes"])
    )
    require(len(axes) == 3 and all(pin.axis == plan["axes"][pin.axis]["axis"]
                                  for pin in axes), "plan-axes")
    contract = Contract(
        plan_sha256=sha256_bytes(plan_body),
        exporter_source_sha256=materials["exporter_source_sha256"],
        cargo_toml_sha256=materials["cargo_toml_sha256"],
        cargo_lock_sha256=materials["cargo_lock_sha256"],
        rust_toolchain_sha256=materials["rust_toolchain_sha256"],
        verifier_source_sha256=materials["verifier_source_sha256"],
        verifier_python_path=verifier["resolved_executable"],
        verifier_python_sha256=materials["verifier_python_sha256"],
        verifier_python_version=tuple(verifier["version_info"]),
        verifier_zlib_version=verifier["zlib_runtime_version"],
        scanner_receipt_sha256=plan["admission_receipt_sha256"],
        generator_source_sha256=plan["generator_source_sha256"],
        generator_binary_sha256=plan["generator_binary_sha256"],
        selected_axes_manifest_sha256=plan["selected_axes_manifest_sha256"],
        selected_historical_source_sha256=plan["selected_historical_source_sha256"],
        current_source_closure_manifest_sha256=
        plan["current_source_closure_manifest_sha256"],
        current_source_closure_identity=plan["current_source_closure_identity"],
        current_build_dep_info_sha256=plan["current_build_dep_info_sha256"],
        current_build_dep_info_local_source_identity=
        plan["current_build_dep_info_local_source_identity"],
        scanner_source_sha256=plan["scanner_source_sha256"],
        field=bytes.fromhex(plan["field_le_hex"]),
        instances=geometry["instances_including_one"],
        witnesses=geometry["witnesses"],
        variables=geometry["variables"],
        constraints=geometry["constraints"],
        public_outputs=geometry["public_outputs"],
        public_inputs=geometry["public_inputs"],
        private_inputs=geometry["private_inputs"],
        labels=geometry["labels"],
        axes=axes,
        matrix_fingerprint=plan["canonical_r1cs_fingerprint"],
        constraint_section_bytes=layout["constraint_section_bytes"],
        wire_map_bytes=layout["identity_wire_map_bytes"],
        output_bytes=layout["complete_file_bytes"],
    )
    validate_contract(contract)
    return contract


def validate_contract(contract: Contract) -> None:
    require(len(contract.field) == 32, "contract-field")
    require(contract.instances == contract.public_inputs + 1 and
            contract.variables == contract.witnesses + contract.instances and
            contract.private_inputs == contract.witnesses and
            contract.labels == contract.variables,
            "contract-geometry")
    require(all(0 <= value <= 0xFFFFFFFF for value in
                (contract.variables, contract.constraints, contract.public_outputs,
                 contract.public_inputs, contract.private_inputs)),
            "contract-u32")
    total_terms = sum(pin.terms for pin in contract.axes)
    constraint_bytes = contract.constraints * 3 * 4 + total_terms * 36
    map_bytes = contract.variables * 8
    require(constraint_bytes == contract.constraint_section_bytes and
            map_bytes == contract.wire_map_bytes and
            112 + constraint_bytes + map_bytes == contract.output_bytes,
            "contract-layout")
    for pin in contract.axes:
        require(80 + contract.constraints * 8 + pin.terms * 40 == pin.raw_bytes,
                "contract-raw-layout", f"axis={pin.axis}")


def load_production_contract() -> Contract:
    plan_body = read_regular_path(PLAN_PATH, 128 * 1024, "plan-read")
    return parse_contract(plan_body)


def validate_materials(contract: Contract) -> None:
    materials = (
        (Path(__file__).resolve(), contract.verifier_source_sha256, "verifier-source"),
        (CARGO_TOML_PATH, contract.cargo_toml_sha256, "cargo-toml"),
        (CARGO_LOCK_PATH, contract.cargo_lock_sha256, "cargo-lock"),
        (RUST_TOOLCHAIN_PATH, contract.rust_toolchain_sha256, "rust-toolchain"),
    )
    for path, expected, label in materials:
        body = read_regular_path(path, 2 * 1024 * 1024, label)
        require(sha256_bytes(body) == expected, "material-identity", label)
    resolved = Path(sys.executable).resolve()
    require(str(resolved) == contract.verifier_python_path,
            "verifier-interpreter-path", str(resolved))
    binary = read_regular_path(resolved, 64 * 1024 * 1024, "verifier-interpreter")
    require(sha256_bytes(binary) == contract.verifier_python_sha256,
            "verifier-interpreter-identity")
    actual_version = (sys.version_info.major, sys.version_info.minor,
                      sys.version_info.micro, sys.version_info.releaselevel,
                      sys.version_info.serial)
    require(actual_version == contract.verifier_python_version and
            platform.python_implementation() == "CPython" and
            zlib.ZLIB_RUNTIME_VERSION == contract.verifier_zlib_version,
            "verifier-toolchain-identity", repr(actual_version))


class PinnedFd:
    def __init__(self, raw_fd: int, code: str):
        require(raw_fd > 2, "descriptor-argument", f"{code}={raw_fd}")
        try:
            self.fd = os.dup(raw_fd)
            os.set_inheritable(self.fd, False)
        except OSError as error:
            raise Reject(code, str(error)) from error
        self.code = code
        self.identity = os.fstat(self.fd)
        require(stat.S_ISREG(self.identity.st_mode), code, "not regular")

    def hash(self) -> tuple[int, str]:
        size, digest, identity = hash_fd(self.fd, self.code)
        require(stat_identity(identity) == stat_identity(self.identity),
                self.code, "identity changed")
        return size, digest

    def clone(self) -> "PinnedFd":
        return PinnedFd(self.fd, self.code)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class SingleMember:
    def __init__(self, source: PinnedFd, pin: AxisPin):
        self.source = source
        self.pin = pin
        size, digest = source.hash()
        require(size == pin.compressed_bytes and digest == pin.compressed_sha256,
                "compressed-identity-pin", f"axis={pin.axis}")
        self.inflate = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self.pending = b""
        self.output = bytearray()
        self.output_at = 0
        self.ended = False
        self.raw_hash = hashlib.sha256()
        self.raw_bytes = 0

    def _available(self) -> int:
        return len(self.output) - self.output_at

    def _compact(self) -> None:
        if self.output_at == 0:
            return
        if self.output_at == len(self.output):
            self.output.clear()
        else:
            del self.output[:self.output_at]
        self.output_at = 0

    def _pump(self, minimum: int = 1, maximum: int = 65536) -> None:
        while self._available() < minimum and not self.ended:
            self._compact()
            source = self.pending
            self.pending = b""
            if not source:
                source = os.read(self.source.fd, 65536)
                if not source:
                    require(self.inflate.eof, "gzip-truncated",
                            f"axis={self.pin.axis}")
                    self.ended = True
                    break
            try:
                decoded = self.inflate.decompress(source, maximum)
            except zlib.error as error:
                raise Reject("gzip-crc-or-stream",
                             f"axis={self.pin.axis} {error}") from error
            if self.inflate.unconsumed_tail:
                self.pending = self.inflate.unconsumed_tail
            self.output.extend(decoded)
            if self.inflate.eof:
                trailing = self.inflate.unused_data + self.pending
                self.pending = b""
                if not trailing:
                    trailing = os.read(self.source.fd, 1)
                require(not trailing, "gzip-trailing-or-second-member",
                        f"axis={self.pin.axis} prefix={trailing[:16].hex()}")
                self.ended = True

    def read_exact(self, size: int) -> bytes:
        require(size >= 0, "raw-read-size", f"axis={self.pin.axis}")
        while self._available() < size:
            self._pump(size, max(65536, size - self._available()))
            require(not self.ended or self._available() >= size,
                    "raw-truncated", f"axis={self.pin.axis}")
        end = self.output_at + size
        result = bytes(self.output[self.output_at:end])
        self.output_at = end
        self.raw_hash.update(result)
        self.raw_bytes += size
        return result

    def finish(self) -> None:
        while not self.ended:
            self._pump(1, 1)
            require(self._available() == 0, "raw-trailing",
                    f"axis={self.pin.axis}")
        require(self._available() == 0, "raw-trailing",
                f"axis={self.pin.axis}")
        require(self.raw_bytes == self.pin.raw_bytes and
                self.raw_hash.hexdigest() == self.pin.raw_sha256,
                "raw-identity-pin", f"axis={self.pin.axis}")
        require(stat_identity(os.fstat(self.source.fd)) ==
                stat_identity(self.source.identity),
                "axis-changed-during-scan", f"axis={self.pin.axis}")
        self.source.close()


class AxisCursor:
    def __init__(self, source: PinnedFd, contract: Contract, pin: AxisPin):
        self.contract = contract
        self.pin = pin
        self.raw = SingleMember(source, pin)
        require(self.raw.read_exact(16) == AXIS_MAGIC,
                "axis-magic", f"axis={pin.axis}")
        require(self.u64() == pin.axis, "axis-number", f"axis={pin.axis}")
        require(self.raw.read_exact(32) == contract.field,
                "axis-field", f"axis={pin.axis}")
        require((self.u64(), self.u64(), self.u64()) ==
                (contract.instances, contract.witnesses, contract.constraints),
                "axis-geometry", f"axis={pin.axis}")
        self.rows = 0
        self.terms = 0
        self.maximum = 0
        self.remaining = 0
        self.previous = None

    def u64(self) -> int:
        return struct.unpack("<Q", self.raw.read_exact(8))[0]

    def start_row(self, row: int) -> tuple[int, bytes]:
        require(row == self.rows and self.remaining == 0,
                "row-state", f"axis={self.pin.axis} row={row}")
        encoded = self.raw.read_exact(8)
        count = struct.unpack("<Q", encoded)[0]
        require(count <= 0xFFFFFFFF, "row-count-u32",
                f"axis={self.pin.axis} row={row}")
        require(self.raw.raw_bytes <= self.pin.raw_bytes and
                count <= (self.pin.raw_bytes - self.raw.raw_bytes) // 40,
                "row-exceeds-raw-frame", f"axis={self.pin.axis} row={row}")
        self.rows += 1
        self.terms += count
        self.maximum = max(self.maximum, count)
        self.remaining = count
        self.previous = None
        return count, encoded

    def next_term(self, row: int, term: int) -> tuple[int, bytes, bytes]:
        require(self.remaining > 0, "term-state",
                f"axis={self.pin.axis} row={row} term={term}")
        encoded = self.raw.read_exact(40)
        coefficient = encoded[:32]
        column = struct.unpack("<Q", encoded[32:])[0]
        require(any(coefficient), "zero-coefficient")
        require(int.from_bytes(coefficient, "little") <
                int.from_bytes(self.contract.field, "little"),
                "noncanonical-coefficient")
        require(column < self.contract.variables and column <= 0xFFFFFFFF,
                "column-out-of-range")
        require(self.previous is None or column > self.previous,
                "duplicate-or-reordered-column")
        self.previous = column
        self.remaining -= 1
        return column, coefficient, encoded

    def finish(self) -> None:
        require(self.rows == self.contract.constraints and self.remaining == 0 and
                self.terms == self.pin.terms and
                self.maximum == self.pin.maximum_row_terms,
                "axis-totals", f"axis={self.pin.axis}")
        self.raw.finish()


def preflight_axes(contract: Contract, axes: tuple[PinnedFd, PinnedFd, PinnedFd]) -> None:
    fingerprint = hashlib.sha256(
        FINGERPRINT_DOMAIN + struct.pack(
            "<QQQ", contract.instances, contract.witnesses, contract.constraints))
    for axis, source in enumerate(axes):
        cursor = AxisCursor(source, contract, contract.axes[axis])
        for row in range(contract.constraints):
            count, encoded = cursor.start_row(row)
            fingerprint.update(encoded)
            for term in range(count):
                _, _, encoded_term = cursor.next_term(row, term)
                fingerprint.update(encoded_term)
        cursor.finish()
    require(fingerprint.hexdigest() == contract.matrix_fingerprint,
            "matrix-fingerprint", fingerprint.hexdigest())


class OutputCursor:
    def __init__(self, source: PinnedFd, expected_bytes: int):
        require(source.identity.st_size == expected_bytes,
                "r1cs-size", str(source.identity.st_size))
        os.lseek(source.fd, 0, os.SEEK_SET)
        self.source = source
        self.offset = 0
        self.digest = hashlib.sha256()

    def take(self, size: int) -> bytes:
        chunks = []
        remaining = size
        while remaining:
            chunk = os.read(self.source.fd, remaining)
            require(bool(chunk), "r1cs-truncated", f"offset={self.offset}")
            chunks.append(chunk)
            remaining -= len(chunk)
        result = b"".join(chunks)
        self.offset += size
        self.digest.update(result)
        return result

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def finish(self, expected_sha256: str) -> None:
        require(not os.read(self.source.fd, 1), "r1cs-trailing")
        require(self.digest.hexdigest() == expected_sha256,
                "r1cs-identity", self.digest.hexdigest())
        require(stat_identity(os.fstat(self.source.fd)) ==
                stat_identity(self.source.identity),
                "r1cs-changed-during-verify")
        self.source.close()


def verify_output(contract: Contract,
                  axes: tuple[PinnedFd, PinnedFd, PinnedFd],
                  r1cs: PinnedFd,
                  expected_sha256: str) -> None:
    sources = [AxisCursor(source, contract, contract.axes[axis])
               for axis, source in enumerate(axes)]
    output = OutputCursor(r1cs, contract.output_bytes)
    require(output.take(4) == b"r1cs" and output.u32() == 1 and output.u32() == 3,
            "r1cs-container")
    require(output.u32() == 1 and output.u64() == 64 and
            output.u32() == 32 and output.take(32) == contract.field,
            "r1cs-header-section")
    header = (output.u32(), output.u32(), output.u32(), output.u32(),
              output.u64(), output.u32())
    require(header == (contract.variables, contract.public_outputs,
                       contract.public_inputs, contract.private_inputs,
                       contract.labels, contract.constraints),
            "r1cs-header", repr(header))
    require(output.u32() == 2 and
            output.u64() == contract.constraint_section_bytes,
            "r1cs-constraint-section")
    section_start = output.offset
    for row in range(contract.constraints):
        for axis, source in enumerate(sources):
            expected_count, _ = source.start_row(row)
            actual_count = output.u32()
            require(actual_count == expected_count,
                    "r1cs-term-count", f"row={row} axis={axis}")
            for term in range(actual_count):
                actual_wire = output.u32()
                actual_coefficient = output.take(32)
                wire, coefficient, _ = source.next_term(row, term)
                require((actual_wire, actual_coefficient) == (wire, coefficient),
                        "r1cs-term-substitution",
                        f"row={row} axis={axis} term={term}")
    require(output.offset - section_start == contract.constraint_section_bytes,
            "r1cs-constraint-section-size")
    for source in sources:
        source.finish()
    require(output.u32() == 3 and output.u64() == contract.wire_map_bytes,
            "r1cs-map-section")
    for wire in range(contract.variables):
        require(output.u64() == wire, "r1cs-map-substitution", f"wire={wire}")
    output.finish(expected_sha256)


def validate_admission_receipt(contract: Contract, source: PinnedFd) -> str:
    body, _ = read_small_fd(source.fd, 64 * 1024, "admission-receipt")
    digest = sha256_bytes(body)
    require(digest == contract.scanner_receipt_sha256,
            "admission-receipt-identity", digest)
    receipt = json.loads(body)
    predicates = receipt.get("admission_predicates", {})
    require(receipt.get("schema") == "kpb-output-r1cs-axes-admission/v1" and
            receipt.get("status") == "PASS" and
            receipt.get("classification") ==
            "READ_ONLY_OUTPUT_FORMAT_ADMISSION_NO_R1CS_EXPORT_SETUP_ZKEY_OR_CEREMONY" and
            receipt.get("selected_relation_fingerprint") ==
            contract.matrix_fingerprint and
            receipt.get("current_relation_fingerprint") ==
            contract.matrix_fingerprint and
            receipt.get("selected_axes_manifest_sha256") ==
            contract.selected_axes_manifest_sha256 and
            receipt.get("selected_historical_source_sha256") ==
            contract.selected_historical_source_sha256 and
            receipt.get("generator_source_sha256") ==
            contract.generator_source_sha256 and
            receipt.get("generator_binary_sha256") ==
            contract.generator_binary_sha256 and
            receipt.get("current_source_closure_manifest_sha256") ==
            contract.current_source_closure_manifest_sha256 and
            receipt.get("current_source_closure_identity") ==
            contract.current_source_closure_identity and
            receipt.get("current_build_dep_info_sha256") ==
            contract.current_build_dep_info_sha256 and
            receipt.get("current_build_dep_info_local_source_identity") ==
            contract.current_build_dep_info_local_source_identity and
            receipt.get("scanner_source_sha256") ==
            contract.scanner_source_sha256 and
            predicates.get("single_gzip_member_crc_and_exact_eof") is True and
            predicates.get("all_rows_and_terms_consumed") is True and
            predicates.get("coefficients_canonical_and_nonzero") is True and
            predicates.get("columns_strictly_increasing_unique_and_in_range") is True and
            predicates.get("matrix_fingerprint_exact") is True and
            predicates.get("source_and_generator_closure_exact") is True and
            receipt.get("r1cs_exported") is False and
            receipt.get("zkey_generated") is False and
            receipt.get("setup_executed") is False and
            receipt.get("phase1_executed") is False and
            receipt.get("phase2_executed") is False and
            receipt.get("ceremony_executed") is False,
            "admission-receipt-fields")
    return digest


def validate_export_receipt(contract: Contract, source: PinnedFd,
                            exporter_binary_sha256: str,
                            exporter_binary_identity: os.stat_result) -> tuple[dict, str]:
    body, _ = read_small_fd(source.fd, 256 * 1024, "export-receipt")
    digest = sha256_bytes(body)
    receipt = json.loads(body)
    require(receipt.get("schema") == "kpb-frozen-output-r1cs-export-receipt/v1" and
            receipt.get("status") == "PASS" and
            receipt.get("classification") ==
            "PRODUCTION_SIZED_R1CS_CONVERSION_ONLY_NO_SETUP_OR_CEREMONY",
            "export-receipt-schema")
    require(receipt.get("plan_sha256") == contract.plan_sha256 and
            receipt.get("exporter_source_sha256") == contract.exporter_source_sha256 and
            receipt.get("exporter_binary_sha256") == exporter_binary_sha256 and
            receipt.get("exporter_binary_descriptor_identity") ==
            identity_json(exporter_binary_identity) and
            receipt.get("cargo_toml_sha256") == contract.cargo_toml_sha256 and
            receipt.get("cargo_lock_sha256") == contract.cargo_lock_sha256 and
            receipt.get("rust_toolchain_sha256") == contract.rust_toolchain_sha256 and
            receipt.get("expected_verifier_source_sha256") ==
            contract.verifier_source_sha256 and
            receipt.get("expected_verifier_python_sha256") ==
            contract.verifier_python_sha256 and
            receipt.get("admission_receipt_sha256") ==
            contract.scanner_receipt_sha256 and
            receipt.get("generator_source_sha256") ==
            contract.generator_source_sha256 and
            receipt.get("generator_binary_sha256") ==
            contract.generator_binary_sha256 and
            receipt.get("selected_axes_manifest_sha256") ==
            contract.selected_axes_manifest_sha256 and
            receipt.get("selected_historical_source_sha256") ==
            contract.selected_historical_source_sha256 and
            receipt.get("current_source_closure_manifest_sha256") ==
            contract.current_source_closure_manifest_sha256 and
            receipt.get("current_source_closure_identity") ==
            contract.current_source_closure_identity and
            receipt.get("current_build_dep_info_sha256") ==
            contract.current_build_dep_info_sha256 and
            receipt.get("current_build_dep_info_local_source_identity") ==
            contract.current_build_dep_info_local_source_identity and
            receipt.get("scanner_source_sha256") ==
            contract.scanner_source_sha256 and
            receipt.get("canonical_r1cs_fingerprint") ==
            contract.matrix_fingerprint,
            "export-receipt-binding")
    output = receipt.get("output", {})
    require(output.get("file") == OUTPUT_NAME and
            output.get("bytes") == contract.output_bytes and
            isinstance(output.get("sha256"), str) and
            len(output["sha256"]) == 64 and
            output.get("section_order") == [1, 2, 3] and
            output.get("constraint_section_bytes") ==
            contract.constraint_section_bytes and
            output.get("identity_wire_map_bytes") == contract.wire_map_bytes and
            output.get("mode") == "0600",
            "export-receipt-output")
    require(receipt.get("independent_verifier_passed") is False and
            receipt.get("r1cs_full_output_exported") is True and
            receipt.get("zkey_generated") is False and
            receipt.get("setup_executed") is False and
            receipt.get("phase1_executed") is False and
            receipt.get("phase2_executed") is False and
            receipt.get("ceremony_executed") is False,
            "export-receipt-authority")
    return receipt, digest


def require_directory(directory_fd: int) -> os.stat_result:
    value = os.fstat(directory_fd)
    require(stat.S_ISDIR(value.st_mode), "output-directory-type")
    require(stat.S_IMODE(value.st_mode) & 0o077 == 0,
            "output-directory-not-private", f"{stat.S_IMODE(value.st_mode):04o}")
    require(value.st_uid == os.geteuid(), "output-directory-owner")
    require(set(os.listdir(directory_fd)) == {OUTPUT_NAME, EXPORT_RECEIPT_NAME},
            "output-directory-contents", repr(sorted(os.listdir(directory_fd))))
    return value


def require_named_identity(directory_fd: int, name: str, expected: PinnedFd) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        actual_fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise Reject("output-name-open", f"{name}: {error}") from error
    try:
        require(stat_identity(os.fstat(actual_fd)) == stat_identity(expected.identity),
                "output-name-identity", name)
    finally:
        os.close(actual_fd)


def atomic_receipt(directory_fd: int, receipt: dict) -> None:
    encoded = json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n"
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC |
             getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(VERIFY_PARTIAL_NAME, flags, 0o600, dir_fd=directory_fd)
    except OSError as error:
        raise Reject("verify-receipt-create-new", str(error)) from error
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(fd, encoded[offset:])
            require(written > 0, "verify-receipt-partial-write")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(VERIFY_PARTIAL_NAME, VERIFY_RECEIPT_NAME,
                src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                follow_symlinks=False)
        os.unlink(VERIFY_PARTIAL_NAME, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError as error:
        raise Reject("verify-receipt-publish", str(error)) from error


def verify(contract: Contract, admission: PinnedFd,
           axes: tuple[PinnedFd, PinnedFd, PinnedFd], r1cs: PinnedFd,
           exporter_binary: PinnedFd, export_receipt_source: PinnedFd,
           output_directory_fd: int, validate_runtime: bool = True) -> dict:
    if validate_runtime:
        validate_materials(contract)
    directory_identity = require_directory(output_directory_fd)
    require_named_identity(output_directory_fd, OUTPUT_NAME, r1cs)
    require_named_identity(output_directory_fd, EXPORT_RECEIPT_NAME,
                           export_receipt_source)
    admission_sha256 = validate_admission_receipt(contract, admission)
    _, exporter_binary_sha256 = exporter_binary.hash()
    export_receipt, export_receipt_sha256 = validate_export_receipt(
        contract, export_receipt_source, exporter_binary_sha256,
        exporter_binary.identity)
    preflight_axes(contract, tuple(source.clone() for source in axes))
    verify_output(contract, tuple(source.clone() for source in axes),
                  r1cs.clone(), export_receipt["output"]["sha256"])
    receipt = {
        "schema": "kpb-frozen-output-r1cs-verification-receipt/v1",
        "status": "PASS",
        "classification":
            "INDEPENDENT_PRODUCTION_SIZED_R1CS_VERIFICATION_NO_SETUP_OR_CEREMONY",
        "plan_sha256": contract.plan_sha256,
        "verifier_source_sha256": contract.verifier_source_sha256,
        "verifier_python_path": contract.verifier_python_path,
        "verifier_python_sha256": contract.verifier_python_sha256,
        "verifier_python_version": list(contract.verifier_python_version),
        "verifier_zlib_runtime_version": contract.verifier_zlib_version,
        "exporter_source_sha256": contract.exporter_source_sha256,
        "exporter_binary_sha256": exporter_binary_sha256,
        "cargo_toml_sha256": contract.cargo_toml_sha256,
        "cargo_lock_sha256": contract.cargo_lock_sha256,
        "rust_toolchain_sha256": contract.rust_toolchain_sha256,
        "admission_receipt_sha256": admission_sha256,
        "generator_source_sha256": contract.generator_source_sha256,
        "generator_binary_sha256": contract.generator_binary_sha256,
        "selected_axes_manifest_sha256": contract.selected_axes_manifest_sha256,
        "selected_historical_source_sha256":
        contract.selected_historical_source_sha256,
        "current_source_closure_manifest_sha256":
        contract.current_source_closure_manifest_sha256,
        "current_source_closure_identity": contract.current_source_closure_identity,
        "current_build_dep_info_sha256": contract.current_build_dep_info_sha256,
        "current_build_dep_info_local_source_identity":
        contract.current_build_dep_info_local_source_identity,
        "scanner_source_sha256": contract.scanner_source_sha256,
        "export_receipt_sha256": export_receipt_sha256,
        "canonical_r1cs_fingerprint": contract.matrix_fingerprint,
        "output_directory_identity": identity_json(directory_identity),
        "output": {
            "file": OUTPUT_NAME,
            "bytes": contract.output_bytes,
            "sha256": export_receipt["output"]["sha256"],
            "every_input_row_term_equal": True,
            "exact_section_sizes_map_and_eof": True,
        },
        "r1cs_full_output_exported": True,
        "zkey_generated": False,
        "setup_executed": False,
        "phase1_executed": False,
        "phase2_executed": False,
        "ceremony_executed": False,
    }
    atomic_receipt(output_directory_fd, receipt)
    return receipt


def parse_fd(value: str, label: str) -> int:
    try:
        result = int(value, 10)
    except ValueError as error:
        raise Reject("descriptor-argument", f"{label}: {error}") from error
    require(result > 2, "descriptor-argument", f"{label}: {result}")
    return result


def main() -> None:
    if len(sys.argv) != 9:
        print(
            "usage: verify_frozen_output_r1cs.py ADMISSION_FD A_FD B_FD C_FD "
            "R1CS_FD EXPORTER_BINARY_FD EXPORT_RECEIPT_FD PRIVATE_OUTPUT_DIRECTORY_FD",
            file=sys.stderr,
        )
        raise SystemExit(2)
    owned = []
    try:
        descriptors = [parse_fd(value, label) for value, label in zip(
            sys.argv[1:],
            ("admission", "A", "B", "C", "r1cs", "exporter", "export-receipt",
             "output-directory"), strict=True)]
        require(len(set(descriptors)) == len(descriptors), "descriptor-reuse")
        admission = PinnedFd(descriptors[0], "admission-descriptor")
        axes = tuple(PinnedFd(descriptors[index], f"axis-{index - 1}-descriptor")
                     for index in range(1, 4))
        r1cs = PinnedFd(descriptors[4], "r1cs-descriptor")
        exporter = PinnedFd(descriptors[5], "exporter-descriptor")
        export_receipt = PinnedFd(descriptors[6], "export-receipt-descriptor")
        owned.extend((admission, *axes, r1cs, exporter, export_receipt))
        output_directory_fd = os.dup(descriptors[7])
        os.set_inheritable(output_directory_fd, False)
        contract = load_production_contract()
        result = verify(contract, admission, axes, r1cs, exporter, export_receipt,
                        output_directory_fd)
        print(json.dumps({
            "schema": "kpb-frozen-output-r1cs-verification-status/v1",
            "status": result["status"],
            "setup_executed": False,
        }, sort_keys=True))
    except (OSError, Reject, KeyError, TypeError, ValueError) as error:
        print(f"FROZEN_OUTPUT_R1CS_VERIFY_REJECT: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    finally:
        for source in owned:
            source.close()
        if "output_directory_fd" in locals():
            os.close(output_directory_fd)


if __name__ == "__main__":
    main()
