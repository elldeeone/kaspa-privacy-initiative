#!/usr/bin/env python3
"""Independent fail-closed admission scan for exact Output A/B/C axes."""

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
REPOSITORY = HERE.parents[3]
MAGIC = b"KPI_R1CS_AXIS_V1"
DOMAIN = b"KPINAS/R1CS/v1\0"
FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
FIELD_BYTES = FIELD.to_bytes(32, "little")
OUTPUT_SOURCE = "ccd4e28a728cbf8ffd6db0dd0fa81a6200c0c6e4ecb20242435f00e5b6aae19e"
OUTPUT_MATRIX = "d8e94558a7b9e3a5cc6187a894cb7f141d85d3c6d862b6a628561a24c4bfdd31"
INSTANCES = 3
WITNESSES = 214_998
VARIABLES = 215_001
CONSTRAINTS = 217_807
NAMES = ("A.r1cs.bin.gz", "B.r1cs.bin.gz", "C.r1cs.bin.gz")


class Reject(ValueError):
    pass


def require(value: bool, code: str) -> None:
    if not value:
        raise Reject(code)


def sha256_bytes(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mode,
            value.st_uid, value.st_mtime_ns, value.st_ctime_ns)


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


class Pinned:
    def __init__(self, path: Path, code: str):
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            self.fd = os.open(path, flags)
        except OSError as error:
            raise Reject(f"{code}: {error}") from error
        self.code = code
        self.stat = os.fstat(self.fd)
        require(stat.S_ISREG(self.stat.st_mode), f"{code}-regular")

    def hash(self) -> tuple[bytes, str]:
        os.lseek(self.fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        chunks = []
        total = 0
        while chunk := os.read(self.fd, 65536):
            total += len(chunk)
            digest.update(chunk)
            chunks.append(chunk)
        require(total == self.stat.st_size, f"{self.code}-size")
        require(identity(os.fstat(self.fd)) == identity(self.stat),
                f"{self.code}-changed")
        os.lseek(self.fd, 0, os.SEEK_SET)
        return b"".join(chunks), digest.hexdigest()

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class Gzip:
    def __init__(self, source: Pinned, pin: dict, axis: int):
        _, digest = source.hash()
        require(source.stat.st_size == pin["compressed_bytes"] and
                digest == pin["compressed_sha256"],
                f"axis-{axis}-compressed-pin")
        self.source = source
        self.pin = pin
        self.axis = axis
        self.inflate = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self.pending = b""
        self.output = bytearray()
        self.output_at = 0
        self.ended = False
        self.digest = hashlib.sha256()
        self.bytes = 0

    def available(self) -> int:
        return len(self.output) - self.output_at

    def compact(self) -> None:
        if self.output_at == 0:
            return
        if self.output_at == len(self.output):
            self.output.clear()
        else:
            del self.output[:self.output_at]
        self.output_at = 0

    def pump(self, minimum: int = 1, maximum: int = 65536) -> None:
        while self.available() < minimum and not self.ended:
            self.compact()
            source = self.pending
            self.pending = b""
            if not source:
                source = os.read(self.source.fd, 65536)
                if not source:
                    require(self.inflate.eof, f"axis-{self.axis}-gzip-truncated")
                    self.ended = True
                    break
            try:
                decoded = self.inflate.decompress(source, maximum)
            except zlib.error as error:
                raise Reject(f"axis-{self.axis}-gzip-crc: {error}") from error
            if self.inflate.unconsumed_tail:
                self.pending = self.inflate.unconsumed_tail
            self.output.extend(decoded)
            if self.inflate.eof:
                trailing = self.inflate.unused_data + self.pending
                self.pending = b""
                if not trailing:
                    trailing = os.read(self.source.fd, 1)
                require(not trailing, f"axis-{self.axis}-gzip-trailing-member")
                self.ended = True

    def exact(self, size: int) -> bytes:
        require(size >= 0, f"axis-{self.axis}-raw-read-size")
        while self.available() < size:
            self.pump(size, max(65536, size - self.available()))
            require(not self.ended or self.available() >= size,
                    f"axis-{self.axis}-raw-truncated")
        end = self.output_at + size
        result = bytes(self.output[self.output_at:end])
        self.output_at = end
        self.digest.update(result)
        self.bytes += size
        return result

    def finish(self) -> None:
        while not self.ended:
            self.pump(1, 1)
            require(self.available() == 0,
                    f"axis-{self.axis}-raw-trailing")
        require(self.available() == 0, f"axis-{self.axis}-raw-trailing")
        require(self.bytes == self.pin["raw_bytes"] and
                self.digest.hexdigest() == self.pin["raw_sha256"],
                f"axis-{self.axis}-raw-pin")
        require(identity(os.fstat(self.source.fd)) == identity(self.source.stat),
                f"axis-{self.axis}-changed")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def verify_source_closure(manifest: dict) -> None:
    closure_path = HERE / "source_closure.json"
    body = closure_path.read_bytes()
    require(sha256_bytes(body) == manifest["source_closure_manifest_sha256"],
            "source-closure-manifest-pin")
    closure = json.loads(body)
    expected_identity = closure.pop("closure_identity")
    require(sha256_bytes(canonical(closure)) == expected_identity and
            expected_identity == manifest["source_closure_identity"],
            "source-closure-identity")
    require(closure["file_count"] == len(closure["files"]),
            "source-closure-count")
    for entry in closure["files"]:
        path = REPOSITORY / entry["path"]
        source = Pinned(path, "source-closure-file")
        try:
            _, digest = source.hash()
            require(digest == entry["sha256"], "source-closure-file-pin")
        finally:
            source.close()


def verify_build_dep_info(generator_path: Path, manifest: dict) -> None:
    dep_path = generator_path.resolve().with_suffix(".d")
    body = dep_path.read_bytes()
    expected = manifest["build_dep_info"]
    require(dep_path.name == expected["file"] and
            len(body) == expected["bytes"] and
            sha256_bytes(body) == expected["sha256"],
            "build-dep-info-pin")
    try:
        dependencies = body.decode().split(": ", 1)[1].split()
    except (UnicodeDecodeError, IndexError) as error:
        raise Reject(f"build-dep-info-format: {error}") from error
    local_sources = []
    for value in dependencies:
        try:
            relative = Path(value).resolve().relative_to(REPOSITORY)
        except ValueError:
            continue
        local_sources.append(relative.as_posix())
    local_sources = sorted(set(local_sources))
    require(local_sources == expected["local_sources"] and
            len(local_sources) == expected["local_source_count"] and
            sha256_bytes(canonical(local_sources)) ==
            expected["local_source_identity"],
            "build-dep-info-local-sources")
    closure = json.loads((HERE / "source_closure.json").read_text())
    covered = {entry["path"] for entry in closure["files"]}
    covered.add(
        (HERE / "source_closure.json").relative_to(REPOSITORY).as_posix())
    require(set(local_sources) <= covered, "build-dep-info-source-not-closed")


def scan_axis(source: Pinned, pin: dict, axis: int,
              fingerprint: hashlib._Hash) -> dict:
    raw = Gzip(source, pin, axis)
    require(raw.exact(16) == MAGIC, f"axis-{axis}-magic")
    require(struct.unpack("<Q", raw.exact(8))[0] == axis,
            f"axis-{axis}-number")
    require(raw.exact(32) == FIELD_BYTES, f"axis-{axis}-field")
    require(struct.unpack("<QQQ", raw.exact(24)) ==
            (INSTANCES, WITNESSES, CONSTRAINTS), f"axis-{axis}-geometry")
    terms = 0
    maximum = 0
    for row in range(CONSTRAINTS):
        encoded_count = raw.exact(8)
        count = struct.unpack("<Q", encoded_count)[0]
        require(count <= 0xFFFFFFFF, f"axis-{axis}-row-{row}-count-u32")
        require(raw.bytes <= pin["raw_bytes"] and
                count <= (pin["raw_bytes"] - raw.bytes) // 40,
                f"axis-{axis}-row-{row}-frame")
        terms += count
        maximum = max(maximum, count)
        fingerprint.update(encoded_count)
        previous = None
        for term in range(count):
            encoded = raw.exact(40)
            coefficient = encoded[:32]
            column = struct.unpack("<Q", encoded[32:])[0]
            require(any(coefficient), f"axis-{axis}-row-{row}-term-{term}-zero")
            require(int.from_bytes(coefficient, "little") < FIELD,
                    f"axis-{axis}-row-{row}-term-{term}-noncanonical")
            require(column < VARIABLES and column <= 0xFFFFFFFF,
                    f"axis-{axis}-row-{row}-term-{term}-column")
            require(previous is None or column > previous,
                    f"axis-{axis}-row-{row}-term-{term}-order")
            previous = column
            fingerprint.update(encoded)
    require(terms == pin["terms"] and maximum == pin["maximum_row_terms"],
            f"axis-{axis}-totals")
    raw.finish()
    return {
        "axis": axis,
        "file_label": NAMES[axis],
        "descriptor_identity": identity_json(source.stat),
        "compressed_bytes": pin["compressed_bytes"],
        "compressed_sha256": pin["compressed_sha256"],
        "raw_bytes": pin["raw_bytes"],
        "raw_sha256": pin["raw_sha256"],
        "rows": CONSTRAINTS,
        "terms": terms,
        "maximum_row_terms": maximum,
    }


def write_receipt(path: Path, value: dict) -> None:
    encoded = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            require(written > 0, "receipt-partial-write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main() -> None:
    if len(sys.argv) != 7:
        raise SystemExit(
            "usage: scan_output_axes.py AXES-MANIFEST.json A.gz B.gz C.gz "
            "GENERATOR-BINARY NEW-RECEIPT.json")
    manifest_source = Pinned(Path(sys.argv[1]), "axes-manifest")
    generator_path = Path(sys.argv[5])
    generator = Pinned(generator_path, "generator-binary")
    sources = [Pinned(Path(sys.argv[index]), f"axis-{index - 2}")
               for index in range(2, 5)]
    try:
        manifest_body, manifest_sha256 = manifest_source.hash()
        manifest = json.loads(manifest_body)
        require(manifest["schema"] == "kpb-output-r1cs-axes/v1" and
                manifest["status"] == "PASS" and
                manifest["classification"] ==
                "PUBLIC_UNASSIGNED_OUTPUT_ROWS_NO_SETUP_ZKEY_PROOF_OR_CEREMONY",
                "manifest-schema")
        require(manifest["output_source_sha256"] == OUTPUT_SOURCE and
                manifest["canonical_r1cs_fingerprint"] == OUTPUT_MATRIX and
                manifest["field_decimal"] == str(FIELD) and
                (manifest["instances_including_one"], manifest["witnesses"],
                 manifest["variables"], manifest["constraints"]) ==
                (INSTANCES, WITNESSES, VARIABLES, CONSTRAINTS),
                "manifest-relation")
        for field in ("private_assignment_included", "setup_executed",
                      "zkey_generated", "phase1_executed", "phase2_executed",
                      "ceremony_executed"):
            require(manifest[field] is False, "manifest-authority")
        require(sha256_bytes((HERE / "src/main.rs").read_bytes()) ==
                manifest["generator_source_sha256"] and
                sha256_bytes((HERE / "Cargo.toml").read_bytes()) ==
                manifest["cargo_toml_sha256"] and
                sha256_bytes((HERE / "Cargo.lock").read_bytes()) ==
                manifest["cargo_lock_sha256"] and
                sha256_bytes((HERE / "rust-toolchain.toml").read_bytes()) ==
                manifest["rust_toolchain_sha256"],
                "generator-materials")
        verify_source_closure(manifest)
        verify_build_dep_info(generator_path, manifest)
        _, generator_sha256 = generator.hash()
        require(generator_sha256 == manifest["generator_binary"]["sha256"] and
                identity_json(generator.stat) == {
                    key: manifest["generator_binary"][key]
                    for key in identity_json(generator.stat)
                }, "generator-binary-identity")
        require(len(manifest["axes"]) == 3, "manifest-axes")
        fingerprint = hashlib.sha256(
            DOMAIN + struct.pack("<QQQ", INSTANCES, WITNESSES, CONSTRAINTS))
        axes = [scan_axis(source, manifest["axes"][axis], axis, fingerprint)
                for axis, source in enumerate(sources)]
        require(fingerprint.hexdigest() == OUTPUT_MATRIX,
                "output-matrix-fingerprint")
        receipt = {
            "schema": "kpb-output-r1cs-axes-admission/v1",
            "status": "PASS",
            "classification": "READ_ONLY_OUTPUT_FORMAT_ADMISSION_NO_R1CS_EXPORT_SETUP_ZKEY_OR_CEREMONY",
            "selected_axes_manifest_sha256": manifest_sha256,
            "selected_historical_source_sha256": OUTPUT_SOURCE,
            "selected_relation_fingerprint": OUTPUT_MATRIX,
            "current_relation_fingerprint": fingerprint.hexdigest(),
            "generator_source_sha256": manifest["generator_source_sha256"],
            "generator_binary_sha256": generator_sha256,
            "current_source_closure_manifest_sha256": manifest["source_closure_manifest_sha256"],
            "current_source_closure_identity": manifest["source_closure_identity"],
            "current_build_dep_info_sha256": manifest["build_dep_info"]["sha256"],
            "current_build_dep_info_local_source_identity":
                manifest["build_dep_info"]["local_source_identity"],
            "scanner_source_sha256": sha256_bytes(Path(__file__).resolve().read_bytes()),
            "instances_including_one": INSTANCES,
            "witnesses": WITNESSES,
            "variables": VARIABLES,
            "constraints": CONSTRAINTS,
            "axes": axes,
            "admission_predicates": {
                "single_gzip_member_crc_and_exact_eof": True,
                "all_rows_and_terms_consumed": True,
                "coefficients_canonical_and_nonzero": True,
                "columns_strictly_increasing_unique_and_in_range": True,
                "matrix_fingerprint_exact": True,
                "source_and_generator_closure_exact": True,
            },
            "r1cs_exported": False,
            "setup_executed": False,
            "zkey_generated": False,
            "phase1_executed": False,
            "phase2_executed": False,
            "ceremony_executed": False,
        }
        write_receipt(Path(sys.argv[6]), receipt)
        print(json.dumps({
            "schema": "kpb-output-r1cs-axes-admission-status/v1",
            "status": "PASS",
            "setup_executed": False,
        }, sort_keys=True))
    except (OSError, Reject, KeyError, TypeError, ValueError) as error:
        print(f"OUTPUT_AXES_ADMISSION_REJECT: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    finally:
        manifest_source.close()
        generator.close()
        for source in sources:
            source.close()


if __name__ == "__main__":
    main()
