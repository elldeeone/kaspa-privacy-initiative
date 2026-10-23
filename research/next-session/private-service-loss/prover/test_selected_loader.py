#!/usr/bin/env python3
"""One selected full-size loader load and one missing-PK unread-pipe control.

The root's frozen plan selects this test binary; its initial hash is evidence,
not a new production authority. Ordinary-file execution trusts host/release
immutability. The parent supplies sandbox mounts and CPU/memory limits. This
script never opens/copies proving parameters or supplies a private witness.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import sys


CLEAN_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "TZ": "UTC",
    "RAYON_NUM_THREADS": "8",
}
CANARY = b"KPX3_PUBLIC_SELECTED_LOADER_UNREAD_CONTROL/v1\n" + b"0123456789abcdef" * 16
CHECKS_TOTAL = 12
MAX_PUBLIC_JSON_BYTES = 1024 * 1024
PHASES = {
    "read_owned_bytes",
    "authenticate_full_bytes",
    "decode_exhaustion_checked_vk_and_dimensions",
}
REPORT_FIELDS = {
    "schema", "domain_hex32", "parameter_manifest_sha256", "vk_sha256",
    "pk_sha256", "pk_bytes", "source_identity", "compiled_build_identity_sha256",
    "parameter_phase_seconds", "network_or_broadcast_performed", "hosted_prover",
}


class ControlError(Exception):
    """Only fixed public error codes are used as arguments."""


class SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        raise ControlError("selected_loader_arguments_invalid")


def require(condition, code):
    if not condition:
        raise ControlError(code)


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "selected_loader_public_json_invalid")
        value[key] = item
    return value


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def public_json(path):
    with path.open("rb") as source:
        raw = source.read(MAX_PUBLIC_JSON_BYTES + 1)
    require(len(raw) <= MAX_PUBLIC_JSON_BYTES, "selected_loader_public_json_invalid")
    value = json.loads(raw, object_pairs_hook=unique)
    require(type(value) is dict, "selected_loader_public_json_invalid")
    return raw, value


def digest_shape(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def manifest_identity(path):
    raw, manifest = public_json(path)
    require(raw == compact(manifest), "selected_loader_manifest_noncanonical")
    require(manifest.get("schema") == "kpx3-public-proving-parameters/v1",
            "selected_loader_manifest_invalid")
    for field in ("domain_hex32", "vk_sha256", "pk_sha256", "compiled_build_identity_sha256"):
        require(digest_shape(manifest.get(field)), "selected_loader_manifest_invalid")
    require(type(manifest.get("pk_bytes")) is int and manifest["pk_bytes"] > 0,
            "selected_loader_manifest_invalid")
    source = manifest.get("core_source_identity")
    require(type(source) is dict and source and all(type(key) is str and digest_shape(value)
            for key, value in source.items()), "selected_loader_manifest_invalid")
    return manifest, hashlib.sha256(raw).hexdigest()


def checked_binary(path, expected=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o500,
                "selected_loader_binary_invalid")
        digest = hashlib.sha256()
        first = source.read(1024 * 1024)
        require(first.startswith(b"\x7fELF"), "selected_loader_binary_invalid")
        digest.update(first)
        while block := source.read(1024 * 1024):
            digest.update(block)
        for info in (os.fstat(source.fileno()), path.stat(follow_symlinks=False)):
            require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o500,
                    "selected_loader_binary_changed")
            require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                    == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
                    "selected_loader_binary_changed")
        actual = digest.hexdigest()
        require(expected is None or actual == expected, "selected_loader_binary_changed")
        return actual


def phases_valid(phases):
    return type(phases) is dict and set(phases) == PHASES and all(
        type(value) in (int, float) and math.isfinite(value) and value >= 0
        for value in phases.values()
    )


def loader_report(directory, manifest, manifest_sha256):
    try:
        report_path = directory / "report.json"
        require(not directory.is_symlink() and directory.is_dir()
                and stat.S_IMODE(directory.stat().st_mode) == 0o700,
                "selected_loader_report_invalid")
        require({entry.name for entry in directory.iterdir()} == {"report.json"},
                "selected_loader_report_invalid")
        info = report_path.lstat()
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
                "selected_loader_report_invalid")
        _, report = public_json(report_path)
        phases = report.get("parameter_phase_seconds")
        valid = (
            set(report) == REPORT_FIELDS
            and report.get("schema") == "kpx3-own-prover-public-report/v1"
            and report.get("domain_hex32") == manifest["domain_hex32"]
            and report.get("parameter_manifest_sha256") == manifest_sha256
            and report.get("vk_sha256") == manifest["vk_sha256"]
            and report.get("pk_sha256") == manifest["pk_sha256"]
            and report.get("pk_bytes") == manifest["pk_bytes"]
            and report.get("source_identity") == manifest["core_source_identity"]
            and report.get("compiled_build_identity_sha256") == manifest["compiled_build_identity_sha256"]
            and report.get("network_or_broadcast_performed") is False
            and report.get("hosted_prover") is False
        )
        return valid, phases_valid(phases), phases if phases_valid(phases) else {}
    except Exception:
        return False, False, {}


def execute(args, report):
    binary = args.binary.absolute()
    manifest, manifest_sha256 = manifest_identity(args.manifest)
    initial = checked_binary(binary)
    report.update({
        "binary_sha256": initial,
        "parameter_manifest_sha256": manifest_sha256,
        "domain_hex32": manifest["domain_hex32"],
        "vk_sha256": manifest["vk_sha256"],
        "compiled_build_identity_sha256": manifest["compiled_build_identity_sha256"],
        "pk_bytes": manifest["pk_bytes"],
        "pk_sha256": manifest["pk_sha256"],
    })
    ready = {
        "event": "parameters-ready",
        "parameter_manifest_sha256": manifest_sha256,
        "domain_hex32": manifest["domain_hex32"],
        "vk_sha256": manifest["vk_sha256"],
        "compiled_build_identity_sha256": manifest["compiled_build_identity_sha256"],
    }
    loader_output = args.output / "loader-only"
    checked_binary(binary, initial)  # Authenticate mode/full SHA before launch.
    positive = subprocess.run(
        [str(binary), "loader-only", str(args.public_pk), str(loader_output)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=dict(CLEAN_ENVIRONMENT), check=False,
    )
    valid_report, valid_phases, phases = loader_report(loader_output, manifest, manifest_sha256)
    checks = [
        positive.returncode == 0,
        positive.stdout == compact(ready) + b"\n",
        valid_report,
        valid_phases,
        positive.stderr == b"",
        checked_binary(binary, initial) == initial,
    ]
    report["checks_passed"] = sum(checks)
    report["loader_phase_seconds"] = phases

    missing_pk = Path("/missing-public-pk")
    proof_output = args.output / "no-proof"
    require(not os.path.lexists(missing_pk), "selected_loader_missing_path_exists")
    read_fd, write_fd = os.pipe()
    try:
        require(os.write(write_fd, CANARY) == len(CANARY), "selected_loader_canary_write")
        os.close(write_fd)
        write_fd = None
        checked_binary(binary, initial)  # Again before the sole negative launch.
        negative = subprocess.run(
            [str(binary), "prove", str(missing_pk), str(read_fd), str(proof_output)],
            pass_fds=(read_fd,), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=dict(CLEAN_ENVIRONMENT), check=False,
        )
        retained = bytearray()
        while block := os.read(read_fd, len(CANARY) + 1):
            retained.extend(block)
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
    checks.extend((
        negative.returncode != 0,
        negative.stdout == b'{"code":"parameter_pk_io","event":"error"}\n',
        negative.stderr == b"",
        retained == CANARY,
        not os.path.lexists(proof_output),
        checked_binary(binary, initial) == initial,
    ))
    report["checks_passed"] = sum(checks)
    report["witness_bytes_retained"] = len(retained)
    require(all(checks), "selected_loader_control_failed")


def save_new_report(directory, report):
    descriptor = os.open(directory / "report.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(compact(report) + b"\n")
        output.flush()
        os.fsync(output.fileno())
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main():
    report = None
    try:
        parser = SafeParser(prog="test_selected_loader.py", add_help=False)
        for name in ("binary", "manifest", "public-pk", "output"):
            parser.add_argument("--" + name, type=Path, required=True)
        args = parser.parse_args()
        os.mkdir(args.output, 0o700)
        os.chmod(args.output, 0o700)
        args.output = args.output.absolute()
        report = {
            "schema": "kpx3-selected-loader-controls/v1",
            "status": "fail",
            "error_code": "selected_loader_not_completed",
            "checks_total": CHECKS_TOTAL,
            "checks_passed": 0,
            "loader_phase_seconds": {},
            "witness_bytes_offered": len(CANARY),
            "witness_bytes_retained": 0,
        }
        execute(args, report)
        report["status"] = "pass"
        report["error_code"] = "parameter_pk_io"
    except ControlError as error:
        code = error.args[0]
        if report is None:
            print(json.dumps({"event": "error", "code": code}, sort_keys=True))
            return 1
        report["error_code"] = code
    except BaseException:
        if report is None:
            print('{"code":"selected_loader_control_io","event":"error"}')
            return 1
        report["error_code"] = "selected_loader_control_io"
    try:
        save_new_report(args.output, report)
    except BaseException:
        print('{"code":"selected_loader_report_write","event":"error"}')
        return 1
    print(compact(report).decode())
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
