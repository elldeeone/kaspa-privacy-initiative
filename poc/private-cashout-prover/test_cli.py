#!/usr/bin/env python3
"""Actual-process check that compiled selection failures read no witness bytes.

The canary is deliberately public synthetic test data. Child captures stay in
memory; the retained report contains only counts, fixed codes and binary SHA256.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


CANARY = b"KPX3_PUBLIC_BEFORE_WITNESS_CONTROL/v1\n" + b"0123456789abcdef" * 16
CHECKS_TOTAL = 8


class ControlError(Exception):
    """Only fixed public codes are permitted as exception arguments."""


class SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        raise ControlError("control_arguments_invalid")


def arguments():
    parser = SafeParser(prog="test_cli.py", description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--expected-code",
        choices=("trial_unselected", "parameters_unselected"),
        required=True,
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def binary_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as binary:
        if not stat.S_ISREG(os.fstat(binary.fileno()).st_mode):
            raise ControlError("control_binary_invalid")
        while block := binary.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def save_new_report(directory, report):
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(
        directory / "report.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def execute(args, report):
    binary = args.binary.resolve(strict=True)
    before = binary_sha256(binary)
    report["binary_sha256"] = before
    with tempfile.TemporaryDirectory(prefix="cli-control-", dir=args.output) as temporary:
        temporary = Path(temporary)
        missing_pk = temporary / "missing-public-parameters.bin"
        proof_output = temporary / "new-private-proof-output"
        read_fd, write_fd = os.pipe()
        try:
            # One tiny atomic pipe write before launch; the parent keeps its read
            # descriptor. Both readers consume the same stream, with no seeking.
            if os.write(write_fd, CANARY) != len(CANARY):
                raise ControlError("control_canary_write")
            os.close(write_fd)
            write_fd = None
            child = subprocess.run(
                [str(binary), "prove", str(missing_pk), str(read_fd), str(proof_output)],
                pass_fds=(read_fd,),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=120,
            )
            retained = bytearray()
            while block := os.read(read_fd, len(CANARY) + 1):
                retained.extend(block)
        finally:
            os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)

        expected_stdout = (
            json.dumps(
                {"code": args.expected_code, "event": "error"},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        # These sentinels and their hashes are checked only in memory. None may
        # enter the report, including on a failing child or failed assertion.
        canary_digest = hashlib.sha256(CANARY)
        forbidden = [
            CANARY,
            b"KPX3_PUBLIC_BEFORE_WITNESS_CONTROL",
            CANARY.hex().encode(),
            canary_digest.digest(),
            canary_digest.hexdigest().encode(),
            canary_digest.hexdigest().upper().encode(),
            os.fsencode(binary),
            os.fsencode(args.binary),
            os.fsencode(args.output),
            os.fsencode(temporary),
            os.fsencode(missing_pk),
            os.fsencode(proof_output),
        ]
        checks = [
            child.returncode != 0,
            child.stdout == expected_stdout,
            b"parameters-ready" not in child.stdout,
            all(value not in child.stderr for value in forbidden if value),
            not os.path.lexists(proof_output),
            retained == CANARY,
            binary_sha256(binary) == before,
            stat.S_IMODE(args.output.stat().st_mode) == 0o700
            and stat.S_IMODE(temporary.stat().st_mode) == 0o700,
        ]
        report["checks_passed"] = sum(checks)
        report["witness_bytes_retained"] = len(retained)
        if not all(checks):
            raise ControlError("control_assertion_failed")


def main():
    report = None
    output = None
    try:
        args = arguments()
        os.mkdir(args.output, mode=0o700)
        os.chmod(args.output, 0o700)
        args.output = args.output.resolve(strict=True)
        output = args.output
        report = {
            "schema": "kpx3-before-witness-cli-control/v1",
            "status": "fail",
            "expected_error_code": args.expected_code,
            "error_code": "control_not_completed",
            "binary_sha256": None,
            "checks_total": CHECKS_TOTAL,
            "checks_passed": 0,
            "witness_bytes_offered": len(CANARY),
            "witness_bytes_retained": 0,
        }
        execute(args, report)
        report["status"] = "pass"
        report["error_code"] = args.expected_code
    except ControlError as error:
        code = error.args[0]
        if report is None:
            print(json.dumps({"event": "error", "code": code}, sort_keys=True))
            return 1
        report["error_code"] = code
    except Exception:
        if report is None:
            print('{"code":"control_io_failed","event":"error"}')
            return 1
        report["error_code"] = "control_io_failed"

    try:
        save_new_report(output, report)
    except Exception:
        print('{"code":"control_report_write_failed","event":"error"}')
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
