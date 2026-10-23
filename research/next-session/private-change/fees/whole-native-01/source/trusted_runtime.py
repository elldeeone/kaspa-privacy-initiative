"""ADR0054 ordinary selected executable, trusted immutable release assumption.

The trusted application selects a SHA-pinned 0500 file in a private release
directory and mounts it read-only. This does not protect against a malicious
host or same-inode writer; the release/host immutability premise is explicit.
"""
import hashlib
import os
from pathlib import Path
import stat
import subprocess

CLEAN_ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC"}


class TrustedExecutable:
    def __init__(self, executable, expected_sha256):
        self.path = Path(executable).resolve(strict=True)
        if (type(expected_sha256) is not str or len(expected_sha256) != 64
                or any(c not in "0123456789abcdef" for c in expected_sha256)):
            raise ValueError("executable-sha256-encoding")
        self.expected_sha256 = expected_sha256
        self.closed = False
        self.check_binary()

    def check_binary(self):
        if self.closed:
            raise ValueError("trusted-executable-closed")
        metadata = self.path.stat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o500:
            raise ValueError("trusted-release-regular-file-mode0500")
        raw = self.path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != self.expected_sha256 or raw[:4] != b"\x7fELF":
            raise ValueError("trusted-executable-software-identity")

    def run(self, arguments, *, cwd=None, input_text=None):
        if input_text is not None and type(input_text) is not str:
            raise TypeError("trusted-runtime-stdin-must-be-text")
        self.check_binary()
        return subprocess.run([str(self.path), *map(str, arguments)], cwd=cwd,
                              capture_output=True, text=True, input=input_text,
                              env=dict(CLEAN_ENVIRONMENT))

    def receipt(self):
        self.check_binary()
        return {"selected_source_path": str(self.path), "executable_sha256": self.expected_sha256,
                "required_mode": "0500", "execution": "ORDINARY_PINNED_TRUSTED_RELEASE",
                "requires_read_only_sandbox_mount": True, "requires_private_trusted_release_directory": True,
                "host_and_release_immutability_assumed": True, "same_inode_host_writer_protection": False,
                "child_environment": dict(CLEAN_ENVIRONMENT)}

    def close(self):
        self.closed = True

    def __enter__(self):
        self.check_binary()
        return self

    def __exit__(self, *_):
        self.close()
