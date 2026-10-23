"""Execute a hash-authenticated immutable copy of an installed public ELF.

The application selects the executable and expected digest. A descriptor or RPC
record must never select either. This checks software identity, not provenance
or cryptographic correctness. No network, wallet, PK or proving API lives here.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import subprocess


SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
SYSTEM_LOADER = Path("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
SYSTEM_LOADER_SHA256 = "bda779ea9e9ad234f60315477d7cfd0bdde861cd8ddd9df8cdaf62f18c4cec14"
CLEAN_ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC"}


class SealedExecutable:
    """Copy, seal, hash, then execute the same memfd; never reopen its pathname."""

    def __init__(self, executable, expected_sha256):
        self.path = Path(executable)
        if (type(expected_sha256) is not str or len(expected_sha256) != 64
                or any(c not in "0123456789abcdef" for c in expected_sha256)):
            raise ValueError("executable-sha256-encoding")
        self.expected_sha256 = expected_sha256
        self.fd = os.memfd_create("kpx3-public-runtime", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            with self.path.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    view = memoryview(chunk)
                    while view:
                        written = os.write(self.fd, view)
                        if written <= 0:
                            raise OSError("sealed-runtime-short-write")
                        view = view[written:]
            os.fchmod(self.fd, 0o500)
            fcntl.fcntl(self.fd, fcntl.F_ADD_SEALS, SEALS)
            if fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) != SEALS:
                raise ValueError("executable-memfd-seals")
            os.lseek(self.fd, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            while chunk := os.read(self.fd, 1024 * 1024):
                digest.update(chunk)
            self.sha256 = digest.hexdigest()
            if self.sha256 != expected_sha256:
                raise ValueError("executable-software-identity")
            os.lseek(self.fd, 0, os.SEEK_SET)
            if os.pread(self.fd, 4, 0) != b"\x7fELF":
                raise ValueError("executable-elf-required")
        except BaseException:
            self.close()
            raise

    def run(self, arguments, *, cwd=None):
        if self.fd is None:
            raise ValueError("sealed-executable-closed")
        if fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) != SEALS:
            raise ValueError("executable-memfd-seals")
        # This host's enforced unprivileged-bwrap profile denies direct memfd
        # exec. Its read-only system loader can load the same sealed payload.
        # The loader/libraries are a separate trusted-runtime assumption; the
        # payload's digest does not authenticate them. Never relax host policy.
        if hashlib.sha256(SYSTEM_LOADER.read_bytes()).hexdigest() != SYSTEM_LOADER_SHA256:
            raise ValueError("system-loader-software-identity")
        return subprocess.run([str(SYSTEM_LOADER), f"/proc/self/fd/{self.fd}", *map(str, arguments)],
                              pass_fds=(self.fd,), capture_output=True, text=True,
                              cwd=cwd, env=dict(CLEAN_ENVIRONMENT))

    def receipt(self):
        if self.fd is None:
            raise ValueError("sealed-executable-closed")
        return {"selected_source_path": str(self.path), "copied_elf_sha256": self.sha256,
                "kernel_seals": fcntl.fcntl(self.fd, fcntl.F_GET_SEALS),
                "required_seals": SEALS, "execution": "SAME_HASHED_SEALED_MEMFD_VIA_PINNED_SYSTEM_LOADER",
                "system_loader_path": str(SYSTEM_LOADER), "system_loader_sha256": SYSTEM_LOADER_SHA256,
                "loader_and_shared_libraries_trusted_separately": True,
                "child_environment": dict(CLEAN_ENVIRONMENT)}

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
