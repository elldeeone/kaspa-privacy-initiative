"""New private-client adapter: authenticated sealed ELF through pinned loader.

The payload is immutable; trusted Python/system loader/shared libraries remain
an installation assumption. No caller-supplied expected hash is authoritative.
Adapted from the separately owned new public executor, without changing it.
"""
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import subprocess

from owner_rules import need

SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
LOADER = Path('/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2')
LOADER_SHA256 = 'bda779ea9e9ad234f60315477d7cfd0bdde861cd8ddd9df8cdaf62f18c4cec14'
CLEAN_ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def checked_loader():
    info = LOADER.stat()
    # In this unprivileged namespace, host-root ownership is reported as the
    # unmapped UID65534. Authenticate the fixed loader bytes and require it
    # non-writable here; its host installation is an explicit trusted premise.
    need(stat.S_ISREG(info.st_mode) and info.st_mode & 0o022 == 0 and not os.access(LOADER, os.W_OK),
         'trusted-system-loader-permissions')
    need(hashlib.sha256(LOADER.read_bytes()).hexdigest() == LOADER_SHA256,
         'trusted-system-loader-identity')
    return str(LOADER)


class SealedExecutable:
    def __init__(self, path, expected_sha256):
        need(type(expected_sha256) is str and len(expected_sha256) == 64
             and all(c in '0123456789abcdef' for c in expected_sha256), 'selected-executable-required')
        checked_loader()
        self.fd = os.memfd_create('kpx3-owner-runtime', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            with Path(path).open('rb') as source:
                while chunk := source.read(1024 * 1024):
                    view = memoryview(chunk)
                    while view:
                        written = os.write(self.fd, view)
                        need(written > 0, 'sealed-runtime-write')
                        view = view[written:]
            os.fchmod(self.fd, 0o500)
            fcntl.fcntl(self.fd, fcntl.F_ADD_SEALS, SEALS)
            need(fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) == SEALS, 'sealed-runtime-seals')
            os.lseek(self.fd, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            while chunk := os.read(self.fd, 1024 * 1024):
                digest.update(chunk)
            self.sha256 = digest.hexdigest()
            need(self.sha256 == expected_sha256, 'selected-executable-identity')
            need(os.pread(self.fd, 4, 0) == b'\x7fELF', 'selected-elf-required')
            os.lseek(self.fd, 0, os.SEEK_SET)
        except BaseException:
            self.close()
            raise

    def command(self, arguments):
        need(self.fd is not None and fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) == SEALS,
             'sealed-runtime-closed-or-unsealed')
        return [checked_loader(), f'/proc/self/fd/{self.fd}', *map(str, arguments)]

    def run(self, arguments=(), *, input=None, cwd=None):
        return subprocess.run(self.command(arguments), input=input, text=True,
                              capture_output=True, pass_fds=(self.fd,), cwd=cwd,
                              env=dict(CLEAN_ENVIRONMENT))

    def popen(self, arguments, *, extra_fds=(), cwd=None):
        return subprocess.Popen(self.command(arguments), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                pass_fds=(self.fd, *extra_fds), cwd=cwd,
                                env=dict(CLEAN_ENVIRONMENT))

    def receipt(self):
        return {'sha256': self.sha256, 'execution': 'SAME_SEALED_ELF_VIA_PINNED_SYSTEM_LOADER',
                'kernel_seals': fcntl.fcntl(self.fd, fcntl.F_GET_SEALS),
                'system_loader_sha256': LOADER_SHA256,
                'python_system_loader_shared_libraries_trusted_separately': True,
                'child_environment': dict(CLEAN_ENVIRONMENT)}

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
