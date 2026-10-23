"""ADR0054: ordinary SHA-checked selected0500 ELF in a trusted release.

The release files are read-only sandbox inputs. Host/release-inode immutability
during an operation, Python and system libraries are trusted premises. This
does not defend against a malicious host writer between hash and execution.
No special executable FD, loader entry point or policy change is used.
"""
import hashlib
import os
from pathlib import Path
import stat
import subprocess

from owner_rules import need, no_symlinks

CLEAN_ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


class SelectedExecutable:
    def __init__(self, path, expected_sha256):
        need(type(expected_sha256) is str and len(expected_sha256) == 64
             and all(c in '0123456789abcdef' for c in expected_sha256), 'selected-executable-required')
        self.path = no_symlinks(path)
        self.expected_sha256 = expected_sha256
        self.closed = False
        self.check()

    def check(self):
        need(not self.closed, 'selected-executable-closed')
        info = self.path.stat()
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o500
             and os.access(self.path, os.X_OK) and not os.access(self.path, os.W_OK),
             'selected-readonly-0500-executable')
        digest = hashlib.sha256()
        with self.path.open('rb') as source:
            need(source.read(4) == b'\x7fELF', 'selected-elf-required')
            source.seek(0)
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        self.sha256 = digest.hexdigest()
        need(self.sha256 == self.expected_sha256, 'selected-executable-identity')

    def command(self, arguments):
        self.check()
        return [str(self.path), *map(str, arguments)]

    def run(self, arguments=(), *, input=None, cwd=None):
        return subprocess.run(self.command(arguments), input=input, text=True,
                              capture_output=True, cwd=cwd, env=dict(CLEAN_ENVIRONMENT))

    def popen(self, arguments, *, extra_fds=(), cwd=None):
        # Only data FDs such as the empty private witness pipe are inherited.
        return subprocess.Popen(self.command(arguments), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                pass_fds=tuple(extra_fds), cwd=cwd,
                                env=dict(CLEAN_ENVIRONMENT))

    def receipt(self):
        return {'selected_elf_sha256': self.sha256, 'execution': 'ORDINARY_SELECTED_0500_ELF',
                'trusted_readonly_release_path': str(self.path),
                'trusted_host_release_inode_unchanged_during_operation': True,
                'python_system_libraries_trusted_separately': True,
                'child_environment': dict(CLEAN_ENVIRONMENT)}

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
