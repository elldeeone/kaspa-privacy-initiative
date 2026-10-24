"""Trusted invocation handles. Never opens an owner file or logs child argv.

Resource scheduling belongs to the root supervisor. Actual MPC is held until
its current source/runtime gate is released; these helpers do not bypass it.
"""
from pathlib import Path
import subprocess
import sys

from public import need

ROOT = Path(__file__).resolve().parents[1]
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


class OwnerHandles:
    def __init__(self, parents, old_trials):
        need(len(parents) == 3 and len(old_trials) == 2, 'exact-private-handle-counts')
        self.parents = [Path(root).absolute() for root in parents]
        self.old_trials = [Path(root).absolute() for root in old_trials]
        for root in self.parents:
            need('..' not in root.parts and all(not p.is_symlink() for p in (root, *root.parents))
                 and root.is_dir(), 'canonical-private-parent-handle')
            need((root / 'owner').is_dir() and (root / 'mpc').is_dir(), 'fixed-owner-MPC-leaves')
        need(all(not left.is_relative_to(right) for i, left in enumerate(self.parents)
                 for j, right in enumerate(self.parents) if i != j), 'disjoint-party-private-parents')

    def owner(self, operation, party, output, extra):
        need(operation in ('init', 'prepare', 'authorize') and type(party) is int and 0 <= party < 3,
             'fixed-owner-operation')
        command = ['/usr/bin/python3', '-B', str(ROOT / 'wallet/run_owner.py'), operation,
                   '--owner-directory', str(self.parents[party] / 'owner'),
                   '--mpc-directory', str(self.parents[party] / 'mpc'), '--output', str(output)]
        for root in self.old_trials:
            command += ['--exclude-old-trial', str(root)]
        for root in self.parents:
            command += ['--exclude-new-private-directory', str(root)]
        for root in self.parents:
            command += ['--peer-owner-directory', str(root / 'owner')]
        return command + list(extra)

    def construction(self, operation, output, extra):
        need(operation in ('prepare', 'run'), 'fixed-construction-operation')
        command = ['/usr/bin/python3', '-B', str(ROOT / 'construction/backend.py'), operation,
                   '--output', str(output)]
        for root in self.old_trials:
            command += ['--exclude-private-root', str(root)]
        for root in self.parents:
            command += ['--exclude-owner-private-directory', str(root)]
        if operation == 'run':
            command += ['--owner-input-directory', *(str(root / 'mpc') for root in self.parents)]
        return command + list(extra)

    @staticmethod
    def execute(command):
        # A scheduled trusted supervisor supplies these fixed argv lists.
        # Private diagnostics and opaque filesystem handles never become
        # public artifacts or coordinator IPC. Each child sanitizes its output.
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, env=CLEAN)
        need(result.returncode == 0, 'selected-owner-or-construction-operation-incomplete')


def isolated_assembly(packet_bytes, output):
    """Run the untrusted public assembler with only four public source leaves."""
    sys.path.insert(0, str(ROOT / 'construction'))
    from backend import bubble
    command = bubble() + [
        '--ro-bind', str(ROOT / 'integration/coordinator.py'), '/app/integration/coordinator.py',
        '--ro-bind', str(ROOT / 'integration/public.py'), '/app/integration/public.py',
        '--ro-bind', str(ROOT / 'integration/trees.py'), '/app/integration/trees.py',
        '--ro-bind', str(ROOT / 'verification/wire.py'), '/app/verification/wire.py',
        '--bind', str(output), '/out', '--chdir', '/app/integration',
        '/usr/bin/python3', '-B', '/app/integration/coordinator.py']
    result = subprocess.run(command, input=packet_bytes, capture_output=True, env=CLEAN)
    need(result.returncode == 0, 'public-only-assembler-process-incomplete')
