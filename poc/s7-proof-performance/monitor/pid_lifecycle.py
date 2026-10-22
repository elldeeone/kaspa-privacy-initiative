"""Future monitor correction; never used by the frozen 2026-10-22 GPU runs.

A previously verified worker can lose exe/cmdline during exit while NVML still
reports its allocation. Keep counting that allocation; do not invent a new role.
Callers must establish cgroup ownership and enforce the summed VRAM limit.
"""
import os
from pathlib import Path


def read_identity(pid):
    """Read PID/start/state consistently; unavailable metadata stays unavailable."""
    root = Path('/proc') / str(pid)
    try:
        stat = (root / 'stat').read_text()
        fields = stat[stat.rfind(')') + 2:].split()
        ticks, state = int(fields[19]), fields[0]
        try:
            exe = os.readlink(root / 'exe')
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            exe = None
        try:
            cmdline = (root / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            cmdline = None
        after = (root / 'stat').read_text()
        after_fields = after[after.rfind(')') + 2:].split()
        if int(after_fields[19]) != ticks:
            return None
        return {'pid': int(pid), 'start_ticks': ticks, 'state': after_fields[0],
                'exe': exe, 'cmdline': cmdline}
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None


class WorkerLifecycle:
    def __init__(self, expected_exe):
        self.expected_exe = expected_exe
        self.verified = {}

    def register_expected(self, identity, *, owned, role):
        """Register only after the caller authenticates the exact worker config.

        This does not infer primary/secondary roles from PID order or --config
        alone. The caller supplies its independently checked configuration role.
        """
        if (not identity or not owned or role not in ('primary', 'secondary')
                or identity['state'] in ('Z', 'X')
                or identity.get('exe') != self.expected_exe
                or '--config' not in (identity.get('cmdline') or '').split()
                or '--rpc' in (identity.get('cmdline') or '').split()):
            raise ValueError('not an authenticated live GPU worker')
        key = identity['pid'], identity['start_ticks']
        if any(value['role'] == role and other != key for other, value in self.verified.items()):
            raise ValueError('unexpected replacement for a fixed worker role')
        self.verified[key] = dict(identity, role=role)

    def classify(self, identity, *, owned):
        def result(status, *, stop=False, complete=False):
            return {'status': status, 'stop_owned_unit': stop,
                    'resource_evidence_complete': complete, 'identity': identity}

        if identity is None:
            return result('identity_unavailable')
        key = identity['pid'], identity['start_ticks']
        if not owned:
            return result('foreign_live_or_unowned_identity', stop=True)
        if any(pid == key[0] and ticks != key[1] for pid, ticks in self.verified):
            return result('reused_pid_identity', stop=True)
        if identity['state'] in ('Z', 'X'):
            if key in self.verified:
                # Known ownership survives missing exe/cmdline for this exact
                # exited identity. Its reported NVML allocation is NOT zeroed.
                return result('known_exited_stale_gpu_sample', complete=True)
            return result('unknown_exited_identity')
        exe, cmd = identity.get('exe'), identity.get('cmdline')
        if exe == self.expected_exe and cmd and '--config' in cmd.split() and '--rpc' not in cmd.split():
            if key in self.verified:
                return result('expected_live_worker', complete=True)
            return result('unregistered_live_worker')
        if exe is None or not cmd:
            return result('live_identity_metadata_unavailable')
        return result('unexpected_live_gpu_worker', stop=True)


def evaluate_gpu_topology(rows, identities, lifecycle, *, owned_pids):
    """Runner integration seam; raw NVML rows remain unchanged for VRAM summing."""
    states = [lifecycle.classify(identities.get(row['pid']), owned=row['pid'] in owned_pids)
              for row in rows]
    return {'stop_owned_unit': len(rows) > 2 or any(s['stop_owned_unit'] for s in states),
            'resource_evidence_complete': all(s['resource_evidence_complete'] for s in states),
            'classifications': states,
            'summed_reported_mib': sum(row['used_mib'] for row in rows)}
