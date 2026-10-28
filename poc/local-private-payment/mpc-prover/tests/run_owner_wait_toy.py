#!/usr/bin/env python3
"""One actual owner-TLS/MASCOT proof after >60s deliberate pre-owner idle.

Only the PUBLIC fixture runner is adapted. The crypto binaries and owner wire
protocol are unchanged. This harness has no production timing/mode interface.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('owner_wait_toy_base', ROOT / 'run_toy.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
original = base.Attempt.wait_stage


def wait_with_idle(self, required):
    original(self, required)
    if required == 'owner-listeners-ready':
        start = time.monotonic()
        time.sleep(65)
        exits = {role: process.poll() for role, process in self.processes.items() if role.startswith('P')}
        record = {'schema': 'kpi-actual-mpc-owner-idle-control/v1',
                  'run_id': self.args.run_id, 'deliberate_idle_seconds': 65,
                  'elapsed_seconds': time.monotonic() - start, 'P_exit_codes_before_owner': exits,
                  'no_owner_started_during_idle': not any(k.startswith('C') for k in self.processes),
                  'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  'base_runner_sha256': hashlib.sha256((ROOT / 'run_toy.py').read_bytes()).hexdigest()}
        base.write_json(self.public / 'PUBLIC-IDLE-CONTROL.json', record)
        if any(code is not None for code in exits.values()):
            raise RuntimeError('owner idle control failed before owner intake')
        print(json.dumps({'stage': 'actual-three-party-idle-over60s-passed', 'run_id': self.args.run_id}), flush=True)


if __name__ == '__main__':
    base.Attempt.wait_stage = wait_with_idle
    base.main()
