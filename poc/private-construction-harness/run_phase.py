#!/usr/bin/env python3
"""Run one public API experiment phase inside the caller's minimal namespace."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

PHASES = {
    'acquire': [
        ['cargo', 'generate-lockfile', '--manifest-path', '/work/Cargo.toml'],
        ['cargo', 'fetch', '--locked', '--manifest-path', '/work/Cargo.toml'],
        ['cargo', 'metadata', '--locked', '--offline', '--format-version=1', '--manifest-path', '/work/Cargo.toml'],
    ],
    'build': [['cargo', 'build', '--release', '--locked', '--offline', '--jobs=2', '--manifest-path', '/work/Cargo.toml']],
    'run': [['/target/release/private-construction-harness']],
}

phase = sys.argv[1]
commands = PHASES[phase]
output = Path('/out') / phase
output.mkdir(mode=0o700)
assert not Path('/home/luke').exists(), 'original home must be absent'
assert not Path('/var/tmp/kpi-capacity-public-parameters-a5ce95a4-01').exists(), 'old public PK source absent'
relative = next(line.split('::', 1)[1] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
cgroup = Path('/sys/fs/cgroup') / relative.lstrip('/')

def counters():
    names = ('cpu.max', 'memory.max', 'memory.swap.max', 'memory.peak', 'memory.swap.peak', 'cpu.stat', 'memory.events')
    return {name: (cgroup / name).read_text().strip() if (cgroup / name).exists() else None for name in names}

started = time.monotonic()
before = counters()
steps = []
for index, command in enumerate(commands):
    step_started = time.monotonic()
    with (output / f'{index:02d}-stdout.txt').open('xb') as stdout, (output / f'{index:02d}-stderr.txt').open('xb') as stderr:
        result = subprocess.run(command, cwd='/work', stdout=stdout, stderr=stderr)
    steps.append({'command': command, 'returncode': result.returncode, 'wall_seconds': time.monotonic()-step_started})
    if result.returncode:
        break
record = {'schema': 'kpi-public-construction-phase-execution/v1', 'phase': phase,
    'steps': steps, 'wall_seconds': time.monotonic()-started,
    'before_cgroup': before, 'end_of_work_cgroup': counters(),
    'original_home_and_PK_sources_absent': True,
    'network_isolation_expected': phase != 'acquire',
    'workload_peaks_are_cgroup_counters_not_wrapper_rusage': True,
    'limits_are_operational_not_research_qualification': True}
if phase == 'build' and steps[-1]['returncode'] == 0:
    binary = Path('/target/release/private-construction-harness')
    record['executable'] = {'bytes': binary.stat().st_size, 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
(output / 'EXECUTION.json').write_text(json.dumps(record, sort_keys=True, indent=2)+'\n')
print(json.dumps(record, sort_keys=True), flush=True)
sys.exit(steps[-1]['returncode'])
