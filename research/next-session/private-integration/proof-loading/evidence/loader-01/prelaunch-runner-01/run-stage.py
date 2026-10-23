#!/usr/bin/env python3
"""One released loader-only stage; public cgroup/resource accounting only."""
from pathlib import Path
import datetime
import hashlib
import json
import subprocess
import time

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
HERE = Path(__file__).resolve().parent
PRIVATE_OUT = Path('/home/luke/projects/kpi-intensive-2026-10-22/selected-development-prover-target/loader-stage01')
UNIT = 'kpi-selected-prover-loader-01.service'


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def properties():
    result = subprocess.run(
        ['systemctl', '--user', 'show', UNIT, '--property=ActiveState,SubState,MainPID,ControlGroup,Result,ExecMainStatus,ExecMainStartTimestamp'],
        text=True, capture_output=True, check=True)
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def number(path):
    try:
        return int(path.read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def main():
    # Freeze includes all authoritative small inputs and this runner, but not a
    # redundant extra read of the 1 GB PK. The binary authenticates it itself.
    freeze = json.loads((HERE / 'runtime-freeze.json').read_text())
    for item in freeze['small_files']:
        raw = Path(item['path']).read_bytes()
        if hashlib.sha256(raw).hexdigest() != item['sha256']:
            raise RuntimeError('frozen runtime identity mismatch: ' + item['path'])
    PRIVATE_OUT.mkdir()  # Refuse overwrite before launching anything.
    started = utc()
    subprocess.run([
        'systemd-run', '--user', '--unit=' + UNIT,
        '--property=CPUQuota=1400%', '--property=MemoryMax=18G',
        '--property=MemorySwapMax=0', '--property=TasksMax=1024',
        '--property=RuntimeMaxSec=3600', '--property=KillMode=control-group',
        '--property=TimeoutStopSec=20',
        '--property=StandardOutput=append:' + str(HERE / 'execution.log'),
        '--property=StandardError=append:' + str(HERE / 'execution.log'),
        '/bin/bash', str(HERE / 'runtime.sh')], check=True)
    first = properties()
    (HERE / 'start.json').write_text(json.dumps({'utc': started, 'unit': UNIT, 'properties': first}, indent=2) + '\n')
    peak = None
    samples = 0
    with (HERE / 'cgroup-samples.jsonl').open('x') as output:
        while True:
            current = properties()
            group = current.get('ControlGroup', '')
            cg = Path('/sys/fs/cgroup') / group.lstrip('/') if group else None
            sample = {'utc': utc(), 'active': current.get('ActiveState'), 'main_pid': current.get('MainPID'),
                      'memory_peak_bytes': number(cg / 'memory.peak') if cg else None,
                      'memory_current_bytes': number(cg / 'memory.current') if cg else None,
                      'memory_swap_current_bytes': number(cg / 'memory.swap.current') if cg else None}
            output.write(json.dumps(sample) + '\n')
            output.flush()
            samples += 1
            observed = sample['memory_peak_bytes']
            if observed is not None:
                peak = max(peak or 0, observed)
            if current.get('ActiveState') in ('inactive', 'failed'):
                break
            time.sleep(0.5)
    group = first.get('ControlGroup', '')
    cg = Path('/sys/fs/cgroup') / group.lstrip('/') if group else None
    cgroup_empty = cg is None or not cg.exists() or not (cg / 'cgroup.procs').read_text().strip()
    cleanup = {'utc': utc(), 'properties': current, 'owned_cgroup_absent_or_empty': cgroup_empty,
               'all_owned_processes_gone': current.get('MainPID') == '0' and cgroup_empty,
               'sample_count': samples, 'observed_cgroup_memory_peak_bytes': peak,
               'missing_peak_is_unavailable_not_zero': peak is None}
    (HERE / 'cleanup.json').write_text(json.dumps(cleanup, indent=2) + '\n')
    if current.get('Result') != 'success' or current.get('ExecMainStatus') != '0' or not cleanup['all_owned_processes_gone']:
        raise RuntimeError('loader stage or cleanup failed; preserve all evidence')
    print(json.dumps(cleanup))


if __name__ == '__main__':
    main()
