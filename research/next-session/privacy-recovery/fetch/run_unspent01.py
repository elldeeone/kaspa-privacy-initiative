#!/usr/bin/env python3
"""Supervise a descriptor-only read-only fetch in its own limited user unit."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[4]
BASE = Path(__file__).resolve().parent / 'unspent-01'


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write(path, value):
    with path.open('x') as file:
        json.dump(value, file, indent=2, sort_keys=True)
        file.write('\n')


def state(unit):
    result = subprocess.run(['systemctl', '--user', 'show', unit, '--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec'], capture_output=True, text=True)
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def number(path):
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def main():
    name = sys.argv[1]
    if name not in ('bob-vector', 'bob-electron', 'charlie-vector', 'charlie-electron'):
        raise ValueError('expected bob-vector, bob-electron, charlie-vector or charlie-electron')
    run = BASE / (name + '-01')
    freeze = json.loads((BASE / 'FREEZE.json').read_bytes())
    for pin in freeze['files']:
        raw = (ROOT / pin['path']).read_bytes()
        if len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']:
            raise ValueError('frozen public input changed: ' + pin['path'])
    plan = json.loads((run / 'RUNTIME-PLAN.json').read_bytes())
    unit = plan['unit']
    write(run / 'start.json', {'started_at': now(), 'unit': unit,
        'freeze_sha256': hashlib.sha256((BASE / 'FREEZE.json').read_bytes()).hexdigest(),
        'network_read_only': True})
    started = time.monotonic()
    launch = subprocess.run(['systemd-run', '--user', '--collect', '--unit=' + unit,
        '--property=StandardOutput=journal', '--property=StandardError=journal', '--property=CPUQuota=200%', '--property=MemoryMax=4G', '--property=MemorySwapMax=0',
        '--property=RuntimeMaxSec=3600', '--property=KillMode=control-group',
        '/bin/bash', str(run / 'runtime.sh')], capture_output=True, text=True)
    (run / 'launch.log').write_text(launch.stdout + launch.stderr)
    if launch.returncode:
        raise ValueError('read-only fetch unit did not launch')
    samples = []
    last_group = None
    try:
        with (run / 'telemetry.jsonl').open('x') as log:
            while True:
                status = state(unit)
                group = status.get('ControlGroup')
                if group:
                    last_group = Path('/sys/fs/cgroup') / group.lstrip('/')
                sample = {'at': now(), 'elapsed_seconds': time.monotonic() - started,
                    'state': status,
                    'memory_current': number(last_group / 'memory.current') if last_group else None,
                    'memory_peak': number(last_group / 'memory.peak') if last_group else None,
                    'swap_current': number(last_group / 'memory.swap.current') if last_group else None}
                log.write(json.dumps(sample, sort_keys=True) + '\n'); log.flush(); samples.append(sample)
                if status.get('ActiveState') in ('inactive', 'failed') or status.get('LoadState') == 'not-found':
                    break
                time.sleep(0.5)
    finally:
        subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True)
        journal = subprocess.run(['journalctl', '--user', '-u', unit, '--no-pager', '-o', 'cat'], capture_output=True, text=True)
        (run / 'unit-output.log').write_text(journal.stdout + journal.stderr)
        status = state(unit)
        procs = (last_group / 'cgroup.procs').read_text().strip() if last_group and (last_group / 'cgroup.procs').exists() else ''
        write(run / 'cleanup.json', {'at': now(), 'state': status,
            'owned_cgroup_processes_empty': procs == '', 'MainPID_zero_or_unloaded': status.get('MainPID', '0') == '0'})
    result_path = run / 'network-data/fetch.json'
    timing = (run / 'resources.log').read_text() if (run / 'resources.log').exists() else ''
    code = re.search(r'Exit status:\s*(\d+)', timing)
    complete = result_path.exists() and code is not None and code.group(1) == '0'
    data = json.loads(result_path.read_bytes()) if complete else None
    peaks = [row['memory_peak'] for row in samples if row['memory_peak'] is not None]
    swaps = [row['swap_current'] for row in samples if row['swap_current'] is not None]
    result = {'completed_at': now(), 'status': 'FETCHED_PENDING_REPLAY' if complete else 'INCOMPLETE',
        'endpoint': plan['endpoint'], 'wall_seconds': time.monotonic() - started,
        'transactions_fetched': len(data['transactions']) if data else None,
        'fetch_json_sha256': hashlib.sha256(result_path.read_bytes()).hexdigest() if data else None,
        'sampled_cgroup_peak_bytes': max(peaks) if peaks else None,
        'sampled_swap_peak_bytes': max(swaps) if swaps else None,
        'raw_pages': len(data['pages']) if data else None, 'no_balance_or_recovery_claim': True}
    write(run / 'RESULT.json', result)
    print(json.dumps(result, sort_keys=True), flush=True)
    if not complete:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
