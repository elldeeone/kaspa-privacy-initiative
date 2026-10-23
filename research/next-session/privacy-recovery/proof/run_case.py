#!/usr/bin/env python3
"""Run one frozen full-CS case; parse errors are never UNSAT evidence."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def run(directory, unit):
    directory = Path(directory).resolve()
    plan = json.loads((directory / 'PLAN.json').read_bytes())
    freeze = json.loads((directory / 'RUNTIME-FREEZE.json').read_bytes())
    for entry in freeze['files']:
        raw = Path(entry['path']).read_bytes()
        if len(raw) != entry['bytes'] or hashlib.sha256(raw).hexdigest() != entry['sha256']:
            raise ValueError('frozen input changed: ' + entry['path'])
    status = subprocess.run(['systemctl', '--user', 'show', unit, '--property=LoadState', '--value'],
                            capture_output=True, text=True)
    if status.stdout.strip() not in ('not-found', ''):
        raise ValueError('unit identity already used')
    properties = ['LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlGroup',
                  'CPUUsageNSec', 'MemoryCurrent', 'MemoryPeak', 'MemorySwapCurrent', 'InvocationID']
    started = now()
    rows = []
    child = None
    with (directory / 'unit.log').open('x') as log:
        try:
            child = subprocess.Popen(['systemd-run', '--user', '--wait', '--pipe', '--unit=' + unit,
                '--property=CPUQuota=' + str(plan['cpu_workers'] * 100) + '%',
                '--property=MemoryMax=' + str(plan['memory_max_bytes']), '--property=MemorySwapMax=0',
                '--property=RuntimeMaxSec=3600', '/usr/bin/time', '-v', '-o', str(directory / 'resources.log'),
                '/bin/bash', str(directory / 'runtime.sh')], stdout=log, stderr=subprocess.STDOUT)
            while child.poll() is None:
                result = subprocess.run(['systemctl', '--user', 'show', unit,
                    '--property=' + ','.join(properties)], capture_output=True, text=True)
                row = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
                row['observed_utc'] = now()
                group = row.get('ControlGroup')
                if group:
                    base = Path('/sys/fs/cgroup') / group.lstrip('/')
                    for name in ('memory.current', 'memory.peak', 'memory.swap.current', 'cgroup.procs'):
                        try:
                            row[name] = (base / name).read_text().strip()
                        except OSError:
                            row[name] = None
                rows.append(row)
                time.sleep(0.5)
            returncode = child.wait()
        finally:
            subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True)
            if child is not None and child.poll() is None:
                child.wait(timeout=30)
            save(directory / 'telemetry.json', rows)
    final = subprocess.run(['systemctl', '--user', 'show', unit,
        '--property=' + ','.join(properties)], capture_output=True, text=True)
    state = dict(line.split('=', 1) for line in final.stdout.splitlines() if '=' in line)
    save(directory / 'CLEANUP.json', {'observed_utc': now(), 'unit': unit, 'state': state,
                                   'controller_returncode': returncode})
    report_path = directory / 'result/report.json'
    report = json.loads(report_path.read_bytes()) if report_path.exists() else None
    complete = (returncode == 0 and report is not None
        and type(report.get('satisfied')) is bool
        and report['satisfied'] == plan['expected_satisfied']
        and report['instance_variables'] == 3)
    if complete:
        original = json.loads(Path(plan['fixture_path']).read_bytes())
        observed = json.loads((directory / 'result/fixture.json').read_bytes())
        complete = original == observed
    result = {'schema': 'kpx3-complete-r1cs-case-result/v1', 'case': plan['case'],
        'start_utc': started, 'end_utc': now(), 'returncode': returncode, 'complete': complete,
        'expected_satisfied': plan['expected_satisfied'], 'actual_satisfied': None if report is None else report['satisfied'],
        'fixture_sha256': plan['fixture_sha256'], 'binary_sha256': plan['binary_sha256'],
        'report_sha256': hashlib.sha256(report_path.read_bytes()).hexdigest() if report else None,
        'host_parse_rejection_counted_as_unsat': False, 'telemetry_samples': len(rows)}
    save(directory / 'RESULT.json', result)
    print(json.dumps(result, sort_keys=True), flush=True)
    if not complete:
        raise SystemExit(1)


if __name__ == '__main__':
    run(sys.argv[1], sys.argv[2])
