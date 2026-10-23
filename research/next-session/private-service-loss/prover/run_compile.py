#!/usr/bin/env python3
"""Compile selected cold software only; no parameter load, unit test or proof."""
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


def main():
    evidence = Path(sys.argv[1]).resolve()
    plan = json.loads((evidence / 'PLAN.json').read_bytes())
    for pin in json.loads((evidence / 'RUNTIME-FREEZE.json').read_bytes())['files']:
        raw = Path(pin['path']).read_bytes()
        if len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']:
            raise ValueError('frozen source/build input changed')
    unit = plan['unit']
    if subprocess.run(['systemctl', '--user', 'show', unit, '--property=LoadState', '--value'],
                      capture_output=True, text=True).stdout.strip() not in ('', 'not-found'):
        raise ValueError('build unit identity already used')
    properties = ['ActiveState', 'SubState', 'MainPID', 'ControlGroup', 'CPUUsageNSec',
                  'MemoryCurrent', 'MemoryPeak', 'MemorySwapCurrent']
    rows, child, returncode, error = [], None, None, None
    start = now()
    try:
        with (evidence / 'unit.log').open('x') as log:
            child = subprocess.Popen(['systemd-run', '--user', '--wait', '--pipe', '--unit=' + unit,
                '--property=CPUQuota=' + str(plan['cpu_workers'] * 100) + '%',
                '--property=MemoryMax=' + str(plan['memory_max_bytes']), '--property=MemorySwapMax=0',
                '--property=RuntimeMaxSec=10800', '/bin/bash', str(evidence / 'runtime.sh')],
                stdout=log, stderr=subprocess.STDOUT)
            while child.poll() is None:
                result = subprocess.run(['systemctl', '--user', 'show', unit,
                    '--property=' + ','.join(properties)], capture_output=True, text=True)
                row = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
                row['observed_utc'] = now()
                group = row.get('ControlGroup')
                if group:
                    for name in ('memory.current', 'memory.peak', 'memory.swap.current'):
                        try:
                            row[name] = (Path('/sys/fs/cgroup') / group.lstrip('/') / name).read_text().strip()
                        except OSError:
                            row[name] = None
                rows.append(row)
                time.sleep(0.5)
            returncode = child.wait()
    except BaseException as caught:
        error = type(caught).__name__
        raise
    finally:
        subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True)
        if child is not None and child.poll() is None:
            child.wait(timeout=30)
        final = subprocess.run(['systemctl', '--user', 'show', unit,
            '--property=' + ','.join(properties)], capture_output=True, text=True)
        save(evidence / 'telemetry.json', rows)
        save(evidence / 'CLEANUP.json', {'state':dict(line.split('=',1) for line in final.stdout.splitlines() if '=' in line),
            'returncode':returncode, 'error':error, 'observed_utc':now(), 'unit':unit})
    save(evidence / 'RESULT.json', {'start_utc':start, 'end_utc':now(), 'returncode':returncode,
        'selected_full_relation_setup_or_proof_run':False, 'old_PK_or_matrix_mounted':False,
        'private_profile_or_witness_mounted':False, 'parameter_loading_or_unit_test_run':False})
    print(json.dumps({'returncode':returncode, 'unit':unit}), flush=True)
    if returncode:
        raise SystemExit(returncode)


if __name__ == '__main__':
    main()
