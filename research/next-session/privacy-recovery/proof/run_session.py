#!/usr/bin/env python3
"""Monitor one fresh resident-key session; no key reload or old-matrix API."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def copy_exact(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.read_bytes() != source.read_bytes():
            raise ValueError('immutable public output changed')
    else:
        shutil.copyfile(source, destination)


def main():
    evidence = Path(sys.argv[1]).resolve()
    plan = json.loads((evidence / 'PLAN.json').read_bytes())
    for entry in json.loads((evidence / 'RUNTIME-FREEZE.json').read_bytes())['files']:
        if Path(entry['path']).stat().st_size != entry['bytes'] or digest(entry['path']) != entry['sha256']:
            raise ValueError('frozen session input changed')
    stage = Path(plan['stage_directory'])
    if stage.exists():
        raise ValueError('fresh session stage required')
    stage.mkdir(mode=0o700)
    fifo = stage / 'commands.fifo'
    os.mkfifo(fifo, 0o600)
    control = os.open(fifo, os.O_RDWR)
    unit = plan['unit']
    if subprocess.run(['systemctl', '--user', 'show', unit, '--property=LoadState', '--value'],
                      capture_output=True, text=True).stdout.strip() not in ('not-found', ''):
        os.close(control)
        raise ValueError('session unit identity already used')
    properties = ['ActiveState', 'SubState', 'MainPID', 'ControlGroup', 'CPUUsageNSec',
                  'MemoryCurrent', 'MemoryPeak', 'MemorySwapCurrent', 'InvocationID']
    rows, seen = [], set()
    child = None
    returncode = None
    began = now()
    error = None
    try:
        with (evidence / 'unit.log').open('x') as log:
            child = subprocess.Popen(['systemd-run', '--user', '--wait', '--pipe', '--unit=' + unit,
                '--property=CPUQuota=' + str(plan['cpu_workers'] * 100) + '%',
                '--property=MemoryMax=' + str(plan['memory_max_bytes']), '--property=MemorySwapMax=0',
                '--property=RuntimeMaxSec=10800', '/bin/bash', str(evidence / 'runtime.sh')],
                stdin=control, stdout=log, stderr=subprocess.STDOUT)
            save(evidence / 'START.json', {'started_utc': began, 'unit': unit,
                'proxy_pid': child.pid, 'command_fifo': str(fifo), 'stage_directory': str(stage)})
            print(json.dumps({'event': 'session-started', 'unit': unit}), flush=True)
            while child.poll() is None:
                state = subprocess.run(['systemctl', '--user', 'show', unit,
                    '--property=' + ','.join(properties)], capture_output=True, text=True)
                row = dict(line.split('=', 1) for line in state.stdout.splitlines() if '=' in line)
                row['observed_utc'] = now()
                group = row.get('ControlGroup')
                if group:
                    cgroup = Path('/sys/fs/cgroup') / group.lstrip('/')
                    for name in ('memory.current', 'memory.peak', 'memory.swap.current', 'cgroup.procs'):
                        try:
                            row[name] = (cgroup / name).read_text().strip()
                        except OSError:
                            row[name] = None
                    row['process_memory'] = []
                    for pid in str(row.get('cgroup.procs') or '').split():
                        try:
                            lines = (Path('/proc') / pid / 'status').read_text().splitlines()
                            fields = {line.split(':', 1)[0]: line.split(':', 1)[1].strip()
                                      for line in lines if line.startswith(('Name:', 'VmRSS:', 'VmHWM:'))}
                            row['process_memory'].append(dict(pid=int(pid), **fields))
                        except OSError:
                            pass
                rows.append(row)
                # Producer emits these events only after its public report and
                # output files have been synced. Existence alone is insufficient.
                for line in (evidence / 'unit.log').read_text().splitlines():
                    try:
                        message = json.loads(line)
                    except ValueError:
                        continue
                    if message.get('event') == 'ready' and 'ready' not in seen:
                        report = json.loads((stage / 'setup-01/report.json').read_bytes())
                        if report['source_identity'] != plan['source_identity']:
                            raise ValueError('fresh compiled source identity mismatch')
                        expected = {'a': 3195134, 'b_g1': 3195134, 'b_g2': 3195134,
                                    'l': 3195131, 'h': 4194303, 'instances_including_one': 3}
                        if report['queries'] != expected:
                            raise ValueError('fresh matrix/query dimensions mismatch')
                        for name in ('report.json', 'verification-key.bin'):
                            copy_exact(stage / 'setup-01' / name, evidence / 'setup-01' / name)
                        ready = {'event': 'ready', 'vk_hex328': report['vk_hex328'],
                            'vk_path': str(evidence / 'setup-01/verification-key.bin'),
                            'vk_sha256': report['vk_sha256'], 'command_fifo': str(fifo),
                            'existing_PK_or_matrix_loaded': False, 'queries': expected}
                        save(evidence / 'READY.json', ready)
                        seen.add('ready')
                        print(json.dumps(ready), flush=True)
                    elif message.get('event') == 'proof-complete':
                        path = Path(message['report_path'])
                        if path.parts[:3] != ('/', 'out', 'proofs') or path.name != 'report.json':
                            raise ValueError('unexpected proof output path')
                        label = path.parent.name
                        if label not in plan['proof_case_names']:
                            raise ValueError('unselected proof case')
                        if label in seen:
                            continue
                        output = stage / 'proofs' / label
                        report = json.loads((output / 'report.json').read_bytes())
                        submission = json.loads((evidence / 'commands' / label / 'SUBMISSION.json').read_bytes())
                        if report.get('genuine_Groth16_verified') is not True:
                            raise ValueError('proof verification did not complete')
                        if report['fixture_sha256'] != submission['fixture_sha256']:
                            raise ValueError('proof did not use exact frozen submitted fixture')
                        if report['source_identity'] != plan['source_identity']:
                            raise ValueError('proof compiled source identity changed')
                        ready = json.loads((evidence / 'READY.json').read_bytes())
                        if report['vk_sha256'] != ready['vk_sha256']:
                            raise ValueError('proof changed the selected fresh key')
                        for name in ('report.json', 'proof128.bin', 'verification-key.bin', 'authorization528.bin'):
                            copy_exact(output / name, evidence / 'proofs' / label / name)
                        seen.add(label)
                        print(json.dumps({'event': 'proof-complete', 'case': label,
                            'report_path': str(evidence / 'proofs' / label / 'report.json')}), flush=True)
                time.sleep(0.5)
            returncode = child.wait()
    except BaseException as caught:
        error = type(caught).__name__ + ': ' + str(caught)
        raise
    finally:
        subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True)
        os.close(control)
        if child is not None and child.poll() is None:
            child.wait(timeout=30)
        state = subprocess.run(['systemctl', '--user', 'show', unit,
            '--property=' + ','.join(properties)], capture_output=True, text=True)
        save(evidence / 'telemetry.json', rows)
        save(evidence / 'CLEANUP.json', {'observed_utc': now(), 'state':
            dict(line.split('=', 1) for line in state.stdout.splitlines() if '=' in line),
            'returncode': returncode, 'error': error, 'unit': unit})
        resources = stage / 'resources-app.log'
        if resources.exists():
            copy_exact(resources, evidence / 'resources-app.log')
    result = {'schema': 'kpx3-one-fresh-setup-five-statement-proofs/v1',
        'start_utc': began, 'end_utc': now(), 'returncode': returncode,
        'fresh_setup_count': 1, 'expected_proof_cases': plan['proof_case_names'],
        'completed_proof_cases': sorted(seen - {'ready'}),
        'all_complete': returncode == 0 and set(plan['proof_case_names']).issubset(seen),
        'existing_PK_or_matrix_loaded': False, 'native_validation_here': False,
        'whole_process_resources_include_setup_all_proofs_and_idle_waiting': True,
        'phase_peaks_not_independent': True, 'p95_qualified': False}
    save(evidence / 'RESULT.json', result)
    print(json.dumps(result), flush=True)
    if not result['all_complete']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
