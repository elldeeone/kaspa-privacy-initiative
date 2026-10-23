#!/usr/bin/env python3
"""Execute each distinct frozen CS case once with bounded useful parallelism."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run_case(case, controller):
    directory = Path(case['directory'])
    if sha(directory / 'RUNTIME-FREEZE.json') != case['runtime_freeze_sha256']:
        raise ValueError('case freeze changed')
    process = subprocess.run([sys.executable, '-B', str(controller), str(directory), case['unit']],
                             capture_output=True, text=True)
    (directory / 'controller-output.log').write_text(process.stdout + process.stderr)
    return {'case': case['case'], 'returncode': process.returncode,
            'result_path': str(directory / 'RESULT.json')}


def main():
    directory = Path(sys.argv[1]).resolve()
    plan_path = directory / 'PLAN.json'
    plan = json.loads(plan_path.read_bytes())
    freeze = json.loads((directory / 'RUNTIME-FREEZE.json').read_bytes())
    for entry in freeze['files']:
        if Path(entry['path']).stat().st_size != entry['bytes'] or sha(entry['path']) != entry['sha256']:
            raise ValueError('batch input changed')
    if (directory / 'RESULTS.json').exists():
        raise ValueError('completed batch identity must not repeat')
    first_path = Path(plan['positive_spend_completed_once'])
    if sha(first_path) != plan['positive_spend_sha256']:
        raise ValueError('first positive closure changed')
    first = json.loads(first_path.read_bytes())
    if first['complete'] is not True or first['actual_satisfied'] is not True:
        raise ValueError('first sizing case did not pass')
    controller = directory.parent / 'run_case.py'
    begin = time.monotonic()
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    completed = []
    peak = 0
    with ThreadPoolExecutor(max_workers=plan['parallel_cases']) as pool:
        futures = [pool.submit(run_case, case, controller) for case in plan['cases']]
        for future in as_completed(futures):
            item = future.result()
            completed.append(item)
            # All active case cgroups are private to this batch. Their current
            # memory includes allocation/page-cache accounting, not RSS alone.
            current = 0
            for case in plan['cases']:
                telemetry = Path(case['directory']) / 'telemetry.json'
                # Live controllers retain their sample vectors until cleanup;
                # query each unit's cgroup directly instead of guessing RSS.
                result = subprocess.run(['systemctl', '--user', 'show', case['unit'],
                    '--property=MemoryCurrent', '--value'], capture_output=True, text=True)
                if result.stdout.strip().isdigit():
                    current += int(result.stdout.strip())
            peak = max(peak, current)
            print(json.dumps({'completed': len(completed), 'remaining': len(plan['cases']) - len(completed),
                              'case': item['case'], 'returncode': item['returncode']}), flush=True)
    reports = [first]
    for item in completed:
        path = Path(item['result_path'])
        reports.append(json.loads(path.read_bytes()) if path.exists() else
                       {'case': item['case'], 'complete': False, 'actual_satisfied': None})
    satisfied = sum(item.get('complete') is True and item.get('actual_satisfied') is True for item in reports)
    unsatisfied = sum(item.get('complete') is True and item.get('actual_satisfied') is False for item in reports)
    result = {'schema': 'kpx3-complete-private-action-CS-controls/v1', 'classification': 'PUBLIC_SYNTHETIC_DO_NOT_FUND',
        'plan_sha256': sha(plan_path), 'start_utc': started,
        'end_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'wall_seconds': time.monotonic() - begin,
        'actual_sat': satisfied, 'actual_unsat': unsatisfied, 'expected_sat': 8, 'expected_unsat': 41,
        'all_complete': len(reports) == 49 and satisfied == 8 and unsatisfied == 41,
        'first_case_executed_once': True, 'parser_or_host_errors_counted_as_unsat': False,
        'parallel_cases': plan['parallel_cases'], 'completion_sampled_aggregate_cgroup_memory_peak_bytes': peak,
        'memory_sampling_boundary': 'Completion-time samples only; per-case 0.5-second telemetry is authoritative for local peaks.',
        'cases': sorted(reports, key=lambda item: item['case'])}
    (directory / 'RESULTS.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: result[key] for key in ('all_complete', 'actual_sat', 'actual_unsat', 'wall_seconds')}), flush=True)
    if not result['all_complete']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
