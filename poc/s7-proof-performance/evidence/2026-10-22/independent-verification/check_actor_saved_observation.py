#!/usr/bin/env python3
"""Read saved actor telemetry and current cleanup state; never launches work."""
import hashlib
import json
import re
import subprocess
from pathlib import Path

BASE = Path('/home/luke/projects/kpi-intensive-2026-10-22')
PERF = BASE/'performance-target'
NAME = 'actor18-8gib-20261022-01'
MONITOR = PERF/(NAME+'-monitor')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_start(pid):
    try:
        raw = (Path('/proc')/str(pid)/'stat').read_text()
        return int(raw.rsplit(')', 1)[1].split()[19])
    except FileNotFoundError:
        return None


def main():
    terminal = json.loads((MONITOR/'terminal-result.json').read_bytes())
    cleanup = json.loads((MONITOR/'post-guard-cleanup.json').read_bytes())
    samples = [json.loads(line) for line in (MONITOR/'resource-samples.jsonl').read_text().splitlines()]
    raw_log = (MONITOR/'stdout.log').read_text()
    log = re.sub(r'\x1b\[[0-9;]*m', '', raw_log)
    flagged = [s for s in samples if s.get('unexpected_gpu_topology')]
    assert len(flagged) == 1 and len(flagged[0]['unexpected_gpu_topology']) == 1
    flag = flagged[0]
    missing = flag['unexpected_gpu_topology'][0]
    assert missing['pid'] == 2387963 and missing['start_ticks'] == 39888998
    assert missing['cmdline'] == '' and missing['exe'] == '/proc/2387963/exe'
    earlier_valid = [p for s in samples if s['seconds'] < flag['seconds'] for p in s.get('processes', [])
                     if p['pid'] == missing['pid'] and p['start_ticks'] == missing['start_ticks']
                     and p['exe'] == str(BASE/'proof-target/tools/r0vm-cuda') and '--config' in p['cmdline']]
    assert earlier_valid
    peak = max(sum(p['used_mib'] for p in s.get('matching_gpu_processes', [])) for s in samples)
    assert peak == terminal['sampled_matching_gpu_peak_mib'] == 5532
    assert terminal['vram_guard_exceeded'] is False and terminal['unexpected_gpu_topology'] is True
    assert terminal['actor_profile_memory_measurement_complete'] is False
    assert len(samples) == terminal['successful_gpu_samples'] == 2974
    assert terminal['gpu_sample_errors'] == terminal['cgroup_sample_errors'] == terminal['shared_gpu_samples'] == 0
    assert all(len(s.get('matching_gpu_processes', [])) <= 2 for s in samples)
    assert max(s.get('swap_current', 0) for s in samples) == 0
    counts = {name: len(re.findall(r': '+name+r':', log)) for name in ['ProveSegmentDone', 'LiftDone', 'JoinDone', 'JobDone']}
    # JobDone is emitted by the manager; the count is retained separately from the task counts.
    assert counts['JoinDone'] == 389 and counts['LiftDone'] == 390 and counts['JobDone'] == 1
    processes = []
    for row in cleanup['identities']:
        observed = current_start(row['pid'])
        alive = observed == row['start_ticks']
        assert not alive
        processes.append({'pid': row['pid'], 'start_ticks': row['start_ticks'], 'same_identity_alive_independently': alive})
    assert len(processes) == 6
    unit = 'kpi-b2-performance-'+NAME+'.service'
    result = subprocess.run(['systemctl', '--user', 'show', unit, '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID', '-p', 'ControlGroup'], capture_output=True, text=True)
    properties = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    assert properties['ActiveState'] == 'inactive' and properties['SubState'] == 'dead'
    assert properties['MainPID'] == '0' and properties['ControlGroup'] == ''
    gpu = subprocess.run(['nvidia-smi', '--query-compute-apps=pid,used_gpu_memory', '--format=csv,noheader,nounits'], capture_output=True, text=True)
    assert gpu.returncode == 0 and not gpu.stdout.strip()
    files = ['terminal-result.json', 'post-guard-cleanup.json', 'launch.json', 'stdout.log', 'stderr.log', 'resource-samples.jsonl', 'resources.txt']
    assert not (PERF/NAME/'report.json').exists() and not (PERF/NAME/'receipt.bin').exists()
    candidate = PERF/NAME/'candidate-receipt.bin'
    assert sha(candidate) == '2891e246e4feff140528a28215562ac1bb512a206f3792b56a6277a89ef722cc'
    report = {
        'scope': 'Read-only saved actor artifacts and live cleanup state; no repeat or proof generation.',
        'identities': {str(MONITOR/f): sha(MONITOR/f) for f in files},
        'candidate_sha256': sha(candidate),
        'independent_crypto_verification_report_sha256': sha(Path(__file__).with_name('actor18-8gib-receipt-independent-01')/'independent-report.json'),
        'operational_result': 'FAIL retained; missing post-Drop/client report and incomplete memory qualification',
        'guard_diagnosis': 'Known primary PID/start identity became empty cmdline/missing executable while exiting; frozen topology check classified it as unexpected. No additional GPU process observed.',
        'guard_sample_at': flag['at'], 'guard_identity': missing,
        'shutdown_warning_precedes_guard': 'SDK Failed to shutdown warnings at22:02:55.043546/.067847 precede guard22:02:55.101701; causality must not be reversed.',
        'job_done_timestamp': '2026-10-22T22:02:55.041987Z',
        'proof_request_timestamp': '2026-10-22T21:55:26.810255Z',
        'log_request_to_jobdone_seconds': 448.231732,
        'duration_limit': 'Log interval is not the missing API response/Drop/complete elapsed report; above60-second diagnostic and not p95/end-to-end.',
        'task_counts_from_log': counts,
        'samples': len(samples), 'sampled_matching_gpu_peak_mib': peak,
        'vram_guard_limit_mib': 7680, 'vram_guard_exceeded': False,
        'completed_memory_qualification': False,
        'cgroup_memory_peak_bytes': terminal['cgroup_memory_peak_bytes'],
        'observed_swap_peak_bytes': 0,
        'processes': processes, 'unit_now': properties, 'gpu_compute_apps_empty_now': True,
        'old6656_gate_failure_unchanged': True,
    }
    target = Path(__file__).with_name('actor18-8gib-cleanup-and-observation-independent.json')
    with target.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'crypto': 'PASS separately verified', 'operational': 'FAIL', 'cleanup': 'PASS', 'report_sha256': sha(target)}))


if __name__ == '__main__':
    main()
