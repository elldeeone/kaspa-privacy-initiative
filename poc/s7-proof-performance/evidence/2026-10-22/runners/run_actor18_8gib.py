#!/usr/bin/env python3
"""Separate actor18-8gib-20261022-01 profile; old6656MiB admissionFAIL stays frozen."""
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import time
import sys

ROOT = pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
assert len(sys.argv) == 1
BACKEND = 'actor'
NAME = 'actor18-8gib-20261022-01'
TARGET = ROOT.parent / 'performance-target'
UNIT = 'kpi-b2-performance-' + NAME + '.service'
MONITOR = TARGET / (NAME + '-monitor')
HOST = TARGET / 'selected-client/kpi-s7-proof-performance'
WORKER = ROOT.parent / 'proof-target/tools/r0vm-cuda'
INPUT = ROOT.parent / 'lifecycle-outer-target/publication/input.bin'
PROGRAMS = ROOT.parent / 'lifecycle-outer-target/programs-stage00'
OUTPUT = TARGET / NAME

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def write(name, data):
    (MONITOR / name).write_text(json.dumps(data, indent=2) + '\n')

def properties():
    p = subprocess.run(['systemctl', '--user', 'show', UNIT,
        '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID', '-p', 'ControlGroup',
        '-p', 'ExecMainStatus', '-p', 'Result', '-p', 'MemoryPeak', '-p', 'MemorySwapPeak',
        '-p', 'CPUUsageNSec', '-p', 'MemoryMax', '-p', 'MemorySwapMax', '-p', 'CPUQuotaPerSecUSec',
        '-p', 'ExecMainStartTimestamp', '-p', 'ExecMainExitTimestamp'], capture_output=True, text=True)
    return dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)

def process(pid):
    try:
        p = pathlib.Path('/proc') / str(pid)
        stat = (p / 'stat').read_text()
        fields = stat[stat.rfind(')')+2:].split()
        return {'pid': pid, 'start_ticks': int(fields[19]),
                'exe': str((p / 'exe').resolve()),
                'cmdline': (p / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')}
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None

def main():
    freeze = json.loads((TARGET / 'selected-client/actor18-8gib-20261022-01-freeze.json').read_text())
    assert freeze['experiment_id'] == NAME
    assert freeze['primary_peak_mib'] + freeze['recursion_peak_mib'] + 512 <= 7680
    for label, item in freeze['selected_evidence'].items():
        with pathlib.Path(item['path']).open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == item['sha256'], label
    with pathlib.Path(__file__).open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == freeze['runner_sha256']
    old_gate = json.loads((TARGET / 'ipc18-memory-gate.json').read_text())
    assert old_gate['admission_passes'] is False and old_gate['independent_receipt_verified'] is True
    for path, expected in [
        (HOST, freeze['client_sha256']),
        (WORKER, '3f22b68b6d32904fe766e14e62ce011febdc946dd98d015747f40ce5fb5fffc7'),
        (INPUT, 'eab451e4701d2fa65c5a5a2cf23a0d1c9483723951c0382989c8e0e9decfaa39'),
        (PROGRAMS / 'guest.program.bin', '7f853b7cbdf0044a061057eac9e0ddc826b949969db06c31adf6bdf1215c805f'),
    ]:
        with path.open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == expected, path
    for relative, expected in freeze['source_files'].items():
        with (TARGET / 'selected-client/source' / relative).open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == expected, relative
    check_gpu = subprocess.run(['nvidia-smi', '--query-compute-apps=pid', '--format=csv,noheader,nounits'],capture_output=True,text=True,check=True)
    assert not check_gpu.stdout.strip(), 'another GPU process is already active'
    assert not OUTPUT.exists()
    MONITOR.mkdir()
    scratch = TARGET / (NAME + '-work')
    scratch.mkdir()
    cache = TARGET / (NAME + '-cache')
    cache.mkdir()
    home = TARGET / (NAME + '-home')
    home.mkdir()

    # Verify the chosen network namespace supports the SDK's local IPC socket
    # before any proving begins. No guest execution or GPU is used here.
    check = subprocess.run(['/usr/bin/bwrap', '--unshare-net', '--ro-bind', '/', '/',
        '--dev', '/dev', '--proc', '/proc', '/usr/bin/python3', '-c',
        'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(); '
        'c=socket.socket(); c.connect(s.getsockname()); a,_=s.accept(); print("local IPC available; external network isolated")'],
        check=True, capture_output=True, text=True, timeout=10)
    (MONITOR / 'network-preflight.txt').write_text(check.stdout)

    env = ['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LANG=C.UTF-8', 'HOME=' + os.environ['HOME'],
        'RISC0_PROVER=' + BACKEND, 'RISC0_SERVER_PATH=' + str(WORKER),
        'RISC0_WORK_DIR=' + str(scratch), 'RISC0_HOME=' + str(home),
        'XDG_CACHE_HOME=' + str(cache), 'GITHUB_TOKEN=',
        'RAYON_NUM_THREADS=6', 'OMP_NUM_THREADS=6', 'TOKIO_WORKER_THREADS=6', 'RISC0_DEFAULT_PROVER_NUM_GPUS=1', 'CUDA_VISIBLE_DEVICES=0',
        'RISC0_INFO=1', 'TMPDIR=/tmp', 'RUST_LOG=info,risc0_zkvm::host::server::prove=debug,risc0_zkvm::host::recursion::prove=debug', 'LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu']
    workload = ['/usr/bin/bwrap', '--die-with-parent', '--unshare-net',
        '--ro-bind', '/', '/', '--bind', str(TARGET), str(TARGET),
        '--ro-bind', str(TARGET / 'selected-client'), str(TARGET / 'selected-client'),
        '--ro-bind', str(TARGET / 'tools'), str(TARGET / 'tools'),
        '--dev-bind', '/dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp',
        '--chdir', str(ROOT), '/usr/bin/time', '-v', '-o', str(MONITOR / 'resources.txt'),
        *env, str(HOST), BACKEND, str(PROGRAMS), str(INPUT), str(OUTPUT)]
    command = ['systemd-run', '--user', '--unit=' + UNIT, '--service-type=exec',
        '--property=RemainAfterExit=yes', '--property=RuntimeMaxSec=3600',
        '--property=MemoryMax=8G', '--property=MemorySwapMax=0', '--property=CPUQuota=600%',
        '--property=KillMode=control-group', '--property=TimeoutStopSec=10',
        '--property=WorkingDirectory=' + str(ROOT),
        '--property=StandardOutput=append:' + str(MONITOR / 'stdout.log'),
        '--property=StandardError=append:' + str(MONITOR / 'stderr.log'), *workload]
    started = time.monotonic()
    launch = {'unit': UNIT, 'start_utc': now(), 'deadline_utc':
        (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=3600)).isoformat(),
        'plan_sha256': freeze['plan_sha256'], 'client_sha256': freeze['client_sha256'], 'experiment_id': NAME, 'sampled_gpu_guard_mib': 7680, 'old6656_admission_remains_failed': True,
        'command': command, 'scope': 'one complete genuine unchanged B2 claim with backend ' + BACKEND + ', segment_limit_po218; no compression',
        'cuda_worker_sha256': '3f22b68b6d32904fe766e14e62ce011febdc946dd98d015747f40ce5fb5fffc7'}
    result = subprocess.run(command, capture_output=True, text=True)
    launch.update(launch_returncode=result.returncode, launch_stdout=result.stdout, launch_stderr=result.stderr)
    write('launch.json', launch)
    if result.returncode:
        raise SystemExit(result.stderr)
    launch['properties_after_start'] = properties()
    write('launch.json', launch)
    print(json.dumps({key: launch[key] for key in ['unit', 'start_utc', 'deadline_utc', 'properties_after_start']}), flush=True)

    peak_gpu = 0
    peak_memory = 0
    topology_failed = False
    guard_exceeded = False
    gpu_sample_errors = 0
    cgroup_sample_errors = 0
    shared_gpu_samples = 0
    successful_gpu_samples = 0
    observed = {}
    with (MONITOR / 'resource-samples.jsonl').open('w') as stream:
        while True:
            props = properties()
            sample = {'at': now(), 'seconds': time.monotonic()-started, 'unit': props}
            cg = props.get('ControlGroup')
            pids = set()
            if cg:
                group = pathlib.Path('/sys/fs/cgroup') / cg.lstrip('/')
                try:
                    pids = {int(pid) for pid in (group / 'cgroup.procs').read_text().split()}
                    sample['memory_current'] = int((group / 'memory.current').read_text())
                    sample['memory_peak'] = int((group / 'memory.peak').read_text())
                    sample['swap_current'] = int((group / 'memory.swap.current').read_text())
                    sample['cpu_stat'] = (group / 'cpu.stat').read_text()
                    peak_memory = max(peak_memory, sample['memory_peak'])
                except FileNotFoundError as error:
                    sample['cgroup_sample_error'] = str(error)
                    cgroup_sample_errors += 1
            sample['processes'] = [info for pid in sorted(pids) if (info := process(pid))]
            for info in sample['processes']:
                observed[(info['pid'], info['start_ticks'])] = info
            try:
                gpu = subprocess.run(['nvidia-smi', '--query-compute-apps=pid,used_gpu_memory',
                    '--format=csv,noheader,nounits'], capture_output=True, text=True, timeout=5)
                sample['gpu_query_returncode'] = gpu.returncode
                if gpu.returncode:
                    raise ValueError('GPU process query failed: ' + gpu.stderr.strip())
                owned = []
                foreign = []
                for line in gpu.stdout.splitlines():
                    pid, memory = [value.strip() for value in line.split(',')]
                    # A worker can start between cgroup.procs and NVML reads.
                    # Resolve such a PID against the exact owned cgroup, never
                    # infer ownership from executable name or a stale PID.
                    if int(pid) not in pids and cg:
                        try:
                            membership = (pathlib.Path('/proc') / pid / 'cgroup').read_text().splitlines()
                            if '0::' + cg in membership:
                                pids.add(int(pid))
                                if (info := process(int(pid))):
                                    observed[(info['pid'], info['start_ticks'])] = info
                                    sample['processes'].append(info)
                        except (FileNotFoundError, ProcessLookupError, PermissionError):
                            pass
                    if int(pid) in pids:
                        owned.append({'pid': int(pid), 'used_mib': int(memory)})
                    else:
                        foreign.append({'pid': int(pid), 'used_mib': int(memory)})
                unexpected = []
                for row in owned:
                    info = process(row['pid'])
                    if not info:
                        raise ValueError('GPU PID identity missing during topology check')
                    if info['exe'] != str(WORKER) or '--rpc' in info['cmdline'] or '--config' not in info['cmdline']:
                        unexpected.append(info)
                if len(owned) > 2 or unexpected:
                    sample['unexpected_gpu_topology'] = unexpected or owned
                    topology_failed = True
                    subprocess.run(['systemctl','--user','stop',UNIT],check=True)
                sample['unmatched_gpu_processes'] = foreign
                shared_gpu_samples += bool(foreign)
                sample['matching_gpu_processes'] = owned
                summed_gpu = sum(row['used_mib'] for row in owned)
                peak_gpu = max(peak_gpu, summed_gpu)
                if summed_gpu > 7680:
                    sample['vram_guard_exceeded'] = True
                    guard_exceeded = True
                    subprocess.run(['systemctl','--user','stop',UNIT],check=True)
                telemetry = subprocess.run(['nvidia-smi', '--query-gpu=index,memory.used,utilization.gpu,power.draw,temperature.gpu,clocks.current.sm,clocks.current.memory,pstate',
                    '--format=csv,noheader,nounits'], capture_output=True, text=True, timeout=5)
                sample['gpu_telemetry_returncode'] = telemetry.returncode
                if telemetry.returncode or not telemetry.stdout.strip():
                    raise ValueError('GPU clock/global query failed: ' + telemetry.stderr.strip())
                sample['gpu_global_csv'] = telemetry.stdout.strip()
                successful_gpu_samples += 1
            except (ValueError, subprocess.TimeoutExpired) as error:
                sample['gpu_sample_error'] = str(error)
                gpu_sample_errors += 1
            stream.write(json.dumps(sample)+'\n'); stream.flush()
            if props.get('SubState') in ['exited','failed','dead'] or props.get('ActiveState') in ['inactive','failed']:
                final = props
                break
            if time.monotonic()-started > 3610:
                subprocess.run(['systemctl','--user','stop',UNIT],check=True)
            time.sleep(0.1)

    write('terminal-result.json', {'unit': UNIT, 'completed_utc': now(), 'seconds': time.monotonic()-started,
        'properties_before_stop': final, 'sampled_matching_gpu_peak_mib': peak_gpu,
        'cgroup_memory_peak_bytes': peak_memory, 'vram_guard_exceeded': guard_exceeded, 'unexpected_gpu_topology': topology_failed,
        'gpu_sample_errors': gpu_sample_errors, 'cgroup_sample_errors': cgroup_sample_errors,
        'shared_gpu_samples': shared_gpu_samples, 'successful_gpu_samples': successful_gpu_samples,
        'actor_profile_memory_measurement_complete': bool(successful_gpu_samples and not gpu_sample_errors and not cgroup_sample_errors and not shared_gpu_samples and not topology_failed), 'backend': BACKEND, 'segment_limit_po2': 18, 'sampling_requested_interval_seconds': 0.1,
        'measurement_limits': 'GPU samples can miss brief peaks; only matching unit process IDs counted. Global GPU power/utilization are not process-specific.'})
    subprocess.run(['systemctl','--user','stop',UNIT],check=True)
    cleanup = []
    for (pid,ticks), old in observed.items():
        current = process(pid)
        cleanup.append({'pid':pid,'start_ticks':ticks,'same_identity_alive':bool(current and current['start_ticks']==ticks)})
    write('cleanup.json',cleanup)
    print((MONITOR/'terminal-result.json').read_text(),flush=True)
    assert not any(row['same_identity_alive'] for row in cleanup), 'owned workload process survived cleanup'
    if topology_failed:
        raise SystemExit('Unexpected GPU process topology; retained failure, no automatic retry')
    if guard_exceeded:
        raise SystemExit('Matching GPU memory exceeded7680MiB; retained failure, no automatic retry')
    if final.get('ExecMainStatus') != '0' or final.get('Result') != 'success':
        raise SystemExit('GPU proof failed; see preserved unit logs and candidate artifacts')

if __name__ == '__main__':
    main()
