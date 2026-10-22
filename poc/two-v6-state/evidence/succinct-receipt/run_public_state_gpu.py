#!/usr/bin/env python3
"""One selected NONFUNDABLE historical-state GPU proof; matching process telemetry."""
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import time

ROOT = pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/proof')
TARGET = ROOT.parent / 'proof-target'
UNIT = 'kpi-two-v6-state-gpu-proof-20261022.service'
MONITOR = TARGET / 'two-v6-state-proof-monitor'
HOST = TARGET / 'two-v6-state-selected-host/kpi-two-v6-state-proof-host'
WORKER = TARGET / 'tools/r0vm-cuda'
INPUT = ROOT / 'poc/two-v6-state/public-fixtures/historical-anchor/input.bin'
PROGRAMS = TARGET / 'two-v6-state-programs'
OUTPUT = TARGET / 'two-v6-state-proof'

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
    reconstruction = json.loads((TARGET / 'two-v6-state-build-archive/reproduction.json').read_text())
    assert reconstruction['byte_identical_to_original_record'] and reconstruction['selected_pin_restored']
    assert reconstruction['restored_selected_sha256'] == 'efba3e34eaca4b42e01c27ee92389bf0a46fa3708f7e15e77a43037384d90d01'
    selection = json.loads((ROOT / 'poc/two-v6-state/host/pins/guest-selection.json').read_text())
    assert selection['image'] == 'e9d7bd51e12b253c5cb7839d6854cf30d387dea95aff4e853feb47eb6d0edcf9'
    assert selection['root_selection_sha256'] == '8dda29d52299cab6e8da2079b57340defa99bb6e473b9da62580ceaae97bd75d'
    for path, expected in [
        (HOST, 'efba3e34eaca4b42e01c27ee92389bf0a46fa3708f7e15e77a43037384d90d01'),
        (WORKER, '3f22b68b6d32904fe766e14e62ce011febdc946dd98d015747f40ce5fb5fffc7'),
        (INPUT, '544219aaba5b4738a546691eed6cc7b93a4cda6f2c3b158ef51fbf8c4bcbf462'),
        (PROGRAMS / 'guest.program.bin', 'd1336290bd4b8555edea9c5d7dd56aa4883f1d185b0a4aca9b08105b0537097a'),
    ]:
        with path.open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == expected, path
    assert not OUTPUT.exists()
    MONITOR.mkdir()
    scratch = TARGET / 'two-v6-state-gpu-work'
    scratch.mkdir()
    cache = TARGET / 'two-v6-state-gpu-cache'
    cache.mkdir()
    home = TARGET / 'two-v6-state-gpu-risc0-home'
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
        'RISC0_PROVER=ipc', 'RISC0_SERVER_PATH=' + str(WORKER),
        'RISC0_WORK_DIR=' + str(scratch), 'RISC0_HOME=' + str(home),
        'XDG_CACHE_HOME=' + str(cache), 'GITHUB_TOKEN=',
        'RAYON_NUM_THREADS=8', 'OMP_NUM_THREADS=8', 'CUDA_VISIBLE_DEVICES=0',
        'RUST_LOG=info', 'LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu']
    workload = ['/usr/bin/bwrap', '--die-with-parent', '--unshare-net',
        '--ro-bind', '/', '/', '--bind', str(TARGET), str(TARGET),
        '--dev-bind', '/dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp',
        '--chdir', str(ROOT), '/usr/bin/time', '-v', '-o', str(MONITOR / 'resources.txt'),
        *env, str(HOST), 'prove', 'historical-anchor', str(PROGRAMS), str(INPUT), str(OUTPUT)]
    command = ['systemd-run', '--user', '--unit=' + UNIT, '--service-type=exec',
        '--property=RemainAfterExit=yes', '--property=RuntimeMaxSec=3600',
        '--property=MemoryMax=10G', '--property=MemorySwapMax=0', '--property=CPUQuota=800%',
        '--property=KillMode=control-group', '--property=TimeoutStopSec=10',
        '--property=WorkingDirectory=' + str(ROOT),
        '--property=StandardOutput=append:' + str(MONITOR / 'stdout.log'),
        '--property=StandardError=append:' + str(MONITOR / 'stderr.log'), *workload]
    started = time.monotonic()
    launch = {'unit': UNIT, 'start_utc': now(), 'deadline_utc':
        (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=3600)).isoformat(),
        'command': command, 'scope': 'one genuine NONFUNDABLE historical-anchor synthetic-state Succinct receipt attempt',
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
                    peak_memory = max(peak_memory, sample['memory_peak'])
                except FileNotFoundError:
                    pass
            sample['processes'] = [info for pid in sorted(pids) if (info := process(pid))]
            for info in sample['processes']:
                observed[(info['pid'], info['start_ticks'])] = info
            try:
                gpu = subprocess.run(['nvidia-smi', '--query-compute-apps=pid,used_gpu_memory',
                    '--format=csv,noheader,nounits'], capture_output=True, text=True, timeout=5)
                owned = []
                for line in gpu.stdout.splitlines():
                    pid, memory = [value.strip() for value in line.split(',')]
                    if int(pid) in pids:
                        owned.append({'pid': int(pid), 'used_mib': int(memory)})
                sample['matching_gpu_processes'] = owned
                peak_gpu = max(peak_gpu, sum(row['used_mib'] for row in owned))
                telemetry = subprocess.run(['nvidia-smi', '--query-gpu=index,memory.used,utilization.gpu,power.draw,temperature.gpu',
                    '--format=csv,noheader,nounits'], capture_output=True, text=True, timeout=5)
                sample['gpu_global_csv'] = telemetry.stdout.strip()
            except (ValueError, subprocess.TimeoutExpired) as error:
                sample['gpu_sample_error'] = str(error)
            stream.write(json.dumps(sample)+'\n'); stream.flush()
            if props.get('SubState') in ['exited','failed','dead'] or props.get('ActiveState') in ['inactive','failed']:
                final = props
                break
            if time.monotonic()-started > 3610:
                subprocess.run(['systemctl','--user','stop',UNIT],check=True)
            time.sleep(0.5)

    write('terminal-result.json', {'unit': UNIT, 'completed_utc': now(), 'seconds': time.monotonic()-started,
        'properties_before_stop': final, 'sampled_matching_gpu_peak_mib': peak_gpu,
        'cgroup_memory_peak_bytes': peak_memory, 'sampling_interval_seconds': 0.5,
        'measurement_limits': 'GPU samples can miss brief peaks; only matching unit process IDs counted. Global GPU power/utilization are not process-specific.'})
    subprocess.run(['systemctl','--user','stop',UNIT],check=True)
    cleanup = []
    for (pid,ticks), old in observed.items():
        current = process(pid)
        cleanup.append({'pid':pid,'start_ticks':ticks,'same_identity_alive':bool(current and current['start_ticks']==ticks)})
    write('cleanup.json',cleanup)
    print((MONITOR/'terminal-result.json').read_text(),flush=True)
    assert not any(row['same_identity_alive'] for row in cleanup), 'owned workload process survived cleanup'
    if final.get('ExecMainStatus') != '0' or final.get('Result') != 'success':
        raise SystemExit('GPU proof failed; see preserved unit logs and candidate artifacts')

if __name__ == '__main__':
    main()
