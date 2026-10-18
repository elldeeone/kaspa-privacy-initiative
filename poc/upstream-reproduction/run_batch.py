#!/usr/bin/env python3
"""Measure one local upstream proof and verify using the unchanged CPU package.

Inputs are public upstream fixtures. Never pass private wallet material here.
Fresh output directories are required; failures and candidate receipts survive.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def group_stats(group):
    pids, rss = set(), 0
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            fields = (path/'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) == group:
                pids.add(int(path.name))
                rss += max(0, int(fields[21])) * os.sysconf('SC_PAGE_SIZE')
        except (OSError, ValueError, IndexError):
            pass
    return pids, rss


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('cuda_prover', type=Path)
    parser.add_argument('case', choices=['deposit', 'credit-transfer', 'exit', 'reconcile'])
    parser.add_argument('output', type=Path)
    parser.add_argument('--producer', type=Path, help='explicitly recorded segmentation-adapted host')
    parser.add_argument('--seconds', type=int, default=3600, help='remaining shared allowance, at most 3600')
    args = parser.parse_args()
    assert 0 < args.seconds <= 3600
    package, cuda, output = (p.resolve() for p in (args.package, args.cuda_prover, args.output))
    producer = (args.producer or package/'bin/kpi-private-native-producer').resolve()
    verifier = package/'bin/kpi-private-native-verifier'
    assert sha(verifier) == 'd9ee19513d2ba2b4296e0e9c4199c175ba2d0948b0f130d3df53a5e875415109'
    assert 'RISC0_DEV_MODE' not in os.environ
    output.mkdir(parents=True, exist_ok=False)
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'LD_LIBRARY_PATH') if k in os.environ}
    env.update(RISC0_PROVER='ipc', RISC0_SERVER_PATH=str(cuda),
               RISC0_DEFAULT_PROVER_NUM_GPUS='1', RAYON_NUM_THREADS='4',
               OMP_NUM_THREADS='4', OPENBLAS_NUM_THREADS='4', RUST_LOG='info')
    cpus = sorted(os.sched_getaffinity(0))[:4]
    command = ['timeout', '--signal=KILL', str(args.seconds), 'taskset', '-c',
               ','.join(map(str, cpus)), str(producer), 'prove', args.case,
               str(package/'inputs'), str(output/'proof')]
    report = dict(case=args.case, command=command, producerSha256=sha(producer),
                  verifierSha256=sha(verifier), cudaProverSha256=sha(cuda),
                  cpuAffinity=cpus, threads=4, samplingIntervalSeconds=1,
                  startUtc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  devMode=False, actualTN10Broadcast=False, privateWitnesses=False)
    (output/'invocation.json').write_text(json.dumps(report, indent=2)+'\n')
    started = time.monotonic()
    peak_rss = peak_gpu = 0
    gpu_observed = False
    child = None
    try:
        with (output/'stdout.log').open('x') as stdout, (output/'stderr.log').open('x') as stderr, \
                (output/'samples.jsonl').open('x') as samples:
            child = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
            while child.poll() is None:
                pids, rss = group_stats(child.pid)
                matching = []
                try:
                    query = subprocess.run(['nvidia-smi', '--query-compute-apps=pid,used_gpu_memory',
                                            '--format=csv,noheader,nounits'], capture_output=True, text=True, timeout=15)
                    telemetry_code, telemetry_text = query.returncode, query.stdout
                except (OSError, subprocess.TimeoutExpired):
                    telemetry_code, telemetry_text = None, ''
                if telemetry_code == 0:
                    for line in telemetry_text.splitlines():
                        fields = [f.strip() for f in line.split(',')]
                        if len(fields) == 2 and fields[0].isdigit() and fields[1].isdigit() and int(fields[0]) in pids:
                            matching.append(dict(pid=int(fields[0]), vramMiB=int(fields[1])))
                vram = sum(row['vramMiB'] for row in matching)
                peak_rss, peak_gpu = max(peak_rss, rss), max(peak_gpu, vram)
                gpu_observed |= bool(matching)
                samples.write(json.dumps(dict(seconds=time.monotonic()-started, summedRssBytes=rss,
                                               matchingGpuProcesses=matching, telemetryExitCode=telemetry_code))+'\n')
                samples.flush()
                time.sleep(1)
            report.update(exitCode=child.returncode, producerProcessSeconds=time.monotonic()-started,
                          peakSampledSummedRssBytes=peak_rss, peakSampledMatchingVramMiB=peak_gpu,
                          matchingGpuProcessObserved=gpu_observed)
    finally:
        if child is not None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
        (output/'measurement.json').write_text(json.dumps(report, indent=2)+'\n')
    receipt = output/'proof/receipt.bin'
    if not receipt.exists():
        receipt = output/'proof/candidate-receipt.bin'
    if receipt.exists():
        cpu_env = {k: env[k] for k in ('PATH', 'HOME', 'LD_LIBRARY_PATH') if k in env}
        with (output/'cpu.log').open('x') as log:
            subprocess.run([str(verifier), 'verify-receipt', args.case, str(receipt), str(output/'cpu')],
                           env=cpu_env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=120)
            if args.case == 'exit':
                subprocess.run([str(verifier), 'verify-native-exit', str(receipt), str(output/'native-exit')],
                               env=cpu_env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=120)
        report.update(receiptSha256=sha(receipt), independentCpuVerified=True)
        (output/'measurement.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    raise SystemExit(report['exitCode'])


if __name__ == '__main__':
    main()
