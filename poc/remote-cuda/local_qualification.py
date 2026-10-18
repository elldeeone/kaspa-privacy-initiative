#!/usr/bin/env python3
"""Separate local sm86 qualification. Never calls the remote L40S service.

Uses only the pinned public five-phase workload and an sm86 CUDA build. This
script deliberately does not weaken hardware() or lease checks for rentals.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from common import atomic, sha
from package import CLAIMS, IMAGE, checked_archive
from worker import PHASES, check_inputs, gpu_query, run_phase

SOURCE = '14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6'
LOCK = '15995a3395e61847c403182721c13c56f8735c8d22ed989dc350c5621d812024'


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def local_gpu_phase(arguments, limit, prefix, deadline, gpu_uuid):
    # Desktop graphics can raise device-wide utilization. Require SM activity
    # attributed to a PID observed in this proof's process group as well.
    with tempfile.TemporaryFile(mode='w+') as raw:
        sampler = subprocess.Popen(['nvidia-smi', 'pmon', '-s', 'um', '-d', '1'],
                                   stdout=raw, stderr=subprocess.DEVNULL)
        try:
            # pmon's first utilization window is one second. Start its window
            # before subsecond recursion work rather than sampling only after
            # that process has already exited. Proof timing starts below.
            time.sleep(0.55)
            report = run_phase(arguments, limit, prefix, deadline, True, gpu_uuid)
        finally:
            sampler.terminate()
            sampler.wait(timeout=10)
        pids = set()
        for line in prefix.with_suffix('.samples.jsonl').read_text().splitlines():
            pids.update(json.loads(line)['groupPids'])
        raw.seek(0)
        matching = []
        for line in raw:
            fields = line.split()
            if len(fields) >= 5 and fields[0] == '0' and fields[1].isdigit():
                if int(fields[1]) in pids and fields[3].isdigit():
                    matching.append({'pid': int(fields[1]), 'smPercent': int(fields[3])})
    observed = any(row['smPercent'] > 0 for row in matching)
    atomic(prefix.with_suffix('.process-gpu.json'), {'matchingProcessSamples': matching,
                                                   'positiveProcessSmObserved': observed})
    report['positiveProcessSmObserved'] = observed
    if not observed and report['failure'] is None:
        report['failure'] = 'per-process-gpu-sm-activity-not-established'
    atomic(prefix.with_suffix('.resources.json'), report)
    return report


def preflight(package, build_directory):
    require(__debug__, 'legacy worker validation requires Python without -O')
    require('RISC0_DEV_MODE' not in os.environ, 'development mode must be absent')
    build = json.loads((build_directory / 'cuda-build.json').read_text())
    require(build['sourceCommit'] == SOURCE and build['upstreamCargoLockSha256'] == LOCK,
            'upstream source or lock identity mismatch')
    require(build['features'] == ['cuda', 'disable-dev-mode'] and build['nvccFlags'] == '-arch=sm_86',
            'local sm86 CUDA and disabled development mode required')
    binary = build_directory / 'bin/r0vm-cuda'
    require(sha(binary.read_bytes()) == build['binarySha256'], 'CUDA binary identity mismatch')
    policy = json.loads((package / 'workload.json').read_text())
    reference = json.loads((Path(__file__).parent / 'evidence/workload.json').read_text())
    require(policy == reference and policy['expectedProgramImage'] == IMAGE and policy['cpuClaims'] == CLAIMS,
            'original workload policy mismatch')
    check_inputs(package, policy)
    rows = gpu_query(['--query-gpu=name,uuid,memory.total,driver_version,compute_cap'])
    require(len(rows) == 1 and rows[0][0] == 'NVIDIA GeForce RTX 3070' and rows[0][4] == '8.6',
            'this local experiment requires exactly one RTX 3070 sm86')
    require(not gpu_query(['--query-compute-apps=pid,gpu_uuid,used_gpu_memory']), 'another compute process is active')
    return binary, policy, {'name': rows[0][0], 'uuid': rows[0][1], 'vramMiB': float(rows[0][2]),
                           'driverVersion': rows[0][3], 'computeCapability': rows[0][4], 'build': build}


def qualify(package, build_directory, output, recursion_only=False):
    started = time.monotonic()
    binary, policy, hardware = preflight(package, build_directory)
    output.mkdir(parents=False, exist_ok=False)
    atomic(output / 'hardware.json', {**hardware, 'scope': 'LOCAL_RTX3070_NOT_REMOTE_L40S',
        'availableCpuAffinity': sorted(os.sched_getaffinity(0)), 'realFundsOrBroadcasts': False,
        'firstUseJit': 'included in the first proof phase; fresh experiment-local CUDA cache'})
    shutil.copytree(package / 'inputs', output / 'assets')
    input_proofs = {}
    phases = PHASES
    if recursion_only:
        # Retained CPU proofs are inputs, never CUDA-produced receipts. This
        # diagnostic must never satisfy the original five-GPU-phase gate.
        evidence = Path(__file__).parent / 'evidence'
        manifest = json.loads((evidence / 'manifest.json').read_text())
        reference = checked_archive(evidence / 'public-package.tar.gz',
                                    manifest['files']['public-package.tar.gz']['sha256'])
        for index in (24, 25):
            name = f'segment-{index}.bin'
            raw = (package / 'baseline' / name).read_bytes()
            require(raw == reference['baseline/' + name], 'original CPU proof identity mismatch')
            (output / 'assets' / name).write_bytes(raw)
            input_proofs[name] = {'origin': 'retained original CPU proof', 'sha256': sha(raw)}
        atomic(output / 'input-proof-origins.json', input_proofs)
        phases = [phase for phase in PHASES if not phase[0].startswith('segment-')]
    os.environ['RISC0_SERVER_PATH'] = str(binary)
    host = str(package / 'bin/kpi-takeover-host')
    deadline = started + 3600
    reports, completed = {}, []
    for phase, limit, command in phases:
        arguments = [host, 'phase-diagnostics', command[0], str(output / 'assets'), *command[1:]]
        report = local_gpu_phase(arguments, limit, output / phase, deadline, hardware['uuid'])
        reports[phase] = report
        if report['exitCode'] != 0 or report['failure']:
            break
        receipt = json.loads((output / 'assets' / (phase + '-verified.json')).read_text())
        require(receipt['claimDigest'] == policy['cpuClaims'][phase], 'returned claim differs from original CPU claim')
        completed.append(phase)
        atomic(output / 'progress.json', {'completed': completed, 'reports': reports})
    # Always try to verify the receipts that were actually saved. No receipts
    # or a partial set cannot satisfy the strict five-receipt qualification.
    mode = 'compare' if len(completed) == len(phases) else 'compare-partial'
    command = [host, 'phase-diagnostics', mode, str(output / 'assets')]
    reports['independent-cpu-compare'] = run_phase(command, 120, output / 'independent-cpu-compare',
                                                  time.monotonic() + 150, False, hardware['uuid'])
    comparison_path = output / 'assets/cpu-comparison.json'
    comparison = json.loads(comparison_path.read_text()) if comparison_path.exists() else None
    accepted = (len(completed) == len(phases) and comparison is not None and comparison['allFiveSealsVerified'] and
                all(row['exitCode'] == 0 and row['failure'] is None for row in reports.values()))
    result = {'scope': ('LOCAL_RECURSION_DIAGNOSTIC_CPU_SEGMENT_INPUTS' if recursion_only else
                       'LOCAL_RTX3070_PARTIAL_WORKLOAD_NOT_FULL_CLASSIFIER'),
              'cudaQualificationPassed': accepted and not recursion_only,
              'recursionDiagnosticPassed': accepted if recursion_only else None,
              'inputProofOrigins': input_proofs, 'completedPhases': completed, 'reports': reports,
              'comparison': comparison, 'wallSeconds': time.monotonic() - started,
              'gpuRentalCreated': False, 'nativeTransactions': 0, 'fullClassifierProved': False,
              'independentVerification': 'original pinned CPU verifier in a separate process on this host'}
    atomic(output / 'result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('build', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--recursion-only', action='store_true',
                        help='GPU lifts/join of original CPU segment receipts; never five-phase qualification')
    args = parser.parse_args()
    if args.preflight_only:
        _, _, hardware = preflight(args.package.resolve(), args.build.resolve())
        print(json.dumps({'scope': 'LOCAL_PREFLIGHT_ONLY_NOT_CUDA_PROOF', 'hardware': hardware['name']}))
        return 0
    result = qualify(args.package.resolve(), args.build.resolve(), args.output.resolve(), args.recursion_only)
    print(json.dumps({key: result[key] for key in ('scope', 'cudaQualificationPassed', 'recursionDiagnosticPassed',
                                                'completedPhases', 'fullClassifierProved')}))
    return 0 if result['cudaQualificationPassed'] or result['recursionDiagnosticPassed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
