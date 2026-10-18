#!/usr/bin/env python3
"""Prove the full offline wallet relation on the qualified local RTX3070."""
import argparse
import json
import os
from pathlib import Path
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'remote-cuda'))
import worker
from common import atomic, sha
from local_qualification import local_gpu_phase, preflight, require


def run(package, build, host, case, output):
    binary, _, hardware = preflight(package, build)
    require(host.is_file(), 'wallet host missing')
    output.mkdir(exist_ok=False)
    atomic(output / 'provenance.json', {
        'scope': 'FULL_OFFLINE_WALLET_NOT_PROVED_OUTER_OR_NATIVE_BACKING',
        'hardware': hardware, 'hostSha256': sha(host.read_bytes()),
        'caseSha256': sha((case / 'case.json').read_bytes()),
        'runnerSha256': sha(Path(__file__).read_bytes()),
        'computeThreads': 4, 'segmentPo2': 19,
        'mainnet': False, 'nativeTransactions': 0,
        'privateWitnessPublished': False,
    })
    os.environ['RISC0_SERVER_PATH'] = str(binary)
    # Generous operational budgets; these do not change security predicates.
    worker.MEMORY = 32 * 1024 ** 3
    reports = {}
    reports['profile'] = worker.run_phase(
        [str(host), 'profile', str(case), str(output / 'profile')],
        86400, output / 'profile-resources', time.monotonic() + 86430,
        False, hardware['uuid'])
    atomic(output / 'progress.json', reports)
    require(not reports['profile']['exitCode'] and not reports['profile']['failure'],
            'wallet VM execution failed; logs retained')
    preflight(package, build)
    reports['proof'] = local_gpu_phase(
        [str(host), 'prove', str(case), str(output / 'proof')],
        86400, output / 'proof-resources', time.monotonic() + 86430,
        hardware['uuid'])
    atomic(output / 'progress.json', reports)
    require(not reports['proof']['exitCode'] and not reports['proof']['failure'],
            'wallet GPU proof failed; logs retained')
    reports['verification'] = worker.run_phase(
        [str(host), 'verify', str(case),
         str(output / 'proof/wallet-receipt.bin'), str(output / 'verification')],
        3600, output / 'verification-resources', time.monotonic() + 3630,
        False, hardware['uuid'])
    atomic(output / 'progress.json', reports)
    require(not reports['verification']['exitCode'] and not reports['verification']['failure'],
            'saved wallet receipt CPU verification failed')
    atomic(output / 'result.json', {
        'scope': 'REAL_OFFLINE_WALLET_RECEIPT_NOT_PROVED_OUTER_OR_NATIVE_BACKING',
        'walletReceiptVerified': True, 'reports': reports,
        'mainnet': False, 'nativeTransactions': 0})
    print(json.dumps({'walletReceiptVerified': True, 'case': case.name}))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('package', 'build', 'host', 'case', 'output'):
        p.add_argument(name, type=Path)
    a = p.parse_args()
    if a.output.exists(): p.error('output exists; choose a fresh directory')
    try:
        run(*(getattr(a, name).resolve() for name in ('package', 'build', 'host', 'case', 'output')))
    except Exception as error:
        if not isinstance(error, FileExistsError) and a.output.is_dir():
            atomic(a.output / 'failure.json', {'walletReceiptVerified': False, 'error': str(error)})
        raise


if __name__ == '__main__':
    main()
