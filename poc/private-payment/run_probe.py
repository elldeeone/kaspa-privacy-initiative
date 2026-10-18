#!/usr/bin/env python3
"""Prove one public Orchard primitive vector; never authorize a payment."""
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
    require(host.is_file(), 'primitive probe host missing')
    output.mkdir(exist_ok=False)
    atomic(output / 'provenance.json', {
        'scope': 'PUBLIC_ORCHARD_PRIMITIVE_VM_COMPATIBILITY_NOT_PAYMENT_PROOF',
        'hardware': hardware, 'hostSha256': sha(host.read_bytes()),
        'caseSha256': sha((case / 'case.json').read_bytes()),
        'runnerSha256': sha(Path(__file__).read_bytes()),
        'hostSourceSha256': sha((Path(__file__).parent / 'primitive-vectors/src/bin/probe_host.rs').read_bytes()),
        'guestSourceSha256': sha((Path(__file__).parent / 'primitive-probe-guest/src/main.rs').read_bytes()),
        'computeThreads': 4, 'mainnet': False, 'nativeTransactions': 0,
    })
    os.environ['RISC0_SERVER_PATH'] = str(binary)
    worker.MEMORY = 20 * 1024 ** 3
    reports = {}
    reports['profile'] = worker.run_phase([str(host), 'profile', str(case), str(output / 'profile')],
        3600, output / 'profile-resources', time.monotonic() + 3630, False, hardware['uuid'])
    atomic(output / 'progress.json', reports)
    require(not reports['profile']['exitCode'] and not reports['profile']['failure'], 'primitive VM execution failed; logs retained')
    preflight(package, build)
    reports['proof'] = local_gpu_phase([str(host), 'prove', str(case), str(output / 'proof')],
        7200, output / 'proof-resources', time.monotonic() + 7230, hardware['uuid'])
    atomic(output / 'progress.json', reports)
    require(not reports['proof']['exitCode'] and not reports['proof']['failure'], 'primitive GPU proof failed; logs retained')
    # A distinct process loads retained bytes against the frozen upstream
    # expectation. It shares the pinned SDK and is not an independent audit.
    reports['verification'] = worker.run_phase([str(host), 'verify', str(case),
        str(output / 'proof/candidate-receipt.bin'), str(output / 'verification')],
        120, output / 'verification-resources', time.monotonic() + 150, False, hardware['uuid'])
    atomic(output / 'progress.json', reports)
    require(not reports['verification']['exitCode'] and not reports['verification']['failure'], 'saved-receipt CPU verification failed')
    result = {'scope': 'PUBLIC_PRIMITIVE_RECEIPT_NOT_PRIVATE_PAYMENT_RELATION',
        'primitiveVmReceiptVerified': True, 'fullWalletRelationImplemented': False,
        'reports': reports, 'mainnet': False, 'nativeTransactions': 0}
    atomic(output / 'result.json', result)
    print(json.dumps({'primitiveVmReceiptVerified': True, 'scope': result['scope']}))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('package', 'build', 'host', 'case', 'output'):
        p.add_argument(name, type=Path)
    a = p.parse_args()
    if a.output.exists():
        p.error('output exists; choose a fresh directory')
    try:
        run(*(getattr(a, name).resolve() for name in ('package', 'build', 'host', 'case', 'output')))
    except Exception as error:
        if not isinstance(error, FileExistsError) and a.output.is_dir():
            atomic(a.output / 'failure.json', {'primitiveVmReceiptVerified': False, 'error': str(error)})
        raise


if __name__ == '__main__':
    main()
