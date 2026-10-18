#!/usr/bin/env python3
"""Execute invalid full-wallet witnesses in the real VM; produces no proof."""
import json
import os
from pathlib import Path
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'remote-cuda'))
import worker
from common import atomic, sha


def main():
    host, build, cases, output = map(lambda s: Path(s).resolve(), sys.argv[1:])
    if 'RISC0_DEV_MODE' in os.environ: raise RuntimeError('development mode forbidden')
    metadata = json.loads((build / 'cuda-build.json').read_text())
    binary = build / 'bin/r0vm-cuda'
    if sha(binary.read_bytes()) != metadata['binarySha256']:
        raise RuntimeError('pinned VM binary changed')
    os.environ['RISC0_SERVER_PATH'] = str(binary)
    output.mkdir(exist_ok=False)
    reports = {}
    for case in sorted(cases.iterdir()):
        result = worker.run_phase(
            [str(host), 'execute-negative', str(case), str(output / case.name)],
            3600, output / f'{case.name}-resources', time.monotonic() + 3630, False, '')
        if result['exitCode'] or result['failure']:
            atomic(output / 'failure.json', {'case': case.name, 'resources': result})
            raise RuntimeError(f'VM rejection control failed: {case.name}; logs retained')
        reports[case.name] = json.loads((output / case.name / 'report.json').read_text())
    atomic(output / 'result.json', {
        'scope': 'INVALID_WALLET_VM_EXECUTION_CONTROLS_NOT_INVALIDITY_PROOFS',
        'vmRejections': reports, 'hostSha256': sha(host.read_bytes()),
        'vmBinarySha256': sha(binary.read_bytes()), 'nativeTransactions': 0})
    print(f'{len(reports)} invalid full-wallet VM executions rejected for expected relation reasons')


if __name__ == '__main__': main()
