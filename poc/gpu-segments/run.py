#!/usr/bin/env python3
"""Compare RTX3070 segment sizes and prove the unchanged public classifier."""
import argparse
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'remote-cuda'))
import worker
from common import atomic, sha
from local_qualification import preflight, local_gpu_phase, require


def run(package, build, adapter, output):
    binary, _, hardware = preflight(package, build)
    require(adapter.is_file(), 'adapter binary missing')
    output.mkdir(exist_ok=False)
    atomic(output / 'provenance.json', {'scope': 'RTX3070_NEW_SEGMENTATION_SAME_PROXY_STATEMENT',
        'hardware': hardware, 'adapterSha256': sha(adapter.read_bytes()),
        'adapterSourceSha256': sha(Path(__file__).with_name('main.rs').read_bytes()),
        'runnerSourceSha256': sha(Path(__file__).read_bytes()), 'computeThreads': 4,
        'mainnet': False, 'nativeTransactions': 0, 'paidServices': 0})
    os.environ['RISC0_SERVER_PATH'] = str(binary)
    worker.MEMORY = 20 * 1024 ** 3
    results, choices = {}, []
    for po2 in (19, 18):
        preflight(package, build)
        label = f'po2-{po2}'
        directory = output / label
        # Export uses the genuine SDK executor, but is not a proof/GPU claim.
        export = worker.run_phase([str(adapter), 'export', str(package), str(directory), str(po2)],
            900, output / (label + '-export'), time.monotonic() + 930, False, hardware['uuid'])
        results[label] = {'export': export}
        if export['exitCode'] or export['failure']:
            atomic(output / 'progress.json', results)
            continue
        proof = local_gpu_phase([str(adapter), 'bench', str(directory)], 1800,
            output / (label + '-benchmark'), time.monotonic() + 1830, hardware['uuid'])
        results[label]['benchmark'] = proof
        if not proof['exitCode'] and not proof['failure']:
            bench = json.loads((directory / 'benchmark.json').read_text())
            session = json.loads((directory / 'session.json').read_text())
            require(bench['sealAndClaimMutationsRejected'] and not bench['developmentMode'], 'benchmark proof controls missing')
            rows = bench['timings']
            segment = sum(x['apiSeconds'] for x in rows if x['stage'] == 'segment') / 2
            lift = sum(x['apiSeconds'] for x in rows if x['stage'] == 'lift') / 2
            join = next(x['apiSeconds'] for x in rows if x['stage'] == 'join')
            # Selection heuristic only. Full-session time must be measured.
            estimate = session['segmentCount'] * (segment + lift) + (session['segmentCount'] - 1) * join
            choices.append({'po2': po2, 'estimatedSequentialApiSeconds': estimate,
                            'measuredTwoSegmentBenchmark': bench, 'segmentCount': session['segmentCount']})
        atomic(output / 'progress.json', results)
    require(choices, 'no segment size produced a verified GPU benchmark; see preserved progress/logs')
    choices.sort(key=lambda x: x['estimatedSequentialApiSeconds'])
    atomic(output / 'selection.json', {'scope': 'HEURISTIC_NOT_MEASURED_FULL_PROOF_TIME', 'rankedChoices': choices})
    # Use the official complete succinct-prover API, retaining candidates and
    # failures. Alternative fitting segmentation is permitted after a failure.
    completed = None
    for choice in choices:
        preflight(package, build)
        po2 = choice['po2']; label = f'full-po2-{po2}'
        proof = local_gpu_phase([str(adapter), 'prove', str(package), str(output / label), str(po2)],
            7200, output / label, time.monotonic() + 7230, hardware['uuid'])
        results[label] = proof
        atomic(output / 'progress.json', results)
        if proof['exitCode'] or proof['failure']:
            continue
        expected = output / 'independent-expectations'
        expected.mkdir()
        journal = (package / 'inputs/expected-journal.bin').read_bytes()
        # This is the original pinned public expectation, never receipt data.
        atomic(expected / 'expectations.json', {'expectedProgramImage': '397bcdca688462b9573a4b55e3516e1a2511140512c53337eb54da0849a93716',
                                              'mainJournalSha256': sha(journal)})
        (expected / 'expected-journal.bin').write_bytes(journal)
        check = worker.run_phase([str(package / 'bin/kpi-takeover-host'), 'outer-proof-128m', 'verify',
            str(expected), str(output / label), str(output / 'independent-verification')],
            120, output / 'independent-cpu', time.monotonic() + 150, False, hardware['uuid'])
        results['independent-cpu'] = check
        require(not check['exitCode'] and not check['failure'], 'independent original CPU verification failed')
        complete = json.loads((output / label / 'complete.json').read_text())
        completed = {'po2': po2, 'proof': complete,
                     'verification': json.loads((output / 'independent-verification/verification.json').read_text())}
        break
    result = {'scope': 'FULL_PROXY_CLASSIFIER_NOT_FULL_PRIVATE_PAYMENT_RELATION',
              'fullProxyClassifierProved': completed is not None, 'completed': completed,
              'reports': results, 'mainnet': False, 'nativeTransactions': 0, 'paidServices': 0}
    atomic(output / 'result.json', result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('package', 'build', 'adapter', 'output'):
        p.add_argument(name, type=Path)
    a = p.parse_args()
    # A repeated command must not write a failure marker into prior evidence.
    if a.output.exists():
        p.error('result directory already exists; choose a fresh output')
    try:
        result = run(*(getattr(a, name).resolve() for name in ('package', 'build', 'adapter', 'output')))
    except Exception as error:
        if not isinstance(error, FileExistsError) and a.output.is_dir():
            atomic(a.output / 'failure.json', {'fullProxyClassifierProved': False, 'error': str(error)})
        raise
    print(json.dumps({'fullProxyClassifierProved': result['fullProxyClassifierProved'],
                      'scope': result['scope']}))
    return 0 if result['fullProxyClassifierProved'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
