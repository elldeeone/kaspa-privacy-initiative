#!/usr/bin/env python3
"""Reproduce Stage 2's audit from retained chain bodies, without any network."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
CASES = {
    'compact-rehearsal': ('2026-10-19-compact/rehearsal', True),
    'compact-trial': ('2026-10-19-compact/trial', False),
    'recovery-trial': ('2026-10-19-recovery/trial', True),
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, obj):
    with path.open('x') as out:
        json.dump(obj, out, indent=2)
        out.write('\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    parser.add_argument('--venv', type=Path,
                        default=Path('/home/luke/.local/share/kpi-shared-pool-tools'))
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    observer = HERE/'compact_observer.py'
    evidence = {}
    with tempfile.TemporaryDirectory(prefix='kpi-chain-audit-') as tmp:
        for name, (relative, values) in CASES.items():
            source = HERE/'evidence'/relative/'chain-confirmed.json'
            original = source.read_bytes()
            records = json.loads(original)['transactions']
            projected = {'schema': 'kpi-compact-chain-observer-v1', 'network': 'testnet-10',
                         'records': [{'transaction': r['transaction'],
                                      'header': r.get('header', r.get('acceptedHeader'))} for r in records]}
            raw = (json.dumps(projected, sort_keys=True, separators=(',', ':'))+'\n').encode()
            chain = Path(tmp)/(name+'.json')
            chain.write_bytes(raw)
            output = root/name
            output.mkdir()
            sandbox = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
                       '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
                       '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
                       '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
                       '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
                       '--ro-bind', str(args.venv.resolve()), '/venv',
                       '--ro-bind', str(observer), '/observer.py',
                       '--ro-bind', str(chain), '/chain.json',
                       '--bind', str(output), '/result', '--chdir', '/result']
            probe = ('import pathlib,json; '
                     "assert not pathlib.Path('/home/luke').exists(); "
                     "interfaces=[l.split(':')[0].strip() for l in pathlib.Path('/proc/net/dev').read_text().splitlines() if ':' in l]; "
                     "assert interfaces==['lo']; "
                     "print(json.dumps({'host_home_accessible':False,'network_interfaces':interfaces,"
                     "'private_truth_mounted':False,'chain_input':'/chain.json',"
                     "'protocol_software':'/observer.py'}))")
            isolated = subprocess.run(sandbox+['--', '/venv/bin/python', '-c', probe],
                                      check=True, capture_output=True, text=True)
            write(output/'isolation.json', json.loads(isolated.stdout))
            command = sandbox+['--', '/venv/bin/python', '/observer.py', '/chain.json', '/result/observer.json']
            if values:
                command.append('--joint-values')
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            write(output/'execution.json', {'exit_code': result.returncode,
                                           'stdout': json.loads(result.stdout), 'stderr': result.stderr})
            evidence[name] = {'retained_chain_file': 'poc/shared-pool/evidence/'+relative+'/chain-confirmed.json',
                              'retained_chain_sha256': digest(original), 'observer_input_sha256': digest(raw),
                              'observer_output_sha256': digest((output/'observer.json').read_bytes()),
                              'joint_values': values, 'transactions': len(records)}

    # Scoring runs OUTSIDE the attack sandbox after all attack outputs exist.
    # These selected workload facts were already published in COMPACT.md; this
    # is a separate consistency check, not blinded population-level accuracy.
    scored = []
    for name in ['compact-rehearsal', 'compact-trial']:
        relative = CASES[name][0]
        source = json.loads((HERE/'evidence'/relative/'chain-confirmed.json').read_text())
        true_source = source['transactions'][1]['transaction']['id']
        observed = json.loads((root/name/'observer.json').read_text())
        first = observed['rows'][0]
        for horizon in ['at_withdrawal', 'complete_trace']:
            row = first[horizon]['anchor_single_spend']
            candidates = observed['candidate_sets'][row['candidate_set']]['creation_transaction_candidates']
            if true_source not in candidates:
                raise ValueError('documented ground truth excluded')
            scored.append({'case': name, 'horizon': horizon, 'withdrawal_txid': first['withdrawal_txid'],
                           'documented_source_txid': true_source,
                           'correct_singleton': row['singleton_source_prediction'] == true_source,
                           'source_candidates': row['source_candidate_count'],
                           'position_candidates': row['position_candidate_count']})
    write(root/'scoring.json', {'truth_source': 'COMPACT.md: question and workload; not observer input',
                              'selected_withdrawals': 2, 'horizons_per_withdrawal': 2,
                              'rows': scored, 'population_accuracy': None,
                              'scope': 'Exploratory source certificates; no claim about owner identity'})
    write(root/'provenance.json', {
        'baseline': 'af9bae8afabbdb56bc52b59980ffb48f5f824af5', 'cases': evidence,
        'software_sha256': {p.name: digest(p.read_bytes()) for p in
                            [observer, Path(__file__), HERE/'test_compact_observer.py', HERE/'PRIVACY-AUDIT-SPEC.md']},
        'new_native_transactions': 0, 'new_native_fees_sompi': 0,
        'chain_projection': 'Only transaction and accepted block header, canonical compact JSON with sorted keys and final newline',
        'scope': 'Offline reanalysis of earlier accepted synthetic TN10 traces; no fresh network observation'})
    print(json.dumps({'complete': True, 'cases': len(CASES),
                      'selected_source_certificates_correct': all(r['correct_singleton'] for r in scored),
                      'new_native_transactions': 0, 'new_native_fees_sompi': 0}))


if __name__ == '__main__':
    main()
