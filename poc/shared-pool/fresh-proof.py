#!/usr/bin/env python3
"""Run/analyze/export H9 offline. All raw alternatives stay outside Git."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
CASES = ['singleton', 'low-a', 'low-b']
SOURCE_FILES = ['src/compact/fresh.rs', 'src/compact/mod.rs', 'src/compact/circuit.rs',
                'src/compact/covenant.rs', 'src/compact/tree.rs', 'src/compact/experiment.rs',
                'src/native.rs', 'src/protocol.rs', 'FRESH-PROOF-SPEC.md']


def read(path):
    return json.loads(path.read_text())


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    with path.open('x') as out:
        json.dump(value, out, indent=2)
        out.write('\n')
    path.chmod(0o600)


def directory(path):
    path.mkdir(parents=True, mode=0o700, exist_ok=False)


def sandbox():
    return ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
            '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'PYTHONDONTWRITEBYTECODE', '1']


def probe(base, output, inputs):
    code = ("import pathlib,json; assert not pathlib.Path('/home/luke').exists(); "
            "interfaces=[l.split(':')[0].strip() for l in pathlib.Path('/proc/net/dev').read_text().splitlines() if ':' in l]; "
            "assert interfaces==['lo']; print(json.dumps({'host_home_accessible':False,'network_interfaces':interfaces}))")
    result = subprocess.run(base+['--', '/usr/bin/python3', '-c', code], check=True, capture_output=True, text=True)
    value = json.loads(result.stdout)
    value['input_mounts'] = inputs
    save(output, value)


def prove(args):
    if args.root.is_relative_to(REPO):
        raise ValueError('raw run must be outside the repository')
    directory(args.root)
    pins = {str((HERE/p).relative_to(REPO)): sha((HERE/p).read_bytes()) for p in SOURCE_FILES}
    save(args.root/'source-pins.json', pins)
    save(args.root/'binary.json', {'sha256': sha(args.binary.read_bytes())})
    base = sandbox()+['--setenv', 'RAYON_NUM_THREADS', '4', '--ro-bind', str(args.binary), '/program',
                      '--ro-bind', str(args.params), '/params', '--bind', str(args.root), '/run-root']
    probe(base, args.root/'prover-isolation.json', ['/program', '/params'])
    save(args.root/'prover.resources.scope.json', {'measured_process': 'program_inside_sandbox'})
    with (args.root/'prover.stdout.json').open('x') as out, (args.root/'prover.stderr.log').open('x') as err:
        subprocess.run(base+['--', '/usr/bin/time', '-v', '-o', '/run-root/prover.resources.txt',
                       '/program', 'run', '/params', '/run-root/fixtures'],
                       stdout=out, stderr=err, check=True)


def score(truth, chain, observed):
    # Runs only in this controller, after the isolated observer has exited.
    true_by_step = {r['step']: r for r in truth['spends']}
    transactions = [r['transaction'] for r in chain['records']]
    results = {}
    for horizon in ['at_withdrawal', 'complete_trace']:
        result = {}
        for attack in ['anchor_single_spend', 'joint_values']:
            rows = []
            for observed_row in observed['rows']:
                row = observed_row[horizon][attack]
                real = true_by_step[observed_row['step']]
                true_source = transactions[real['source_step']]['id']
                candidates = observed['candidate_sets'][row['candidate_set']]
                if true_source not in candidates['creation_transaction_candidates'] or real['position'] not in candidates['consumed_position_candidates']:
                    raise ValueError('observer excluded hidden ground truth')
                ties = row['nearest_time_source_ties']
                rows.append({'source_candidates': row['source_candidate_count'],
                             'note_candidates': row['position_candidate_count'],
                             'unique_correct': row['singleton_source_prediction'] == true_source,
                             'recency_correct': ties[0] == true_source,
                             'recency_tie_count': len(ties),
                             'uniform_prior_expected_correct': 1/row['source_candidate_count']})
            total = len(rows)
            unique = sum(r['unique_correct'] for r in rows)
            target_index = next(i for i, r in enumerate(observed['rows']) if r['step'] == truth['target_step'])
            result[attack] = {
                'withdrawals': total, 'singleton_predictions': unique,
                'singleton_precision': 1.0 if unique else None, 'coverage': unique/total,
                'abstentions': total-unique,
                'full_coverage_recency_correct': sum(r['recency_correct'] for r in rows),
                'full_coverage_recency_success': sum(r['recency_correct'] for r in rows)/total,
                'uniform_candidate_prior_expected_success': sum(r['uniform_prior_expected_correct'] for r in rows)/total,
                'target': rows[target_index],
                'source_candidate_counts': [r['source_candidates'] for r in rows],
                'note_candidate_counts': [r['note_candidates'] for r in rows],
                'population_confidence_interval': None,
            }
        results[horizon] = result
    return results


def analyze(args):
    if args.root.is_relative_to(REPO):
        raise ValueError('raw run must be outside the repository')
    if sha(args.binary.read_bytes()) != read(args.root/'binary.json')['sha256']:
        raise ValueError('binary changed since proving')
    for name, digest in read(args.root/'source-pins.json').items():
        if sha((REPO/name).read_bytes()) != digest:
            raise ValueError('proving source/specification changed: '+name)
    if not read(args.root/'fixtures/result.json')['complete']:
        raise ValueError('proof generation incomplete')
    analysis = args.root/'analysis'
    directory(analysis)
    save(analysis/'validator.json', {'sha256': sha(args.validator.read_bytes()),
         'command': 'kpi-compact validate TX INPUT_CONTEXT',
         'scope': 'existing native validator, explicit synthetic UTXO contexts'})
    summary = {}
    for name in CASES:
        fixture = args.root/'fixtures'/name
        result = read(fixture/'result.json')
        truth = read(fixture/'private/truth.json')
        arms = {}
        for arm in ['old', 'fresh']:
            output = analysis/name/arm
            directory(output)
            settle_output = output/'settlement'; directory(settle_output)
            request = fixture/'private'/(arm+'-settlement.json')
            base = sandbox()+['--ro-bind', str(args.binary), '/program',
                              '--ro-bind', str(request), '/request.json',
                              '--bind', str(settle_output), '/output']
            probe(base, settle_output/'isolation.json', ['/program', '/request.json'])
            settled = subprocess.run(base+['--', '/program', 'settle', '/request.json', '/output'],
                                     check=True, capture_output=True, text=True)
            if json.loads(settled.stdout) != read(settle_output/'result.json'):
                raise ValueError('settlement receipt mismatch')
            trace = fixture/('private/old-arm' if arm == 'old' else 'fresh-arm')
            expected = read(trace/f'{truth["target_step"]:04}.json')
            if read(settle_output/'transaction.json') != expected:
                raise ValueError('isolated public rebuild differs from selected target')
            # Read every saved JSON transaction back into the existing native
            # validator, including ordinary funding. The proof harness also
            # validates the constructed transactions before serialization.
            replay = sandbox()+['--ro-bind', str(args.validator), '/validator',
                                '--ro-bind', str(trace), '/trace']
            replayed = []
            expected_metrics = read(trace/'metrics.json')
            for step in range(result['transactions_per_arm']):
                checked = subprocess.run(replay+['--', '/validator', 'validate',
                    f'/trace/{step:04}.json', f'/trace/{step:04}.inputs.json'],
                    check=True, capture_output=True, text=True)
                receipt = json.loads(checked.stdout)
                if not receipt['native_full'] or receipt['metrics'] != expected_metrics[step]:
                    raise ValueError('native JSON replay disagrees with construction')
                replayed.append(receipt)
            save(output/'native-replay.json', {'transactions': len(replayed), 'receipts': replayed,
                 'scope': 'native Full, policy and script metering with supplied synthetic UTXOs'})
            observer_output = output/'observer'; directory(observer_output)
            base = sandbox()+['--ro-bind', str(args.venv), '/venv',
                              '--ro-bind', str(HERE/'compact_observer.py'), '/compact_observer.py',
                              '--ro-bind', str(HERE/'fresh_observer.py'), '/fresh_observer.py',
                              '--ro-bind', str(trace/'chain.json'), '/chain.json',
                              '--bind', str(observer_output), '/output']
            probe(base, observer_output/'isolation.json', ['/compact_observer.py', '/fresh_observer.py', '/chain.json'])
            observed = subprocess.run(base+['--', '/venv/bin/python', '/fresh_observer.py', '/chain.json', '/output/observer.json'],
                                      check=True, capture_output=True, text=True)
            save(observer_output/'execution.json', {'exit_code': observed.returncode, 'stdout': json.loads(observed.stdout)})
            arms[arm] = score(truth, read(trace/'chain.json'), read(observer_output/'observer.json'))
        safe_controls = [{k: v for k, v in row.items() if k != 'private_error'}
                         for row in read(fixture/'private/native-controls.json')]
        if not all(r['native_rejected'] for r in safe_controls):
            raise ValueError('accepted negative control')
        # Counts and aggregates only: no old-arm source IDs, NFs or statements.
        summary[name] = {'execution': {k: v for k, v in result.items()
                                      if k not in {'fallback_sha256', 'target_step'}},
                         'controls': safe_controls, 'scores': arms}
    save(analysis/'summary.json', {'complete': True, 'cases': summary,
         'new_native_transactions': 0, 'new_native_fees_sompi': 0,
         'clock': 'synthetic matched schedule; no sleeping or mined timestamps',
         'scope': 'one ledger per fixture; mechanism comparison, not population anonymity or Stage 2 statistical qualification'})
    print(json.dumps({'analysis_complete': True, 'cases': len(summary)}))


def secret_material(root):
    secrets, old_proofs, old_auths = set(), set(), set()
    for name in CASES:
        private = root/'fixtures'/name/'private'
        material = read(private/'wallets.json')
        for wallet in material['wallets']:
            secrets.update(bytes(wallet[field]) for field in ['spending', 'viewing', 'native'])
        secrets.add(bytes(material['initial_note']['rho']))
        secrets.add(bytes(material['funding_key']))
        old, fresh = read(private/'fallback.bundle.json'), read(private/'fresh.bundle.json')
        old_proofs.add(bytes.fromhex(old['proof']))
        if old['authorization'] != fresh['authorization']:
            old_auths.add(bytes.fromhex(old['authorization']))
    return secrets, old_proofs, old_auths


def check_bytes(raw, forbidden):
    lower = raw.lower()
    private_lengths = {len(value) for value in forbidden}
    for value in forbidden:
        if value in raw or value.hex().encode() in lower:
            raise ValueError('private key or unused fallback material in export')
    try:
        decoded = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return
    def walk(item):
        if isinstance(item, list):
            if len(item) in private_lengths and all(type(x) is int and 0 <= x <= 255 for x in item) and bytes(item) in forbidden:
                raise ValueError('private material array in export')
            for value in item: walk(value)
        elif isinstance(item, dict):
            if {'spending', 'viewing', 'privateKey', 'private_key', 'initial_note', 'rho', 'funding_key'} & item.keys():
                raise ValueError('private field in export')
            for value in item.values(): walk(value)
    walk(decoded)


def export(args):
    summary = read(args.root/'analysis/summary.json')
    if not summary['complete']:
        raise ValueError('analysis incomplete')
    secrets, old_proofs, old_auths = secret_material(args.root)
    forbidden = secrets | old_proofs | old_auths
    # Exercise the export guard with real unused material, without printing it.
    tested = 0
    for value in [next(iter(secrets)), *old_proofs, *old_auths]:
        try: check_bytes(json.dumps({'probe': value.hex()}).encode(), forbidden)
        except ValueError: tested += 1
        else: raise ValueError('export guard accepted a secret/fallback injection')
    directory(args.destination)
    exported = {}
    def copy(source, relative):
        raw = source.read_bytes(); check_bytes(raw, forbidden)
        target = args.destination/relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        exported[relative] = sha(raw)
    copy(args.root/'analysis/summary.json', 'summary.json')
    copy(args.root/'source-pins.json', 'source-pins.json')
    copy(args.root/'binary.json', 'binary.json')
    copy(args.root/'prover-isolation.json', 'prover-isolation.json')
    copy(args.root/'analysis/validator.json', 'validator.json')
    # Detailed process-resource output can contain host paths; export only
    # explicitly selected numeric measurements from it.
    resources = (args.root/'prover.resources.txt').read_text()
    rss = next(int(line.split(':')[-1]) for line in resources.splitlines() if 'Maximum resident set size' in line)
    elapsed = next(line.split('):', 1)[-1].strip() for line in resources.splitlines() if 'Elapsed (wall clock)' in line)
    scope_path = args.root/'prover.resources.scope.json'
    process_measured = scope_path.exists() and read(scope_path)['measured_process'] == 'program_inside_sandbox'
    fixture_result = read(args.root/'fixtures/result.json')
    save(args.destination/'resources.json', {'prover_maximum_resident_kib': rss if process_measured else None,
        'outer_wrapper_maximum_resident_kib': None if process_measured else rss,
        'elapsed_wall_clock': elapsed,
        'memory_scope': 'prover measured inside sandbox' if process_measured else
                        'initial launcher timed bubblewrap externally; prover peak memory was not measured',
        'parameter_load_ms': fixture_result['parameter_load_ms'], 'vk_sha256': fixture_result['vk_sha256'],
        'rayon_threads': 4, 'scope': 'one process across three fixtures; local CPU, offline'})
    for name in CASES:
        fixture = args.root/'fixtures'/name
        count = summary['cases'][name]['execution']['transactions_per_arm']
        for step in range(count):
            for suffix in ['.json', '.inputs.json']:
                relative = f'{step:04}{suffix}'
                copy(fixture/'fresh-arm'/relative, f'{name}/fresh-arm/{relative}')
        for filename in ['chain.json', 'metrics.json']:
            copy(fixture/'fresh-arm'/filename, f'{name}/fresh-arm/{filename}')
        for arm in ['old', 'fresh']:
            copy(args.root/'analysis'/name/arm/'native-replay.json', f'{name}/{arm}-native-replay.json')
            for filename in ['result.json', 'isolation.json']:
                copy(args.root/'analysis'/name/arm/'settlement'/filename, f'{name}/{arm}-settlement-{filename}')
            copy(args.root/'analysis'/name/arm/'observer/isolation.json', f'{name}/{arm}-observer-isolation.json')
        copy(args.root/'analysis'/name/'fresh/observer/observer.json', f'{name}/fresh-observer.json')
    exported['resources.json'] = sha((args.destination/'resources.json').read_bytes())
    save(args.destination/'export.json', {'allowlist_only': True, 'exported_sha256': exported,
        'wallet_secret_values_checked': len(secrets), 'unused_fallback_proofs_checked': len(old_proofs),
        'distinct_old_authorizations_checked': len(old_auths), 'secret_injection_controls_passed': tested,
        'same_anchor_control': 'singleton authorization equals fresh public authorization; unused old proof stays private',
        'omitted': ['all old-arm transactions', 'both pending bundles', 'private settlement requests',
                    'wallets', 'note openings', 'truth', 'rejected transactions and raw native errors'],
        'analysis_software_sha256': {p.name: sha(p.read_bytes()) for p in
                                    [Path(__file__), HERE/'compact_observer.py', HERE/'fresh_observer.py']},
        'scope': 'fresh-arm synthetic offline evidence; no real-world privacy or live-network claim'})
    for path in args.destination.rglob('*'):
        if path.is_file(): check_bytes(path.read_bytes(), forbidden)
    print(json.dumps({'export_complete': True, 'files': len(exported)+1,
                      'old_proofs_exported': 0, 'old_transactions_exported': 0}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['run', 'analyze', 'export'])
    parser.add_argument('root', type=Path)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--params', type=Path)
    parser.add_argument('--validator', type=Path,
                        help='existing kpi-compact binary; defaults to sibling of --binary')
    parser.add_argument('--venv', type=Path, default=Path('/home/luke/.local/share/kpi-shared-pool-tools'))
    parser.add_argument('--destination', type=Path)
    args = parser.parse_args()
    for name in ['root', 'binary', 'params', 'venv', 'destination', 'validator']:
        value = getattr(args, name)
        if value is not None: setattr(args, name, value.resolve())
    os.umask(0o077)
    if args.command in ['run', 'analyze'] and args.binary is None: parser.error('--binary required')
    if args.command in ['run', 'analyze'] and args.validator is None:
        args.validator = args.binary.with_name('kpi-compact')
    if args.command == 'run':
        if args.params is None: parser.error('--params required')
        prove(args); analyze(args)
    elif args.command == 'analyze': analyze(args)
    else:
        if args.destination is None: parser.error('--destination required')
        export(args)


if __name__ == '__main__':
    main()
