#!/usr/bin/env python3
"""H11 controller/scorer. Isolated observers never import or mount this file."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import time

from privacy_study_generate import generate, shared_funding

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
VENV = Path('/home/luke/.local/share/kpi-shared-pool-tools')
HORIZONS = ['at_withdrawal', 'complete_drain']
ATTACKS = ['timing', 'amount', 'joint']


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    return json.loads(path.read_text())


def save(path, obj):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('x') as f:
        json.dump(obj, f, indent=2); f.write('\n')
    path.chmod(0o600)


def sandbox():
    return ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
            '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'PYTHONDONTWRITEBYTECODE', '1']


def observe(chain, directory):
    directory.mkdir(mode=0o700)
    save(directory/'input.json', chain)
    out = directory/'output'; out.mkdir(mode=0o700)
    base = sandbox()+['--ro-bind', str(VENV), '/venv',
        '--ro-bind', str(HERE/'privacy_study_observer.py'), '/observer.py',
        '--ro-bind', str(HERE/'privacy_study_flow.py'), '/privacy_study_flow.py',
        '--ro-bind', str(directory/'input.json'), '/input.json', '--bind', str(out), '/output']
    probe = "import pathlib,json; assert not pathlib.Path('/home').exists(); n=[l.split(':')[0].strip() for l in pathlib.Path('/proc/net/dev').read_text().splitlines() if ':' in l]; assert n==['lo']; print(json.dumps({'home_visible':False,'interfaces':n}))"
    receipt = subprocess.run(base+['--', '/usr/bin/python3', '-c', probe], capture_output=True, text=True, check=True)
    isolation = json.loads(receipt.stdout)
    isolation['inputs'] = ['/observer.py', '/privacy_study_flow.py', '/input.json', '/venv']
    save(directory/'isolation.json', isolation)
    start = time.monotonic()
    subprocess.run(base+['--', '/venv/bin/python', '/observer.py', '/input.json', '/output/result.json'],
                   stdout=subprocess.DEVNULL, check=True)
    result = read(out/'result.json')
    if result['input_sha256'] != sha((directory/'input.json').read_bytes()):
        raise ValueError('observer input identity')
    save(directory/'runtime.json', {'seconds': time.monotonic()-start})
    return result


def score(truth, observed):
    result = {}
    for horizon in HORIZONS:
        scores = {}
        for attack in ATTACKS:
            rows = []
            for row in observed['rows']:
                real = truth[row['id']]; got = row[horizon][attack]
                if real['source'] not in got['sources'] or real['position'] not in got['positions']:
                    raise ValueError('observer excluded actual source/note')
                one = {'correct': int(got['prediction'] == real['source']),
                       'sources': len(got['sources']), 'notes': len(got['positions']),
                       'unique': int(len(got['sources']) == 1), 'uniform': got['uniform_expected']}
                if attack == 'joint':
                    if real['ancestor'] not in got['deposit_ancestors']:
                        raise ValueError('observer excluded actual deposit ancestry')
                    one['ancestors'] = len(got['deposit_ancestors'])
                    one['funding_groups'] = len(got['funding_groups'])
                rows.append(one)
            count = len(rows)
            unique = sum(r['unique'] for r in rows)
            scores[attack] = {'withdrawals': count, 'correct': sum(r['correct'] for r in rows),
                'accuracy': sum(r['correct'] for r in rows)/count,
                'coverage': unique/count, 'singleton_precision': 1.0 if unique else None,
                'abstentions': count-unique, 'uniform_expected_success': statistics.mean(r['uniform'] for r in rows),
                'rows': rows}
        result[horizon] = scores
    return result


def cases():
    yield 'singleton', 210000, 'sparse', False, True
    for regime, base in [('sparse', 211000), ('burst', 212000)]:
        for i in range(32):
            yield f'{regime}-{i:02}', base+i, regime, False, False
    for regime, base in [('sparse', 213000), ('burst', 214000)]:
        for i in range(8):
            yield f'equal-{regime}-{i:02}', base+i, regime, True, False


def prepare(root):
    if root.is_relative_to(REPO):
        raise ValueError('private work must be outside repository')
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    save(root/'freeze.json', {'spec_sha256': sha((HERE/'PRIVACY-STUDY-SPEC.md').read_bytes()),
        'spec_commit': '294dfc6', 'base_commit': 'b3a6259', 'generated_before_scoring': True})
    save(root/'source-pins.json', {name: sha((HERE/name).read_bytes()) for name in
        ['privacy-study.py', 'privacy_study_observer.py', 'privacy_study_flow.py', 'privacy_study_generate.py',
         'privacy_study_native.py', 'src/compact/study.rs', 'src/compact/circuit.rs',
         'src/compact/deposits/covenant.rs', 'src/compact/deposits/mod.rs']})
    for name, seed, regime, equal, singleton in cases():
        data = generate(seed, regime, equal, singleton)
        save(root/name/'private.json', data)
        if name in ('sparse-00', 'burst-00'):
            save(root/'native-plans'/f'{name}.json', data['native_plan'])
    print(json.dumps({'prepared': 81, 'root': str(root)}), flush=True)


def evaluate(root):
    if read(root/'freeze.json')['spec_sha256'] != sha((HERE/'PRIVACY-STUDY-SPEC.md').read_bytes()):
        raise ValueError('frozen specification changed')
    for name, digest in read(root/'source-pins.json').items():
        if sha((HERE/name).read_bytes()) != digest:
            raise ValueError('implementation changed since generation: '+name)
    def one(name):
        home = root/name
        if (home/'scores.json').exists():
            return name, read(home/'scores.json')
        data = read(home/'private.json')
        scores = {}
        results = {}
        for arm, chain in data['arms'].items():
            target = home/arm
            if (target/'output/result.json').exists():
                observed = read(target/'output/result.json')
                if observed['input_sha256'] != sha((target/'input.json').read_bytes()) or read(target/'input.json') != chain:
                    raise ValueError('resume input mismatch')
            else:
                observed = observe(chain, target)
            results[arm] = observed
            scores[arm] = score(data['truth'], observed)
        # Delaying the entire drain with no new arrivals must not invent cover.
        if results['fresh']['rows'] != results['waited']['rows']:
            raise ValueError('waiting without traffic changed source candidates/ranks')
        # The ancestry control is evaluated, not counted as another sample.
        shared = observe(shared_funding(data['arms']['fresh']), home/'shared')
        shared_score = score(data['truth'], shared)
        for a, b in zip(shared['rows'], results['fresh']['rows'], strict=True):
            for h in HORIZONS:
                if a[h]['joint']['sources'] != b[h]['joint']['sources'] or a[h]['joint']['funding_groups'] != [data['arms']['fresh']['initial']['funding_group']]:
                    raise ValueError('shared ancestry control')
        scores['shared'] = shared_score
        if name == 'singleton' and any(r['sources'] != 1 for a in scores.values()
                for h in HORIZONS for r in a[h]['joint']['rows']):
            raise ValueError('singleton manufactured privacy')
        save(home/'scores.json', scores)
        print(json.dumps({'completed': name, 'of': 81}), flush=True)
        return name, scores
    with ThreadPoolExecutor(max_workers=8) as pool:
        all_scores = dict(pool.map(one, [row[0] for row in cases()]))
    save(root/'scores.json', all_scores)
    summarize(root)


def percentile(values, q):
    v = sorted(values); at = (len(v)-1)*q; low = int(at)
    return v[low] if low == len(v)-1 else v[low]+(v[low+1]-v[low])*(at-low)


def summarize(root):
    all_scores = read(root/'scores.json')
    result = {'schema': 'kpi-privacy-study-summary-v1', 'regimes': {},
              'scope': 'Synthetic integer-model study with separate native calibration',
              'new_chain_transactions': 0, 'new_chain_fees_sompi': 0}
    rng = random.Random(215000)
    for group in ['sparse', 'burst', 'equal-sparse', 'equal-burst', 'singleton']:
        names = [k for k in all_scores if k == group or k.startswith(group+'-')]
        samples = [all_scores[n] for n in names]
        group_result = {'ledgers': len(samples), 'arms': {}}
        for arm in ['saved', 'fresh', 'waited', 'shared']:
            hs = {}
            for horizon in HORIZONS:
                attacks = {}
                for attack in ATTACKS:
                    stats = [s[arm][horizon][attack] for s in samples]
                    rows = [r for s in stats for r in s['rows']]
                    attacks[attack] = {'accuracy': statistics.mean(s['accuracy'] for s in stats),
                        'coverage': statistics.mean(s['coverage'] for s in stats),
                        'singleton_precision': 1.0 if any(r['unique'] for r in rows) else None,
                        'abstentions': sum(s['abstentions'] for s in stats),
                        'uniform_expected_success': statistics.mean(s['uniform_expected_success'] for s in stats),
                        'source_candidates_mean': statistics.mean(r['sources'] for r in rows),
                        'source_candidates_median': statistics.median(r['sources'] for r in rows),
                        'note_candidates_mean': statistics.mean(r['notes'] for r in rows)}
                    if attack == 'joint':
                        attacks[attack].update(deposit_candidates_mean=statistics.mean(r['ancestors'] for r in rows),
                            deposit_unique_fraction=statistics.mean(r['ancestors'] == 1 for r in rows),
                            funding_groups_mean=statistics.mean(r['funding_groups'] for r in rows))
                hs[horizon] = attacks
            group_result['arms'][arm] = hs
        base = max(group_result['arms']['saved']['complete_drain'][a]['accuracy'] for a in ATTACKS)
        fresh = max(group_result['arms']['fresh']['complete_drain'][a]['accuracy'] for a in ATTACKS)
        reduction = (base-fresh)/base if base else None
        relative, absolute = [], []
        for _ in range(10000):
            picked = [samples[rng.randrange(len(samples))] for _ in samples]
            values = [max(statistics.mean(s[arm]['complete_drain'][a]['accuracy'] for s in picked)
                          for a in ATTACKS) for arm in ['saved', 'fresh']]
            absolute.append(values[0]-values[1])
            relative.append((values[0]-values[1])/values[0] if values[0] else 0.0)
        interval = [percentile(relative, .025), percentile(relative, .975)]
        group_result['primary'] = {'saved_strongest_accuracy': base, 'fresh_strongest_accuracy': fresh,
            'relative_reduction': reduction, 'paired_relative_95': interval,
            'paired_absolute_95': [percentile(absolute, .025), percentile(absolute, .975)],
            'inference_screen_pass': reduction is not None and reduction >= .25 and interval[0] > 0,
            'population_inference': False}
        group_result['model_cost'] = {'pool_fees_sompi': sum(e['fee'] for e in read(root/names[0]/'private.json')['arms']['fresh']['events']),
            'additional_native_fees_sompi': 0, 'additional_transactions': 0,
            'fresh_scheduling_delay_minutes': 0, 'waited_scheduling_delay_minutes': 20,
            'proof_latency': 'Measured separately in two native calibrations; not modeled network delay'}
        result['regimes'][group] = group_result
    result['both_primary_inference_screens_pass'] = all(result['regimes'][g]['primary']['inference_screen_pass'] for g in ['sparse', 'burst'])
    save(root/'summary.json', result)
    print(json.dumps({'complete': True, 'both_primary_inference_screens_pass': result['both_primary_inference_screens_pass']}))


def main():
    p = argparse.ArgumentParser(); p.add_argument('command', choices=['prepare', 'evaluate', 'summarize'])
    p.add_argument('root', type=Path); args = p.parse_args()
    os.umask(0o077)
    root = args.root.resolve()
    {'prepare': prepare, 'evaluate': evaluate, 'summarize': summarize}[args.command](root)


if __name__ == '__main__':
    main()
