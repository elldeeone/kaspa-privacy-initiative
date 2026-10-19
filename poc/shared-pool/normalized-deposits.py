#!/usr/bin/env python3
"""H12 controller and scorer. Observers mount only the unchanged H11 attack."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import random
import statistics

from normalization_generate import generate, POLICIES
from privacy_study_generate import shared_funding

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('h11_controller', HERE/'privacy-study.py')
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
SPEC = HERE/'NORMALIZED-DEPOSITS-SPEC.md'


def cases():
    for regime, start in [('sparse', 221000), ('burst', 222000)]:
        for index in range(32):
            yield f'{regime}-{index:02}', start+index, regime, None
    yield 'singleton', 220000, 'sparse', 'singleton'
    yield 'early', 220001, 'sparse', 'early'


def pins():
    names = ['normalized-deposits.py', 'normalization_generate.py', 'privacy-study.py',
             'privacy_study_observer.py', 'privacy_study_flow.py', 'privacy_study_native.py',
             'src/compact/circuit.rs', 'src/compact/deposits/covenant.rs', 'src/compact/deposits/mod.rs']
    return {name: c.sha((HERE/name).read_bytes()) for name in names}


def prepare(root):
    if root.is_relative_to(c.REPO):
        raise ValueError('private workloads must remain outside Git')
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    c.save(root/'freeze.json', {'spec_sha256': c.sha(SPEC.read_bytes()),
        'spec_commit': 'a522e59', 'base_commit': '5cfa94d', 'generated_before_scoring': True})
    c.save(root/'source-pins.json', pins())
    for name, seed, regime, control in cases():
        c.save(root/'model'/name/'private.json', generate(seed, regime, control))
    print(json.dumps({'prepared_paired_ledgers': 66, 'root': str(root)}), flush=True)


def deposit_scores(truth, chain, observed):
    deposits = [chain['initial']['id']]+[e['id'] for e in chain['events'] if e['kind'] == 'deposit']
    exits = {e['id']: e for e in chain['events'] if e['kind'] == 'exit'}
    result = {}
    for horizon in c.HORIZONS:
        rows = []
        for row in observed['rows']:
            found = row[horizon]['joint']; actual = truth[row['id']]['ancestor']
            ancestors = sorted(found['deposit_ancestors'], key=deposits.index)
            if actual not in ancestors:
                raise ValueError('actual funding deposit excluded')
            known = 1+sum(e['kind'] == 'deposit' and e['minute'] < exits[row['id']]['minute'] for e in chain['events'])
            rows.append({'candidates': len(ancestors), 'unique': int(len(ancestors) == 1),
                'latest_correct': int(ancestors[-1] == actual), 'oldest_correct': int(ancestors[0] == actual),
                'uniform_success': 1/len(ancestors), 'eligible_prior_success': 1/known,
                'funding_groups': len(found['funding_groups'])})
        result[horizon] = {key: statistics.mean(r[key] for r in rows) for key in rows[0]}
        result[horizon].update(withdrawals=len(rows), singleton_precision=1.0 if any(r['unique'] for r in rows) else None,
                               abstentions=sum(not r['unique'] for r in rows), rows=rows)
    return result


def observe_checked(chain, path):
    if (path/'output/result.json').exists():
        found = c.read(path/'output/result.json')
        if c.read(path/'input.json') != chain or found['input_sha256'] != c.sha((path/'input.json').read_bytes()):
            raise ValueError('resumed observation identity differs')
        return found
    return c.observe(chain, path)


def evaluate(root):
    if c.read(root/'freeze.json')['spec_sha256'] != c.sha(SPEC.read_bytes()) or c.read(root/'source-pins.json') != pins():
        raise ValueError('frozen specification or analysis implementation changed')

    def one(name):
        base = root/'model'/name
        if (base/'scores.json').exists():
            return name, c.read(base/'scores.json')
        data = c.read(base/'private.json'); scores = {}
        for policy in POLICIES:
            ledger = data['policies'][policy]; chain = ledger['arms']['fresh']
            found = observe_checked(chain, base/policy)
            scores[policy] = {'source': c.score(ledger['truth'], found),
                             'deposit': deposit_scores(ledger['truth'], chain, found)}
        if name in ('sparse-00', 'burst-00'):
            ledger = data['policies']['net']
            shared = shared_funding(ledger['arms']['fresh'])
            got = observe_checked(shared, base/'shared')
            control = deposit_scores(ledger['truth'], shared, got)
            for h in c.HORIZONS:
                assert control[h]['candidates'] == scores['net']['deposit'][h]['candidates']
                assert control[h]['funding_groups'] == 1
            scores['shared'] = control
        if name == 'singleton':
            assert all(scores[p]['deposit'][h]['unique'] == 1 for p in POLICIES for h in c.HORIZONS)
        if name == 'early':
            assert all(scores[p]['deposit']['at_withdrawal']['rows'][0]['candidates'] == 1 for p in POLICIES)
        c.save(base/'scores.json', scores)
        print(json.dumps({'completed': name, 'paired_ledgers': 66}), flush=True)
        return name, scores

    with ThreadPoolExecutor(max_workers=4) as pool:
        scores = dict(pool.map(one, [x[0] for x in cases()]))
    c.save(root/'scores.json', scores)
    summarize(root)


def summarize(root):
    scores = c.read(root/'scores.json'); result = {'schema': 'kpi-normalization-summary-v1', 'regimes': {},
        'scope': 'Paired synthetic workloads, four equalized deposit roots; no real-world anonymity measurement',
        'new_chain_fees_sompi': 0, 'new_chain_transactions': 0}
    rng = random.Random(223000)
    for regime in ('sparse', 'burst'):
        names = [name for name in scores if name.startswith(regime+'-')]
        samples = [scores[name] for name in names]
        arms = {}
        for p in POLICIES:
            arms[p] = {}
            for h in c.HORIZONS:
                rows = [r for s in samples for r in s[p]['deposit'][h]['rows']]
                arms[p][h] = {key: statistics.mean(s[p]['deposit'][h][key] for s in samples)
                    for key in ('unique', 'candidates', 'latest_correct', 'oldest_correct',
                                'uniform_success', 'eligible_prior_success', 'funding_groups')}
                arms[p][h].update(withdrawals=len(rows), uniquely_identified=sum(r['unique'] for r in rows),
                    singleton_precision=1.0 if any(r['unique'] for r in rows) else None,
                    strongest_deposit_accuracy=max(arms[p][h]['latest_correct'], arms[p][h]['oldest_correct']),
                    source_accuracy={a: statistics.mean(s[p]['source'][h][a]['accuracy'] for s in samples) for a in c.ATTACKS},
                    source_candidates_mean=statistics.mean(r['sources'] for s in samples for r in s[p]['source'][h]['joint']['rows']),
                    note_candidates_mean=statistics.mean(r['notes'] for s in samples for r in s[p]['source'][h]['joint']['rows']))
        intervals = {}
        for comparator in ('varied', 'gross'):
            differences = [s[comparator]['deposit']['complete_drain']['unique']-s['net']['deposit']['complete_drain']['unique'] for s in samples]
            draws = [sum(differences[rng.randrange(len(samples))] for _ in samples)/len(samples) for _ in range(10000)]
            intervals[comparator] = {'absolute_reduction': statistics.mean(differences),
                'paired_95': [c.percentile(draws, .025), c.percentile(draws, .975)]}
        net = arms['net']['complete_drain']; varied = arms['varied']['complete_drain']
        reduction = (varied['unique']-net['unique'])/varied['unique'] if varied['unique'] else None
        passed = (reduction is not None and reduction >= .5 and intervals['varied']['paired_95'][0] > 0
            and net['unique'] <= .25 and net['candidates'] >= 3 and net['strongest_deposit_accuracy'] <= .5
            and intervals['gross']['paired_95'][0] > 0)
        first = c.read(root/'model'/names[0]/'private.json')
        fees = {p: sum(e['fee'] for e in first['policies'][p]['arms']['fresh']['events']) for p in POLICIES}
        assert len(set(fees.values())) == 1
        result['regimes'][regime] = {'paired_ledgers': len(samples), 'arms': arms,
            'comparison': intervals, 'relative_unique_reduction_vs_varied': reduction,
            'inference_screen_pass': passed, 'modeled_cost': {'pool_fee_sompi': fees['net'],
                'extra_fee_sompi': 0, 'extra_transactions': 0, 'extra_scheduled_delay_minutes': 0}}
    result['both_inference_screens_pass'] = all(x['inference_screen_pass'] for x in result['regimes'].values())
    result['controls'] = {name: scores[name] for name in ('singleton', 'early')}
    c.save(root/'summary.json', result)
    print(json.dumps({'complete': True, 'both_inference_screens_pass': result['both_inference_screens_pass']}), flush=True)


def native_inputs(root):
    if not c.read(root/'summary.json')['both_inference_screens_pass']:
        raise ValueError('inference screen failed; no native expansion')
    output = root/'native'; output.mkdir(mode=0o700)
    for name in ('sparse-00', 'burst-00'):
        data = c.read(root/'model'/name/'private.json')['policies']['net']
        c.save(output/name/'private.json', data)
        c.save(output/'native-plans'/f'{name}.json', data['native_plan'])
        scores = {}
        for arm, chain in data['arms'].items():
            found = observe_checked(chain, output/name/arm)
            scores[arm] = c.score(data['truth'], found)
        c.save(output/name/'scores.json', scores)
    print(json.dumps({'native_inputs': str(output), 'first_equal_net_case_per_regime': True}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['prepare', 'evaluate', 'summarize', 'native-inputs'])
    parser.add_argument('root', type=Path); args = parser.parse_args(); os.umask(0o077)
    {'prepare': prepare, 'evaluate': evaluate, 'summarize': summarize, 'native-inputs': native_inputs}[args.command](args.root.resolve())
