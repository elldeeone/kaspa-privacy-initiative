#!/usr/bin/env python3
"""H11 genuine proof preparation and isolated no-prover settlement/calibration."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

from privacy_study_native import normalized

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('controller', HERE/'privacy-study.py')
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
DEFAULT_BINARY = Path('/home/luke/projects/kaspa-privacy-self-funded/poc/self-funded/target/release/kpi-privacy-study')


def probe(base, path, inputs):
    code = "import pathlib,json; assert not pathlib.Path('/home').exists(); assert not pathlib.Path('/params').exists(); n=[l.split(':')[0].strip() for l in pathlib.Path('/proc/net/dev').read_text().splitlines() if ':' in l]; assert n==['lo']; print(json.dumps({'home_visible':False,'params_visible':False,'interfaces':n}))"
    got = subprocess.run(base+['--','/usr/bin/python3','-c',code], check=True, capture_output=True, text=True)
    c.save(path, {**json.loads(got.stdout), 'inputs': inputs})


def prepare(root, binary, params):
    out = root/'native-runtime'; out.mkdir(mode=0o700)
    base = c.sandbox()+['--setenv','RAYON_NUM_THREADS','4', '--ro-bind',str(binary),'/program',
        '--ro-bind',str(params),'/params', '--ro-bind',str(root/'native-plans'),'/plans',
        '--bind',str(out),'/run']
    c.save(out/'binary.json', {'sha256':c.sha(binary.read_bytes()), 'rayon_threads':4})
    with (out/'stdout.json').open('x') as stdout, (out/'stderr.log').open('x') as stderr:
        subprocess.run(base+['--','/usr/bin/time','-v','-o','/run/resources.txt','/program',
            'prepare','/params','/plans','/run/prepared'], check=True, stdout=stdout, stderr=stderr)


def analyze(root, binary):
    prepared = root/'native-runtime/prepared'
    preparation = c.read(prepared/'preparation.json')
    if not preparation['complete'] or preparation['binary_sha256'] != c.sha(binary.read_bytes()):
        raise ValueError('native preparation/binary mismatch')
    results = {}
    for name in ['sparse-00','burst-00']:
        data = c.read(root/name/'private.json')
        receipts, metrics = {}, {}
        for arm in ['saved','fresh']:
            output = root/'native-analysis'/name/arm; output.mkdir(parents=True, mode=0o700)
            request = prepared/name/f'{arm}-request.json'
            base = c.sandbox()+['--ro-bind',str(binary),'/program','--ro-bind',str(request),'/request.json',
                               '--bind',str(output),'/out']
            probe(base, output/'settlement-isolation.json', ['/program','/request.json'])
            with (output/'settlement.stdout.json').open('x') as stdout:
                subprocess.run(base+['--','/program','settle','/request.json','/out/settled'], stdout=stdout, check=True)
            observed_dir = output/'observer'; observed_dir.mkdir(mode=0o700)
            base = c.sandbox()+['--ro-bind',str(c.VENV),'/venv',
                '--ro-bind',str(HERE/'privacy_study_native.py'),'/privacy_study_native.py',
                '--ro-bind',str(HERE/'privacy_study_observer.py'),'/privacy_study_observer.py',
                '--ro-bind',str(HERE/'privacy_study_flow.py'),'/privacy_study_flow.py',
                '--ro-bind',str(output/'settled/chain.json'),'/native.json','--bind',str(observed_dir),'/out']
            probe(base, output/'observer-isolation.json', ['/native.json','/privacy_study_native.py','/privacy_study_observer.py','/privacy_study_flow.py','/venv'])
            subprocess.run(base+['--','/venv/bin/python','/privacy_study_native.py','/native.json','/out/result.json'], check=True)
            actual = c.read(observed_dir/'result.json')
            model = data['arms'][arm]
            if normalized(model) != normalized(actual['projection']):
                raise ValueError('native public projection differs from frozen workload')
            old_ids = [model['initial']['id']]+[e['id'] for e in model['events']]
            new_ids = [actual['projection']['initial']['id']]+[e['id'] for e in actual['projection']['events']]
            mapping = dict(zip(old_ids,new_ids,strict=True))
            truth = {mapping[k]:{**t,'source':mapping[t['source']], 'ancestor':mapping[t['ancestor']]}
                     for k,t in data['truth'].items()}
            scores = c.score(truth,actual['observer'])
            model_scores = c.read(root/name/'scores.json')[arm]
            if scores != model_scores:
                raise ValueError('native/model inference mismatch')
            # Compare actual sets, not just aggregate scores/cardinalities.
            model_observed = c.read(root/name/arm/'output/result.json')
            for x,y in zip(model_observed['rows'],actual['observer']['rows'],strict=True):
                for h in c.HORIZONS:
                    for a in c.ATTACKS:
                        if x[h][a]['positions'] != y[h][a]['positions'] or sorted(mapping[s] for s in x[h][a]['sources']) != y[h][a]['sources']:
                            raise ValueError('native/model candidate sets differ')
            receipts[arm] = c.read(output/'settled/result.json')
            metrics[arm] = c.read(output/'settled/metrics.json')
            c.save(output/'calibration.json', {'projection_matches_model':True,'candidate_sets_match_model':True,
                 'scores_match_model':True,'scope':'Genuine native proof/transaction calibration with synthetic UTXO contexts'})
        if metrics['saved'] != metrics['fresh'] or receipts['saved']['fees_sompi'] != receipts['fresh']['fees_sompi']:
            raise ValueError('matched native fee/mass changed')
        results[name] = {'arms':receipts, 'same_mass_and_fees':True, 'model_and_native_candidates_agree':True,
                         'preparation':c.read(prepared/name/'preparation.json')}
    c.save(root/'native-summary.json', {'complete':True,'cases':results,
        'parameter_load_ms':preparation['parameter_load_ms'],'pk_sha256':preparation['pk_sha256'],
        'vk_sha256':preparation['vk_sha256'],'binary_sha256':preparation['binary_sha256'],
        'scope':'Two offline calibrations, four complete drains; no live relay/finality or general anonymity result'})
    print(json.dumps({'native_calibration_complete':True,'cases':2,'both_arms_drained':True}))


if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('command',choices=['prepare','analyze'])
    p.add_argument('root',type=Path);p.add_argument('--binary',type=Path,default=DEFAULT_BINARY)
    p.add_argument('--params',type=Path,default=Path('/home/luke/.local/share/kpi-compact-tests/params-v1'))
    args=p.parse_args();os.umask(0o077)
    if args.command=='prepare':prepare(args.root.resolve(),args.binary.resolve(),args.params.resolve())
    else:analyze(args.root.resolve(),args.binary.resolve())
