#!/usr/bin/env python3
"""Decode accepted H12 native bodies in an observer without private inputs."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess

from privacy_study_generate import shared_funding
from privacy_study_native import normalized

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('h12',HERE/'normalized-deposits.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
c=h.c


def analyze(study,run):
    if not c.read(run/'result.json')['complete']:
        raise ValueError('live run is incomplete')
    out=run/'observer';out.mkdir(mode=0o700)
    base=c.sandbox()+['--ro-bind',str(c.VENV),'/venv',
        '--ro-bind',str(run/'chain.json'),'/native.json','--bind',str(out),'/out']
    for name in ('privacy_study_native.py','privacy_study_observer.py','privacy_study_flow.py'):
        base+=['--ro-bind',str(HERE/name),'/'+name]
    probe="import pathlib,json; assert not pathlib.Path('/home').exists(); assert not pathlib.Path('/params').exists(); n=[x.split(':')[0].strip() for x in pathlib.Path('/proc/net/dev').read_text().splitlines() if ':' in x]; assert n==['lo']; print(json.dumps({'home_visible':False,'private_material_visible':False,'interfaces':n}))"
    got=subprocess.run(base+['--','python3','-c',probe],capture_output=True,text=True,check=True)
    c.save(out/'isolation.json',json.loads(got.stdout))
    subprocess.run(base+['--','/venv/bin/python','/privacy_study_native.py','/native.json','/out/result.json'],check=True)
    actual=c.read(out/'result.json'); data=c.read(study/'model/sparse-00/private.json')['policies']['net']
    model=shared_funding(data['arms']['fresh'])
    a=normalized(actual['projection']); b=normalized(model)
    # The live legacy clock field is explicitly an accepted dependency ordinal.
    # Check order/amount/shape equality without claiming minute-level matching.
    a['initial']['minute']=b['initial']['minute']
    for x,y in zip(a['events'],b['events'],strict=True):x['minute']=y['minute']
    if a!=b:raise ValueError('accepted native public economics/order differs from model')
    old_ids=[model['initial']['id']]+[e['id'] for e in model['events']]
    new_ids=[actual['projection']['initial']['id']]+[e['id'] for e in actual['projection']['events']]
    mapping=dict(zip(old_ids,new_ids,strict=True))
    truth={mapping[k]:{**t,'source':mapping[t['source']],'ancestor':mapping[t['ancestor']]} for k,t in data['truth'].items()}
    c.score(truth,actual['observer'])
    expected=c.read(study/'model/sparse-00/shared/output/result.json')
    for x,y in zip(expected['rows'],actual['observer']['rows'],strict=True):
        for horizon in c.HORIZONS:
            for attack in c.ATTACKS:
                old,new=x[horizon][attack],y[horizon][attack]
                if old['positions']!=new['positions'] or sorted(mapping[z] for z in old['sources'])!=new['sources']:
                    raise ValueError('accepted native source candidates differ')
                if attack=='joint' and sorted(mapping[z] for z in old['deposit_ancestors'])!=sorted(new['deposit_ancestors']):
                    raise ValueError('accepted native deposit candidates differ')
    result={'accepted_projection_matches_economics_and_order':True,'exact_candidate_sets_match':True,
        'funding_groups':1,'deposit_scores':h.deposit_scores(truth,actual['projection'],actual['observer']),
        'scope':'Accepted native bytes; chain-only fixed attacks, shared funding, no synthetic timing or network privacy claim'}
    c.save(out/'calibration.json',result)
    print(json.dumps({'live_observer_matches_model':True,'role':c.read(run/'result.json')['role']}))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('study',type=Path);p.add_argument('run',type=Path);a=p.parse_args()
    analyze(a.study.resolve(),a.run.resolve())
