#!/usr/bin/env python3
"""H14 controller/scorer. Observer never mounts this file or private workload."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import time
from two_input_privacy_generate import build

HERE=Path(__file__).resolve().parent
VENV=Path('/home/luke/.local/share/kpi-shared-pool-tools')
FREEZE='1bf14d0'


def read(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,obj):
    p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with p.open('x') as f:json.dump(obj,f,indent=2);f.write('\n')
    p.chmod(0o600)


def check_freeze():
    hashes={}
    for name in ('TWO-INPUT-PRIVACY-SPEC.md','two-input-privacy-workloads.json'):
        frozen=subprocess.check_output(['git','show',f'{FREEZE}:poc/shared-pool/{name}'],cwd=HERE)
        if frozen!=(HERE/name).read_bytes():raise ValueError('frozen specification changed')
        hashes[name]=sha(HERE/name)
    return dict(freeze_commit=FREEZE,files=hashes)


def prepare(root):
    freeze=check_freeze();root.mkdir(mode=0o700)
    manifest=read(HERE/'two-input-privacy-workloads.json')
    for a in range(2):
        for s in range(2):
            plan,arms,truth=build(manifest,a,s);case=root/f'a{a}-s{s}'
            for name,obj in [('plan',plan),('truth',truth),*arms.items()]:save(case/f'{name}.json',obj)
    save(root/'freeze.json',freeze)


def sandbox():
    return ['bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
        '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
        '--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp',
        '--setenv','PATH','/usr/bin:/bin','--setenv','PYTHONDONTWRITEBYTECODE','1']


def observe(case,arm):
    public=case/f'{arm}.json';out=case/f'{arm}-observation';out.mkdir(mode=0o700)
    pins=dict(input_sha256=sha(public),observer_sha256=sha(HERE/'two_input_privacy_observer.py'),solver_sha256=sha(HERE/'two_input_privacy_z3.py'),exact_sha256=sha(HERE/'two_input_privacy_exact.py'))
    save(out/'pins.json',pins)
    base=sandbox()+['--ro-bind',str(VENV),'/venv',
        '--ro-bind',str(HERE/'two_input_privacy_observer.py'),'/observer.py',
        '--ro-bind',str(HERE/'two_input_privacy_observer.py'),'/two_input_privacy_observer.py',
        '--ro-bind',str(HERE/'two_input_privacy_z3.py'),'/two_input_privacy_z3.py',
        '--ro-bind',str(HERE/'two_input_privacy_exact.py'),'/two_input_privacy_exact.py',
        '--ro-bind',str(public),'/input.json','--bind',str(out),'/output']
    probe="import pathlib,json; denied=[p for p in ['/home','/workload.json','/truth.json','/generator.py'] if not pathlib.Path(p).exists()]; assert len(denied)==4; n=[l.split(':')[0].strip() for l in pathlib.Path('/proc/net/dev').read_text().splitlines() if ':' in l]; assert n==['lo']; print(json.dumps({'inaccessible':denied,'interfaces':n}))"
    receipt=subprocess.run(base+['--','/usr/bin/python3','-c',probe],capture_output=True,text=True,check=True)
    save(out/'isolation.json',json.loads(receipt.stdout))
    start=time.monotonic()
    with (out/'observer.log').open('x') as log:
        subprocess.run(base+['--','/venv/bin/python','/observer.py','/input.json','/output/predictions.json'],stdout=log,stderr=log,check=True)
    result=read(out/'predictions.json')
    if result['input_sha256']!=pins['input_sha256']:raise ValueError('input identity')
    # Truth is opened here, only after the isolated observer writes predictions.
    score=score_result(read(case/'truth.json'),read(public),result)
    save(out/'score.json',score)
    print(f'{case.name} {arm}: scored {len(result["rows"])} events in {time.monotonic()-start:.1f}s',flush=True)
    return dict(case=case.name,arm=arm,score=score,seconds=result['seconds'],queries=result['feasibility_queries'])


def score_result(truth,chain,observed):
    births=[-1]
    for i,e in enumerate(chain['events']):births.extend([i]*len(e['new']))
    scores=[]
    if {r['event'] for r in observed['rows']}!={int(i) for i in truth} or len(observed['rows'])!=len(truth):
        raise ValueError('missing or duplicate inference targets')
    for row in observed['rows']:
        t=truth[str(row['event'])];actual=sorted(t['inputs']);source=sorted({births[p] for p in actual})
        required={row['event'],len(chain['events'])-1}
        if t['category']=='payment':required|={i for i,e in enumerate(chain['events']) if e['mode']==2 and i>=row['event']}
        reported=[h['through'] for h in row['joint']]
        if not required.issubset(reported) or len(reported)!=len(set(reported)):
            raise ValueError('missing or duplicate observation horizons')
        horizons=[('structural',None,row['structural']),('amount',None,row['amount'])]+[('joint',r['through'],r) for r in row['joint']]
        for attack,through,r in horizons:
            if actual not in r['input_sets'] or source not in r['source_sets']:raise ValueError('ground truth excluded')
            scores.append(dict(event=row['event'],category=t['category'],attack=attack,through=through,
                input_candidates=len(r['input_sets']),source_candidates=len(r['source_sets']),
                correct_inputs=r['prediction']==actual,correct_sources=r['source_prediction']==source,
                unique_inputs=len(r['input_sets'])==1,unique_sources=len(r['source_sets'])==1))
    summaries={}
    for cat in ('payment','partial','exit','bootstrap'):
        summaries[cat]={}
        for attack in ('structural','amount','joint'):
            for horizon in ('at_event','after_drain') if attack=='joint' else ('at_event',):
                rows=[s for s in scores if s['category']==cat and s['attack']==attack and
                      (s['through'] is None or s['through']==(s['event'] if horizon=='at_event' else len(chain['events'])-1))]
                unique=[r for r in rows if r['unique_sources']]
                summaries[cat][f'{attack}:{horizon}']=dict(targets=len(rows),correct_sources=sum(r['correct_sources'] for r in rows),
                    correct_inputs=sum(r['correct_inputs'] for r in rows),unique_sources=len(unique),
                    unique_inputs=sum(r['unique_inputs'] for r in rows),singleton_precision=(sum(r['correct_sources'] for r in unique)/len(unique) if unique else None),
                    coverage=len(unique)/len(rows) if rows else None,
                    source_candidate_counts=[r['source_candidates'] for r in rows],input_candidate_counts=[r['input_candidates'] for r in rows])
    return dict(rows=scores,summaries=summaries,all_truth_survives=True)


def run(root,workers):
    freeze=check_freeze()
    save(root/'execution-pins.json',dict(freeze=freeze,source_hashes={n:sha(HERE/n) for n in
        ('two-input-privacy.py','two_input_privacy_generate.py','two_input_privacy_observer.py','two_input_privacy_z3.py','two_input_privacy_exact.py','two_input_privacy_tests.py')},
        python=subprocess.check_output([str(VENV/'bin/python'),'--version'],text=True).strip(),
        libraries=subprocess.check_output([str(VENV/'bin/python'),'-c','import ortools;print(ortools.__version__)'],text=True).strip()))
    jobs=[(root/f'a{a}-s{s}',arm) for a in range(2) for s in range(2) for arm in ('fresh','saved')]
    with ThreadPoolExecutor(max_workers=workers) as pool:results=list(pool.map(lambda pair:observe(*pair),jobs))
    pairs=[]
    for a in range(2):
        for s in range(2):
            case=f'a{a}-s{s}';p={r['arm']:r['score']['summaries']['payment']['joint:after_drain'] for r in results if r['case']==case}
            pairs.append(dict(case=case,fresh=p['fresh'],saved=p['saved'],
                fresh_ambiguous=6-p['fresh']['unique_sources'],saved_ambiguous=6-p['saved']['unique_sources'],
                fresh_source_candidates=sum(p['fresh']['source_candidate_counts']),saved_source_candidates=sum(p['saved']['source_candidate_counts'])))
    passes=all(p['fresh_ambiguous']>=3 for p in pairs) and any(p['fresh_source_candidates']>p['saved_source_candidates'] for p in pairs)
    save(root/'study-results.json',dict(pairs=pairs,observer_screen_passes=passes,
        calibration_required=True,real_world_privacy_claim=False,
        executions=[{k:v for k,v in r.items() if k!='score'} for r in results],
        actual_tkas_spent=0,hypothetical_fee_sompi_per_arm=760000000))
    print(json.dumps(dict(pairs=pairs,observer_screen_passes=passes)),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('command',choices=('prepare','run'));p.add_argument('root',type=Path);p.add_argument('--workers',type=int,default=2)
    a=p.parse_args()
    if a.command=='prepare':prepare(a.root)
    else:run(a.root,a.workers)
