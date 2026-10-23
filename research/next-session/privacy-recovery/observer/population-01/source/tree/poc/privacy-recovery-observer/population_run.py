#!/usr/bin/env python3
"""One bounded model run: blind stream responses, global seal, separate scorer."""
import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

ROOT=Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
PACKET=ROOT/'research/next-session/privacy-recovery/observer/population-01'
BRIDGE=Path('/home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/kpi-future-recipient-crypto')
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
SAVE_KEYS=('work','notes','events','hidden','cashout_end','funding','costs','payouts',
    'external_coins','earmarked','audit','payment_index','arm','regime','rate','reserve')


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path,value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


def sandbox(mounts):
    cmd=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
        '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
        '--symlink','usr/lib64','/lib64','--ro-bind','/etc/alternatives','/etc/alternatives',
        '--proc','/proc','--dev','/dev','--tmpfs','/tmp','--setenv','PATH','/usr/bin:/bin']
    for mode,source,target in mounts: cmd += [mode,str(source),target]
    return cmd


def observe(ledger,directory):
    from population_model import PROFILES
    prefixes=[i+1 for i,e in enumerate(ledger.events) if e['mode']=='private' and not e['payout']]
    count=0
    with (directory/'predictions.jsonl').open('w') as sealed:
        for profile,members in PROFILES.items():
            for horizon in ('payment','cashouts','drainage'):
                ends=prefixes if horizon=='payment' else [ledger.cashout_end if horizon=='cashouts' else len(ledger.events)]
                cmd=sandbox([('--ro-bind',HERE/'population_attack.py','/attack.py')])
                proc=subprocess.Popen(cmd+['/usr/bin/python3','-B','/attack.py'],stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
                try:
                    for end in ends:
                        public=ledger.public(end)
                        view=ledger.view(members,end)
                        request=dict(public=public,view=view,only_last=horizon=='payment')
                        # No future request is written before this response is sealed.
                        proc.stdin.write(json.dumps(request,separators=(',',':'))+'\n');proc.stdin.flush()
                        line=proc.stdout.readline()
                        if not line: raise ValueError('observer response missing')
                        prediction=json.loads(line)
                        job=dict(profile=profile,horizon=horizon,public_end=end,prediction=prediction)
                        sealed.write(json.dumps(job,sort_keys=True,separators=(',',':'))+'\n')
                        sealed.flush();os.fsync(sealed.fileno())
                        count+=1
                    proc.stdin.close()
                    if proc.wait()!=0: raise ValueError('observer exited unsuccessfully')
                    if proc.stdout.read(): raise ValueError('unexpected extra observer response')
                    error=proc.stderr.read()
                    if error: raise ValueError('observer wrote unexpected error output')
                finally:
                    if proc.poll() is None: proc.kill();proc.wait()
    return count


def generation_worker(task):
    from population_model import ARMS,plan,replay
    from recipient import Crypto
    index,regime,request_seed,opaque_seed,out,crypto_path=task
    work=plan(bytes.fromhex(request_seed),regime)
    save(Path(out)/f'cluster-{index:02d}-DEMANDS.json',work)
    work_hash=hashlib.sha256(json.dumps(work,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    result=[]
    for rate in (100,200,500):
        for arm in ARMS:
            directory=Path(out)/f'cluster-{index:02d}-{arm}-{rate}'
            directory.mkdir()
            try:
                ledger,error=replay(work,bytes.fromhex(opaque_seed),arm,Crypto(crypto_path),regime,rate)
                if hashlib.sha256(json.dumps(ledger.work,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=work_hash:
                    raise ValueError('original demand plan changed')
                save(directory/'public.json',ledger.public())
                save(directory/'truth.json',{k:getattr(ledger,k) for k in SAVE_KEYS})
                if error: raise ValueError(error)
                jobs=observe(ledger,directory)
                status=dict(cluster=index,regime=regime,arm=arm,rate=rate,complete=True,
                    work_sha256=work_hash,
                    observer_jobs=jobs,public_sha256=sha(directory/'public.json'),
                    prediction_sha256=sha(directory/'predictions.jsonl'),truth_sha256=sha(directory/'truth.json'))
            except Exception as error:
                status=dict(cluster=index,regime=regime,arm=arm,rate=rate,complete=False,
                    failure_type=type(error).__name__,failure=str(error))
            save(directory/'STATUS.json',status)
            result.append(dict(directory=directory.name,**status))
    return result


def work(args):
    sys.path.insert(0,str(HERE.parents[0]/'future-recipient/v2'))
    from population_fees import validate_published_profile
    checked=validate_published_profile()
    seeds=json.loads(args.seeds.read_text())
    tasks=[(r['cluster'],r['regime'],r['requests'],r['opaque'],str(args.out),str(args.crypto)) for r in seeds]
    statuses=[]
    with concurrent.futures.ProcessPoolExecutor(max_workers=4) as pool:
        for rows in pool.map(generation_worker,tasks): statuses.extend(rows)
    save(args.out/'GENERATION.json',dict(actual_profile_metrics_checked=checked,expected_cases=72,cases=statuses))


def public_controls(args):
    sys.path.insert(0,str(HERE.parents[0]/'future-recipient/v2'))
    from recipient import Crypto
    from population_controls import controls,development
    save(args.out/'CONTROLS.json',dict(format_and_fees=controls(),
        public_development=development(Crypto(args.crypto))))


def score_worker(directory):
    from population_model import Ledger
    from population_score import score
    status=json.loads((directory/'STATUS.json').read_text())
    if not status['complete']: return dict(directory=directory.name,complete=False,failure=status)
    try:
        data=json.loads((directory/'truth.json').read_text())
        data['payment_index']={int(k):v for k,v in data['payment_index'].items()}
        ledger=Ledger.__new__(Ledger);ledger.__dict__.update(data)
        jobs=[json.loads(line) for line in (directory/'predictions.jsonl').read_text().splitlines()]
        result=score(ledger,jobs)
        save(directory/'score.json',result)
        return dict(directory=directory.name,complete=True,score_file_sha256=sha(directory/'score.json'),
                    cluster=status['cluster'],**result)
    except Exception as error:
        failure=dict(directory=directory.name,complete=False,failure_type=type(error).__name__,failure=str(error))
        save(directory/'SCORE-FAILURE.json',failure)
        return failure


def aggregate(rows):
    complete=[r for r in rows if r['complete']]
    metrics=('sender','recipient','relationship','amount_exact','amount_within_10pct')
    summaries=[]
    # Each configuration contributes one value per independently sampled cluster.
    for arm in ('direct_reveal','rerandomize_reveal','private_exit'):
      for rate in (100,200,500):
       for scope in ('pooled','overlap-independent','sparse-independent'):
        selected=[r for r in complete if r['arm']==arm and r['rate']==rate
                  and (scope=='pooled' or r['regime']==scope)]
        for profile in ('C','C+P','C+P+A'):
         for horizon in ('payment','cashouts','drainage'):
          for variant in ('prior','opening','residual','cash_inverse'):
           for metric in metrics:
            counters=[r['results'][profile][horizon][variant]['metrics'][metric] for r in selected]
            usable=[c for c in counters if c['eligible']]
            mean=sum(c['correct']/c['eligible'] for c in usable)/len(usable) if usable else None
            upper=min(1,mean+math.sqrt(math.log(10000/.05)/(2*len(usable)))) if usable else None
            summaries.append(dict(arm=arm,rate=rate,scope=scope,profile=profile,horizon=horizon,
                variant=variant,metric=metric,clusters=len(usable),
                correct=sum(c['correct'] for c in counters),eligible=sum(c['eligible'] for c in counters),
                independent_cluster_mean=mean,one_sided95_bonferroni10000_upper=upper,
                incomplete=len(usable)!=(8 if scope=='pooled' else 4)))
           for percent in (5,10,25):
            counters=[r['results'][profile][horizon][variant]['selective_relationship'][str(percent)] for r in selected]
            usable=[c for c in counters if c['eligible']]
            mean=sum(c['correct']/c['eligible'] for c in usable)/len(usable) if usable else None
            summaries.append(dict(arm=arm,rate=rate,scope=scope,profile=profile,horizon=horizon,
                variant=variant,metric='selective_relationship_'+str(percent),clusters=len(usable),
                correct=sum(c['correct'] for c in counters),eligible=sum(c['eligible'] for c in counters),
                independent_cluster_mean=mean,
                one_sided95_bonferroni10000_upper=min(1,mean+math.sqrt(math.log(10000/.05)/(2*len(usable)))) if usable else None,
                incomplete=len(usable)!=(8 if scope=='pooled' else 4)))
          for variant in ('opening','residual','cash_inverse'):
           for metric in ('sender','recipient','amount_within_10pct'):
            differences=[]
            for r in selected:
                a=r['results'][profile][horizon][variant]['metrics'][metric]
                b=r['results'][profile][horizon]['prior']['metrics'][metric]
                if a['eligible'] and b['eligible']:
                    differences.append(a['correct']/a['eligible']-b['correct']/b['eligible'])
            mean=sum(differences)/len(differences) if differences else None
            summaries.append(dict(arm=arm,rate=rate,scope=scope,profile=profile,horizon=horizon,
                variant=variant,metric=metric+'_advantage_over_prior',clusters=len(differences),
                independent_cluster_mean=mean,
                one_sided95_bonferroni10000_upper=min(1,mean+math.sqrt(2*math.log(10000/.05)/len(differences))) if differences else None,
                incomplete=len(differences)!=(8 if scope=='pooled' else 4)))
    return dict(schema='kpx3-population-comparison/v1',classification='SYNTHETIC_CONSTRAINT_MODEL',
        actual_model_batches=1,expected_cases=72,completed_cases=len(complete),
        incomplete_cases=[r for r in rows if not r['complete']],summaries=summaries,
        per_case_scores=[dict(directory=r['directory'],sha256=r['score_file_sha256']) for r in complete],
        privacy_qualification=False,fee_qualification=False,
        unchanged_common_price_prior=dict(successes=21103,denominator=100025,gate_percent=20,status='FAIL_UNCHANGED'),
        limits=['No Groth16 proof, native VM, accepted chain or independent human qualification.',
            'New amount-context fees are pinned source arithmetic, not repriced signed authorizations.',
            'Eight ledger clusters give wide intervals; no absence-of-breach pass.',
            'Fixed attack family does not exhaust all privacy attacks.'])


def scoring(args):
    directories=sorted(p for p in args.out.iterdir() if p.is_dir() and p.name.startswith('cluster-'))
    with concurrent.futures.ProcessPoolExecutor(max_workers=4) as pool:
        rows=list(pool.map(score_worker,directories))
    save(args.out/'RESULT.json',aggregate(rows))


def run():
    freeze=json.loads((PACKET/'PRE-RUN-FREEZE.json').read_text())
    for row in freeze['pins']:
        path=Path(row['path'])
        if path.stat().st_size!=row['bytes'] or sha(path)!=row['sha256']:
            raise ValueError('frozen source/input/binary mismatch')
    out=PACKET/'run';out.mkdir(exist_ok=False)
    group=next(line.split(':',2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0:'))
    cg=Path('/sys/fs/cgroup')/group.lstrip('/')
    caps={n:(cg/n).read_text().strip() for n in ('cpu.max','memory.max','memory.swap.max')}
    quota,period=map(int,caps['cpu.max'].split())
    if quota>4*period or int(caps['memory.max'])!=4*1024**3 or caps['memory.swap.max']!='0':
        raise ValueError('resource envelope mismatch')
    save(out/'LIVE-CGROUP.json',dict(cgroup=group,actual_limits=caps))
    import socket
    denied=[]
    for family in (socket.AF_INET,socket.AF_INET6):
        try:
            sock=socket.socket(family,socket.SOCK_STREAM)
        except OSError as error:
            denied.append(dict(family=int(family),errno=error.errno))
        else:
            sock.close();raise ValueError('Internet socket restriction missing')
    save(out/'NETWORK-DENIAL.json',dict(actual_denials=denied,
        trusted_generator_host_filesystem_access=True,
        generator_inputs='curated frozen source, existing bridge, fresh experiment seeds, artifacts',
        observer='single filesystem/network-isolated bwrap; code and sequential C/P stdin only'))
    tree=PACKET/'source/tree'
    host_script=tree/'poc/privacy-recovery-observer/population_run.py'
    script='/work/poc/privacy-recovery-observer/population_run.py'
    started=time.monotonic()
    cleanenv={'PATH':'/usr/bin:/bin','PYTHONNOUSERSITE':'1'}
    subprocess.run(['/usr/bin/python3','-I','-B',str(host_script),'--stage','control',
        '--out',str(out),'--crypto',str(BRIDGE)],env=cleanenv,check=True)
    # Fresh experiment seeds only, drawn AFTER public controls; no existing
    # wallet/profile/seed is opened and no failed workload is resampled.
    seeds=[dict(cluster=i,regime='overlap-independent' if i<4 else 'sparse-independent',
                requests=secrets.token_hex(32),opaque=secrets.token_hex(32)) for i in range(8)]
    if len({r[k] for r in seeds for k in ('requests','opaque')})!=16: raise ValueError('seed collision')
    private_dir=Path('/home/luke/.local/state/kpi-privacy-observer')/('population-01-'+secrets.token_hex(8))
    private_dir.mkdir(mode=0o700,parents=True,exist_ok=False)
    os.chmod(private_dir,0o700)
    seed_path=private_dir/'seeds.json'
    fd=os.open(seed_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f: json.dump(seeds,f)
    save(out/'SEED-COMMITMENT.json',dict(private_seed_path=str(seed_path),
        seed_bundle_sha256=sha(seed_path),count=8,published=False))
    subprocess.run(['/usr/bin/time','-v','-o',str(out/'generate-observe-resources.log'),
        '/usr/bin/python3','-I','-B',str(host_script),'--stage','work',
        '--seeds',str(seed_path),'--out',str(out),'--crypto',str(BRIDGE)],env=cleanenv,check=True)
    generation=json.loads((out/'GENERATION.json').read_text())
    pins=[]
    for row in generation['cases']:
        directory=out/row['directory']
        for name in ('STATUS.json','public.json','truth.json','predictions.jsonl'):
            path=directory/name
            if path.exists(): pins.append(dict(path=str(path.relative_to(out)),sha256=sha(path)))
    save(out/'GLOBAL-PREDICTION-BARRIER.json',dict(scorer_launched=False,
        all_prediction_workers_finished=True,case_roster=generation['cases'],pins=pins))
    # Fresh sandbox, no generation seeds or crypto adapter; only scorer truth.
    scorecmd=sandbox([('--ro-bind',tree,'/work'),('--bind',out,'/out')])
    subprocess.run(scorecmd+['/usr/bin/time','-v','-o','/out/score-resources.log',
        '/usr/bin/python3','-B',script,'--stage','score','--out','/out'],check=True)
    for row in pins:
        if sha(out/row['path'])!=row['sha256']: raise ValueError('barrier artifact changed')
    save(out/'EXECUTION.json',dict(actual_model_batches=1,wall_seconds=time.monotonic()-started,
        global_barrier_before_scorer=True,result_sha256=sha(out/'RESULT.json'),exit=0))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--stage',choices=('run','control','work','score'),default='run')
    p.add_argument('--out',type=Path);p.add_argument('--seeds',type=Path);p.add_argument('--crypto',type=Path)
    args=p.parse_args()
    if args.stage=='run': run()
    elif args.stage=='control': public_controls(args)
    elif args.stage=='work': work(args)
    else: scoring(args)
