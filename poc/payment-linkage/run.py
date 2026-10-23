#!/usr/bin/env python3
"""Frozen source + independent namespaces + global prediction barrier.

This file never starts on import. Root must explicitly release the heldout run.
It creates only new disposable model seeds, never opens a real wallet/profile.
"""
import argparse
import errno
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import time

from schema import canonical,digest,parse
from aggregate import aggregate

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
PYTHON=Path('/home/luke/.local/share/kpi-shared-pool-tools/bin/python')
VENV=PYTHON.parent.parent
CRYPTO=Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/crypto')
CRYPTO_SHA='6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'
OBSERVER=('schema.py','certificate.py','construct.py','model.py','observe.py')
SCORER=('schema.py','certificate.py','prediction.py','score.py','score_cli.py')
GENERATOR=('schema.py','generate.py','generate_cli.py')


def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    with path.open('xb') as file:file.write(canonical(value));file.flush();os.fsync(file.fileno())
    path.chmod(0o600)
    parent_fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(parent_fd)
    finally:os.close(parent_fd)

def sandbox(software,files,prefix='/work'):
    command=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
       '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
       '--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp',
       '--ro-bind',str(VENV),str(VENV),'--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8',
       '--setenv','PYTHONHASHSEED','0']
    for name in files:command.extend(['--ro-bind',str(software/'poc/payment-linkage'/name),prefix+'/'+name])
    return command

def run(args):
    output=Path(args.output).resolve();output.mkdir(mode=0o700,parents=True,exist_ok=False)
    assert not output.is_relative_to(ROOT),'private runtime outside Git'
    # The outer root launcher supplies RestrictAddressFamilies=AF_UNIX AF_NETLINK.
    for family in (socket.AF_INET,socket.AF_INET6):
        try:
            sock=socket.socket(family,socket.SOCK_STREAM)
        except OSError as error:
            if error.errno in (errno.EPERM,errno.EACCES,errno.EAFNOSUPPORT):continue
            raise
        else:sock.close();raise RuntimeError('controller Internet sockets not denied')
    freeze=parse(Path(args.freeze).read_bytes());release_raw=Path(args.release).read_bytes()
    assert sha(release_raw)==args.release_sha256
    release=parse(release_raw);assert release['authorization']=='RUN_FROZEN_LINKAGE_STUDY'
    assert release['source_freeze_sha256']==sha(Path(args.freeze).read_bytes())
    assert hashlib.sha256(CRYPTO.read_bytes()).hexdigest()==CRYPTO_SHA
    software=output/'software';software.mkdir(mode=0o700)
    for row in freeze['files']:
        source=ROOT/row['path'];raw=source.read_bytes();assert sha(raw)==row['sha256'] and len(raw)==row['bytes']
        target=software/row['path'];target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(0o400)
    # Sampling-seed commitment is not a wallet-key/crypto-material fingerprint.
    work=[secrets.token_bytes(32) for _ in range(4)];material=[secrets.token_bytes(32) for _ in range(4)]
    seeds={'schema':'kpx3-linkage-study-material/v1','workload_hex32':[v.hex() for v in work],
           'material_hex32':[v.hex() for v in material]}
    seed_file=output/'PRIVATE-MATERIAL.json';save(seed_file,seeds)
    save(output/'WORKLOAD-COMMITMENTS.json',{'schema':'kpx3-linkage-sampling-commitments/v1',
        'commitments':[sha(b'KPI/LINKAGE/WORKLOAD-COMMIT/v1\0'+v) for v in work],
        'crypto_material_key_seed_or_private_input_hashes_published':False})
    # Generator is a sibling namespace, never nested inside an attacker namespace.
    genout=output/'generator-output';genout.mkdir(mode=0o700)
    command=sandbox(software,GENERATOR,'/work/poc/payment-linkage')
    for relative in ('poc/future-recipient/v2/recipient.py',
                     'research/next-session/private-change/fees/WHOLE-EMITTED-COSTS-01.json'):
        command.extend(['--ro-bind',str(software/relative),'/work/'+relative])
    # Mirror only exact selected dependencies under the synthetic /work root.
    # No repository parent, wallet profile or unrelated host data is mounted.
    command.extend(['--ro-bind',str(CRYPTO),'/crypto','--ro-bind',str(seed_file),'/seeds.json',
       '--bind',str(genout),'/out','--chdir','/work/poc/payment-linkage',str(PYTHON),'-B','/work/poc/payment-linkage/generate_cli.py',
       '/seeds.json','/crypto','/out/cases'])
    process=subprocess.run(command,capture_output=True)
    save(output/'GENERATOR-RESULT.json',{'returncode':process.returncode,'stdout':process.stdout.decode(),
                                        'stderr':process.stderr.decode(),'namespace_inputs_exclude_existing_private_profiles':True})
    assert process.returncode==0,'generator failed; retain artifacts, no redraw'
    index=parse((genout/'cases/PRIVATE-CASES.json').read_bytes());jobs=[]
    predroot=output/'predictions';predroot.mkdir(mode=0o700)
    for case in index['cases']:
        for view in case['views']:
            jobs.append((case,view))
    assert len(jobs)==96
    # A conservative public-topology bound is checked BEFORE any observer runs.
    # It assumes no symmetry savings and reads no hidden labels or keys.
    query_upper=0
    for _,view in jobs:
        pub=parse((genout/'cases'/view['public_file']).read_bytes())
        from schema import decode
        ledger=decode(pub)
        query_upper+=1+2*len(ledger.notes)+sum(
            sum(n.birth<e.ordinal for n in ledger.notes.values())+len(ledger.source_ids)+1
            for e in ledger.events if e.payout)
    assert query_upper<=1000000,'public query scope outside frozen generous envelope'
    save(output/'PUBLIC-QUERY-BOUND.json',{'upper_without_symmetry':query_upper,
                                         'frozen_total_budget':1000000,'hidden_truth_used':False})
    def observe(job):
        case,view=job;public_file=genout/'cases'/view['public_file'];raw=public_file.read_bytes()
        name=case['case']+'-'+view['horizon']+'-'+view['profile'].replace('+','plus')
        cmd=sandbox(software,OBSERVER)+['--chdir','/work',str(PYTHON),'-B','/work/observe.py']
        cp=subprocess.run(cmd,input=raw,capture_output=True)
        pred=predroot/(name+'.json');error=predroot/(name+'.stderr.txt')
        with pred.open('xb') as f:f.write(cp.stdout);f.flush();os.fsync(f.fileno())
        with error.open('xb') as f:f.write(cp.stderr);f.flush();os.fsync(f.fileno())
        pred.chmod(0o600);error.chmod(0o600)
        result=parse(cp.stdout);assert cp.returncode==0 and result.get('public_sha256')==sha(raw)
        return {'case':case['case'],'horizon':view['horizon'],'profile':view['profile'],
                'public_relative':view['public_file'],'prediction_file':pred.name,
                'public_sha256':sha(raw),'prediction_sha256':sha(cp.stdout),'status':result['status'],
                'queries':result.get('queries',0)}
    started=time.monotonic()
    with ThreadPoolExecutor(max_workers=2) as pool:predictions=list(pool.map(observe,jobs))
    assert len(predictions)==96 and sum(p['queries'] for p in predictions)<=1000000
    prediction_dir_fd=os.open(predroot,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(prediction_dir_fd)
    finally:os.close(prediction_dir_fd)
    # Every prediction's data and directory entries are durable BEFORE this barrier.
    barrier={'schema':'kpx3-linkage-all-predictions-barrier/v1','source_freeze_sha256':sha(Path(args.freeze).read_bytes()),
             'prediction_count':96,'predictions':predictions,'all_predictions_before_any_scorer':True,
             'elapsed_prediction_seconds':time.monotonic()-started}
    save(output/'PREDICTION-BARRIER.json',barrier)
    for item in predictions:
        assert sha((predroot/item['prediction_file']).read_bytes())==item['prediction_sha256']
    scores=[];scoreroot=output/'scores';scoreroot.mkdir(mode=0o700)
    for item in predictions:
        public=genout/'cases'/item['public_relative'];prediction=predroot/item['prediction_file']
        truth=genout/'cases'/item['case']/'truth.json'
        cmd=sandbox(software,SCORER)+['--ro-bind',str(public),'/public.json',
            '--ro-bind',str(prediction),'/prediction.json','--ro-bind',str(truth),'/truth.json',
            '--chdir','/work',str(PYTHON),'-B','/work/score_cli.py','/public.json','/prediction.json','/truth.json']
        cp=subprocess.run(cmd,capture_output=True)
        name=item['prediction_file'];(scoreroot/(name+'.stderr')).write_bytes(cp.stderr)
        assert cp.returncode==0,'scorer invariant failure; retain full batch, no refit'
        score=parse(cp.stdout);save(scoreroot/name,score);scores.append(score)
    result=aggregate(scores);save(output/'RESULTS.json',result)
    print(json.dumps({'complete':result['all_complete'],'completed_cells':result['complete_score_cells'],
                       'total_solver_queries':sum(p['queries'] for p in predictions),'privacy_qualification':False}))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--freeze',required=True)
    parser.add_argument('--release',required=True);parser.add_argument('--release-sha256',required=True)
    parser.add_argument('--output',required=True);run(parser.parse_args())
