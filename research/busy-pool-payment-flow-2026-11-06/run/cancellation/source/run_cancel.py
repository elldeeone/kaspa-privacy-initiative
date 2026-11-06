#!/usr/bin/env python3
"""Wait for the main campaign, then measure safe stale-worker interruption."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid
import psutil
from verify_cancel import verify

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
TOOLS=Path('/home/luke/projects/kpi-intensive-2026-10-22/proof-target/tools')
ASSETS=Path('/home/luke/projects/kpi-intensive-2026-10-22/observer/artifacts/groth16-compression-preparation/risc0-home')

def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def write(p,v):
    with p.open('x') as f:json.dump(v,f,indent=2,sort_keys=True);f.write('\n')

def stop_owned(process):
    """Stop the separately created job session, then verify its known children."""
    root=psutil.Process(process.pid)
    owned=[root,*root.children(recursive=True)]
    identities={p.pid:p.create_time() for p in owned}
    assert os.getpgid(process.pid)==process.pid
    started=time.monotonic()
    os.killpg(process.pid,signal.SIGTERM)
    try:code=process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        if root.create_time()==identities[root.pid]:root.kill()
        code=process.wait(timeout=10)
    _,alive=psutil.wait_procs(owned[1:],timeout=2)
    for p in alive:
        try:
            if p.create_time()==identities[p.pid]:p.kill()
        except psutil.NoSuchProcess:pass
    _,alive=psutil.wait_procs(alive,timeout=2)
    # Orphan zombies consume no work; PID reuse is never treated as ownership.
    active=[]
    for p in alive:
        try:
            if p.create_time()==identities[p.pid] and p.status()!=psutil.STATUS_ZOMBIE:active.append(p.pid)
        except psutil.NoSuchProcess:pass
    assert not active, f'owned processes still active: {active}'
    return {'cleanupSeconds':time.monotonic()-started,'ownedPids':sorted(identities),
            'allOwnedWorkersStopped':True,'exitCode':code}

def main():
    run,monitor=map(lambda p:Path(p).resolve(),sys.argv[1:3])
    print(json.dumps({'waitingForMainCampaign':str(monitor)}),flush=True)
    while not (monitor/'RESOURCES.json').exists():time.sleep(2)
    assert json.loads((monitor/'RESOURCES.json').read_text())['returnCode']==0
    host=monitor/'host'
    program=ROOT/'research/reusable-withdrawal-approvals-2026-11-06/run/program.bin'
    parent_freeze=json.loads((monitor/'FREEZE.json').read_text())
    assert sha(host)==parent_freeze['hostSha256'] and sha(program)==parent_freeze['programSha256']
    baseline=json.loads(subprocess.check_output([str(host),'replay',str(program),str(run)],text=True))
    assert baseline['independentPublicReplay'] is True
    parent=ROOT/'.local/busy-pool-cancellation';parent.mkdir(exist_ok=True)
    out=parent/str(uuid.uuid4());out.mkdir(mode=0o700)
    worker=TOOLS/'r0vm-cuda'
    assert sha(worker)=='3f22b68b6d32904fe766e14e62ce011febdc946dd98d015747f40ce5fb5fffc7'
    selection=ROOT/'research/busy-pool-payment-flow-2026-11-06/CANCELLATION-SELECTION.md'
    source=out/'source';source.mkdir()
    import shutil
    sources={}
    for p,name in [(Path(__file__),'run_cancel.py'),(HERE/'verify_cancel.py','verify_cancel.py'),(HERE/'analyse.py','analyse.py'),(selection,'SELECTION.md.txt')]:
        shutil.copyfile(p,source/name);sources[name]=sha(p)
    shutil.copyfile(run/'stale/input.bin',out/'old-input.bin')
    shutil.copyfile(run/'priority-withdrawal/input.bin',out/'fresh-input.bin')
    write(out/'FREEZE.json',{'baselineFreezeSha256':sha(monitor/'FREEZE.json'),'hostSha256':sha(host),
          'programSha256':sha(program),'sourceSha256':sources,'oldInputSha256':sha(out/'old-input.bin'),
          'freshInputSha256':sha(out/'fresh-input.bin'),'noDevelopmentMode':True})
    (out/'scratch').mkdir();(out/'cache').mkdir()
    env=dict(os.environ,RAYON_NUM_THREADS='4',OMP_NUM_THREADS='4',MALLOC_ARENA_MAX='2',RISC0_PROVER='ipc',
             RISC0_SERVER_PATH=str(worker),RISC0_WORK_DIR=str(out/'scratch'),RISC0_HOME=str(ASSETS),
             XDG_CACHE_HOME=str(out/'cache'),CUDA_VISIBLE_DEVICES='0')
    assert 'RISC0_DEV_MODE' not in env and 'KPI_BATCH_REUSE_FROM' not in env
    def launch(input_name,output_name):
        stdout=(out/(output_name+'.stdout.log')).open('x')
        stderr=(out/(output_name+'.stderr.log')).open('x')
        try:
            return subprocess.Popen([str(host),'prove',str(program),str(out/input_name),str(out/output_name)],
                                    env=env,stdout=stdout,stderr=stderr,start_new_session=True)
        finally:stdout.close();stderr.close()
    print(json.dumps({'cancellationRuntime':str(out)}),flush=True)
    started=time.monotonic();old=launch('old-input.bin','cancelled');gpu_seen=False
    try:
        with (out/'SAMPLES.jsonl').open('x') as samples:
            while time.monotonic()-started<30:
                assert old.poll() is None, 'old job finished before cancellation'
                pids={old.pid,*[p.pid for p in psutil.Process(old.pid).children(recursive=True)]}
                sample={'seconds':time.monotonic()-started,'ownedPids':sorted(pids)}
                try:
                    raw=subprocess.check_output(['nvidia-smi','--query-compute-apps=pid,used_gpu_memory','--format=csv,noheader,nounits'],text=True,timeout=5)
                    matches=[line for line in raw.splitlines() if int(line.split(',')[0].strip()) in pids]
                    gpu_seen=gpu_seen or bool(matches);sample['ownedCudaApps']=matches
                except (subprocess.SubprocessError,ValueError) as error:sample['telemetryError']=str(error)
                samples.write(json.dumps(sample)+'\n');samples.flush();time.sleep(0.5)
        cancelled_seconds=time.monotonic()-started
        cleanup=stop_owned(old)
    finally:
        if old.poll() is None:stop_owned(old)
    assert gpu_seen, 'no owned CUDA work observed'
    assert not (out/'cancelled/candidate-compressed.bin').exists()
    fresh=launch('fresh-input.bin','refreshed')
    try:
        assert fresh.wait()==0, 'fresh proof failed'
    finally:
        if fresh.poll() is None:stop_owned(fresh)
    replay=verify(run,out/'refreshed',host,program)
    report=json.loads((out/'refreshed/proof-report.json').read_text())
    result={'scope':'supplementary worker control; original actual-advance race retained separately',
            'cancelledWorkSeconds':cancelled_seconds,'ownedCudaObserved':gpu_seen,**cleanup,
            'replacementProofSeconds':report['totalProofSeconds'],
            'withdrawalReadySecondsFromControlStart':time.monotonic()-started,
            'newWalletApprovals':0,'nativeTransactionBodyAndFeesUnchanged':True,'replay':replay,
            'completeBusyArrivalComparisonRepeated':False,'chainAccepted':False,
            'originalApprovalHash':json.loads((run/'APPROVALS.json').read_text())['hash']}
    write(out/'RESULT.json',result)
    print(json.dumps({'cancellationRuntime':str(out),'completed':True,'result':result}),flush=True)

if __name__=='__main__':main()
