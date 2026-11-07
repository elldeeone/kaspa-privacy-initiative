#!/usr/bin/env python3
"""Finish a frozen same-input comparison with one GPU worker at a time."""
import argparse, json, os, pathlib, subprocess, time

def main():
    p=argparse.ArgumentParser();p.add_argument('configuration',type=pathlib.Path);a=p.parse_args()
    c=json.loads(a.configuration.read_text());run=pathlib.Path(c['run'])
    env=dict(os.environ,RISC0_PROVER='ipc',RISC0_SERVER_PATH='/home/luke/projects/kpi-intensive-2026-10-22/proof-target/tools/r0vm-cuda',RISC0_HOME='/home/luke/projects/kpi-intensive-2026-10-22/observer/artifacts/groth16-compression-preparation/risc0-home',CUDA_VISIBLE_DEVICES='0',RAYON_NUM_THREADS='4',OMP_NUM_THREADS='4',MALLOC_ARENA_MAX='2')
    env.pop('RISC0_DEV_MODE',None);env.pop('KPI_BATCH_REUSE_FROM',None)
    while not (run/'authorization-cache/REPORT.json').exists():
        pid=int((run/'authorize.pid').read_text())
        try:os.kill(pid,0)
        except ProcessLookupError:raise RuntimeError('authorization failed; preserve log and stop')
        time.sleep(1)
    def call(label,args):
        work=run/(label+'-work');work.mkdir()
        env['RISC0_WORK_DIR']=str(work);env['XDG_CACHE_HOME']=str(run/'xdg-cache')
        with (run/(label+'.log')).open('x') as log:
            print('START',label,flush=True)
            subprocess.run([c['host'],*map(str,args)],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
            print('DONE',label,flush=True)
    for i in range(3):
        label=f'composed-{i}'
        call(label,['settle',c['authorization'],c['settlement'],run/f'cases/{i}/input.bin',run/'authorization-cache/receipt.bin',run/label])
        subprocess.run([c['host'],'native',c['settlement'],str(run/f'cases/{i}'),str(run/label)],env=env,check=True)
    call('direct-2',['direct',c['settlement'],run/'cases/2/input.bin',run/'direct-2'])
    subprocess.run([c['host'],'native',c['settlement'],str(run/'cases/2'),str(run/'direct-2')],env=env,check=True)
    cache=json.loads((run/'authorization-cache/REPORT.json').read_text())
    composed=[json.loads((run/f'composed-{i}/REPORT.json').read_text()) for i in range(3)]
    direct=json.loads((run/'direct-2/REPORT.json').read_text())
    assert (run/'composed-2/expected-journal.bin').read_bytes()==(run/'direct-2/expected-journal.bin').read_bytes()
    delta=direct['seconds']-composed[2]['seconds']
    result={'scope':'same-image, same-input native Full supplied-state diagnostics; no ancestry or chain claim','cache':cache,'fresh':composed,'direct':direct,'sameEconomicJournal':True,'reuseBreakEvenAttempts':cache['seconds']/delta if delta>0 else None,'coldCachedAttemptSeconds':cache['seconds']+composed[2]['seconds']}
    with (run/'DIAGNOSTIC.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result),flush=True)

if __name__=='__main__':main()
