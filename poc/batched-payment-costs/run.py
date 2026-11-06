#!/usr/bin/env python3
"""One local, measured proof campaign; no provider/RPC/broadcast capabilities."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
import psutil
import shutil

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
TOOLS=Path('/home/luke/projects/kpi-intensive-2026-10-22/proof-target/tools')
ASSETS=Path('/home/luke/projects/kpi-intensive-2026-10-22/observer/artifacts/groth16-compression-preparation/risc0-home')

def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def write(p,value):
    with p.open('x') as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')

def main():
    extras_core=Path(sys.argv[2]).resolve() if len(sys.argv)>2 and sys.argv[1]=='--extras' else None
    resume_core=Path(sys.argv[2]).resolve() if len(sys.argv)>2 and sys.argv[1]=='--resume' else None
    target=ROOT/'.local/ci-target'
    env=dict(os.environ,CARGO_TARGET_DIR=str(target),RAYON_NUM_THREADS='4',OMP_NUM_THREADS='4',PYTHONDONTWRITEBYTECODE='1')
    assert 'RISC0_DEV_MODE' not in env
    subprocess.run(['cargo','+1.97.1','build','--locked','--release','--manifest-path',str(HERE/'host/Cargo.toml')],cwd=ROOT,env=env,check=True)
    guest_env=dict(env,RISC0_FEATURE_bigint2='1',RUSTC=str(TOOLS/'risc0-rust/bin/rustc'),RUSTFLAGS='-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"')
    subprocess.run(['cargo','+1.97.1','build','--locked','--release','--target','riscv32im-risc0-zkvm-elf','--manifest-path',str(HERE/'guest/Cargo.toml')],cwd=ROOT,env=guest_env,check=True)
    parent=ROOT/'.local/batched-payment-costs';parent.mkdir(exist_ok=True)
    identity=str(uuid.uuid4());monitor=parent/(identity+'-monitor');monitor.mkdir(mode=0o700)
    run=parent/identity
    binary=target/'release/kpi-batched-payment-costs'
    program=monitor/'guest.program.bin'
    image=subprocess.check_output([str(binary),'wrap',str(target/'riscv32im-risc0-zkvm-elf/release/kpi-batched-payment-guest'),str(program)],cwd=ROOT,text=True).strip()
    files=sorted(p for p in HERE.rglob('*') if p.is_file() and p.suffix in ('.rs','.toml','.lock','.py'))
    files += [ROOT/'docs/adr/0109-complete-cost-and-batched-payout-test.md']+sorted((ROOT/'research/batched-payment-costs-2026-11-06').glob('*.md'))
    files += sorted((ROOT/'poc/private-note-wallet/src').glob('*.rs'))+sorted((ROOT/'poc/accelerated-bn254/common/src').glob('*.rs'))
    worker=TOOLS/'r0vm-cuda'
    assert sha(worker)=='3f22b68b6d32904fe766e14e62ce011febdc946dd98d015747f40ce5fb5fffc7'
    snapshot=monitor/'source';snapshot.mkdir()
    for p in files:
        dest=snapshot/p.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
    write(monitor/'FREEZE.json',{'frozenAtUtc':datetime.now(timezone.utc).isoformat(),'baseCommit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'image':image,'programSha256':sha(program),'hostSha256':sha(binary),'workerSha256':sha(worker),'sourceSha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'scope':'fresh local GPU proofs, native Full validation with explicit supplied source UTXO; not paid or chain evidence'})
    scratch=monitor/'scratch';scratch.mkdir();cache=monitor/'cache';cache.mkdir()
    if resume_core:env.update(KPI_BATCH_REUSE_FROM=str(resume_core),KPI_BATCH_OUTPUT=str(run))
    env.update(RUST_BACKTRACE='1',RISC0_PROVER='ipc',RISC0_SERVER_PATH=str(worker),RISC0_WORK_DIR=str(scratch),RISC0_HOME=str(ASSETS),XDG_CACHE_HOME=str(cache),CUDA_VISIBLE_DEVICES='0')
    print(json.dumps({'runtime':str(run),'monitor':str(monitor),'image':image}),flush=True)
    started=time.monotonic();last_t=started;last_power=None;energy_ws=0.0;peak_rss=0;peak_gpu=0;other_gpu=set()
    with (monitor/'stdout.log').open('x') as stdout,(monitor/'stderr.log').open('x') as stderr:
        command=[str(binary),'extras',str(program),str(extras_core),str(run)] if extras_core else [str(binary),'run',str(program),str(run)]
        write(monitor/'INVOCATION.json',{'command':command,'launchedAtUtc':datetime.now(timezone.utc).isoformat(),'coreRuntime':str(extras_core) if extras_core else None})
        process=subprocess.Popen(command,cwd=ROOT,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
        with (monitor/'resource-samples.jsonl').open('x') as samples:
            while process.poll() is None:
                now=time.monotonic();owned=[]
                try:owned=[psutil.Process(process.pid),*psutil.Process(process.pid).children(recursive=True)]
                except psutil.Error:pass
                pids={p.pid for p in owned};rss=0;cpu=0
                for p in owned:
                    try:rss+=p.memory_info().rss;times=p.cpu_times();cpu+=times.user+times.system
                    except psutil.Error:pass
                peak_rss=max(peak_rss,rss)
                sample={'seconds':now-started,'ownedPids':sorted(pids),'summedRssBytes':rss,'currentOwnedCpuSeconds':cpu}
                try:
                    apps=subprocess.check_output(['nvidia-smi','--query-compute-apps=pid,used_gpu_memory','--format=csv,noheader,nounits'],text=True,timeout=5)
                    gpu=0
                    for line in apps.splitlines():
                        pid,mem=(x.strip() for x in line.split(','));pid=int(pid)
                        if pid in pids:gpu+=int(mem)
                        else:other_gpu.add(pid)
                    peak_gpu=max(peak_gpu,gpu);sample['matchingGpuMemoryMiB']=gpu
                    telemetry=subprocess.check_output(['nvidia-smi','--query-gpu=power.draw,utilization.gpu,temperature.gpu','--format=csv,noheader,nounits'],text=True,timeout=5).strip()
                    power=float(telemetry.split(',')[0]);sample['gpuGlobalTelemetry']=telemetry
                    if last_power is not None:energy_ws+=(now-last_t)*(power+last_power)/2
                    last_power=power
                except (subprocess.SubprocessError,ValueError) as error:sample['telemetryError']=str(error)
                last_t=now;samples.write(json.dumps(sample)+'\n');samples.flush()
                time.sleep(1)
        code=process.wait()
    write(monitor/'RESOURCES.json',{'returnCode':code,'elapsedSeconds':time.monotonic()-started,'peakSampledSummedRssBytes':peak_rss,'peakSampledMatchingGpuMemoryMiB':peak_gpu,'sampledGlobalGpuEnergyWh':energy_ws/3600,'otherGpuComputePids':sorted(other_gpu),'providerCharges':0,'limits':'GPU power is device-wide including display/idle; samples may miss peaks and shared RSS may double-count. CPU/whole-host electricity/depreciation are not priced.','actualInvoice':'no provider allocation or invoice; local hardware usage is reported separately'})
    if code:raise SystemExit(f'Run failed ({code}); preserve {monitor} and {run}')
    print(json.dumps({'runtime':str(run),'resources':str(monitor/'RESOURCES.json'),'completed':True}),flush=True)

if __name__=='__main__':main()
