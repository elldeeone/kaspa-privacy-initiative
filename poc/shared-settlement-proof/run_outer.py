#!/usr/bin/env python3
"""One fixed PUBLIC ADR59 outer stage, measured in its own offline cgroup."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT.parent/'adr59-public-R0-01'
RUNTIME = ROOT.parent/'adr59-R0-selected-runtime-01'
SELECTION = ROOT/'research/next-session/independent-payments/fees/R0-RUNTIME-SELECTION-01.json'
SELECTION_SHA = 'efbbd191dec2feed0dffa6367a833c19bf2dbbf77fae22de1d1116c2397631ad'
ASSETS = ROOT.parent/'observer/artifacts/groth16-compression-preparation/risc0-home'
AUTH = ROOT/'research/next-session/independent-payments/fees/RUNTIME-AUTHENTICATION-03.json'
AUTH_SHA = 'cefdd00b2c97342d0d19108f59f240eaef5f417cdf967cb08cce36be376add59'

def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def write(path, data):
    with path.open('x') as stream:
        json.dump(data, stream, sort_keys=True, indent=2); stream.write('\n')

def props(unit):
    keys = ['ActiveState','SubState','MainPID','ControlGroup','ExecMainStatus','Result',
            'MemoryPeak','MemorySwapPeak','CPUUsageNSec','MemoryMax','MemorySwapMax','CPUQuotaPerSecUSec']
    r = subprocess.run(['systemctl','--user','show',unit,*sum((['-p',k] for k in keys),[])],
                       capture_output=True,text=True,check=True)
    return dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)

def main():
    assert len(sys.argv)==2 and sys.argv[1] in ['execute','prove','verify','compress','verify-compressed','native-proof']
    mode = sys.argv[1]
    assert 'RISC0_DEV_MODE' not in os.environ
    assert sha(SELECTION)==SELECTION_SHA
    selection=json.loads(SELECTION.read_bytes())
    for row in selection['whole_runtime_files']:
        p=Path(row['path']); assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256']
    assert sha(BASE/'input.bin')==selection['input_sha256']
    assert sha(BASE/'expected-journal.bin')==selection['journal_sha256']
    if mode in ['execute','prove','compress']:
        assert sha(AUTH)==AUTH_SHA
        auth=json.loads(AUTH.read_bytes())
        for row in auth['whole_bytes_reauthenticated']:
            p=Path(row['path']); assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256']
    if mode=='prove':
        assert json.loads((BASE/'execute/report.json').read_bytes())['public_guest_execution_passed'] is True
    output=BASE/mode; monitor=BASE/(mode+'-monitor'); monitor.mkdir()
    scratch=BASE/(mode+'-work'); scratch.mkdir()
    cache=BASE/(mode+'-cache'); cache.mkdir()
    assert not output.exists()
    j=str(BASE/'expected-journal.bin')
    if mode in ['execute','prove']:
        args=[mode,str(RUNTIME/'guest.program.bin'),str(BASE/'input.bin'),j,str(output)]
    elif mode in ['verify','verify-compressed','native-proof']:
        receipt=BASE/('compress/groth16-receipt.bin' if mode!='verify' else 'prove/receipt.bin')
        args=['native-proof' if mode=='native-proof' else 'verify',str(receipt),j,str(output)]
    else:
        receipt=BASE/'prove/receipt.bin'
        args=['compress',str(receipt),sha(receipt),j,str(output)]
    heavy=mode in ['execute','prove','compress']; cpus=14 if heavy else 2; memory='20G' if heavy else '3G'
    unit='kpi-adr59-R0-'+mode+'-01.service'
    env=['/usr/bin/env','-i','HOME=/home/luke','PATH=/usr/bin:/bin','LANG=C.UTF-8',
         'RISC0_PROVER=ipc','RISC0_SERVER_PATH='+str(RUNTIME/'r0vm-cuda'),
         'RISC0_WORK_DIR='+str(scratch),'RISC0_HOME='+str(ASSETS),'XDG_CACHE_HOME='+str(cache),
         'GITHUB_TOKEN=','RAYON_NUM_THREADS='+str(cpus),'OMP_NUM_THREADS='+str(cpus),
         'CUDA_VISIBLE_DEVICES=0','RUST_LOG=info','LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu']
    command=['systemd-run','--user','--unit='+unit,'--service-type=exec','-p','RemainAfterExit=yes',
             '-p','MemoryMax='+memory,'-p','MemorySwapMax=0','-p','CPUQuota='+str(cpus*100)+'%',
             '-p','KillMode=control-group','-p','TimeoutStopSec=15',
             '-p','StandardOutput=append:'+str(monitor/'stdout.log'),
             '-p','StandardError=append:'+str(monitor/'stderr.log'),
             '/usr/bin/bwrap','--die-with-parent','--unshare-net','--ro-bind','/','/',
             '--bind',str(BASE),str(BASE),'--dev-bind','/dev','/dev','--proc','/proc','--tmpfs','/tmp',
             '--chdir',str(ROOT),'/usr/bin/time','-v','-o',str(monitor/'resources.txt'),
             *env,str(RUNTIME/'host'),*args]
    write(monitor/'launch.json',{'command':command,'runtime_selection_sha256':SELECTION_SHA,
          'controller_sha256':sha(__file__),'mode':mode,'private_owner_inputs':False,
          'network_namespace':'isolated; local IPC permitted','source_or_backup_absence_claim':False,
          'runtime_authentication_sha256':AUTH_SHA,'operational_limit_is_not_validity':True})
    start=time.monotonic()
    peak_gpu=0; observed=set(); final={}
    try:
        subprocess.run(command,capture_output=True,text=True,check=True)
        with (monitor/'samples.jsonl').open('x') as stream:
            while True:
                p=props(unit); sample={'seconds':time.monotonic()-start,'unit':p}
                group=Path('/sys/fs/cgroup')/p.get('ControlGroup','').lstrip('/')
                try:
                    if not p.get('ControlGroup'):
                        sample['kernel_cgroup_process_observation']='unavailable_empty_control_group'
                        raise FileNotFoundError('no owned cgroup path')
                    pids={int(v) for v in (group/'cgroup.procs').read_text().split()}
                    sample['memory_current']=int((group/'memory.current').read_text())
                    sample['memory_peak']=int((group/'memory.peak').read_text())
                    sample['swap_current']=int((group/'memory.swap.current').read_text())
                except (FileNotFoundError,ValueError): pids=set()
                for pid in pids:
                    try:
                        proc=Path('/proc')/str(pid); raw=(proc/'stat').read_text()
                        ticks=int(raw[raw.rfind(')')+2:].split()[19]); observed.add((pid,ticks))
                    except (FileNotFoundError,ProcessLookupError): pass
                gpu=subprocess.run(['nvidia-smi','--query-compute-apps=pid,used_gpu_memory',
                                    '--format=csv,noheader,nounits'],capture_output=True,text=True)
                owned=[]
                for line in gpu.stdout.splitlines():
                    try:
                        pid,mib=map(int,line.split(','))
                        if pid in pids: owned.append({'pid':pid,'used_mib':mib})
                    except ValueError: pass
                peak_gpu=max(peak_gpu,sum(v['used_mib'] for v in owned)); sample['matching_gpu_processes']=owned
                sample['global_gpu_csv']=subprocess.run(['nvidia-smi',
                    '--query-gpu=index,memory.used,utilization.gpu,power.draw,temperature.gpu',
                    '--format=csv,noheader,nounits'],capture_output=True,text=True).stdout.strip()
                stream.write(json.dumps(sample,sort_keys=True)+'\n');stream.flush()
                if p.get('SubState') in ['exited','failed','dead'] or p.get('ActiveState') in ['inactive','failed']:
                    final=p; break
                time.sleep(1)
    finally:
        stop=subprocess.run(['systemctl','--user','stop',unit],capture_output=True,text=True)
        still=[]
        for pid,ticks in observed:
            try:
                raw=(Path('/proc')/str(pid)/'stat').read_text()
                if int(raw[raw.rfind(')')+2:].split()[19])==ticks:still.append(pid)
            except (FileNotFoundError,ProcessLookupError):pass
        write(monitor/'terminal.json',{'mode':mode,'seconds':time.monotonic()-start,'final_properties':final,
              'sampled_matching_gpu_peak_mib':peak_gpu,'owned_processes_still_alive':still,
              'stop_exit_code':stop.returncode,'stop_stderr':stop.stderr,
              'sampling_limit':'One-second GPU samples can miss peaks; global telemetry is not process-specific.'})
        assert not still,'owned worker survived cleanup'
        subprocess.run(['systemctl','--user','reset-failed',unit],capture_output=True)
    assert final.get('ExecMainStatus')=='0' and final.get('Result')=='success','stage failed; preserved logs/candidates are not qualification'
    print((output/'report.json').read_text(),flush=True)

if __name__=='__main__':main()
