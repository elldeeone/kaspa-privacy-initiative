#!/usr/bin/python3
# Trusted orchestration only: own-unit counters/process identities; no financial input reads.
import json,os,subprocess,sys,time
from pathlib import Path
unit,folder=sys.argv[1:];base=Path(folder);base.mkdir(mode=0o700)
props=['LoadState','ActiveState','SubState','MainPID','ControlGroup','ExecMainStatus','Result','MemoryPeak','MemorySwapPeak','CPUUsageNSec','CPUQuotaPerSecUSec','MemoryMax','MemorySwapMax']
def command(args):return subprocess.run(args,capture_output=True,text=True)
def show():
 r=command(['/usr/bin/systemctl','--user','show',unit]+['--property='+x for x in props])
 if r.returncode:raise RuntimeError('owned-unit-properties-unavailable')
 return dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)
def start(pid):
 try:return Path('/proc/'+str(pid)+'/stat').read_text().rsplit(') ',1)[1].split()[19]
 except (OSError,IndexError):return None
def number(path):
 try:return int(path.read_text().strip())
 except (OSError,ValueError):return None
def processes(group):
 p=Path('/sys/fs/cgroup')/group.lstrip('/')
 try:return {int(x) for x in (p/'cgroup.procs').read_text().split()},p
 except OSError:return set(),p
def gpu(pids):
 r=command(['/usr/bin/nvidia-smi','--query-compute-apps=pid,used_gpu_memory','--format=csv,noheader,nounits'])
 if r.returncode:return None
 out=[]
 for line in r.stdout.splitlines():
  try:
   pid,mib=map(int,line.split(','))
   if pid in pids:out.append({'pid':pid,'used_gpu_memory_MiB':mib,'start_ticks':start(pid)})
  except ValueError:pass
 return out
observed={};samples=[];initial=None;last=None;cleanup={};started=time.monotonic()
try:
 while True:
  state=show();group=state.get('ControlGroup','');pids,cgroup=processes(group) if group else (set(),Path('/nonexistent'))
  for pid in pids:
   ticks=start(pid)
   if ticks is not None:observed[str(pid)+':'+ticks]={'pid':pid,'start_ticks':ticks}
  row={'elapsed_seconds':time.monotonic()-started,'properties':state,'cgroup_PIDs':sorted(pids),'memory_current':number(cgroup/'memory.current'),'memory_peak':number(cgroup/'memory.peak'),'memory_swap_current':number(cgroup/'memory.swap.current'),'owned_GPU_compute_apps':gpu(pids)};samples.append(row)
  if initial is None:initial=state
  last=state
  if state.get('ActiveState')=='failed' or state.get('SubState') in ('exited','dead') and state.get('MainPID')=='0':break
  time.sleep(1)
finally:
 stop=command(['/usr/bin/systemctl','--user','stop',unit]);after=show()
 alive=[v for v in observed.values() if start(v['pid'])==v['start_ticks']]
 cleanup={'stop_returncode':stop.returncode,'properties_after_stop':after,'original_observed_processes_still_alive':alive,'owned_unit_inactive_MainPID0':after.get('ActiveState')=='inactive' and after.get('MainPID')=='0','owned_GPU_sampling_scope':'only contemporaneous owned cgroup PIDs; sampled maximum is not guaranteed lifetime peak'}
 result={'schema':'kpx6-public-R0-owned-unit-observation/v1','unit':unit,'sampling_seconds':1,'elapsed_seconds':time.monotonic()-started,'initial':initial,'final_before_stop':last,'observed_process_identities':list(observed.values()),'samples':samples,'cleanup':cleanup,'private_financial_input_bytes_read_by_monitor':False}
 with (base/'OBSERVATION.json').open('x') as f:json.dump(result,f,sort_keys=True,indent=2);f.write('\n')
 print(json.dumps({'unit':unit,'final':last,'cleanup':cleanup,'samples':len(samples)},sort_keys=True),flush=True)
 if not cleanup['owned_unit_inactive_MainPID0'] or alive:raise SystemExit(2)
if last.get('ExecMainStatus')!='0' or last.get('Result')!='success':raise SystemExit(3)
