#!/usr/bin/env python3
"""Bounded offline execution. Input/binary RO, disjoint dedicated output RW."""
import hashlib,json,os,pathlib,subprocess,sys,time
binary,input_path,execution,mode=sys.argv[1:]
binary=pathlib.Path(binary).resolve();input_path=pathlib.Path(input_path).resolve();execution=pathlib.Path(execution).resolve()
if execution.exists():raise SystemExit('refusing preexisting execution directory')
if mode not in ('actual','boundaries'):raise SystemExit('unknown phase')
execution.mkdir(parents=True)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def snapshot_pid(pid):
 try:
  stat=pathlib.Path(f'/proc/{pid}/stat').read_text();tail=stat[stat.rfind(')')+2:].split()
  return {'pid':pid,'start_ticks':int(tail[19]),'cmdline':pathlib.Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace')}
 except (OSError,ValueError):return None
cg_rel=next(x.split(':',2)[2] for x in pathlib.Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
cg=pathlib.Path('/sys/fs/cgroup')/cg_rel.lstrip('/')
cmd=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--ro-bind',str(binary),'/checker','--ro-bind',str(input_path),'/input.json','--bind',str(execution),'/output','--chdir','/output','/checker','/input.json','/output/results',mode]
before={'binary_sha256':sha(binary),'input_sha256':sha(input_path)}
launch={'argv':cmd,'before':before,'self':snapshot_pid(os.getpid()),'cgroup':str(cg),'wall_start_ns':time.time_ns(),'monotonic_start_ns':time.monotonic_ns(),'network':'unshared','input_mount':'read-only, no writable ancestor or alias','output_mount':'dedicated execution directory only'}
(execution/'launch.json').write_text(json.dumps(launch,indent=2)+'\n')
seen={};observed=[]
with (execution/'stdout.log').open('wb') as out,(execution/'stderr.log').open('wb') as err:
 child=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=out,stderr=err)
 while True:
  try:pids=[int(x) for x in (cg/'cgroup.procs').read_text().split()]
  except OSError:pids=[]
  for pid in pids:
   snap=snapshot_pid(pid)
   if snap and (pid,snap['start_ticks']) not in seen:
    seen[pid,snap['start_ticks']]=snap
   if snap and '/checker /input.json /output/results' in snap['cmdline'] and not observed:
    try:
     mounts=pathlib.Path(f'/proc/{pid}/mountinfo').read_text()
     (execution/'checker-mountinfo.txt').write_text(mounts)
     observed.append({'pid':pid,'start_ticks':snap['start_ticks'],'mount_rows':[line for line in mounts.splitlines() if line.split()[4] in ('/checker','/input.json','/output')]})
    except OSError:pass
  if child.poll() is not None:break
  time.sleep(.001)
 code=child.wait()
after={'binary_sha256':sha(binary),'input_sha256':sha(input_path)}
resources={}
for name in ('memory.peak','memory.swap.peak','memory.events','cpu.stat','cgroup.procs','cgroup.events'):
 try:resources[name]=(cg/name).read_text()
 except OSError as e:resources[name]=str(e)
result={'returncode':code,'wall_end_ns':time.time_ns(),'monotonic_end_ns':time.monotonic_ns(),'before':before,'after':after,'input_binary_unchanged':before==after,'live_checker_namespace_observed':observed,'observed_processes':list(seen.values()),'resource_snapshot_while_auditor_alive':resources}
(execution/'run-metadata.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'returncode':code,'seconds':(result['monotonic_end_ns']-launch['monotonic_start_ns'])/1e9,'memory_peak':resources.get('memory.peak'),'checker_namespace_observed':bool(observed)}))
if before!=after:raise SystemExit('input/binary changed during execution')
raise SystemExit(code)
