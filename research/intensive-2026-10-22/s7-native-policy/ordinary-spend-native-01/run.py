import pathlib,subprocess,json,hashlib,time,os,datetime
p=pathlib.Path(__file__).resolve().parent
f=json.loads((p/'input-freeze.json').read_text())
def check():
 for row in f['inputs']:
  if hashlib.sha256(pathlib.Path(row['snapshot']).read_bytes()).hexdigest()!=row['sha256']:raise RuntimeError('input changed:'+row['snapshot'])
check();start=time.monotonic();started=datetime.datetime.now(datetime.timezone.utc).isoformat()
cg=pathlib.Path('/sys/fs/cgroup'+pathlib.Path('/proc/self/cgroup').read_text().strip().split('::',1)[1]);pid=os.getpid();ticks=pathlib.Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]
with (p/'stdout.log').open('w') as stdout,(p/'stderr.log').open('w') as stderr:r=subprocess.run(json.loads((p/'command.json').read_text()),stdout=stdout,stderr=stderr)
check()
res={}
for n in ['memory.peak','memory.swap.peak','cpu.stat','cgroup.events','cgroup.procs']:
 try:res[n]=(cg/n).read_text()
 except OSError as e:res[n]=str(e)
(p/'result.json').write_text(json.dumps({'exit_code':r.returncode,'elapsed_seconds':time.monotonic()-start,'started_utc':started,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'resource_auditor_pid':pid,'resource_auditor_start_ticks':ticks,'owned_cgroup':str(cg),'inputs_before_after_equal':True,'resource_at_checker_return':res},indent=2)+'\n')
raise SystemExit(r.returncode)
