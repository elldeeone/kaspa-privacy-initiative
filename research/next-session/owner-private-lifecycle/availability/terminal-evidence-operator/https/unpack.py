from pathlib import Path
import hashlib,json,os,resource,runpy,subprocess,time
ROOT=Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
BASE=Path('/var/tmp/kpi-owner-private-lifecycle-01/assets/terminal-verification-HTTPS-01')
STAGE=BASE/'strict-unpack-stage-01'
PINS={'poc/recovery-coldbuild/unpack_bundle.py':'19c41c96b41c968a0ed0dfefe3a38fe855a323ce366b1f1aba46ef155a6d2a22','poc/recovery-coldbuild/software_bundle.py':'b3e933ca76cfad21e70b50568824b6f9fff3034c58c4cbf5d8d36d7932e1a705'}
PINNED={
 'archive':('software-archive',52866973,'6b5a60ddd37eefbff871c61a257aa0173899940df9faf3c042d932ad4de7a0fa'),
 'members':('software-members',11061,'74d08130fe997890a44fb4b1cb85a85836107f69866f6f14b854a8a22afa61ce'),
 'inventory':('software-inventory',10510,'24067398ebec6624c2e7bd677404c7c01523341b0ec2e5fdcb0e140516c09bca')}
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def write(p,raw):
 p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
ENTRY=r'''from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
sys.path.insert(0,'/trusted/poc/recovery-coldbuild')
import unpack_bundle
options=json.loads(Path('/inputs/OPTIONS.json').read_bytes())
absence={str(i):not Path(path).exists() for i,path in enumerate(options['absence'])}
assert all(absence.values()),'original-host-path-available'
receipt=unpack_bundle.unpack(Path('/inputs/archive'),Path('/inputs/members'),'6b5a60ddd37eefbff871c61a257aa0173899940df9faf3c042d932ad4de7a0fa',52866973,'74d08130fe997890a44fb4b1cb85a85836107f69866f6f14b854a8a22afa61ce','24067398ebec6624c2e7bd677404c7c01523341b0ec2e5fdcb0e140516c09bca',Path('/out/software'))
assert hashlib.sha256(Path('/inputs/inventory').read_bytes()).hexdigest()==receipt['typed_software_inventory_sha256']
Path('/out/RESULT.json').write_text(json.dumps({'schema':'kpx8-terminal-HTTPS-strict-unpack/v1','original_paths_absent':all(absence.values()),'network_unshared':True,'GPU_unavailable':not Path('/dev/nvidia0').exists(),'unpack':receipt,'newly_fetched_payload_executed_or_imported':False},sort_keys=True,indent=2)+'\n')
'''
h=runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
result=json.loads(h['read'](BASE/'client-output/restored/RESULT.json'))
assert result['status']=='ALL_SELECTED_BYTES_RESTORED' and len(result['restored_objects'])==result['required_objects']
restored={row['asset_id']:row for row in result['restored_objects']}
sources=[(p,h['read'](ROOT/p,pin)) for p,pin in PINS.items()]
inputs={}
for name,(identifier,size,pin) in PINNED.items():
 row=restored[identifier]
 assert (row['bytes'],row['sha256'],row['provider_id'])==(size,pin,'github-release')
 assert row['relative_path']=='objects/'+identifier+'--'+pin
 path=BASE/'client-output/restored'/row['relative_path']
 raw=h['read'](path,pin)
 assert len(raw)==size
 inputs[name]=raw
assert not STAGE.exists();STAGE.mkdir(mode=0o700)
for p,raw in sources:write(STAGE/'trusted'/p,raw)
for name,raw in inputs.items():write(STAGE/'inputs'/name,raw)
write(STAGE/'entry.py',ENTRY.encode())
options={'absence':['/home/luke',str(ROOT),'/var/tmp/kpi-owner-private-lifecycle-01','/home/luke/.cargo','/home/luke/.cache/kpi-sdk']+[str(p) for p in h['m'].GUARD.directories]}
write(STAGE/'OPTIONS.json',encoded(options));out=STAGE/'output';out.mkdir(mode=0o700)
command=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session']
for system in ('/usr','/lib','/lib64'):
 if Path(system).exists():command.extend(('--ro-bind',system,system))
command.extend(('--proc','/proc','--dev','/dev','--tmpfs','/tmp','--dir','/home','--ro-bind',str(STAGE/'trusted'),'/trusted','--dir','/inputs','--ro-bind',str(STAGE/'OPTIONS.json'),'/inputs/OPTIONS.json','--ro-bind',str(STAGE/'entry.py'),'/entry.py','--bind',str(out),'/out'))
for name in inputs:command.extend(('--ro-bind',str(STAGE/'inputs'/name),'/inputs/'+name))
command.extend(('--chdir','/trusted','/usr/bin/python3','-B','/entry.py'))
write(STAGE/'COMMAND.json',encoded(command))
start=time.monotonic();usage_start=resource.getrusage(resource.RUSAGE_CHILDREN)
process=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,text=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
usage_end=resource.getrusage(resource.RUSAGE_CHILDREN);elapsed=time.monotonic()-start
write(STAGE/'stdout.log',process.stdout.encode());write(STAGE/'stderr.log',process.stderr.encode())
receipt={'schema':'kpx8-terminal-HTTPS-strict-unpack-run/v1','returncode':process.returncode,'elapsed_seconds':elapsed,'trusted_source_pins':PINS,'entry_sha256':digest(ENTRY.encode()),'source_result_sha256':digest(h['read'](BASE/'client-output/restored/RESULT.json')),'network_unshared':True,'private_files_opened':0,'newly_fetched_payload_executed_or_imported':False}
if (out/'RESULT.json').exists():receipt['result_sha256']=digest(h['read'](out/'RESULT.json'))
write(STAGE/'EXECUTION.json',encoded(receipt));print(json.dumps(receipt,sort_keys=True))
raise SystemExit(process.returncode)
