"""Operational use of the unchanged selected public-byte HTTPS transport."""
from pathlib import Path
import argparse, hashlib, importlib.util, json, os, resource, runpy, subprocess, time

PROFILE = '69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f'
INVENTORY = '24067398ebec6624c2e7bd677404c7c01523341b0ec2e5fdcb0e140516c09bca'
RESTORE = '68a0d7ca0e5cdc7b3a6b5ca06e334d8abdf6545794e9522f36af76d39608a343'
SOURCES = ('poc/four-wallet-storage/restore.py',
 'poc/current-wrapper-runtime/transport/public_fetch.py',
 'poc/current-wrapper-runtime/transport/trusted_util.py',
 'poc/current-wrapper-runtime/transport/vendor/capsule.py',
 'poc/current-wrapper-runtime/transport/vendor/chunk_public.py')
ISSUER_HOSTS = ['forge', '10.0.3.141', 'localhost', '127.0.0.1']
GITHUB_HOSTS = {'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
CLEAN = {'PATH':'/usr/bin:/bin', 'LANG':'C.UTF-8', 'PYTHONDONTWRITEBYTECODE':'1'}

def digest(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return (json.dumps(value, sort_keys=True, indent=2)+'\n').encode()
def write(path, raw):
 path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
 fd=os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o400)
 with os.fdopen(fd, 'wb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())

ENTRY=r'''from pathlib import Path
import hashlib,importlib.util,json,resource,time
p=Path('/runtime-source/poc/four-wallet-storage/restore.py')
raw=p.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='68a0d7ca0e5cdc7b3a6b5ca06e334d8abdf6545794e9522f36af76d39608a343'
m=importlib.util.module_from_spec(importlib.util.spec_from_loader('selected_public_storage',loader=None))
m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__)
o=m.parse(Path('/inputs/OPTIONS.json').read_bytes())
absent={r['id']:not Path(r['path']).exists() for r in o['absence']}
assert absent and all(absent.values()),'original-host-path-available'
Path('/out/ABSENCE.json').write_text(json.dumps({'schema':'kpx8-terminal-public-HTTPS-absence/v1','all_original_paths_absent':all(absent.values()),'absence':absent,'wallet_private_mounts':False,'network_unshared':False},sort_keys=True,indent=2)+'\n')
start=time.monotonic()
result=m.restore(Path('/inputs/SELECTION.json').read_bytes(),o['selection_sha256'],Path('/out/restored'),excluded=['original-issuer'],denied_hosts=o['denied_hosts'])
u=resource.getrusage(resource.RUSAGE_SELF);v=resource.getrusage(resource.RUSAGE_CHILDREN)
summary={'schema':'kpx8-terminal-public-HTTPS-byte-result/v1','status':result['status'],'restored_objects':len(result['restored_objects']),'required_objects':result['required_objects'],'required_bytes':o['required_bytes'],'wall_seconds':time.monotonic()-start,'CPU_seconds_self_and_children':u.ru_utime+u.ru_stime+v.ru_utime+v.ru_stime,'all_original_paths_absent':all(absent.values()),'original_issuer_provider_excluded':True,'independent_administration_demonstrated':False,'retention_guarantee_demonstrated':False,'backup_seed_PK_or_R0_mounted':False,'newly_fetched_software_executed_or_imported':False,'financial_replay_or_payout_claimed':False}
Path('/out/BYTE-RESULT.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
print(json.dumps(summary,sort_keys=True))
raise SystemExit(0 if result['status']=='ALL_SELECTED_BYTES_RESTORED' else 1)
'''

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('selection','software-root','software-inventory','output'):
  p.add_argument('--'+name,required=True,type=Path)
 p.add_argument('--selection-sha256',required=True)
 a=p.parse_args()
 h=runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
 selection_raw=h['read'](a.selection,a.selection_sha256)
 inventory=json.loads(h['read'](a.software_inventory,INVENTORY))
 by_path={r['path']:r for r in inventory['files']};sources=[]
 for rel in SOURCES:
  row=by_path[rel];raw=h['read'](a.software_root/rel,row['sha256'])
  assert len(raw)==row['bytes'];sources.append((row,raw))
 assert by_path[SOURCES[0]]['sha256']==RESTORE
 m=importlib.util.module_from_spec(importlib.util.spec_from_loader('selected_public_storage',loader=None))
 m.__file__=str(a.software_root/SOURCES[0]);exec(compile(sources[0][1],m.__file__,'exec'),m.__dict__)
 selection,providers=m.selection(selection_raw,a.selection_sha256)
 assert selection['profile_reference_sha256']==PROFILE
 assert set(providers)=={'original-issuer','github-release'}
 assert set(providers['original-issuer']['allowed_hosts'])==set(ISSUER_HOSTS)
 assert set(providers['github-release']['allowed_hosts'])==GITHUB_HOSTS
 for asset in selection['assets']:
  assert asset['replicas'] and all(r['provider_id']=='github-release' and r['url'].startswith('https://github.com/elldeeone/kaspa-privacy-initiative/releases/download/owner-private-kas-recovery-2026-10-24/') for r in asset['replicas'])
 # The externally pinned selection must include the public terminal manifest,
 # not only its references. Its interpretation occurs after byte recovery.
 assert any(r['id']=='terminal-verification-manifest' and r['kind']=='other_public_metadata' for r in selection['assets'])
 base=a.output.absolute()
 assert '..' not in base.parts and base.is_relative_to(Path('/var/tmp/kpi-owner-private-lifecycle-01/assets'))
 assert not any(q.is_symlink() for q in (base,*base.parents))
 assert all(not base.is_relative_to(q) for q in h['m'].GUARD.directories)
 assert not base.exists();base.mkdir(mode=0o700)
 for row,raw in sources:write(base/'runtime-source'/row['path'],raw)
 write(base/'inputs/SELECTION.json',selection_raw)
 absent=[{'id':'original-home','path':'/home/luke'},
  {'id':'original-repository','path':'/home/luke/projects/kpi-intensive-2026-10-22/continuation'},
  {'id':'original-main-checkout','path':'/home/luke/projects/kaspa-privacy-initiative'},
  {'id':'original-cargo-cache','path':'/home/luke/.cargo'},
  {'id':'original-sdk-cache','path':'/home/luke/.cache/kpi-sdk'},
  {'id':'original-whole-profile-parent','path':'/var/tmp/kpi-owner-private-lifecycle-01'}]
 absent.extend({'id':'guarded-private-parent-'+str(i),'path':str(r)} for i,r in enumerate(h['m'].GUARD.directories))
 options={'selection_sha256':a.selection_sha256,'denied_hosts':ISSUER_HOSTS,'required_bytes':sum(r['bytes'] for r in selection['assets']),'absence':absent}
 write(base/'inputs/OPTIONS.json',encoded(options));write(base/'entry.py',ENTRY.encode())
 bootstrap={'schema':'kpx8-terminal-public-HTTPS-bootstrap/v1','files':[r for r,_ in sources],'entry_sha256':digest(ENTRY.encode()),'selection_sha256':a.selection_sha256,'software_inventory_sha256':INVENTORY,'required_objects':len(selection['assets']),'required_bytes':options['required_bytes'],'same_administration':True,'financial_replay_or_owner_authorization':False}
 write(base/'BOOTSTRAP.json',encoded(bootstrap))
 out=base/'client-output';out.mkdir(mode=0o700)
 cmd=['/usr/bin/bwrap','--unshare-user','--unshare-pid','--unshare-uts','--unshare-ipc','--die-with-parent','--new-session']
 for system in ('/usr','/lib','/lib64'):
  if Path(system).exists():cmd.extend(('--ro-bind',system,system))
 cmd.extend(('--dir','/etc','--ro-bind','/etc/ssl','/etc/ssl'))
 for name in ('resolv.conf','nsswitch.conf','hosts','ld.so.cache'):
  q=Path('/etc')/name
  if q.exists():cmd.extend(('--ro-bind',str(q),str(q)))
 cmd.extend(('--proc','/proc','--dev','/dev','--tmpfs','/tmp','--dir','/home',
  '--ro-bind',str(base/'runtime-source'),'/runtime-source',
  '--ro-bind',str(base/'inputs'),'/inputs','--ro-bind',str(base/'entry.py'),'/entry.py',
  '--bind',str(out),'/out','--chdir','/runtime-source','/usr/bin/python3','-B','/entry.py'))
 write(base/'COMMAND.json',encoded(cmd));started=time.monotonic()
 r=subprocess.run(cmd,stdin=subprocess.DEVNULL,capture_output=True,env=CLEAN)
 write(base/'stdout.log',r.stdout);write(base/'stderr.log',r.stderr)
 receipt=bootstrap|{'schema':'kpx8-terminal-public-HTTPS-run/v1','returncode':r.returncode,'wall_seconds':time.monotonic()-started,'same_physical_host_new_namespace':True,'network_unshared':False,'original_backup_seed_or_private_content_read':False,'newly_fetched_software_executed_or_imported':False}
 for rel in ('ABSENCE.json','BYTE-RESULT.json','restored/RESULT.json'):
  q=out/rel
  if q.exists():receipt[rel.replace('/','_')+'_sha256']=digest(h['read'](q))
 write(base/'EXECUTION.json',encoded(receipt));print(json.dumps(receipt,sort_keys=True))
 raise SystemExit(r.returncode)

if __name__=='__main__':main()
