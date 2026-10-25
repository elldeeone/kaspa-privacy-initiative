"""Materialize only authenticated fresh terminal objects, then fixed cold replay."""
from pathlib import Path, PurePosixPath
import argparse, hashlib, json, os, runpy, stat, subprocess, time

BASE=Path('/var/tmp/kpi-owner-private-lifecycle-01/assets/terminal-verification-HTTPS-01')
PROFILE='69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f'
DOMAIN='be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480'
REPLAY='eaf2fd951211faecefee7019f2fe1d7caaf908b18f71f6a4e00958b6cef8f863'
INVENTORY='24067398ebec6624c2e7bd677404c7c01523341b0ec2e5fdcb0e140516c09bca'
CODEC='8f724750bb4cc849e2e4bde26fc8da2b5bc7f9a7e4ffd09153ee1af15858d208'

def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pairs(rows):
 d={}
 for k,v in rows:
  if k in d:raise ValueError('duplicate JSON field')
  d[k]=v
 return d
def parse(raw):return json.loads(raw,object_pairs_hook=pairs)
def relative(s):
 p=PurePosixPath(s)
 assert isinstance(s,str) and s and str(p)==s and not p.is_absolute() and '..' not in p.parts and '.' not in p.parts
 return p
def attrs(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink'))
def write(path,raw):
 path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--index-sha256',required=True)
 p.add_argument('--selection-sha256',required=True)
 a=p.parse_args();h=runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
 selected=parse(h['read'](BASE/'inputs/SELECTION.json',a.selection_sha256))
 assert selected['profile_reference_sha256']==PROFILE
 selection={r['id']:r for r in selected['assets']};assert len(selection)==len(selected['assets'])
 result_raw=h['read'](BASE/'client-output/restored/RESULT.json');result=parse(result_raw)
 assert result['status']=='ALL_SELECTED_BYTES_RESTORED' and len(result['restored_objects'])==result['required_objects']==len(selection)
 restored={r['asset_id']:r for r in result['restored_objects']};assert set(restored)==set(selection)
 def obj(identifier):
  r=restored[identifier];s=selection[identifier]
  assert r['provider_id']=='github-release' and (r['bytes'],r['sha256'])==(s['bytes'],s['sha256'])
  assert r['relative_path']=='objects/'+identifier+'--'+s['sha256']
  return BASE/'client-output/restored'/r['relative_path']
 raw=h['read'](obj('terminal-verification-manifest'),a.index_sha256);index=parse(raw)
 assert selection['terminal-verification-manifest']['sha256']==a.index_sha256
 assert set(index)=={'schema','domain_hex32','financial_profile_sha256','trial_id','accepted_pool_transaction_ids','accepted_cases','checkpoint_sha256','initial_R2_inventory_sha256','initial_R2_snapshot_changed','owner_client_associations_selected','financial_verifier_or_consensus_claimed_by_packager','availability_claimed_by_manifest','objects'}
 assert index['schema']=='kpx8-terminal-public-evidence-index/v1' and index['domain_hex32']==DOMAIN and index['financial_profile_sha256']==PROFILE
 assert len(index['accepted_pool_transaction_ids'])==12 and len(set(index['accepted_pool_transaction_ids']))==12
 assert index['initial_R2_snapshot_changed'] is False and index['owner_client_associations_selected'] is False
 rows={r['id']:r for r in index['objects']};assert len(rows)==len(index['objects']) and set(rows)|{'terminal-verification-manifest'}==set(selection)
 assert len({r['placement'] for r in rows.values()})==len(rows)
 for identifier,row in rows.items():
  assert set(row)=={'id','kind','bytes','sha256','placement','release_filename','public_urls'}
  s=selection[identifier];assert (row['bytes'],row['sha256'],row['kind'])==(s['bytes'],s['sha256'],s['kind'])
  assert row['public_urls'] and {r['url'] for r in s['replicas']}==set(row['public_urls'])
  relative(row['placement']);obj(identifier)
 stage=BASE/'materialized';assert not stage.exists();stage.mkdir(mode=0o700)
 for identifier,row in rows.items():
  source=obj(identifier);target=stage/relative(row['placement']);target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
  source,before=h['m'].GUARD.metadata(source);assert stat.S_ISREG(before.st_mode) and before.st_nlink==1
  fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);out=None
  try:
   assert attrs(os.fstat(fd))==attrs(before)
   out=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400);digest=hashlib.sha256();count=0
   while True:
    part=os.read(fd,4<<20)
    if not part:break
    count+=len(part);assert count<=row['bytes'];digest.update(part)
    view=memoryview(part)
    while view:written=os.write(out,view);assert written>0;view=view[written:]
   assert count==row['bytes'] and digest.hexdigest()==row['sha256'] and attrs(os.fstat(fd))==attrs(before)
   os.fsync(out)
  finally:
   os.close(fd)
   if out is not None:os.close(out)
 by_place={r['placement']:r for r in rows.values()}
 packet_row=rows['terminal-replay-packet'];assert packet_row['placement']=='data/REPLAY-PACKET.json'
 packet=parse(h['read'](stage/packet_row['placement'],packet_row['sha256']))
 assert packet['expected']['checkpoint_sha256']==index['checkpoint_sha256']
 assert all(pin in {r['sha256'] for r in rows.values()} for pin in packet['expected'].values())
 for row in [*packet['inputs'].values(),*packet['pages']]:
  chosen=by_place['data/'+row['path']];assert (chosen['bytes'],chosen['sha256'])==(row['bytes'],row['sha256'])
 fetch=packet['inputs']['fetch'];observed=parse(h['read'](stage/'data'/relative(fetch['path']),fetch['sha256']))
 assert [r['transaction']['id'] for r in observed['transactions']]==index['accepted_pool_transaction_ids']
 wrapper=rows['closed-replay-bootstrap'];assert wrapper['sha256']==REPLAY and wrapper['bytes']==17231 and wrapper['placement']=='overlay/poc/owner-private-lifecycle/recovery/replay_closed.py'
 h['read'](stage/wrapper['placement'],REPLAY);h['read'](stage/'metadata/SOFTWARE-BUNDLE.json',INVENTORY);h['read'](stage/'objects/native-codec',CODEC)
 software=BASE/'strict-unpack-stage-01/output/software'
 h['read'](software/'SOFTWARE-BUNDLE.json',INVENTORY)
 command=['/usr/bin/python3','-B',str(stage/wrapper['placement']),'--software-root',str(software),'--software-inventory',str(stage/'metadata/SOFTWARE-BUNDLE.json'),'--data-root',str(stage/'data'),'--packet',str(stage/packet_row['placement']),'--packet-sha256',packet_row['sha256'],'--codec',str(stage/'objects/native-codec'),'--output',str(BASE/'closed-terminal-replay-01')]
 for root in h['m'].GUARD.directories:command+=['--exclude-private-directory',str(root)]
 write(stage/'INDEX.json',raw);write(stage/'COMMAND.json',encoded(command));started=time.monotonic()
 process=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
 write(stage/'stdout.log',process.stdout);write(stage/'stderr.log',process.stderr)
 receipt={'schema':'kpx8-fresh-HTTPS-terminal-public-replay/v1','index_sha256':a.index_sha256,'transport_selection_sha256':a.selection_sha256,'transport_result_sha256':sha(result_raw),'replay_bootstrap_sha256':REPLAY,'software_inventory_sha256':INVENTORY,'materialized_objects':len(rows),'retained_full_pages':len(packet['pages']),'returncode':process.returncode,'replay_launch_wall_seconds':time.monotonic()-started,'payloads_from_new_terminal_HTTPS_store_only':True,'original_backup_seed_PK_or_R0_mounted':False,'owner_client_associations_exported':False,'same_physical_host_separate_namespace':True,'independent_administration_demonstrated':False}
 if process.returncode==0:receipt['closed_replay_result_sha256']=sha(h['read'](BASE/'closed-terminal-replay-01/RESULT.json'))
 write(BASE/'TERMINAL-REPLAY-EXECUTION.json',encoded(receipt));print(json.dumps(receipt,sort_keys=True));raise SystemExit(process.returncode)

if __name__=='__main__':main()
