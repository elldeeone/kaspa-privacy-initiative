#!/usr/bin/env python3
"""One-backup ordinary runtime from an externally selected restored public tree.

This launcher is trusted installed software. Downloaded manifests never select
code authority themselves: root must independently select inventory SHA. Only
explicit fixed runtime/source members are mounted; no fixture generator or whole
repository/backup parent is visible. No backup content/hash or auto-broadcast API.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OWNER_NAMES = ('reuse', 'paths', 'selected', 'no_append', 'runtime', 'recovery', 'owner')
OLD_NAMES = ('primitives', 'receiver', 'actions', 'native_runtime')
PUBLIC_NAMES = ('wire', 'policy', 'virtual')
BASE = '/home/luke/projects/kpi-intensive-2026-10-22/'
RUNTIME_DEST = {
    'prover': BASE+'capacity-exit-selected-prover-01/prover',
    'w-codec': BASE+'shared-settlement-wallet-release-01/w-codec',
    'native-validator': '/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/native-validator',
    'node': '/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node',
    'crypto': '/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/crypto'}
SDK_DEST = '/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa/'
CLEAN = {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC'}


def need(value, code):
    if not value:raise ValueError(code)


def checked(value):
    path=Path(value).absolute()
    need('..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents)), 'unsafe-path')
    return path


def outside(value):
    path=checked(value);need(not path.is_relative_to(ROOT),'private-path-inside-project')
    probe=path if path.is_dir() else path.parent
    while not probe.exists():probe=probe.parent
    result=subprocess.run(['/usr/bin/git','-c','safe.directory=*','-C',str(probe),
        'rev-parse','--is-inside-work-tree'],capture_output=True,text=True,env=CLEAN)
    need(result.returncode!=0 or result.stdout.strip()!='true','private-path-inside-Git')
    return path


def parse(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate-JSON-key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite-number')))


def digest(raw):return hashlib.sha256(raw).hexdigest()


def regular(path, forbidden):
    path=checked(path);info=path.stat()
    need(stat.S_ISREG(info.st_mode) and (info.st_dev,info.st_ino)!=forbidden,'public-backup-alias-or-type')
    return path,info


def mapping():
    result={}
    for name in OWNER_NAMES:
        result['runtime-source/poc/shared-settlement-wallet/'+name+'.py']='/work/poc/shared-settlement-wallet/'+name+'.py'
    for name in OLD_NAMES:
        result['runtime-source/poc/compact-batch-lifecycle/'+name+'.py']='/work/poc/compact-batch-lifecycle/'+name+'.py'
    for name in PUBLIC_NAMES:
        result['runtime-source/poc/shared-settlement/'+name+'.py']='/work/poc/shared-settlement/'+name+'.py'
    for relative in ('poc/future-recipient/v2/recipient.py','poc/private-cashout-trial/sdk.mjs'):
        result['runtime-source/'+relative]='/work/'+relative
    for name,target in RUNTIME_DEST.items():result['runtime/'+name]=target
    for name in ('kaspa.js','kaspa_bg.wasm','package.json'):result['runtime-sdk/'+name]=SDK_DEST+name
    return result


def verified_entries(args, forbidden):
    # The iterator is materialized ONCE; every re-read repeats dev/inode checks.
    regular(args.inventory,forbidden)
    raw=checked(args.inventory).read_bytes()
    need(digest(raw)==args.inventory_sha256,'externally-selected-inventory-hash')
    value=parse(raw)
    need(type(value)is dict and set(value)=={'schema','classification','files'}
        and value['schema']=='kpx4-public-software-bundle/v1'
        and value['classification']=='PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY'
        and type(value['files'])is list,'typed-software-inventory')
    rows=[];seen=set();tree=checked(args.software_root)
    for entry in value['files']:
        need(type(entry)is dict and set(entry)=={'kind','path','bytes','sha256'},'typed-software-entry')
        relative=entry['path'];parts=PurePosixPath(relative) if type(relative)is str else None
        need(parts is not None and relative and not parts.is_absolute() and relative==str(parts)
            and all(part not in ('.','..') for part in parts.parts) and '\\' not in relative
            and relative not in seen,'canonical-unique-software-path')
        need(entry['kind'] in ('runtime-source','selected-executable','public-metadata','public-canary','source')
            and type(entry['bytes'])is int and entry['bytes']>=0 and type(entry['sha256'])is str
            and len(entry['sha256'])==64 and all(c in '0123456789abcdef' for c in entry['sha256']),
            'typed-software-fields')
        seen.add(relative);path,info=regular(tree/relative,forbidden)
        need(info.st_size==entry['bytes'],'software-length-metadata')
        rows.append((entry,path))
    need(set(mapping()).issubset(seen),'complete-fixed-owner-runtime-closure')
    # Validate ALL metadata before reading/hashing the FIRST listed member.
    return tuple(rows)


def save(path,value):
    with Path(path).open('x') as file:json.dump(value,file,sort_keys=True);file.write('\n')
    Path(path).chmod(0o600)


def main(args):
    need(args.op in ('recover','prepare-full-cashout'),'selected-operation')
    need(type(args.workers)is int and 1<=args.workers<=14,'workers')
    need(type(args.max_inputs)is int and args.max_inputs in (1,2),'max-inputs')
    need(type(args.fee_rate)is int and 0<args.fee_rate<1<<64,'fee-rate')
    need((args.pk is not None)==(args.op=='prepare-full-cashout'),'PK-only-private-preparation')
    backup=outside(args.backup);info=backup.stat()
    need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o600,'one-original-backup-metadata')
    forbidden=(info.st_dev,info.st_ino)
    directory=outside(args.controller);need(not directory.exists(),'fresh-private-controller')
    for path in (args.profile,args.prestate,args.history,args.manifest,args.inventory,
                 *([args.pk] if args.pk else [])):
        regular(path,forbidden)
    rows=verified_entries(args,forbidden)
    directory.mkdir(parents=True,mode=0o700)
    software=directory/'software';software.mkdir(mode=0o700)
    for entry,path in rows:
        regular(path,forbidden);raw=path.read_bytes()
        need(len(raw)==entry['bytes'] and digest(raw)==entry['sha256'],'selected-software-bytes')
        target=software/entry['path'];target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with target.open('xb') as file:file.write(raw)
        target.chmod(0o500 if entry['kind']=='selected-executable' else 0o400)
    inputs=directory/'public-inputs';inputs.mkdir(mode=0o700)
    for name in ('profile','prestate','history','manifest'):
        path,_=regular(getattr(args,name),forbidden);raw=path.read_bytes()
        if name=='history':need(digest(raw)==args.history_sha256,'external-local-history-pin')
        target=inputs/(name+'.json');target.write_bytes(raw);target.chmod(0o400)
    client=directory/'client-output';client.mkdir(mode=0o700)
    command=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
        '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
        '--symlink','usr/lib64','/lib64','--ro-bind','/etc/alternatives','/etc/alternatives',
        '--proc','/proc','--dev','/dev','--tmpfs','/tmp']
    for relative,destination in mapping().items():
        command+=['--ro-bind',str(software/relative),destination]
    for name in ('profile','prestate','history','manifest'):
        command+=['--ro-bind',str(inputs/(name+'.json')),'/'+name+'.json']
    command+=['--ro-bind',str(backup),'/own-backup.json','--bind',str(client),'/out']
    if args.pk:command+=['--ro-bind',str(checked(args.pk)),'/parameters.pk']
    command+=['--chdir','/work/poc/shared-settlement-wallet','--setenv','PATH','/usr/bin:/bin',
        '--setenv','LANG','C.UTF-8','--setenv','TZ','UTC','/usr/bin/python3','-B',
        '/work/poc/shared-settlement-wallet/owner.py',args.op,'--profile','/profile.json',
        '--prestate','/prestate.json','--history','/history.json','--manifest','/manifest.json',
        '--backup','/own-backup.json','--output','/out/run','--history-sha256',args.history_sha256,
        '--workers',str(args.workers),'--max-inputs',str(args.max_inputs),'--fee-rate',str(args.fee_rate)]
    if args.pk:command+=['--pk','/parameters.pk','--execute']
    for path in args.must_be_absent:command+=['--must-be-absent',str(checked(path))]
    unit='kpi-settlement-owner-'+uuid.uuid4().hex[:12]
    heavy=args.op=='prepare-full-cashout';limits={'CPUQuota':'1400%' if heavy else '200%',
        'MemoryMax':'20G' if heavy else '3G','MemorySwapMax':'0'}
    save(directory/'PRIVATE-RUNTIME-PLAN.json',{'command':command,'unit':unit,'publish_or_hash':False,
        'requested_limits':limits,'trusted_host_and_release_inode_immutability_required':True})
    entry=directory/'entry.py'
    entry.write_text('''from pathlib import Path
import json,subprocess,time
base=Path(__file__).parent
plan=json.loads((base/'PRIVATE-RUNTIME-PLAN.json').read_bytes())
caps={'observed':None}
try:
 group=next(x[3:] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
 root=Path('/sys/fs/cgroup')/group.lstrip('/')
 caps['observed']={x:(root/x).read_text().strip() for x in ('cpu.max','memory.max','memory.swap.max')}
except (OSError,StopIteration):pass
(base/'ACTIVE-CAPS.json').write_text(json.dumps(caps,sort_keys=True)+'\\n')
start=time.monotonic()
result=subprocess.run(['/usr/bin/time','-v','-o',str(base/'resources.log'),*plan['command']],capture_output=True,text=True)
(base/'PRIVATE-STDOUT.log').write_text(result.stdout)
(base/'PRIVATE-STDERR.log').write_text(result.stderr)
(base/'EXECUTION.json').write_text(json.dumps({'returncode':result.returncode,'wall_seconds':time.monotonic()-start},sort_keys=True)+'\\n')
raise SystemExit(result.returncode)
''');entry.chmod(0o400)
    if not args.execute:return {'prepared':True,'executed':False,'backup_or_PK_bytes_read':False}
    launch=['systemd-run','--user','--collect','--wait','--pipe','--unit='+unit]
    for key,value in limits.items():launch+=['-p',key+'='+value]
    launch+=['-p','RuntimeMaxSec=10800','-p','KillMode=control-group','/usr/bin/python3','-B',str(entry)]
    started=time.monotonic();result=subprocess.run(launch,capture_output=True,text=True)
    (directory/'PRIVATE-LAUNCH-STDOUT.log').write_text(result.stdout)
    (directory/'PRIVATE-LAUNCH-STDERR.log').write_text(result.stderr)
    observed=subprocess.run(['systemctl','--user','show',unit,
        '--property=LoadState,ActiveState,SubState,MainPID,ControlGroup'],capture_output=True,text=True)
    state=dict(row.split('=',1) for row in observed.stdout.splitlines() if '=' in row)
    save(directory/'CLEANUP.json',{'manager_state':state,'manager_returncode':observed.returncode,
        'kernel_cgroup_procs_observation':None,'kernel_process_count':None,
        'missing_kernel_observation_is_not_zero':True})
    need(result.returncode==0 and (client/'run/RESULTS.json').is_file(),'owner-runtime-incomplete')
    summary=parse((client/'run/RESULTS.json').read_bytes())
    return {'passed':True,'op':args.op,'wall_seconds':time.monotonic()-started,
        **{key:summary[key] for key in ('recognized_historical_receipt_count',
            'recognized_spent_receipt_count','recognized_unspent_claim_count_before')},
        **({key:summary[key] for key in ('transaction_id','consumed_same_backup_claim_count',
            'recognized_unspent_claim_count_after','native_payout_sompi','fee_sompi','reserve_after_sompi')}
            if heavy else {}),'accepted_chain_or_currentness_claimed':False}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('controller',type=Path)
    parser.add_argument('--op',choices=('recover','prepare-full-cashout'),required=True)
    for name in ('software-root','inventory','profile','prestate','history','manifest','backup'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--inventory-sha256',required=True);parser.add_argument('--history-sha256',required=True)
    parser.add_argument('--pk',type=Path);parser.add_argument('--workers',type=int,default=14)
    parser.add_argument('--max-inputs',type=int,default=2);parser.add_argument('--fee-rate',type=int,default=100)
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--must-be-absent',type=Path,action='append',default=[])
    try:print(json.dumps(main(parser.parse_args()),sort_keys=True))
    except Exception:
        print(json.dumps({'error':'cold-owner-launch-incomplete','accepted_chain_or_currentness_claimed':False}))
        raise SystemExit(1)
