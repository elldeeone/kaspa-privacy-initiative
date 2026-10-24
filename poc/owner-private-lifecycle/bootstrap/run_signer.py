#!/usr/bin/env python3
"""Stage one seed-only owner approval; only a signature receipt is exported."""
import argparse
import os
from pathlib import Path
import stat
import subprocess
import time

from gn3_common import CLEAN, HERE, ROOT, digest, encoded, fields, need, parse, write_new
from gn3_entry import APPROVAL_NAMES, QUOTE_NAMES
from gn3_runtime import GENERIC, SDK_DIR, SDK_PINS
from gn3_selection import decode
from paths import HostPolicy, checked, stable_read

MODULES=('gn3_common.py','gn3.py','gn3_entry.py','gn3_runtime.py','gn3_selection.py',
         'sign_worker.py','sdk.mjs','run_signer.py','paths.py')
REFERENCES=('poc/compact-batch-lifecycle/primitives.py','poc/future-recipient/v2/recipient.py')
PRIVATE_ROOT=Path('/var/tmp/kpi-owner-private-lifecycle-01/private')


def run(a):
    start=time.monotonic()
    policy=HostPolicy(a.exclude_old_trial,a.exclude_private_directory)
    need(PRIVATE_ROOT in policy.new_directories,
         'whole-selected-private-parent-must-be-excluded')
    owner=checked(a.owner)
    need(owner.is_relative_to(PRIVATE_ROOT),'selected-new-original-owner-parent')
    backup,initial=owner/'BACKUP.json',owner/'INITIAL-PUBLIC.json'
    before={}
    for item in (backup,initial):
        info=item.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink==1
             and stat.S_IMODE(info.st_mode)==0o600,'one-original-owner-file-metadata')
        before[item]=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    private=checked(a.private_output);output=checked(a.output)
    need(private.is_relative_to(PRIVATE_ROOT) and not private.exists(),'fresh-declared-private-controller')
    need(not output.exists() and all(not output.is_relative_to(p) for p in policy.directories),
         'fresh-public-signature-export')
    sources=[*(HERE/name for name in MODULES),*(ROOT/name for name in REFERENCES)]
    public=[('selection.json',a.selection,a.selection_sha256),('case.json',a.case,a.case_sha256),
            ('owner-public.json',a.owner_public,a.owner_public_sha256)]
    runtime={name:Path(a.runtime)/name if a.runtime else default for name,(default,_) in GENERIC.items()}
    paths=[*sources,*(row[1] for row in public),*runtime.values(),*(SDK_DIR/name for name in SDK_PINS)]
    policy.guard(paths)  # Complete metadata pass before the first public byte.
    selected=decode(policy.read(a.selection,a.selection_sha256),a.selection_sha256)
    private.mkdir(parents=True,mode=0o700);output.mkdir(parents=True,mode=0o700)
    staged=[];pins=[]
    for source in sources:
        relative=source.relative_to(ROOT);raw=policy.read(source)
        target=private/'software'/relative;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        write_new(target,raw,0o400);staged.append((target,Path('/work')/relative))
        pins.append({'path':str(relative),'sha256':digest(raw),'bytes':len(raw)})
    for name,path in runtime.items():
        raw=policy.read(path,GENERIC[name][1]);need(raw[:4]==b'\x7fELF','selected-ELF')
        target=private/'runtime'/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        write_new(target,raw,0o500);staged.append((target,Path('/runtime')/name))
    for name,expected in SDK_PINS.items():
        raw=policy.read(SDK_DIR/name,expected)
        target=private/'sdk'/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        write_new(target,raw,0o400);staged.append((target,Path('/runtime/sdk')/name))
    for name,path,expected in public:
        raw=policy.read(path,expected);target=private/'inputs'/name
        target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        write_new(target,raw,0o400);staged.append((target,Path('/')/name))
    work=private/'client';work.mkdir(mode=0o700)
    command=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
        '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
        '--symlink','usr/lib64','/lib64','--ro-bind','/etc/alternatives','/etc/alternatives',
        '--proc','/proc','--dev','/dev','--tmpfs','/tmp']
    for source,target in staged: command+=['--ro-bind',str(source),str(target)]
    command+=['--ro-bind',str(backup),'/owner/BACKUP.json',
        '--ro-bind',str(initial),'/owner/INITIAL-PUBLIC.json',
        '--bind',str(work),'/private-work','--bind',str(output),'/export',
        '--chdir','/work/poc/owner-private-lifecycle/bootstrap',
        '--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8','--setenv','TZ','UTC',
        '/usr/bin/python3','-B','/work/poc/owner-private-lifecycle/bootstrap/sign_worker.py',
        '--owner','/owner','--selection','/selection.json','--selection-sha256',a.selection_sha256,
        '--case','/case.json','--case-sha256',a.case_sha256,
        '--owner-public','/owner-public.json','--owner-public-sha256',a.owner_public_sha256,
        '--trial-id',a.trial_id,'--fee-rate',str(a.fee_rate),'--work','/private-work/run',
        '--output','/export','--crypto','/runtime/crypto','--node','/runtime/node',
        '--native','/runtime/native-validator','--sdk-dir','/runtime/sdk']
    write_new(private/'PRIVATE-PLAN.json',encoded({'command':command,'publish_or_hash':False})+b'\n')
    receipt={'schema':'kpx8-isolated-GN3-signature-launch/v1','executed':False,
        'financial_profile_sha256':selected.profile_sha256,'trial_id':a.trial_id,
        'original_seed_contents_read_copied_or_hashed_by_host':False,
        'network_prover_PK_or_broadcast':False,'source_members':pins}
    if a.execute:
        for item,attributes in before.items():
            info=item.lstat()
            need((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==attributes,
                 'own-original-file-mutated-before-mount')
        process=subprocess.run(command,capture_output=True,env=CLEAN)
        write_new(private/'PRIVATE-STDOUT.log',process.stdout)
        write_new(private/'PRIVATE-STDERR.log',process.stderr)
        need(process.returncode==0,'isolated-own-GN3-signature-refused')
        refreshed=HostPolicy(a.exclude_old_trial,a.exclude_private_directory)
        approval=parse(refreshed.read(output/'APPROVAL.json'))
        fields(approval,APPROVAL_NAMES,'signature-only-public-export')
        fields(approval['quote'],QUOTE_NAMES,'signature-only-public-quote')
        need(approval['schema']=='kpx8-GN3-owner-approval/v1'
             and approval['trial_id']==a.trial_id
             and approval['financial_profile_sha256']==selected.profile_sha256,
             'matching-own-signature-export-context')
        receipt.update(executed=True,input_index=approval['input_index'],
                       approval_exported=True,wall_seconds=time.monotonic()-start)
    write_new(output/'RESULTS.json',encoded(receipt)+b'\n',0o400)
    return receipt


if __name__=='__main__':
    os.umask(0o077);p=argparse.ArgumentParser(description=__doc__)
    for name in ('owner','selection','case','owner-public','private-output','output'):
        p.add_argument('--'+name,type=Path,required=True)
    for name in ('selection-sha256','case-sha256','owner-public-sha256','trial-id'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--runtime',type=Path)
    p.add_argument('--exclude-old-trial',type=Path,action='append',required=True)
    p.add_argument('--exclude-private-directory',type=Path,action='append',required=True)
    p.add_argument('--fee-rate',type=int,default=100)
    p.add_argument('--execute',action='store_true')
    try: print(encoded(run(p.parse_args())).decode())
    except (ValueError,OSError,TypeError,KeyError): p.exit(1,'isolated GN3 approval incomplete\n')
