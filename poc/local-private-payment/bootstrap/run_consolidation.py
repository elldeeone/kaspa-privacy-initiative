#!/usr/bin/env python3
"""Stage one seed-only owner consolidation; only the ordinary signed body is public."""
import argparse
import os
from pathlib import Path
import stat
import subprocess
import time

from gn3_common import CLEAN, HERE, ROOT, digest, encoded, fields, need, parse, write_new
from gn3_runtime import GENERIC, SDK_DIR, SDK_PINS
from paths import HostPolicy, checked, stable_read

MODULES=('gn3_common.py','gn3.py','gn3_entry.py','gn3_runtime.py','gn3_selection.py',
         'sign_worker.py','sdk.mjs','run_signer.py','paths.py',
         'fund_worker.py','consolidation_sdk.mjs','run_consolidation.py')
REFERENCES=('poc/local-private-payment/integration/trees.py','poc/future-recipient/v2/recipient.py',
            'poc/local-private-payment/chain/wire.mjs','poc/local-private-payment/chain/public.mjs')
PRIVATE_ROOT=Path('/var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01')


def run(a):
    start=time.monotonic()
    policy=HostPolicy(a.exclude_old_trial,a.exclude_private_directory)
    need(Path('/var/tmp/kpi-owner-private-lifecycle-01/private') in policy.new_directories,
         'whole-selected-private-parent-must-be-excluded')
    owner=checked(a.owner)
    need(owner.is_relative_to(PRIVATE_ROOT),'selected-new-original-owner-parent')
    backup,initial=owner/'BACKUP.json',owner/'INITIAL-PUBLIC.json'
    before={}
    for item in (backup,initial):
        info=item.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink==1
             and stat.S_IMODE(info.st_mode) in (0o400,0o600),'one-original-owner-file-metadata')
        before[item]=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    private=checked(a.private_output);output=checked(a.output)
    need(private.is_relative_to(PRIVATE_ROOT) and not private.exists(),'fresh-declared-private-controller')
    need(not output.exists() and all(not output.is_relative_to(p) for p in policy.directories),
         'fresh-public-signature-export')
    sources=[*(HERE/name for name in MODULES),*(ROOT/name for name in REFERENCES)]
    public=[('observation.json',a.observation,a.observation_sha256),
            ('owner-public.json',a.owner_public,a.owner_public_sha256)]
    runtime={name:Path(a.runtime)/name if a.runtime else default for name,(default,_) in GENERIC.items()}
    paths=[*sources,*(row[1] for row in public),*runtime.values(),*(SDK_DIR/name for name in SDK_PINS)]
    policy.guard(paths)  # Complete metadata pass before the first public byte.
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
        '--chdir','/work/poc/local-private-payment/bootstrap',
        '--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8','--setenv','TZ','UTC',
        '/usr/bin/python3','-B','/work/poc/local-private-payment/bootstrap/fund_worker.py',
        '--owner','/owner','--observation','/observation.json','--observation-sha256',a.observation_sha256,
        '--owner-public','/owner-public.json','--owner-public-sha256',a.owner_public_sha256,
        '--trial-id',a.trial_id,'--work','/private-work/run',
        '--output','/export','--crypto','/runtime/crypto','--node','/runtime/node',
        '--native','/runtime/native-validator','--sdk-dir','/runtime/sdk']
    write_new(private/'PRIVATE-PLAN.json',encoded({'command':command,'publish_or_hash':False})+b'\n')
    receipt={'schema':'kpxa-isolated-own-consolidation-launch/v1','executed':False,
        'trial_id':a.trial_id,'observation_sha256':a.observation_sha256,
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
        result=parse(refreshed.read(output/'RESULTS.json'))
        case_raw=refreshed.read(output/'selected-case.json',result['case_sha256'])
        need(result['schema']=='kpxa-own-ordinary-consolidation/v1'
             and result['trial_id']==a.trial_id and result['native_Full_and_all_inputs_passed'] is True
             and result['observation_sha256']==a.observation_sha256,
             'matching-own-ordinary-consolidation-context')
        receipt.update(executed=True,case_sha256=result['case_sha256'],
                       source_count=len(parse(case_raw)['transaction']['inputs']),
                       wall_seconds=time.monotonic()-start)
    write_new(output/'LAUNCH.json',encoded(receipt)+b'\n',0o400)
    return receipt


if __name__=='__main__':
    os.umask(0o077);p=argparse.ArgumentParser(description=__doc__)
    for name in ('owner','observation','owner-public','private-output','output'):
        p.add_argument('--'+name,type=Path,required=True)
    for name in ('observation-sha256','owner-public-sha256','trial-id'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--runtime',type=Path)
    p.add_argument('--exclude-old-trial',type=Path,action='append',default=[])
    p.add_argument('--exclude-private-directory',type=Path,action='append',default=[Path('/var/tmp/kpi-owner-private-lifecycle-01/private')])
    p.add_argument('--execute',action='store_true')
    try: print(encoded(run(p.parse_args())).decode())
    except (ValueError,OSError,TypeError,KeyError): p.exit(1,'isolated ordinary consolidation incomplete\n')
