#!/usr/bin/env python3
"""One-command fresh, unfunded three-owner identity. No setup, mining or submit."""
import argparse
import concurrent.futures
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
import uuid

from gn3_common import CLEAN,GENESIS,ROOT,digest,encoded,fields,need,parse,write_new
from gn3_runtime import GENERIC
from paths import HostPolicy,checked

BASE=Path('/var/tmp/kpi-owner-private-lifecycle-01')
DOMAIN='be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480'


def run(a):
    start=time.monotonic()
    need(type(a.label) is str and re.fullmatch('[a-z][a-z0-9-]{0,63}',a.label),'fresh-public-trial-label')
    policy=HostPolicy(a.exclude_old_trial,a.exclude_private_directory)
    need(BASE/'private' in policy.new_directories,'whole-selected-private-parent-must-be-excluded')
    private=checked(BASE/'private'/a.label);public=checked(BASE/'public'/a.label)
    need(not private.exists() and not public.exists(),'fresh-unused-trial-identity')
    private.mkdir(parents=True,mode=0o700);public.mkdir(parents=True,mode=0o700)
    trial=str(uuid.uuid4());participants=[secrets.token_hex(32) for _ in range(3)]
    need(len(set(participants))==3 and all(p!='00'*32 for p in participants),'distinct-public-participants')
    for i in range(3):
        (private/f'party-{i}'/'owner').mkdir(parents=True,mode=0o700)
        (private/f'party-{i}'/'mpc').mkdir(mode=0o700)
    def initialize(i):
        command=['/usr/bin/python3','-B',str(ROOT/'poc/owner-private-lifecycle/wallet/run_owner.py'),'init',
            '--owner-directory',str(private/f'party-{i}'/'owner'),
            '--mpc-directory',str(private/f'party-{i}'/'mpc'),
            '--private-run-directory',str(private/'controller'/f'init-{i}'),
            '--output',str(public/f'init-{i}'),'--crypto',str(GENERIC['crypto'][0]),
            '--participant-id',participants[i],'--position',str(i),'--admission-sompi','2000000000','--execute']
        for root in a.exclude_old_trial:command+=['--exclude-old-trial',str(root)]
        for root in a.exclude_private_directory:command+=['--exclude-new-private-directory',str(root)]
        result=subprocess.run(command,env=CLEAN,capture_output=True)
        need(result.returncode==0,'isolated-fresh-owner-init-incomplete')
        guard=HostPolicy(a.exclude_old_trial,a.exclude_private_directory)
        raw=guard.read(public/f'init-{i}'/'PUBLIC.json');value=parse(raw)
        need(value['schema']=='kpx8-owner-initial-public/v1'
             and value['domain_hex32']==DOMAIN and value['participant_id_hex32']==participants[i]
             and type(value['initial_position']) is int and value['initial_position']==i
             and type(value['admission_sompi']) is int and value['admission_sompi']==2_000_000_000,
             'typed-fresh-public-owner-export')
        target=public/f'OWNER-{i}.json';write_new(target,raw,0o400)
        return {'position':i,'public_file':str(target),'sha256':digest(raw)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        owners=list(executor.map(initialize,range(3)))
    receipt={'schema':'kpx8-fresh-unfunded-trial/v1','network_id':'testnet-10',
        'genesis_hash_hex':GENESIS,'domain_hex32':DOMAIN,'trial_id':trial,'label':a.label,
        'admissions_sompi':[2_000_000_000]*3,'owners':owners,
        'three_original_backups_created_by_separate_owner_processes':True,
        'supervisor_seed_backup_contents_or_hashes_read':False,
        'setup_mining_funding_proving_or_broadcast_performed':False,
        'wall_seconds':time.monotonic()-start}
    write_new(public/'TRIAL.json',encoded(receipt)+b'\n',0o400)
    return receipt


if __name__=='__main__':
    os.umask(0o077);p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--label',required=True)
    p.add_argument('--exclude-old-trial',type=Path,action='append',required=True)
    p.add_argument('--exclude-private-directory',type=Path,action='append',required=True)
    try:print(encoded(run(p.parse_args())).decode())
    except (ValueError,OSError,TypeError,KeyError):p.exit(1,'fresh unfunded trial initialization incomplete\n')
