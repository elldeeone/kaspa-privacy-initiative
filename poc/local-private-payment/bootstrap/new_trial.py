#!/usr/bin/env python3
"""One command creates three isolated original owners, genuine encrypted admissions, no network."""
import argparse
import concurrent.futures
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

from gn3_common import ROOT,CLEAN,GENESIS,hx,digest,encoded,fields,need,parse,write_new
from paths import HostPolicy,checked

PRIVATE=Path('/var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01')
PUBLIC=Path('/var/tmp/kpi-local-private-payment-01')
DOMAIN='b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
SOURCES=('wallet/worker.py','wallet/payment.py','wallet/support.py','recovery/history.py')


def initialize_one(private,public,assets_raw,assets_sha,guard):
    """Finite authenticated source/assets only, one own directory, no network."""
    private.mkdir(parents=True,mode=0o700);public.mkdir(parents=True,mode=0o700)
    stage=private/'stage';stage.mkdir(mode=0o700)
    owner=private/'owner';owner.mkdir(mode=0o700)
    assets=parse(assets_raw)
    need(assets['schema']=='kpxa-local-wallet-assets/v1' and assets['domain_hex32']==DOMAIN,'new-wallet-assets')
    selected={str(ROOT/'poc/local-private-payment'/name):None for name in SOURCES}
    for name in ('relation','crypto','recipient','wire','trees'):
        row=assets[name];fields(row,{'path','sha256'},'finite-public-assets')
        selected[str(checked(row['path']))]=row['sha256']
    for role in ('spend','output','exit'):
        row=assets[role];selected[str(checked(row['manifest']))]=row['manifest_sha256']
        if role=='output':selected[str(checked(row['pk']))]=row['pk_sha256']
    guard.guard(selected)
    mounts=[];source_pins=[]
    for index,(source,pin) in enumerate(selected.items()):
        raw=guard.read(source,pin);target=stage/('public-'+str(index))
        write_new(target,raw,0o500 if source in (assets['relation']['path'],assets['crypto']['path']) else 0o400)
        mounts += ['--ro-bind',str(target),source]
        source_pins.append({'path':source,'sha256':digest(raw),'bytes':len(raw)})
    selected_assets=stage/'WALLET-ASSETS.json';write_new(selected_assets,assets_raw,0o400)
    command=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
        '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
        '--symlink','usr/lib64','/lib64','--ro-bind','/etc/alternatives','/etc/alternatives',
        '--proc','/proc','--dev','/dev','--tmpfs','/tmp',*mounts,
        '--ro-bind',str(selected_assets),'/assets.json','--bind',str(owner),'/owner',
        '--bind',str(public),'/out','--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8',
        '--setenv','TZ','UTC','/usr/bin/python3','-B',str(ROOT/'poc/local-private-payment/wallet/worker.py'),
        'init','--owner','/owner','--public-output','/out','--assets','/assets.json',
        '--assets-sha256',assets_sha,'--admission-sompi','2000000000']
    # This plan/log remains private and is never opened or hashed by the host.
    result=subprocess.run(command,env=CLEAN,capture_output=True)
    write_new(private/'INIT-STDOUT.log',result.stdout);write_new(private/'INIT-STDERR.log',result.stderr)
    need(result.returncode==0,'isolated-fresh-owner-init-incomplete')
    raw=guard.read(public/'PUBLIC.json');value=parse(raw)
    fields(value,{'schema','domain_hex32','output_hex520','admission_sompi','funding_spk_hex36'},'exact-public-initial-export')
    need(value['schema']=='kpxa-initial-public/v1' and value['domain_hex32']==DOMAIN
         and type(value['admission_sompi']) is int and value['admission_sompi']==2_000_000_000,
         'typed-public20KAS-export')
    return {'public_file':str(public/'PUBLIC.json'),'sha256':digest(raw),'source_pins':source_pins}


def run(a):
    started=time.monotonic();need(re.fullmatch('[a-z][a-z0-9-]{0,63}',a.label),'canonical-fresh-label')
    guard=HostPolicy();raw=guard.read(a.assets,a.assets_sha256)
    private=checked(PRIVATE/a.label);public=checked(PUBLIC/'trials'/a.label)
    need(not private.exists() and not public.exists(),'fresh-unused-trial-label')
    private.mkdir(parents=True,mode=0o700);public.mkdir(parents=True,mode=0o700)
    trial=str(uuid.uuid4())
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        owners=list(pool.map(lambda i:initialize_one(private/('party-'+str(i)),public/('init-'+str(i)),raw,a.assets_sha256,HostPolicy()),range(3)))
    records=[parse(guard.read(row['public_file'],row['sha256'])) for row in owners]
    need(len({hx(row['output_hex520'],520)[:32] for row in records})==3
         and len({hx(row['funding_spk_hex36'],36) for row in records})==3,'distinct-original-owner-admissions-and-fundingkeys')
    need(all(row['source_pins']==owners[0]['source_pins'] for row in owners),'same-authenticated-public-source-closure')
    receipt={'schema':'kpxa-fresh-unfunded-trial/v1','network_id':'testnet-10','genesis_hash_hex':GENESIS,'domain_hex32':DOMAIN,
        'trial_id':trial,'label':a.label,'admissions_sompi':[2_000_000_000]*3,'owners':owners,
        'three_original_backups_created_by_separate_owner_processes':True,
        'supervisor_seed_backup_contents_or_hashes_read':False,
        'setup_mining_funding_or_broadcast_performed':False,
        'genuine_Output_component_proving_performed':True,'testnet_readiness_claimed':False,
        'wallet_assets_sha256':a.assets_sha256,'wall_seconds':time.monotonic()-started}
    write_new(public/'TRIAL.json',encoded(receipt)+b'\n',0o400)
    return receipt

if __name__=='__main__':
    os.umask(0o077);p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--label',required=True);p.add_argument('--assets',type=Path,required=True);p.add_argument('--assets-sha256',required=True)
    try:print(encoded(run(p.parse_args())).decode())
    except (ValueError,OSError,TypeError,KeyError):p.exit(1,'fresh unfunded trial initialization incomplete\n')
