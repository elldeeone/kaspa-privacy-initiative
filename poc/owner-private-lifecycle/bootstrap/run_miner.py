#!/usr/bin/env python3
"""Public TN10 funding miner. Default only stages; --plan reads templates."""
import argparse
import os
from pathlib import Path
import stat
import subprocess

from gn3_common import CLEAN,HERE,digest,encoded,need,parse,uuid_text,write_new
from gn3_runtime import GENERIC,SDK_DIR,SDK_PINS
from paths import HostPolicy,checked

PRIVATE=Path('/var/tmp/kpi-owner-private-lifecycle-01/private')


def reserve_mining_attempt(trial_id,party,identity_sha256,miner_sha256):
    uuid_text(trial_id)
    need(type(party) is int and party in (0,1,2),'three-public-mining-parties')
    parent=PRIVATE/'funding-registries';registry=parent/trial_id
    for directory in (parent,registry):
        directory.mkdir(exist_ok=True,mode=0o700)
        descriptor=os.open(directory.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    write_new(registry/('party-'+str(party)+'-MINING-USED'),encoded({
        'schema':'kpx8-consumed-ordinary-mining-attempt/v1','trial_id':trial_id,
        'party':party,'funding_identity_sha256':identity_sha256,
        'miner_sha256':miner_sha256,'automatic_restart_or_resubmission':False})+b'\n',0o400)


def run(a):
    guard=HostPolicy(a.exclude_old_trial,a.exclude_private_directory)
    need(PRIVATE in guard.new_directories,'whole-selected-private-parent-must-be-excluded')
    private=checked(a.private_output);output=checked(a.output)
    need(private.is_relative_to(PRIVATE) and not private.exists(),'fresh-private-miner-controller')
    need(not output.exists() and all(not output.is_relative_to(p) for p in guard.directories),
         'fresh-public-miner-result')
    node=GENERIC['node'][0];source=HERE/'miner.mjs'
    guard.guard([a.identity,node,source,*(SDK_DIR/name for name in SDK_PINS)])
    identity=guard.read(a.identity,a.identity_sha256)
    value=parse(identity)
    need(value['schema']=='kpx8-three-owner-funding-identity/v1'
         and value['network_id']=='testnet-10','new-public-three-owner-funding-identity')
    uuid_text(value['trial_id'])
    private.mkdir(parents=True,mode=0o700);output.mkdir(parents=True,mode=0o700)
    node_raw=guard.read(node,GENERIC['node'][1]);write_new(private/'node',node_raw,0o500)
    source_raw=guard.read(source);write_new(private/'miner.mjs',source_raw,0o400)
    write_new(private/'wallet.json',identity,0o400)
    sdk=private/'sdk';sdk.mkdir(mode=0o700)
    for name,pin in SDK_PINS.items():write_new(sdk/name,guard.read(SDK_DIR/name,pin),0o400)
    journal=private/'journal';journal.mkdir(mode=0o700)
    command=['/usr/bin/bwrap','--unshare-all','--share-net','--die-with-parent','--new-session',
        '--clearenv','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin',
        '--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64',
        '--ro-bind','/etc/ssl','/etc/ssl','--ro-bind','/etc/resolv.conf','/etc/resolv.conf',
        '--ro-bind','/etc/hosts','/etc/hosts','--proc','/proc','--dev','/dev','--tmpfs','/tmp',
        '--ro-bind',str(private/'node'),'/node','--ro-bind',str(private/'miner.mjs'),'/program/miner.mjs',
        '--ro-bind',str(private/'wallet.json'),'/wallet.json','--ro-bind',str(sdk),'/sdk',
        '--bind',str(journal),'/journal','--bind',str(output),'/out',
        '--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8',
        '/node','--use-openssl-ca','/program/miner.mjs',
        '--mode','mine' if a.execute_mining else 'plan','--role',str(a.party),
        '--rpc-index',str(a.rpc_index),'--wallet-sha256',a.identity_sha256,
        '--workers',str(a.workers),'--target-sompi',str(a.target_sompi)]
    if a.execute_mining:command+=['--execute']
    write_new(private/'PRIVATE-PLAN.json',encoded({'command':command,'publish_or_hash':False})+b'\n')
    receipt={'schema':'kpx8-TN10-miner-launch/v1','party':a.party,
        'funding_identity_sha256':a.identity_sha256,'miner_sha256':digest(source_raw),
        'node_sha256':GENERIC['node'][1],'SDK_pins':SDK_PINS,
        'executed':False,'mining_or_submission_performed':False,
        'seed_funding_secret_or_PK_mounted':False,'proposed_workers':a.workers}
    if a.plan or a.execute_mining:
        if a.execute_mining:
            # A different controller path cannot reset this trial/party's
            # consumed mining attempt or forget its per-block intents. After
            # interruption use read-only reward reconciliation or a new trial.
            reserve_mining_attempt(value['trial_id'],a.party,a.identity_sha256,digest(source_raw))
        process=subprocess.run(command,env=CLEAN,capture_output=True)
        write_new(private/'PRIVATE-STDOUT.log',process.stdout)
        write_new(private/'PRIVATE-STDERR.log',process.stderr)
        need(process.returncode==0,'read-only-plan-or-ordinary-mining-incomplete')
        receipt.update(executed=True,mining_or_submission_performed=a.execute_mining)
        if a.plan:
            public=parse(process.stdout);need(public['mining_or_submission_executed'] is False,
                                             'read-only-mining-plan')
            write_new(output/'TEMPLATE-PLAN.json',encoded(public)+b'\n',0o400)
        else:
            refreshed=HostPolicy(a.exclude_old_trial,a.exclude_private_directory)
            result=parse(refreshed.read(output/'RESULTS.json'))
            receipt.update(result_status=result['status'],observed_coinbase_sompi=result['coinbase_sompi'])
    write_new(output/'LAUNCH.json',encoded(receipt)+b'\n',0o400)
    return receipt


if __name__=='__main__':
    os.umask(0o077);p=argparse.ArgumentParser(description=__doc__)
    for name in ('identity','private-output','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--identity-sha256',required=True)
    p.add_argument('--party',type=int,choices=(0,1,2),required=True)
    p.add_argument('--rpc-index',type=int,choices=(0,1),default=0)
    p.add_argument('--workers',type=int,default=14)
    p.add_argument('--target-sompi',type=int,default=3_100_000_000)
    modes=p.add_mutually_exclusive_group();modes.add_argument('--plan',action='store_true')
    modes.add_argument('--execute-mining',action='store_true')
    p.add_argument('--exclude-old-trial',type=Path,action='append',required=True)
    p.add_argument('--exclude-private-directory',type=Path,action='append',required=True)
    try:print(encoded(run(p.parse_args())).decode())
    except (ValueError,OSError,TypeError,KeyError):p.exit(1,'ordinary TN10 miner incomplete\n')
