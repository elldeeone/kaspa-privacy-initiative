#!/usr/bin/env python3
"""Derive three public funding addresses from typed owner initialization exports."""
import argparse
from pathlib import Path

from gn3_common import GENESIS, digest, encoded, fields, hx, need, parse, uuid_text, write_new
from gn3_runtime import Runtime
from sign_worker import INITIAL_FIELDS
from paths import HostPolicy

DOMAIN='be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480'


def run(a):
    uuid_text(a.trial_id)
    policy=HostPolicy(a.exclude_old_trial,a.exclude_private_directory)
    need(Path('/var/tmp/kpi-owner-private-lifecycle-01/private') in policy.new_directories,
         'whole-selected-private-parent-must-be-excluded')
    policy.guard(a.owners)
    runtime=Runtime(require_native=False);wallets=[]
    need(len(a.owners)==len(a.owner_sha256)==3,'three-public-owner-exports')
    for index,(path,expected) in enumerate(zip(a.owners,a.owner_sha256)):
        owner=parse(policy.read(path,expected));fields(owner,INITIAL_FIELDS,'typed-owner-public-fields')
        need(owner['schema']=='kpx8-owner-initial-public/v1' and owner['domain_hex32']==DOMAIN
             and type(owner['initial_position']) is int and owner['initial_position']==index
             and type(owner['admission_sompi']) is int and owner['admission_sompi']==2_000_000_000,
             'selected-three-owner-20-KAS-admissions')
        fields(owner['funding'],{'xonly_hex32','script_public_key'},'public-funding-key-fields')
        public=runtime.address(hx(owner['funding']['xonly_hex32'],32))
        need(public['script_public_key']==owner['funding']['script_public_key'],'SDK-funding-address-script-binding')
        wallets.append({'role':str(index),'participant_id_hex32':owner['participant_id_hex32'],**public})
    need(len({row['script_public_key'] for row in wallets})==3,'three-distinct-funding-keys')
    value={'schema':'kpx8-three-owner-funding-identity/v1','network_id':'testnet-10',
        'genesis_hash_hex':GENESIS,'domain_hex32':DOMAIN,'trial_id':a.trial_id,
        'funding_wallets':wallets,'owner_public_sha256':a.owner_sha256,
        'admissions_sompi':[2_000_000_000]*3,
        'private_backup_or_seed_hashes_exported':False,'mining_or_broadcast_performed':False}
    write_new(a.output,encoded(value)+b'\n',0o400)
    return {'schema':value['schema'],'funding_identity_sha256':digest(encoded(value)+b'\n'),
        'output':str(a.output),'owner_count':3,'mining_or_broadcast_performed':False}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--owners',type=Path,nargs=3,required=True)
    p.add_argument('--owner-sha256',nargs=3,required=True)
    p.add_argument('--trial-id',required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--exclude-old-trial',type=Path,action='append',required=True)
    p.add_argument('--exclude-private-directory',type=Path,action='append',required=True)
    try:print(encoded(run(p.parse_args())).decode())
    except (ValueError,OSError,TypeError,KeyError):p.exit(1,'public funding identity refused\n')
