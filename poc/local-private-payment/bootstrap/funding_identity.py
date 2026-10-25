#!/usr/bin/env python3
"""Pure public three-owner funding addresses from fresh encrypted init exports."""
import argparse
from pathlib import Path
from gn3_common import GENESIS,digest,encoded,fields,hx,need,parse,uuid_text,write_new
from gn3_runtime import Runtime
from paths import HostPolicy
DOMAIN='b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'

def run(a):
    guard=HostPolicy();raw=guard.read(a.trial,a.trial_sha256);trial=parse(raw);uuid_text(trial['trial_id'])
    need(trial['schema']=='kpxa-fresh-unfunded-trial/v1' and trial['domain_hex32']==DOMAIN
         and len(trial['owners'])==3,'new-unfunded3owner-trial')
    runtime=Runtime(require_native=False);wallets=[]
    for index,row in enumerate(trial['owners']):
        public=parse(guard.read(row['public_file'],row['sha256']))
        need(public['admission_sompi']==2_000_000_000 and public['domain_hex32']==DOMAIN,'public20KAS-init')
        spk=hx(public['funding_spk_hex36'],36);need(spk[:3]==b'\0\0\x20' and spk[-1:]==b'\xac','ordinary-P2PK-funding')
        address=runtime.address(spk[3:35]);need(address['script_public_key']==spk.hex(),'funding-script')
        wallets.append({'role':str(index),**address})
    need(len({row['script_public_key'] for row in wallets})==3,'distinct-fundingkeys')
    value={'schema':'kpxa-three-owner-funding-identity/v1','network_id':'testnet-10','genesis_hash_hex':GENESIS,
        'domain_hex32':DOMAIN,'trial_id':trial['trial_id'],'funding_wallets':wallets,
        'admissions_sompi':[2_000_000_000]*3,'trial_sha256':a.trial_sha256,
        'private_backup_or_seed_hashes_exported':False,'mining_or_broadcast_performed':False}
    write_new(a.output,encoded(value)+b'\n',0o400)
    return {'output':str(a.output),'sha256':digest(encoded(value)+b'\n'),'mining_or_broadcast_performed':False}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--trial',type=Path,required=True);p.add_argument('--trial-sha256',required=True);p.add_argument('--output',type=Path,required=True)
    try:print(encoded(run(p.parse_args())).decode())
    except (ValueError,OSError,KeyError,TypeError):p.exit(1,'fresh public funding identity refused\n')
