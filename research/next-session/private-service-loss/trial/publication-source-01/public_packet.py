#!/usr/bin/env python3
"""Explicit public-body allowlist; never reads or exports a private witness."""
import argparse
import hashlib
import json
from pathlib import Path

import prepare as p
import trial as t

BODY_KEYS={'version','id','inputs','outputs','lockTime','subnetworkId','gas','payload','mass'}
METRICS=('estimated_bytes','compute_mass','transient_mass','storage_mass','relay_mass',
         'mining_mass','actual_fee_sompi')


def save(path,value):
    with path.open('x') as file:json.dump(value,file,indent=2,sort_keys=True);file.write('\n')


def export(prepared,output):
    t.require(not output.exists(),'fresh-public-packet')
    material=p.read(prepared/'MATERIALIZED.json')
    t.require(material['schema']=='kpx3-private-four-body-preparation/v1','prepared-schema')
    directories=[Path(material['founding_body_directory'])]+[
        Path(row['body_directory']) for row in material['stages']]
    t.require(len(directories)==4,'four-body-count')
    output.mkdir(parents=True)
    rows=[]
    for index,directory in enumerate(directories):
        t.require(prepared.resolve() in directory.resolve().parents,'prepared-body-boundary')
        case=output/f'case-{index:04d}';case.mkdir()
        body=p.read(directory/'transaction.json');contexts=p.read(directory/'strict-context.json')
        native_case=p.read(directory/'validation-case.json');metrics=p.read(directory/'metrics.json')
        t.require(set(body)==BODY_KEYS and set(native_case)=={'transaction','entries'}
            and native_case['transaction']==body,'exact-public-native-case')
        if index:
            signature=bytes.fromhex(body['inputs'][0]['signatureScript'])
            t.require(signature[68:196]==bytes(128),'prospective-zero-proof-only')
        save(case/'transaction.json',body)
        save(case/'supplied-context.json',contexts)
        save(case/'validation-case.json',native_case)
        save(case/'metrics.json',{key:metrics[key] for key in METRICS})
        payload=bytes.fromhex(body['payload'])
        rows.append({'case':index,'transaction_id':body['id'],'fee_sompi':metrics['actual_fee_sompi'],
            'mining_mass':metrics['mining_mass'],'native_VM_executed':False,
            'Groth16_proof':'ZERO128_NOT_VALIDATED' if index else 'NOT_APPLICABLE',
            'public_payout_sompi':int.from_bytes(payload[484:492],'little') if index else 0,
            'public_reserve_after_sompi':int.from_bytes(payload[476:484],'little') if index else body['outputs'][0]['value']})
    source=material['planned_source']
    result={'schema':'kpx3-prospective-private-native-packet/v1',
        'classification':'PUBLIC_PROSPECTIVE_TESTNET_BODIES_NO_VM_NO_FUNDING',
        'trial_id':material['trial_id'],'domain_hex32':material['domain_hex32'],
        'vk_hex328':material['vk_hex328'],
        'planned_source':{key:source[key] for key in ('transaction_id','index','amount_sompi',
            'spk_version','spk_hex','block_daa_score','is_coinbase','covenant_id')},
        'cases':rows,'source_sompi':material['source_sompi'],
        'total_fees_sompi':material['total_fees_sompi'],
        'ordinary_change_sompi':material['ordinary_change_sompi'],
        'native_payouts_sompi':material['native_payouts_sompi'],
        'terminal_reserve_sompi':material['terminal_reserve_sompi'],
        'final_CM_count':material['final_CM_count'],'final_NF_count':material['final_NF_count'],
        'private_witness_hash_path_or_owner_position_map_included':False,
        'SDK_roundtrips_completed':4,'native_VM_executed':False,
        'accepted_chain_backing':False,'funding_or_broadcast':False,
        'privacy_or_fee_or_resource_qualification':False}
    save(output/'PUBLIC-PACKET.json',result)
    files=[]
    for file in sorted(output.rglob('*.json')):
        raw=file.read_bytes();files.append({'path':str(file.relative_to(output)),
            'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
    source_raw=Path(__file__).read_bytes()
    save(output/'FILE-ALLOWLIST.json',{'schema':'kpx3-prospective-public-file-allowlist/v1',
        'exporter_source_sha256':hashlib.sha256(source_raw).hexdigest(),'files':files})
    return {'public_cases':4,'total_fees_sompi':result['total_fees_sompi'],
            'native_VM_executed':False,'funding_or_broadcast':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prepared',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args()
    print(json.dumps(export(args.prepared,args.output),sort_keys=True))
