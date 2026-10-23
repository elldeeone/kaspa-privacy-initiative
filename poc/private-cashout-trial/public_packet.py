#!/usr/bin/env python3
"""Explicit public-body allowlist; never reads or exports a private witness."""
import argparse
import hashlib
import json
from pathlib import Path
import re

import prepare as p
import trial as t

BODY_KEYS={'version','id','inputs','outputs','lockTime','subnetworkId','gas','payload','mass'}
METRICS=('estimated_bytes','compute_mass','transient_mass','storage_mass','relay_mass',
         'mining_mass','actual_fee_sompi')


def checked_public_case(body,contexts,native_case,metrics,private):
    t.require(set(body)==BODY_KEYS and set(native_case)=={'transaction','entries'}
        and native_case['transaction']==body,'exact-public-native-case')
    t.require(body['version']==1 and body['lockTime']==0 and body['gas']==0
        and body['subnetworkId']=='00'*20 and re.fullmatch('[0-9a-f]{64}',body['id'])
        and type(body['mass']) is int and body['mass']>=0
        and type(body['payload']) is str
        and re.fullmatch('[0-9a-f]{'+str(8800 if private else 1072)+'}',body['payload']) is not None
        and body['payload'][:16]==('4b50583341553031' if private else '4b505832474e3031'),
        'canonical-public-transaction')
    t.require(len(body['inputs'])==len(contexts)==len(native_case['entries'])==1,'public-input-count')
    for row in body['inputs']:
        t.require(set(row)=={'previousOutpoint','signatureScript','sequence','computeBudget'}
            and type(row['sequence']) is int and row['sequence']==0xffffffffffffffff
            and type(row['computeBudget']) is int and row['computeBudget']==(1600 if private else 10)
            and re.fullmatch('(?:[0-9a-f]{2})*',row['signatureScript']) is not None,'public-input-fields')
        point=row['previousOutpoint']
        t.require(set(point)=={'transactionId','index'} and type(point['index']) is int
            and 0<=point['index']<=0xffffffff and re.fullmatch('[0-9a-f]{64}',point['transactionId']),
            'public-outpoint-fields')
    for row in body['outputs']:
        t.require(set(row)=={'value','scriptPublicKey','covenant'} and row['covenant'] is None
            and type(row['value']) is int and 0<row['value']<=2_870_000_000_000_000_000
            and re.fullmatch('0000(?:20[0-9a-f]{64}ac|aa20[0-9a-f]{64}87)',row['scriptPublicKey']),
            'public-output-fields')
    for row,entry in zip(contexts,native_case['entries']):
        t.require(set(row)=={'amount_sompi','script_public_key','block_daa_score','is_coinbase','covenant_id'}
            and row['is_coinbase'] is False and row['covenant_id'] is None
            and row==p.context_entry(int(row['amount_sompi']),row['script_public_key'],row['block_daa_score']),
            'public-context-fields')
        expected={'amount':int(row['amount_sompi']),'scriptPublicKey':row['script_public_key'],
            'blockDaaScore':int(row['block_daa_score']),'isCoinbase':False,'covenantId':None}
        t.require(set(entry)==set(expected) and entry==expected,'public-native-entry-context-binding')
    t.require(all(type(metrics[key]) is int and 0<=metrics[key]<=0xffffffffffffffff for key in METRICS),
              'public-numeric-metrics')
    if private:
        signature=bytes.fromhex(body['inputs'][0]['signatureScript'])
        t.require(signature[68:196]==bytes(128),'prospective-zero-proof-only')


def save(path,value):
    with path.open('x') as file:json.dump(value,file,indent=2,sort_keys=True);file.write('\n')


def export(prepared,output):
    t.require(not output.exists(),'fresh-public-packet')
    material=p.read(prepared/'MATERIALIZED.json')
    t.require(material['schema']=='kpx3-private-four-body-preparation/v1','prepared-schema')
    t.require(type(material['trial_id']) is str and re.fullmatch('[0-9a-f-]{36}',material['trial_id'])
        and re.fullmatch('[0-9a-f]{64}',material['domain_hex32'])
        and re.fullmatch('[0-9a-f]{656}',material['vk_hex328'])
        and all(type(material[key]) is int and 0<=material[key]<=2_870_000_000_000_000_000
            for key in ('source_sompi','total_fees_sompi','ordinary_change_sompi','native_payouts_sompi',
                        'terminal_reserve_sompi','final_CM_count','final_NF_count')),
        'public-summary-scalar-fields')
    source=material['planned_source']
    t.require(type(source['transaction_id']) is str and re.fullmatch('[0-9a-f]{64}',source['transaction_id'])
        and type(source['index']) is int and 0<=source['index']<=0xffffffff
        and type(source['amount_sompi']) is int and 0<source['amount_sompi']<=2_870_000_000_000_000_000
        and type(source['spk_version']) is int and source['spk_version']==0
        and type(source['spk_hex']) is str and re.fullmatch('20[0-9a-f]{64}ac',source['spk_hex'])
        and type(source['block_daa_score']) is str and re.fullmatch('0|[1-9][0-9]*',source['block_daa_score'])
        and 0<=int(source['block_daa_score'])<=0xffffffffffffffff
        and source['is_coinbase'] is False and source['covenant_id'] is None,'public-source-scalar-fields')
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
        checked_public_case(body,contexts,native_case,metrics,index>0)
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
