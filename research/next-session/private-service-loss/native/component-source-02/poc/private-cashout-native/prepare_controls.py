#!/usr/bin/env python3
"""Prepare PUBLIC AA wrapper controls. No new VM, PK, proof or setup work."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'research/next-session/private-service-loss/native/component-fixtures-01'
GENESIS='f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
TAG=b'KPX3/PUBLIC-NATIVE-QUOTE/v1\0'


def pin(path):
    raw=path.read_bytes()
    return {'path':str(path.relative_to(ROOT)), 'bytes':len(raw), 'sha256':hashlib.sha256(raw).hexdigest()}


def save(path,value):
    with path.open('x') as file:
        json.dump(value,file,indent=2,sort_keys=True);file.write('\n')


def identity(case,rate=100):
    raw=json.dumps(case,separators=(',',':'),ensure_ascii=False).encode()
    return hashlib.sha256(TAG+len(raw).to_bytes(8,'little')+raw+rate.to_bytes(8,'little')).hexdigest()


def main():
    OUT.mkdir(parents=True,exist_ok=False)
    cases={};sources=[]
    for stage in ('spend','bob-partial','bob-full','charlie-terminal'):
        directory=ROOT/'research/next-session/privacy-recovery/lifecycle/main-execution-01'/stage
        path=directory/'validation-case.json';case=json.loads(path.read_bytes());sources.append(pin(path))
        tx,entry=case['transaction'],case['entries'][0]
        witness=bytes.fromhex(tx['inputs'][0]['signatureScript']);payload=bytes.fromhex(tx['payload'])
        request={'schema':'kpx3-public-native-action/v1','mode':'quote','network_id':'testnet-10','genesis_hash_hex':GENESIS,
            'domain_hex32':payload[8:40].hex(),'current_redeem_hex':witness[199:].hex(),
            'previous_outpoint':tx['inputs'][0]['previousOutpoint'],
            'supplied_utxo':{'amount_sompi':str(entry['amount']),'script_public_key':entry['scriptPublicKey'],
                'block_daa_score':str(entry['blockDaaScore']),'is_coinbase':entry['isCoinbase'],'covenant_id':entry['covenantId']},
            'auth_hex528':payload[:528].hex(),'cipher_hex528':payload[528:1056].hex(),
            'public_witness_hex3344':payload[1056:].hex(),'vk_hex328':'','proof_hex128':'00'*128,'fee_rate_sompi_per_mass':'100'}
        # Only one source-approved VK push is present; manifest pins its exact slot.
        meta=json.loads((ROOT/'poc/private-exit-recovery/kpx3-policy-template.json').read_bytes())
        slot=next(item for item in meta['patch_slots'] if item['kind']=='vk')
        at=199+114+slot['data_offset'];request['vk_hex328']=witness[at:at+328].hex()
        normalized=deepcopy(case)
        normalized['transaction']['inputs'][0]['signatureScript']=(witness[:68]+bytes(128)+witness[196:]).hex()
        quote_id=identity(normalized)
        verify={**request,'mode':'verify','proof_hex128':witness[68:196].hex(),'expected_quote_id':quote_id}
        cases[stage]={'quote':request,'verify':verify,'expected_quote_id':quote_id,
            'expected_transaction':tx,'expected_zero_proof_transaction':normalized['transaction'],
            'expected_metrics':json.loads((directory/'metrics.json').read_bytes())}
        sources.append(pin(directory/'metrics.json'))
    founding=ROOT/'research/next-session/privacy-recovery/lifecycle/prefix-execution-01/founding/transaction.json'
    tx=json.loads(founding.read_bytes());payload=bytes.fromhex(tx['payload']);sources.append(pin(founding))
    g={'schema':'kpx3-public-native-action/v1','mode':'genesis','network_id':'testnet-10','genesis_hash_hex':GENESIS,
       'domain_hex32':'11'*32,'vk_hex328':cases['spend']['quote']['vk_hex328'],
       'note_hex168':payload[40:208].hex(),'cipher_hex264':payload[240:504].hex()}
    save(OUT/'REQUESTS.json',{'classification':'OLD_PUBLIC_AA_SUPPLIED_CONTEXT_WRAPPER_CONTROLS_DO_NOT_FUND',
        'cases':cases,'genesis_fresh_public_domain':g,'sources':sources,
        'actual_fresh_trial_D_proof_compatibility_claimed':False,'PK_or_private_witness_or_seed_read':False})
    print(json.dumps({'public_component_cases':len(cases),'native_VM_executed':False}))


if __name__=='__main__':main()
