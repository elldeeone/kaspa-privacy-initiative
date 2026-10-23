#!/usr/bin/env python3
"""Exact-body tamper controls on genuine public capacity exit proofs.

These are supplied-context rejections, not reorg/finality evidence. A changed
Auth with an old proof is explicitly stale-proof binding, not an isolated
current-spentness test; rehearse.py produces that separate fresh-proof control.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

import capacity as c
from native_selected import CapacityRuntime
from native_runtime import public_case, save, p2sh
from primitives import need


def contexts(case):
    return [{'amount_sompi':str(row['amount']),'script_public_key':row['scriptPublicKey'],
             'block_daa_score':str(row['blockDaaScore']),'is_coinbase':row['isCoinbase'],
             'covenant_id':row['covenantId']} for row in case['entries']]


def payload(body,offset,raw):
    value=bytearray.fromhex(body['payload']);value[offset:offset+len(raw)]=raw;body['payload']=value.hex()


def mutate(label,body):
    if label=='current-outpoint-mismatch':
        body['inputs'][0]['previousOutpoint']['transactionId']='aa'*32
    elif label=='native-payout-destination-substitution':
        body['outputs'][1]['scriptPublicKey']=(b'\0\0\x20'+c.G+b'\xac').hex()
    elif label=='native-reserve-redirected-with-same-amount':
        body['outputs'][0]['scriptPublicKey']=(b'\0\0\x20'+c.TWO_G+b'\xac').hex()
    elif label=='native-payout-plus1-reserve-minus1':
        body['outputs'][1]['value']+=1;body['outputs'][0]['value']-=1
    elif label=='noappend-next-CM-root-changed':
        raw=bytearray.fromhex(body['payload']);raw[404]^=1;body['payload']=raw.hex()
    elif label=='noappend-extra-NF-witness-byte':
        body['payload']+='00'
    elif label=='noappend-missing-NF-witness-byte':
        body['payload']=body['payload'][:-2]
    elif label=='noappend-NF-append-witness-corrupted':
        raw=bytearray.fromhex(body['payload']);raw[1144]^=1;body['payload']=raw.hex()
    elif label=='stale-proof-for-coherent-authorized-amount-change':
        raw=bytearray.fromhex(body['payload'])
        amount=int.from_bytes(raw[476:484],'little')+1
        payout=int.from_bytes(raw[484:492],'little')-1
        raw[476:484]=amount.to_bytes(8,'little');raw[484:492]=payout.to_bytes(8,'little')
        body['payload']=raw.hex();body['outputs'][0]['value']+=1;body['outputs'][1]['value']-=1
    elif label=='terminal-extra-output':
        body['outputs'][0]['value']-=c.FEE
        body['outputs'].append({'value':c.FEE,'scriptPublicKey':body['outputs'][0]['scriptPublicKey'],'covenant':None})
    else:raise ValueError('unknown-control')


def run(source,output):
    source=source.absolute();output=c.fresh(output);runtime=CapacityRuntime()
    labels=['current-outpoint-mismatch','native-payout-destination-substitution',
            'native-reserve-redirected-with-same-amount','native-payout-plus1-reserve-minus1',
            'noappend-next-CM-root-changed','noappend-extra-NF-witness-byte',
            'noappend-missing-NF-witness-byte','noappend-NF-append-witness-corrupted',
            'stale-proof-for-coherent-authorized-amount-change','terminal-extra-output']
    results=[]
    for label in labels:
        selected='native-terminal' if label=='terminal-extra-output' else 'native-first'
        case=json.loads((source/selected/'case.json').read_bytes())
        body=copy.deepcopy(case['transaction']);entries=contexts(case);mutate(label,body)
        target=output/label
        body,metrics=runtime.normalize(body,entries,target/'normalized')
        runtime.sdk(body,entries)
        save(target/'case.json',public_case(body,entries))
        runtime.native.run(['validate-transaction',target/'case.json',target/'native'])
        report=json.loads((target/'native/native-validation.json').read_bytes());engine=report['per_input_ScriptEngine'][0]
        need(report['isolation']=='PASS' and report['Full']['accepted'] is False and engine['accepted'] is False,
             'tampered-body-must-reject')
        at_g16=label=='stale-proof-for-coherent-authorized-amount-change'
        need((engine['units']>=14_750_000)==at_g16,'expected-tamper-rejection-layer')
        if at_g16:need(engine['typed_error']=='ZkIntegrity("Groth16 verification failed")','exact-auth-proof-binding-rejection')
        results.append({'case':label,'actual_native_validation_calls':1,'native_Full_rejected':True,
            'genuine_original_proof_reused':True,'fresh_current_spentness_claimed':False,
            'engine_units':engine['units'],'typed_error':report['Full']['typed_error'],
            'expected_G16_rejection':at_g16,'metrics':metrics,'transaction_id':body['id']})
    result={'schema':'kpx-capacity-native-tamper-controls/v1','classification':'PUBLIC_SYNTHETIC_DO_NOT_FUND',
        'cases':results,'actual_native_validation_calls':len(results),'new_proofs_or_PK_reads':0,
        'all_expected_rejections':True,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'accepted_chain_reorg_currentness_or_privacy_claimed':False}
    save(output/'RESULTS.json',result);print(json.dumps({'native_tamper_rejections':len(results),'new_proofs':0}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();run(a.source,a.output)
