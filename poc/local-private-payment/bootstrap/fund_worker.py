#!/usr/bin/env python3
"""One owner consolidates only its mature coinbase outputs back to itself."""
import argparse
import copy
import os
from pathlib import Path
import uuid

from gn3_common import GENESIS,amount,digest,encoded,fields,hx,need,parse,public_bytes,uint,uuid_text,write_new
from gn3_runtime import Runtime,HERE
from sign_worker import BACKUP_FIELDS,INITIAL_FIELDS,private_read
from gn3_common import reference

DOMAIN=bytes.fromhex('b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c')
OBSERVATION={'schema','network_id','genesis_hash_hex','domain_hex32','trial_id','funding_script_public_key','virtual_daa_score','sources'}


def boundary_integer(value):
    need(type(value) is str and value.isascii() and value.isdecimal()
         and (value=='0' or not value.startswith('0')),'canonical-coinbase-decimal-boundary')
    return uint(int(value))


def sources(value,own_script):
    fields(value,OBSERVATION,'own-mined-observation-fields')
    need(value['schema']=='kpxa-own-mature-coinbase-observation/v1'
         and value['network_id']=='testnet-10' and value['genesis_hash_hex']==GENESIS
         and value['domain_hex32']==DOMAIN.hex()
         and value['funding_script_public_key']==own_script,'selected-own-testnet-mining-observation')
    current=boundary_integer(value['virtual_daa_score']);rows=copy.deepcopy(value['sources'])
    need(type(rows) is list and rows,'positive-own-mature-coinbase-source-set')
    seen=set();total=0
    for row in rows:
        fields(row,{'outpoint','entry'},'own-source-fields')
        fields(row['outpoint'],{'transactionId','index'},'own-source-outpoint')
        hx(row['outpoint']['transactionId'],32);uint(row['outpoint']['index'],32)
        point=(row['outpoint']['transactionId'],row['outpoint']['index'])
        need(point not in seen,'distinct-own-mined-sources');seen.add(point)
        e=row['entry'];fields(e,{'amount','scriptPublicKey','blockDaaScore','isCoinbase','covenantId'},
                             'own-coinbase-context-fields')
        e['amount']=boundary_integer(e['amount']);e['blockDaaScore']=boundary_integer(e['blockDaaScore'])
        amount(e['amount'],True)
        need(e['scriptPublicKey']==own_script and e['isCoinbase'] is True and e['covenantId'] is None
             and current>=e['blockDaaScore']+1000,'same-owner-mature-coinbase1000')
        total+=e['amount']
    amount(total,True)
    return rows,total


def run(a):
    uuid_text(a.trial_id)
    raw=public_bytes(a.observation);need(digest(raw)==a.observation_sha256,'external-own-observation-pin')
    observation=parse(raw)
    raw_public=public_bytes(a.owner_public)
    need(digest(raw_public)==a.owner_public_sha256,'external-own-public-init-pin')
    original=parse(private_read(a.owner/'INITIAL-PUBLIC.json'))
    fields(original,INITIAL_FIELDS,'own-original-initial-fields')
    need(parse(raw_public)==original and original['domain_hex32']==DOMAIN.hex(),
         'own-original-public-initial-record')
    spk=original['funding_spk_hex36']
    need(observation['trial_id']==a.trial_id,'own-fresh-trial-identity')
    chosen,total=sources(observation,spk)
    runtime=Runtime(paths={'crypto':a.crypto,'node':a.node,'native-validator':a.native},sdk_dir=a.sdk_dir)
    payload=b'KPXAMF01'+DOMAIN+uuid.UUID(a.trial_id).bytes+bytes(32)
    a.work.mkdir(parents=True,exist_ok=False,mode=0o700)
    fee=1;seen=set();index=0
    while True:
        need(fee not in seen,'own-consolidation-no-exact-fee-fixed-point');seen.add(fee)
        payout=total-fee;need(payout>=2_100_000_000,'ordinary-self-output-covers-admission-and-headroom')
        case={'transaction':{'version':1,'id':'00'*32,
            'inputs':[{'previousOutpoint':r['outpoint'],'signatureScript':'41'+'00'*64+'01',
                       'sequence':(1<<64)-1,'computeBudget':10} for r in chosen],
            'outputs':[{'value':payout,'scriptPublicKey':spk,'covenant':None}],
            'lockTime':0,'subnetworkId':'00'*20,'gas':0,'payload':payload.hex(),'mass':0},
            'entries':[row['entry'] for row in chosen]}
        case,metrics=runtime.normalize(case,a.work/('quote-'+str(index)))
        required=metrics['mining_mass']*100;amount(required,True)
        if fee==required:break
        fee=required;index+=1
    body,contexts=runtime.sdk_body(case)
    request={'schema':'kpxa-offline-own-mined-consolidation/v1','network_id':'testnet-10',
             'genesis_hash_hex':GENESIS,'operation':'roundtrip','transaction':body,'contexts':contexts}
    reply=parse(runtime.executables['node'].run([HERE/'consolidation_sdk.mjs',a.sdk_dir],request).stdout)
    need(reply['lossless_safe_roundtrip'] is True and reply['network_or_broadcast'] is False,
         'own-ordinary-official-SDK-roundtrip')
    # Public transaction and fee checks precede the one seed-only backup read.
    owner=parse(private_read(a.owner/'BACKUP.json'));fields(owner,BACKUP_FIELDS,'original-seed-only-backup')
    need(owner['schema']=='kpxa-original-seed-backup/v1' and owner['domain_hex32']==DOMAIN.hex(),'own-original-backup-context')
    wallet=reference('recipient').Receiver(hx(owner['seed_hex32'],32),DOMAIN,runtime.crypto)
    key=wallet.keys(0xffffffff)
    need(spk=='000020'+key.invoice.native_pk.hex()+'ac','own-reserved-funding-key')
    signed_request={**request,'operation':'sign-all','funding_secret_hex32':key.native_secret.hex()}
    reply=parse(runtime.executables['node'].run([HERE/'consolidation_sdk.mjs',a.sdk_dir],signed_request).stdout)
    signatures=reply['signature_scripts_hex66']
    need(reply['secret_material_emitted'] is False and reply['network_or_broadcast'] is False
         and type(signatures) is list and len(signatures)==len(case['transaction']['inputs']),
         'signature-only-own-ordinary-export')
    for row,signature in zip(case['transaction']['inputs'],signatures):
        sig=hx(signature,66);need(sig[:1]==b'\x41' and sig[-1:]==b'\x01','ordinary-SIGHASH-ALL-script')
        row['signatureScript']=signature
    signed,exact_metrics=runtime.normalize(case,a.work/'signed-normalization')
    need(signed==case and exact_metrics==metrics,'own-ordinary-signed-exact-fee-mass-ID')
    path=a.work/'native-case.json';write_new(path,encoded(case)+b'\n')
    runtime.executables['native-validator'].run(['validate-transaction',path,a.work/'native'])
    report=parse((a.work/'native/native-validation.json').read_bytes())
    need(report['Full']['accepted'] is True and report['all_input_engines_accepted'] is True
         and len(report['per_input_ScriptEngine'])==len(chosen)
         and all(r['accepted'] is True for r in report['per_input_ScriptEngine']),
         'own-ordinary-Native-Full-all-inputs')
    result={'schema':'kpxa-own-ordinary-consolidation/v1','trial_id':a.trial_id,
        'observation_sha256':a.observation_sha256,'source_amount_sompi':total,
        'ordinary_self_output_sompi':case['transaction']['outputs'][0]['value'],
        'fee_sompi':fee,'native_Full_and_all_inputs_passed':True,
        'case_sha256':digest(encoded(case)+b'\n'),'network_or_broadcast':False,
        'original_backup_host_contents_or_hashes_read':False,'metrics':metrics}
    write_new(a.output/'selected-case.json',encoded(case)+b'\n',0o400)
    write_new(a.output/'RESULTS.json',encoded(result)+b'\n',0o400)
    return {'status':'OWN_ORDINARY_CONSOLIDATION_EXPORTED','network_or_broadcast':False}


if __name__=='__main__':
    os.umask(0o077);p=argparse.ArgumentParser(description=__doc__)
    for name in ('owner','observation','owner-public','work','output','crypto','node','native','sdk-dir'):
        p.add_argument('--'+name,type=Path,required=True)
    for name in ('observation-sha256','owner-public-sha256','trial-id'):p.add_argument('--'+name,required=True)
    try:print(encoded(run(p.parse_args())).decode())
    except (ValueError,OSError,TypeError,KeyError):p.exit(1,'own ordinary consolidation refused\n')
