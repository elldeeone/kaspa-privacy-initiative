#!/usr/bin/env python3
"""Stage only the reviewed founding/payment prefix against accepted metadata.

No key, witness, proving, setup, RPC or submission interface. The body is copied
byte for byte from the independently closed local public rehearsal. Only the
supplied input DAA metadata changes after predecessor confirmation.
"""
import argparse
import copy
import json
from pathlib import Path

import prepare as p
import run_local as local
import trial as t

LOCAL_SHA='1e6c45871183659a2a7cd84597e53161f067a8760b94ef6ec90f8c9cd15bb39b'
COMPLETE_SHA='3639f08983f3c5d2656c56d727d6f4efe06316a8efd5b3529caeb4fae3066635'
RPC='wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh'
STAGES={'founding':0,'private-payment':1}


def write(path,value):
    t.private_write(path,t.encoded(value))


def prepare(stage,closed,identity,observation,checkpoint,output):
    t.selected_adr();t.require(stage in STAGES,'prefix-only-stage')
    local.pin_packet(closed,LOCAL_SHA)
    t.require(t.digest((closed/'LOCAL-COMPLETE.json').read_bytes())==COMPLETE_SHA,
              'closed-four-body-rehearsal')
    source=closed/f'case-{STAGES[stage]:04d}'
    raw=(source/'transaction.json').read_bytes();body=t.parse_json(raw)
    contexts=p.read(source/'supplied-context.json')
    profile=p.read(identity);seen=p.read(observation);birth=p.read(checkpoint)
    t.require(profile['schema']=='kpx3-tn10-private-trial/v1'
        and profile['program_label']=='AUTH528_PRIVATE_CASHOUT/v1'
        and profile['network_id']=='testnet-10' and profile['genesis_hash_hex']==t.GENESIS,
        'selected-public-identity')
    complete=p.read(closed/'LOCAL-COMPLETE.json')
    t.require(profile['trial_id']==complete['trial_id']
        and profile['domain_hex32']==complete['domain_hex32'],'closed-local-trial-identity')
    t.require(seen['network']=='testnet-10' and seen['expected_genesis']==t.GENESIS
        and seen['confirmation_policy']['passes'] is True
        and int(seen['confirmation_policy']['actual_blue_score_distance'])>
            int(seen['confirmation_policy']['min_confirmation_count'])>=20
        and seen['chain_delta_removed']==[],
        'confirmed-predecessor-observation')
    t.require(birth['network']=='testnet-10' and birth['expected_genesis']==t.GENESIS
        and birth['start_hash']==birth['header']['hash'],'birth-checkpoint')
    t.require(len(body['inputs'])==len(contexts)==1
        and body['inputs'][0]['sequence']==0xffffffffffffffff
        and body['lockTime']==0,'disabled-relative-lock-single-input')
    point=body['inputs'][0]['previousOutpoint']
    t.require(seen['transaction_id']==point['transactionId'],'actual-predecessor-id')
    rows=[row for row in seen['current_outputs'] if row['outpoint']==point]
    t.require(len(rows)==1,'one-observed-current-output')
    entry=rows[0]['utxo'];old=contexts[0]
    t.require(set(entry)=={'outpoint','amount_sompi','script_public_key','block_daa_score',
                          'is_coinbase','covenant_id'} and entry['outpoint']==point
        and entry['amount_sompi']==old['amount_sompi']
        and entry['script_public_key']==old['script_public_key']
        and entry['is_coinbase'] is False and entry['covenant_id'] is None
        and int(entry['block_daa_score'])>0,'actual-input-static-context')
    accepted=seen['accepted_body']['outputs'][point['index']]
    t.require(str(accepted['value'])==entry['amount_sompi']
        and accepted['scriptPublicKey']==entry['script_public_key']
        and accepted['covenant'] is None,'accepted-output-equals-current-UTXO')
    current=p.context_entry(int(entry['amount_sompi']),entry['script_public_key'],
                            entry['block_daa_score'])
    expected=copy.deepcopy(old);expected['block_daa_score']=current['block_daa_score']
    t.require(current==expected,'DAA-only-context-change')
    t.require(not output.exists(),'fresh-prefix-stage-output');output.mkdir(mode=0o700,parents=True)
    t.private_write(output/'transaction.json',raw)
    write(output/'supplied-context.json',[current])
    case={'transaction':body,'entries':[{'amount':int(current['amount_sompi']),
        'scriptPublicKey':current['script_public_key'],'blockDaaScore':int(current['block_daa_score']),
        'isCoinbase':False,'covenantId':None}]}
    write(output/'validation-case.json',case)
    payment=p.read(closed/'case-0001/transaction.json')
    redeem=bytes.fromhex(payment['inputs'][0]['signatureScript'])[199:]
    t.require(len(redeem)==24417 and redeem[10:42].hex()==profile['domain_hex32'],
              'reviewed-initial-whole-redeem')
    packet={'schema':'kpx3-live-prefix-stage/v1','stage':stage,'rpc_url':RPC,
        'trial_directory':str(identity.parent.parent),'profile_path':str(identity),
        'profile_sha256':t.digest(identity.read_bytes()),'transaction_id':body['id'],
        'body_sha256':t.digest(raw),'native_binary_sha256':p.GENERIC_SHA,
        'expected_fee_sompi':complete['cases'][STAGES[stage]]['native_Full']['fee_sompi'],
        'start_hash':birth['start_hash'],'birth_checkpoint_sha256':t.digest(checkpoint.read_bytes()),
        'observation_sha256':t.digest(observation.read_bytes()),
        'closed_local_allowlist_sha256':LOCAL_SHA,'input_contexts':[dict(current,outpoint=point)],
        'output0_redeem_hex':redeem.hex() if stage=='founding' else None,
        'native_execution_performed':False,'broadcast_performed':False}
    if stage=='private-payment':
        zero=copy.deepcopy(body);signature=bytes.fromhex(zero['inputs'][0]['signatureScript'])
        zero['inputs'][0]['signatureScript']=(signature[:68]+bytes(128)+signature[196:]).hex()
        params=p.read(closed.parent/'preparation-public-01/PUBLIC-PACKET.json')
        write(output/'zero-proof-quote-request.json',local.request(params,zero,[current]))
    write(output/'STAGED.json',packet)
    return {'stage':stage,'transaction_id':body['id'],'prepared':True,'native_VM':False}


def validate(prepared,output):
    t.selected_adr();packet=p.read(prepared/'STAGED.json');body=p.read(prepared/'transaction.json')
    t.require(packet['stage'] in STAGES and packet['native_binary_sha256']==p.GENERIC_SHA
        and t.digest((prepared/'transaction.json').read_bytes())==packet['body_sha256']
        and body['id']==packet['transaction_id'],'staged-body-identity')
    contexts=p.read(prepared/'supplied-context.json');case=p.read(prepared/'validation-case.json')
    t.require(case['transaction']==body and len(contexts)==1
        and packet['input_contexts']==[dict(contexts[0],outpoint=body['inputs'][0]['previousOutpoint'])]
        and case['entries']==[{'amount':int(contexts[0]['amount_sompi']),
            'scriptPublicKey':contexts[0]['script_public_key'],
            'blockDaaScore':int(contexts[0]['block_daa_score']),'isCoinbase':False,'covenantId':None}],
        'staged-public-case-context-binding')
    t.require(not output.exists(),'fresh-actual-context-native-output');output.mkdir(mode=0o700,parents=True)
    runtime=t.trusted_runtime()
    if packet['stage']=='private-payment':
        request=p.read(prepared/'zero-proof-quote-request.json')
        t.require(request['supplied_utxo']==contexts[0],'fresh-quote-actual-context')
        with runtime.TrustedExecutable(p.NATIVE,p.NATIVE_SHA) as native:
            quote=local.call(native,request)
        zero=copy.deepcopy(body);signature=bytes.fromhex(body['inputs'][0]['signatureScript'])
        zero['inputs'][0]['signatureScript']=(signature[:68]+bytes(128)+signature[196:]).hex()
        t.require(quote['verified'] is False and quote['public_checks_reached_G16'] is True
            and quote['transaction']==zero and quote['supplied_context']==contexts
            and int(quote['fee_sompi'])==packet['expected_fee_sompi'],'fresh-exact-zero-proof-quote')
        write(output/'zero-proof-quote-result.json',quote)
    with runtime.TrustedExecutable(p.GENERIC,p.GENERIC_SHA) as native:
        result=native.run(['validate-transaction',str(prepared/'validation-case.json'),str(output)])
    t.require(result.returncode==0,'actual-context-native-execution')
    report=p.read(output/'native-validation.json')
    t.require(report['Full'].get('accepted') is True and report['all_input_engines_accepted'] is True
        and report['Full']['fee_sompi']==packet['expected_fee_sompi'],'actual-context-Full-all-engines')
    check={key:packet[key] for key in ('body_sha256','transaction_id','profile_sha256','native_binary_sha256')}
    check.update(native_full_accepted=True,all_input_engines_accepted=True,inputs=packet['input_contexts'])
    if packet['stage']=='founding':check['output0_redeem_hex']=packet['output0_redeem_hex']
    write(output/'local-check.json',check)
    write(output/'VALIDATED.json',{'schema':'kpx3-live-prefix-validated/v1','stage':packet['stage'],
        'transaction_id':packet['transaction_id'],'actual_input_contexts':packet['input_contexts'],
        'native_binary_sha256':p.GENERIC_SHA,'native_Full':report['Full'],
        'all_input_engines_accepted':True,'body_changed':False,'broadcast_performed':False})
    return {'stage':packet['stage'],'transaction_id':body['id'],'native_Full':True,'broadcast':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    prep=sub.add_parser('prepare');prep.add_argument('stage',choices=STAGES)
    for name in ('closed','identity','observation','checkpoint','output'):prep.add_argument('--'+name,type=Path,required=True)
    check=sub.add_parser('validate');check.add_argument('--prepared',type=Path,required=True)
    check.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.command=='prepare':result=prepare(args.stage,args.closed,args.identity,args.observation,args.checkpoint,args.output)
    else:result=validate(args.prepared,args.output)
    print(json.dumps(result,sort_keys=True))
