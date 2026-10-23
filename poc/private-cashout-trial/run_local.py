#!/usr/bin/env python3
"""Four public-body Full checks and three zero-proof seams; no private inputs."""
import argparse
import copy
import hashlib
import json
from pathlib import Path

import prepare as p
import trial as t

PARAMETERS_SHA='008689b84cd171187cc75d32402dbf13d6d4e3ed149d3349ecfbc418bfcaad54'
PROOF_FIELDS={'schema','proof_sha256','authorization_sha256','vk_sha256','domain_hex32',
    'compiled_build_identity_sha256','genuine_Groth16_verified','request_parse_prove_and_checked_verification_seconds'}


def save(path,value):
    with path.open('x') as file:json.dump(value,file,indent=2,sort_keys=True);file.write('\n')


def pin_packet(directory,expected):
    path=directory/'FILE-ALLOWLIST.json'
    t.require(t.digest(path.read_bytes())==expected,'reviewed-public-packet-sha256')
    for row in p.read(path)['files']:
        relative=Path(row['path'])
        t.require(not relative.is_absolute() and '..' not in relative.parts,'public-packet-relative-path')
        file=directory/relative;t.no_symlinks(file.absolute());raw=file.read_bytes()
        t.require(len(raw)==row['bytes'] and t.digest(raw)==row['sha256'],'reviewed-public-packet-changed')


def proof(directory,body,parameters,action):
    report=p.read(directory/'report.json')
    blob=(directory/'proof128.bin').read_bytes()
    vk=(directory/'verification-key.bin').read_bytes()
    auth=(directory/'authorization528.bin').read_bytes()
    t.require(set(report)==PROOF_FIELDS|{'action'} and report['action']==action
        and report['schema']=='kpx3-private-resident-proof-result/v1'
        and report['genuine_Groth16_verified'] is True and len(blob)==128 and blob!=bytes(128)
        and len(vk)==328 and vk.hex()==parameters['vk_hex328']
        and auth.hex()==body['payload'][:1056] and report['domain_hex32']==parameters['domain_hex32']
        and report['compiled_build_identity_sha256']==parameters['compiled_build_identity_sha256']
        and report['proof_sha256']==t.digest(blob) and report['authorization_sha256']==t.digest(auth)
        and report['vk_sha256']==t.digest(vk),'genuine-proof-public-identity')
    return blob,report


def request(packet,body,contexts):
    signature=bytes.fromhex(body['inputs'][0]['signatureScript']);payload=bytes.fromhex(body['payload'])
    t.require(len(contexts)==1 and len(payload)==4400 and signature[68:196]==bytes(128),
              'one-public-zero-proof-input')
    return {'schema':'kpx3-public-native-action/v1','mode':'quote','network_id':'testnet-10',
        'genesis_hash_hex':t.GENESIS,'domain_hex32':packet['domain_hex32'],
        'current_redeem_hex':signature[199:].hex(),
        'previous_outpoint':body['inputs'][0]['previousOutpoint'],'supplied_utxo':contexts[0],
        'auth_hex528':payload[:528].hex(),'cipher_hex528':payload[528:1056].hex(),
        'public_witness_hex3344':payload[1056:].hex(),'vk_hex328':packet['vk_hex328'],
        'proof_hex128':bytes(128).hex(),'fee_rate_sompi_per_mass':'100'}


def call(runtime,value):
    result=runtime.run([],input_text=json.dumps(value))
    t.require(result.returncode==0,'native-public-method-refused')
    return t.parse_json(result.stdout)


def run(packet_dir,expected,proof_root,parameter_file,output):
    t.selected_adr();pin_packet(packet_dir,expected)
    t.require(t.digest(parameter_file.read_bytes())==PARAMETERS_SHA,'selected-parameter-manifest')
    parameters=p.read(parameter_file);packet=p.read(packet_dir/'PUBLIC-PACKET.json')
    t.require(parameters['domain_hex32']==packet['domain_hex32']
        and parameters['trial_id']==packet['trial_id']
        and parameters['vk_hex328']==packet['vk_hex328'],'public-parameter-trial-binding')
    t.require(not output.exists(),'fresh-local-native-output');output.mkdir(parents=True)
    runtime=t.trusted_runtime()
    with runtime.TrustedExecutable(p.GENERIC,p.GENERIC_SHA) as generic, \
         runtime.TrustedExecutable(p.NATIVE,p.NATIVE_SHA) as native:
        first=output/'case-0000';first.mkdir()
        response=generic.run(['validate-transaction',str(packet_dir/'case-0000/validation-case.json'),str(first)])
        t.require(response.returncode==0,'ordinary-founding-native-execution')
        founding=p.read(first/'native-validation.json')
        t.require(founding['Full'].get('accepted') is True
            and founding['all_input_engines_accepted'] is True
            and founding['Full']['fee_sompi']==packet['cases'][0]['fee_sompi'],'ordinary-founding-Full')
        previous=p.read(packet_dir/'case-0000/transaction.json')
        p.sdk_call(previous,p.read(packet_dir/'case-0000/supplied-context.json'))
        rows=[{'case':0,'transaction_id':previous['id'],'native_Full':founding['Full'],
               'all_input_engines_accepted':True}]
        save(first/'transaction.json',previous)
        save(first/'supplied-context.json',p.read(packet_dir/'case-0000/supplied-context.json'))
        summaries=[]
        for index,action in enumerate(('payment','continuing-exit','terminal'),1):
            source=packet_dir/f'case-{index:04d}';case=output/f'case-{index:04d}';case.mkdir()
            body,contexts=p.read(source/'transaction.json'),p.read(source/'supplied-context.json')
            t.require(body['inputs'][0]['previousOutpoint']=={'transactionId':previous['id'],'index':0}
                and int(contexts[0]['amount_sompi'])==previous['outputs'][0]['value']
                and contexts[0]['script_public_key']==previous['outputs'][0]['scriptPublicKey'],
                'actual-prior-output-link')
            value=request(packet,body,contexts);quote=call(native,value)
            t.require(quote['verified'] is False and quote['public_checks_reached_G16'] is True
                and quote['transaction']==body and quote['supplied_context']==contexts
                and int(quote['fee_sompi'])==packet['cases'][index]['fee_sompi'],
                'strict-zero-proof-seam-exact-prepared-body')
            save(case/'quote-request.json',value);save(case/'quote-result.json',quote)
            blob,report=proof(proof_root/f'case-{index:04d}',body,parameters,action)
            value['mode']='verify';value['expected_quote_id']=quote['quote_id'];value['proof_hex128']=blob.hex()
            verified=call(native,value)
            actual=verified['transaction'];signature=bytes.fromhex(body['inputs'][0]['signatureScript'])
            wanted=copy.deepcopy(body)
            wanted['inputs'][0]['signatureScript']=(signature[:68]+blob+signature[196:]).hex()
            t.require(verified['verified'] is True and actual==wanted
                and verified['supplied_context']==contexts
                and verified['native_validation']['Full']['accepted'] is True
                and verified['native_validation']['all_input_engines_accepted'] is True,
                'genuine-proof-only-substitution-Full')
            if index==3:
                t.require(verified['successor_state_hex112'] is None,'terminal-no-successor-state')
            p.sdk_call(actual,contexts)
            save(case/'verify-request.json',value);save(case/'native-result.json',verified)
            save(case/'transaction.json',actual);save(case/'supplied-context.json',contexts)
            rows.append({'case':index,'transaction_id':actual['id'],
                'native_Full':verified['native_validation']['Full'],'all_input_engines_accepted':True,
                'public_payout_sompi':packet['cases'][index]['public_payout_sompi'],
                'public_reserve_after_sompi':packet['cases'][index]['public_reserve_after_sompi']})
            summaries.append(report)
            previous=actual
        t.require(len(previous['outputs'])==1 and rows[-1]['public_reserve_after_sompi']==0,
                  'terminal-one-payout-zero-reserve')
        source_value=packet['source_sompi'];fees=sum(row['native_Full']['fee_sompi'] for row in rows)
        payouts=sum(row.get('public_payout_sompi',0) for row in rows)
        t.require(len({row['authorization_sha256'] for row in summaries})==3
            and len({row['proof_sha256'] for row in summaries})==3,'three-distinct-genuine-statements')
        t.require(source_value==packet['ordinary_change_sompi']+fees+payouts,'full-source-reconciliation')
        result={'schema':'kpx3-local-four-body-complete/v1','trial_id':packet['trial_id'],
            'domain_hex32':packet['domain_hex32'],'source_public_packet_sha256':expected,
            'public_parameter_manifest_sha256':PARAMETERS_SHA,'native_Full_positive_operations':4,
            'negative_zero_proof_quote_seams':3,'genuine_Groth16_proofs':3,
            'actual_prior_output_links':3,'SDK_body_roundtrips':4,'cases':rows,
            'source_sompi':source_value,'ordinary_change_sompi':packet['ordinary_change_sompi'],
            'total_fees_sompi':fees,'native_payouts_sompi':payouts,'terminal_reserve_sompi':0,
            'final_CM_count':packet['final_CM_count'],'final_NF_count':packet['final_NF_count'],
            'funding_or_broadcast':False,'accepted_chain_backing':False,
            'cold_recovery_demonstrated_here':False,'privacy_fee_p95_or_production_qualified':False}
        save(output/'PROOFS-PUBLIC.json',{'proofs':summaries})
        save(output/'LOCAL-COMPLETE.json',result)
        pin_packet(packet_dir,expected)
        return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for field in ('packet','proofs','parameters','output'):parser.add_argument('--'+field,type=Path,required=True)
    parser.add_argument('--expected-packet-sha256',required=True)
    args=parser.parse_args()
    try:print(json.dumps(run(args.packet,args.expected_packet_sha256,args.proofs,args.parameters,args.output),sort_keys=True))
    except (ValueError,KeyError,TypeError,OSError):
        raise SystemExit('local public native rehearsal refused; no funding/broadcast') from None
