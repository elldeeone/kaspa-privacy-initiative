#!/usr/bin/env python3
"""Publish scoped counts and the independent public C0 canary only.

Never copies main unbroadcast Auth/NFs/ciphertexts/bodies, private paths,
profiles, backups, witnesses or their hashes. Actual public canary seed material
is explicitly synthetic and must never be funded.
"""
import argparse
import json
import math
from pathlib import Path
import re

import phase

PARAMETERS_SHA='b440d08fddcdbbfb7d6b8355ab097a7bedd3fb85b8aa228f07070d4fcb3a91d0'
VK_SHA='dade8f90f1bec1c9b150f5eb126d73a1c8a1959ef1fb9da1178820debf693bae'
PROOF_FIELDS={'schema','proof_sha256','authorization_sha256','vk_sha256','domain_hex32',
    'compiled_build_identity_sha256','genuine_Groth16_verified',
    'request_parse_prove_and_checked_verification_seconds'}
SUMMARY_SCALARS={'schema','classification','synthetic_funding_context','accepted_chain_backing',
    'actual_source_trial_readiness','main_positive_native_Full_operations','main_genuine_Groth16_proofs',
    'independent_public_synthetic_C0_positive_native_Full_operations',
    'independent_public_synthetic_C0_genuine_proofs','main_prior_output_links','SDK_roundtrips',
    'source_sompi','ordinary_change_sompi','main_all_fees_sompi','main_native_payouts_sompi',
    'main_terminal_reserve_sompi','final_CM_count','final_NF_count',
    'local_original_backup_recognition_zero_tails','parameters_sha256','vk_sha256',
    'C0_not_a_main_trace_spend_and_no_main_NF_or_CM_overlap',
    'earlier_ordinary_funding_costs_included_here','main_raw_Auth_NF_CFs_bodies_and_private_witnesses_exported',
    'new_setup_or_proof_or_RPC_or_funding_or_broadcast',
    'independent_cold_recovery_privacy_fee_or_production_qualified'}
INTEGER_FIELDS={'main_positive_native_Full_operations','main_genuine_Groth16_proofs',
    'independent_public_synthetic_C0_positive_native_Full_operations',
    'independent_public_synthetic_C0_genuine_proofs','main_prior_output_links','SDK_roundtrips',
    'source_sompi','ordinary_change_sompi','main_all_fees_sompi','main_native_payouts_sompi',
    'main_terminal_reserve_sompi','final_CM_count','final_NF_count'}
STRING_FIELDS={'schema','classification','parameters_sha256','vk_sha256'}


def read(path):return phase.parse(path.read_bytes())


def save(path,value):
    with path.open('x') as file:json.dump(value,file,indent=2,sort_keys=True);file.write('\n')


def proof_metadata(report):
    phase.require(set(report)==PROOF_FIELDS and report['genuine_Groth16_verified'] is True
        and report['schema']=='kpx3-private-resident-proof-result/v1'
        and all(type(report[name]) is str and re.fullmatch('[0-9a-f]{64}',report[name]) is not None
            for name in ('proof_sha256','authorization_sha256','vk_sha256','domain_hex32',
                         'compiled_build_identity_sha256'))
        and type(report['request_parse_prove_and_checked_verification_seconds']) in (float,int)
        and math.isfinite(report['request_parse_prove_and_checked_verification_seconds'])
        and report['request_parse_prove_and_checked_verification_seconds']>=0,'safe-selected-proof-metadata')


def canary_public_types(body,contexts,native):
    hx=lambda value,width: type(value) is str and re.fullmatch('[0-9a-f]{'+str(width*2)+'}',value) is not None
    phase.require(set(body)=={'version','id','inputs','outputs','lockTime','subnetworkId','gas','payload','mass'}
        and body['version']==1 and body['lockTime']==body['gas']==0
        and body['subnetworkId']=='00'*20 and hx(body['id'],32) and hx(body['payload'],4400)
        and type(body['mass']) is int and body['mass']>=0
        and len(body['inputs'])==len(body['outputs'])==len(contexts)==1,'strict-public-C0-body')
    input=body['inputs'][0];point=input['previousOutpoint'];output=body['outputs'][0]
    phase.require(set(input)=={'previousOutpoint','signatureScript','sequence','computeBudget'}
        and input['sequence']==(1<<64)-1 and input['computeBudget']==1600
        and hx(input['signatureScript'],24616) and set(point)=={'transactionId','index'}
        and hx(point['transactionId'],32) and type(point['index']) is int and point['index']==0
        and set(output)=={'value','scriptPublicKey','covenant'} and output['covenant'] is None
        and type(output['value']) is int and 0<output['value']<=2_870_000_000_000_000_000
        and re.fullmatch('0000aa20[0-9a-f]{64}87',output['scriptPublicKey']),
        'strict-public-C0-input-output-fields')
    for context in contexts:
        phase.require(set(context)=={'amount_sompi','script_public_key','block_daa_score','is_coinbase','covenant_id'}
            and context['is_coinbase'] is False and context['covenant_id'] is None
            and type(context['amount_sompi']) is str and re.fullmatch('[1-9][0-9]*',context['amount_sompi'])
            and type(context['block_daa_score']) is str and re.fullmatch('0|[1-9][0-9]*',context['block_daa_score'])
            and 0<int(context['amount_sompi'])<=2_870_000_000_000_000_000
            and 0<=int(context['block_daa_score'])<(1<<64)
            and re.fullmatch('0000aa20[0-9a-f]{64}87',context['script_public_key']),
            'strict-public-C0-context-fields')
    phase.require(set(native)=={'Full','ScriptEngine','all_input_engines_accepted','isolation','per_input_ScriptEngine'}
        and set(native['Full'])=={'accepted','fee_sompi'} and native['Full']['accepted'] is True
        and native['all_input_engines_accepted'] is True and native['isolation']=='PASS'
        and native['Full']['fee_sompi']==int(contexts[0]['amount_sompi'])-output['value']
        and len(native['per_input_ScriptEngine'])==1
        and native['ScriptEngine']==native['per_input_ScriptEngine'][0],'strict-public-C0-native-report')
    engine=native['ScriptEngine']
    phase.require(set(engine)=={'accepted','allowed_script_units','input_index','units'}
        and engine['accepted'] is True and engine['input_index']==0
        and all(type(engine[key]) is int and engine[key]>=0
            for key in ('allowed_script_units','input_index','units')),'strict-public-C0-engine-fields')


def publish(prepared,result,proofs,output):
    identity=phase.selected();summary=read(result/'PUBLIC-SUMMARY.json')
    parameter_raw=(phase.PHASE/'prover/parameters-01/public-parameters.json').read_bytes()
    phase.require(phase.digest(parameter_raw)==PARAMETERS_SHA,'selected-public-parameters')
    parameters=phase.parse(parameter_raw)
    phase.require(set(summary)==SUMMARY_SCALARS|{'selected_local_proof_metadata'}
        and all(type(summary[name]) is int and summary[name]>=0 for name in INTEGER_FIELDS)
        and all(type(summary[name]) is str for name in STRING_FIELDS)
        and all(type(summary[name]) is bool for name in SUMMARY_SCALARS-INTEGER_FIELDS-STRING_FIELDS)
        and summary['schema']=='kpx3-private-change-local-summary/v1'
        and summary['classification']=='UNBROADCAST_SUPPLIED_CONTEXT_REHEARSAL'
        and summary['parameters_sha256']==PARAMETERS_SHA and summary['vk_sha256']==VK_SHA
        and summary['accepted_chain_backing'] is False and summary['actual_source_trial_readiness'] is False
        and summary['main_raw_Auth_NF_CFs_bodies_and_private_witnesses_exported'] is False
        and summary['C0_not_a_main_trace_spend_and_no_main_NF_or_CM_overlap'] is True
        and len(summary['selected_local_proof_metadata'])==6,'safe-public-summary-fields')
    for report in summary['selected_local_proof_metadata']:
        proof_metadata(report)
        phase.require(report['domain_hex32']==identity['domain_hex32']
            and report['vk_sha256']==VK_SHA
            and report['compiled_build_identity_sha256']==parameters['compiled_build_identity_sha256'],
            'selected-local-proof-software-identity')
    canary=read(prepared/'zero-change-control/PUBLIC-SYNTHETIC.json')
    phase.require(set(canary)=={'classification','not_a_canonical_main_trial_branch',
        'public_canary_owner_seed_hex32','public_canary_recipient_seed_hex32','fake_outpoint',
        'CM_count_after','NF_count_after','zero_self_change','no_main_claim_or_NF_overlap','broadcast'}
        and canary['classification']=='PUBLIC_SYNTHETIC_DO_NOT_FUND'
        and canary['public_canary_owner_seed_hex32']==phase.digest(b'KPX3/CHANGE/C0/PUBLIC-OWNER/DO-NOT-FUND')
        and canary['public_canary_recipient_seed_hex32']==phase.digest(b'KPX3/CHANGE/C0/PUBLIC-RECIPIENT/DO-NOT-FUND')
        and canary['fake_outpoint']=={'transactionId':phase.digest(b'KPX3/CHANGE/C0/FAKE-OUTPOINT/DO-NOT-FUND\0'
            +bytes.fromhex(identity['domain_hex32'])),'index':0}
        and canary['not_a_canonical_main_trial_branch'] is True and canary['zero_self_change'] is True
        and canary['no_main_claim_or_NF_overlap'] is True and canary['broadcast'] is False
        and canary['CM_count_after']==canary['NF_count_after']==3,'independent-public-canary-identity')
    body=read(result/'zero-change-control/transaction.json')
    contexts=read(result/'zero-change-control/supplied-context.json')
    native=read(result/'zero-change-control/native-validation.json')
    report=read(proofs/'zero-change-control/report.json');proof_metadata(report)
    phase.require(report['vk_sha256']==VK_SHA
        and report['compiled_build_identity_sha256']==parameters['compiled_build_identity_sha256'],
        'selected-public-C0-proof-software-identity')
    canary_public_types(body,contexts,native)
    auth=(proofs/'zero-change-control/authorization528.bin').read_bytes()
    blob=(proofs/'zero-change-control/proof128.bin').read_bytes()
    vk=(proofs/'zero-change-control/verification-key.bin').read_bytes()
    phase.require(body['inputs'][0]['previousOutpoint']==canary['fake_outpoint']
        and body['payload'][:1056]==auth.hex() and len(auth)==528 and len(blob)==128 and len(vk)==328
        and auth[:8]==b'KPX3AU01' and auth[8:40].hex()==identity['domain_hex32']
        and report['domain_hex32']==identity['domain_hex32']
        and bytes.fromhex(body['inputs'][0]['signatureScript'])[68:196]==blob
        and phase.digest(auth)==report['authorization_sha256']
        and phase.digest(blob)==report['proof_sha256'] and phase.digest(vk)==report['vk_sha256']
        and native['Full']['accepted'] is True and native['all_input_engines_accepted'] is True,
        'verified-public-C0-body-proof-context')
    # No arbitrary raw source/metadata container is copied. These exact selected
    # C0 files already passed the independent seven-Full artifact closure.
    phase.require(not output.exists(),'fresh-scoped-public-packet');output.mkdir(parents=True)
    save(output/'PUBLIC-SUMMARY.json',summary)
    c0=output/'PUBLIC-SYNTHETIC-C0-DO-NOT-FUND';c0.mkdir()
    for name,value in (('transaction.json',body),('supplied-context.json',contexts),
                       ('native-validation.json',native),('PUBLIC-SYNTHETIC.json',canary),('report.json',report)):
        save(c0/name,value)
    entries=[{'amount':int(row['amount_sompi']),'scriptPublicKey':row['script_public_key'],
        'blockDaaScore':int(row['block_daa_score']),'isCoinbase':False,'covenantId':None} for row in contexts]
    save(c0/'validation-case.json',{'transaction':body,'entries':entries})
    for name,raw in (('proof128.bin',blob),('authorization528.bin',auth),('verification-key.bin',vk)):
        with (c0/name).open('xb') as file:file.write(raw)
    files=[]
    for file in sorted(path for path in output.rglob('*') if path.is_file()):
        raw=file.read_bytes();files.append({'path':str(file.relative_to(output)),
            'bytes':len(raw),'sha256':phase.digest(raw)})
    save(output/'FILE-ALLOWLIST.json',{'schema':'kpx3-private-change-public-local-allowlist/v1',
        'files':files,'exporter_source_sha256':phase.digest(Path(__file__).read_bytes()),
        'raw_main_statements_proofs_profiles_backups_witnesses_or_paths_included':False,
        'only_complete_raw_statement':'INDEPENDENT_PUBLIC_SYNTHETIC_C0_DO_NOT_FUND',
        'actual_chain_backing_or_source_readiness_or_privacy_qualification':False})
    return {'public_files':len(files),'allowlist_sha256':phase.digest((output/'FILE-ALLOWLIST.json').read_bytes())}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('prepared','result','proofs','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(publish(args.prepared,args.result,args.proofs,args.output),sort_keys=True))
