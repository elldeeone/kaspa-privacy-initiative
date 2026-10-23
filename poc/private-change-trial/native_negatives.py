#!/usr/bin/env python3
"""Six private mutations using original genuine proofs, never new proofs.

All raw variants and candidate digests remain outside Git. Public output is
limited to names, typed failure outcomes and scope; no NF/body/path/key data.
"""
import argparse
import copy
import json
from pathlib import Path

import phase
import wallet_core

G16_UNITS=14_750_000
GENERATOR_DEST='00002079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac'


def read(path):return phase.parse(path.read_bytes())


def save(t,path,value):t.private_write(path,t.encoded(value))


def specifications(positive):
    base_partial=read(positive/'partial-cashout/transaction.json')
    partial_context=read(positive/'partial-cashout/supplied-context.json')
    base_payment=read(positive/'change-payment/transaction.json')
    payment_context=read(positive/'change-payment/supplied-context.json')
    for label,body in (('partial-cashout',base_partial),('change-payment',base_payment)):
        report=read(positive/label/'native-validation.json')
        proof=read(positive/label/'proof-report.json')
        payload=bytes.fromhex(body['payload']);frame=bytes.fromhex(body['inputs'][0]['signatureScript'])
        phase.require(report['Full']['accepted'] is True and report['all_input_engines_accepted'] is True
            and frame[68:196]!=bytes(128) and proof['genuine_Groth16_verified'] is True
            and proof['domain_hex32']==phase.selected()['domain_hex32']==payload[8:40].hex()
            and proof['proof_sha256']==phase.digest(frame[68:196])
            and proof['authorization_sha256']==phase.digest(payload[:528]),
            'closed-genuine-positive-baseline')
    phase.require(base_partial['outputs'][-1]['scriptPublicKey']!=GENERATOR_DEST,
                  'changed-valid-destination')
    rows=[]
    def add(name,body,contexts,engine='VerifyError',late=False):
        baseline=base_partial if name.startswith('partial-') else base_payment
        phase.require(body['inputs'][0]['signatureScript']==baseline['inputs'][0]['signatureScript'],
                      'original-genuine-proof-frame-unchanged')
        rows.append((name,body,copy.deepcopy(contexts),engine,late))
    body=copy.deepcopy(base_partial);body['outputs'][-1]['scriptPublicKey']=GENERATOR_DEST
    add('partial-output-destination-mismatch',body,partial_context)
    body=copy.deepcopy(base_partial);payload=bytearray.fromhex(body['payload'])
    payload[492:528]=bytes.fromhex(GENERATOR_DEST);body['payload']=payload.hex()
    body['outputs'][-1]['scriptPublicKey']=GENERATOR_DEST
    add('partial-auth-and-destination-rebinding',body,partial_context,late=True)
    body=copy.deepcopy(base_partial);payload=bytearray.fromhex(body['payload'])
    payout=int.from_bytes(payload[484:492],'little')+1
    remaining=int.from_bytes(payload[476:484],'little')-1
    payload[484:492]=payout.to_bytes(8,'little');payload[476:484]=remaining.to_bytes(8,'little')
    body['payload']=payload.hex();body['outputs'][0]['value']=remaining;body['outputs'][-1]['value']=payout
    add('partial-payout-reserve-rebinding',body,partial_context,late=True)
    body=copy.deepcopy(base_payment);body['outputs'][0]['value']-=10_000_000
    body['outputs'].append({'value':10_000_000,'scriptPublicKey':GENERATOR_DEST,'covenant':None})
    add('payment-extra-native-output',body,payment_context)
    body=copy.deepcopy(base_payment);payload=bytearray.fromhex(body['payload'])
    payload[1056:3376]=payload[2216:3376]+payload[1056:2216];body['payload']=payload.hex()
    add('payment-NF-update-order',body,payment_context)
    current_context=read(positive/'full-cashout/supplied-context.json')
    phase.require(current_context[0]['script_public_key']!=payment_context[0]['script_public_key'],
                  'different-supplied-current-head')
    phase.require(int(current_context[0]['amount_sompi'])==base_payment['outputs'][0]['value']
        and current_context[0]['script_public_key']==base_payment['outputs'][0]['scriptPublicKey'],
        'supplied-current-context-is-successful-payment-successor')
    add('stale-payment-current-context',copy.deepcopy(base_payment),current_context,engine='EvalFalse')
    phase.require(len(rows)==6,'exact-six-bounded-negatives')
    return rows


def run(positive,output):
    phase.selected();core=wallet_core.load();t,_,p=phase.helpers()
    output=t.outside_git(output);phase.require(not output.exists(),'fresh-private-negative-output')
    t.private_dir(output);results=[]
    with core.owner_runtime.SelectedExecutable(p.GENERIC,p.GENERIC_SHA) as native:
        for name,body,contexts,expected_engine,late in specifications(positive):
            case=output/name;t.private_dir(case)
            entries=[{'amount':int(row['amount_sompi']),'scriptPublicKey':row['script_public_key'],
                'blockDaaScore':int(row['block_daa_score']),'isCoinbase':False,'covenantId':None}
                for row in contexts]
            save(t,case/'input.json',{'transaction':body,'entries':entries})
            normalized=native.run(['control-normalize-freeze',case/'input.json',case/'normalized'])
            phase.require(normalized.returncode==0,'negative-official-noVM-normalization')
            actual=read(case/'normalized/transaction.json')
            wanted=copy.deepcopy(body);wanted['id']=actual['id'];wanted['mass']=actual['mass']
            phase.require(actual==wanted
                and read(case/'normalized/validation-case.json')=={'transaction':actual,'entries':entries},
                'normalization-preserves-intended-original-proof-mutation')
            checked=native.run(['validate-transaction',case/'normalized/validation-case.json',case/'validation'])
            phase.require(checked.returncode==0,'negative-native-validator-completed')
            report=read(case/'validation/native-validation.json')
            expected_full='SignatureInvalid('+expected_engine+')'
            full=report.get('Full',{});engines=report.get('per_input_ScriptEngine',[])
            engine=engines[0] if len(engines)==1 else {}
            units=engine.get('units')
            allowed=engine.get('allowed_script_units')
            exact=(full.get('accepted') is False and full.get('typed_error')==expected_full
                and report.get('all_input_engines_accepted') is False and len(engines)==1
                and report.get('isolation')=='PASS'
                and engine.get('accepted') is False and engine.get('typed_error')==expected_engine
                and report.get('ScriptEngine')==engine and type(units) is int and type(allowed) is int
                and (G16_UNITS<=units<=allowed if late else 0<=units<G16_UNITS))
            results.append({'case':name,'passed':exact,'expected_Full_typed_failure':expected_full,
                'expected_engine_typed_failure':expected_engine,
                'observed_Full_typed_failure':expected_full if full.get('typed_error')==expected_full
                    else 'UNEXPECTED_TYPED_FAILURE_RETAINED_PRIVATELY',
                'observed_engine_typed_failure':expected_engine if engine.get('typed_error')==expected_engine
                    else 'UNEXPECTED_TYPED_FAILURE_RETAINED_PRIVATELY',
                'original_genuine_proof_preserved':True,
                'rejection_scope':'original-proof-Auth-binding-at-G16' if late else 'public-check-before-G16',
                'supplied_context_only_not_chain_freshness':name=='stale-payment-current-context'})
    summary={'schema':'kpx3-private-change-six-native-negatives/v1',
        'classification':'UNBROADCAST_SUPPLIED_CONTEXT_NEGATIVES',
        'cases':results,'passed':sum(row['passed'] for row in results),'total':6,
        'additional_genuine_proofs':0,'original_current_recovery_spent_classifications':2,
        'genuine_current_rebased_occupied_NF_proof_claimed':False,
        'raw_main_variants_Auth_NFs_bodies_proofs_or_candidate_digests_exported':False,
        'setup_RPC_funding_broadcast_or_actual_chain_freshness_test':False,
        'proof_correctness_privacy_fee_or_production_qualified':False}
    save(t,output/'PUBLIC-SUMMARY.json',summary)
    phase.require(summary['passed']==6,'retained-negative-prediction-failure')
    return {'native_negatives_passed':6,'extra_proofs':0,'funding_or_broadcast':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--positive',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(run(args.positive,args.output),sort_keys=True))
