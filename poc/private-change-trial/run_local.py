#!/usr/bin/env python3
"""Verify six private resident proofs against exact private prepared statements.

No backup, profile, witness, PK, setup, prover or network interface. Raw main
transactions/Auth stay in private output; only PUBLIC-SUMMARY is publishable.
"""
import argparse
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import phase
import wallet_core

PARAMETERS_SHA='b440d08fddcdbbfb7d6b8355ab097a7bedd3fb85b8aa228f07070d4fcb3a91d0'
VK_SHA='dade8f90f1bec1c9b150f5eb126d73a1c8a1959ef1fb9da1178820debf693bae'
LABELS=('initial-payment','partial-cashout','change-payment','full-cashout',
        'terminal-cashout','zero-change-control')
REPORT_KEYS={'schema','proof_sha256','authorization_sha256','vk_sha256','domain_hex32',
    'compiled_build_identity_sha256','genuine_Groth16_verified',
    'request_parse_prove_and_checked_verification_seconds'}


def read(path):return phase.parse(path.read_bytes())


def save(t,path,value):t.private_write(path,t.encoded(value))


def public_effects(request):
    auth=bytes.fromhex(request['auth_hex528'])
    phase.require(len(auth)==528 and auth[:8]==b'KPX3AU01','actual-Auth528')
    return SimpleNamespace(auth=auth,ciphertexts=bytes.fromhex(request['cipher_hex528']),
        public_witness=bytes.fromhex(request['public_witness_hex3344']),before=auth[76:188],
        after=auth[364:476],destination=auth[492:528],remaining=int.from_bytes(auth[476:484],'little'),
        payout=int.from_bytes(auth[484:492],'little'),fee=int.from_bytes(auth[196:204],'little'))


def proof(directory,request,parameters):
    blob=(directory/'proof128.bin').read_bytes();auth=(directory/'authorization528.bin').read_bytes()
    vk=(directory/'verification-key.bin').read_bytes();report=read(directory/'report.json')
    phase.require(set(report)==REPORT_KEYS and report['schema']=='kpx3-private-resident-proof-result/v1'
        and report['genuine_Groth16_verified'] is True and len(blob)==128 and blob!=bytes(128)
        and auth.hex()==request['auth_hex528'] and vk.hex()==parameters['vk_hex328']
        and phase.digest(vk)==report['vk_sha256']==VK_SHA
        and phase.digest(auth)==report['authorization_sha256']
        and phase.digest(blob)==report['proof_sha256']
        and report['domain_hex32']==parameters['domain_hex32']
        and report['compiled_build_identity_sha256']==parameters['compiled_build_identity_sha256'],
        'selected-genuine-resident-proof-identity')
    return blob,report


def run(prepared,proofs,parameters_path,output):
    identity=phase.selected();core=wallet_core.load();t,_,p=phase.helpers()
    parameters_raw=parameters_path.read_bytes();parameters=phase.parse(parameters_raw)
    phase.require(phase.digest(parameters_raw)==PARAMETERS_SHA
        and parameters['domain_hex32']==identity['domain_hex32'],'selected-local-parameters')
    metadata=read(prepared/'MATERIALIZED.json')
    phase.require(metadata['schema']=='kpx3-private-change-local-preparation/v1'
        and metadata['trial_id']==identity['trial_id'] and metadata['domain_hex32']==identity['domain_hex32']
        and metadata['parameters_sha256']==PARAMETERS_SHA and metadata['vk_sha256']==VK_SHA
        and metadata['accepted_chain_backing'] is False
        and metadata['main_unbroadcast_Auth_NF_bodies_and_proof_requests_must_remain_private'] is True,
        'private-local-preparation-identity-and-boundary')
    output=t.outside_git(output);phase.require(not output.exists(),'fresh-private-native-output')
    t.private_dir(output)
    with core.owner_runtime.SelectedExecutable(p.GENERIC,p.GENERIC_SHA) as generic, \
         core.owner_runtime.SelectedExecutable(p.NATIVE,p.NATIVE_SHA) as native:
        first=output/'founding';t.private_dir(first)
        body=read(prepared/'founding-final/transaction.json')
        contexts=read(prepared/'founding-final/strict-context.json')
        native_case=read(prepared/'founding-final/validation-case.json')
        phase.require(all(set(row)=={'amount_sompi','script_public_key','block_daa_score',
                'is_coinbase','covenant_id'} and row['is_coinbase'] is False and row['covenant_id'] is None
            and row==p.context_entry(int(row['amount_sompi']),row['script_public_key'],row['block_daa_score'])
            for row in contexts),'strict-ordinary-source-context')
        expected_entries=[{'amount':int(row['amount_sompi']),'scriptPublicKey':row['script_public_key'],
            'blockDaaScore':int(row['block_daa_score']),'isCoinbase':False,'covenantId':None}
            for row in contexts]
        phase.require(native_case=={'transaction':body,'entries':expected_entries},'exact-ordinary-source-case')
        executed=generic.run(['validate-transaction',prepared/'founding-final/validation-case.json',first])
        phase.require(executed.returncode==0,'local-ordinary-native-execution')
        report=read(first/'native-validation.json')
        phase.require(report['Full'].get('accepted') is True and report['all_input_engines_accepted'] is True
            and report['Full']['fee_sompi']==metadata['founding_fee_sompi'],'local-founding-Full')
        phase.require(p.sdk_call(body,contexts)==body,'local-founding-SDK')
        actual_source=sum(int(row['amount_sompi']) for row in contexts)
        actual_change=sum(row['value'] for row in body['outputs'][1:])
        phase.require(len(contexts)==1 and actual_source==metadata['source_sompi']
            and actual_change==metadata['ordinary_change_sompi'],'actual-ordinary-source-and-change')
        save(t,first/'transaction.json',body);save(t,first/'supplied-context.json',contexts)
        previous=body;fees=report['Full']['fee_sompi'];payouts=0;reports=[];main_nfs=set();main_ids=[]
        for index,label in enumerate(LABELS):
            source=prepared/label;case=output/label;t.private_dir(case)
            zero=read(source/'transaction.json');contexts=read(source/'supplied-context.json')
            request=read(source/'selected-public-request.json');quote=read(source/'selected-actual-quote.json')
            effects=public_effects(request)
            phase.require(quote['verified'] is False and quote['public_checks_reached_G16'] is True
                and quote['transaction']==zero and quote['supplied_context']==contexts
                and effects.auth.hex()==zero['payload'][:1056]
                and request['domain_hex32']==identity['domain_hex32']
                and request['vk_hex328']==parameters['vk_hex328'],'exact-selected-actual-quote-input')
            current={'outpoint':request['previous_outpoint'],'current_redeem_hex':request['current_redeem_hex'],
                'reserve_sompi':int(request['supplied_utxo']['amount_sompi']),
                'current_utxo':dict(request['supplied_utxo'],outpoint=request['previous_outpoint'])}
            if index<5:
                phase.require(request['previous_outpoint']=={'transactionId':previous['id'],'index':0}
                    and int(contexts[0]['amount_sompi'])==previous['outputs'][0]['value']
                    and contexts[0]['script_public_key']==previous['outputs'][0]['scriptPublicKey'],
                    'main-actual-prior-output-link')
                main_nfs.update((effects.auth[204:236],effects.auth[236:268]))
            else:
                canary=read(source/'PUBLIC-SYNTHETIC.json')
                phase.require(canary['classification']=='PUBLIC_SYNTHETIC_DO_NOT_FUND'
                    and canary['not_a_canonical_main_trial_branch'] is True
                    and canary['no_main_claim_or_NF_overlap'] is True
                    and request['previous_outpoint']==canary['fake_outpoint']
                    and {effects.auth[204:236],effects.auth[236:268]}.isdisjoint(main_nfs),
                    'independent-public-C0-not-main-state')
            blob,proof_report=proof(proofs/label,request,parameters)
            value=dict(request,mode='verify',proof_hex128=blob.hex(),
                expected_quote_id=quote['quote_id'],fee_rate_sompi_per_mass='100')
            verified=core.change_wallet.native_call(native,value)
            core.change_wallet.check_body(verified,{},current,effects,effects.auth,blob,effects.fee)
            wanted=copy.deepcopy(zero);frame=bytes.fromhex(zero['inputs'][0]['signatureScript'])
            phase.require(frame[68:196]==bytes(128),'zero-proof-frame-before-substitution')
            wanted['inputs'][0]['signatureScript']=(frame[:68]+blob+frame[196:]).hex()
            phase.require(verified['verified'] is True and verified['transaction']==wanted
                and verified['supplied_context']==contexts and verified['quote_id']==quote['quote_id']
                and verified['native_validation']['Full'].get('accepted') is True
                and verified['native_validation']['all_input_engines_accepted'] is True
                and verified['native_validation']['Full']['fee_sompi']==effects.fee,
                'genuine-proof-only-Full-and-exact-actual-quote')
            phase.require(p.sdk_call(verified['transaction'],contexts)==verified['transaction'],'private-action-SDK')
            save(t,case/'transaction.json',verified['transaction']);save(t,case/'supplied-context.json',contexts)
            save(t,case/'native-validation.json',verified['native_validation'])
            save(t,case/'native-result.json',verified);save(t,case/'proof-report.json',proof_report)
            reports.append(proof_report)
            if index<5:
                previous=verified['transaction'];fees+=effects.fee;payouts+=effects.payout;main_ids.append(previous['id'])
                if index==4:
                    phase.require(effects.remaining==0 and len(previous['outputs'])==1
                        and verified['successor_state_hex112'] is None,'main-terminal-one-payout-zero-reserve')
        phase.require(len({report['authorization_sha256'] for report in reports})==6
            and len({report['proof_sha256'] for report in reports})==6,'six-distinct-genuine-statements')
        phase.require(actual_source==actual_change+fees+payouts
            and payouts==metadata['native_payouts_sompi'],'main-whole-source-reconciliation')
        summary={'schema':'kpx3-private-change-local-summary/v1',
            'classification':'UNBROADCAST_SUPPLIED_CONTEXT_REHEARSAL',
            'synthetic_funding_context':metadata['synthetic_funding_context'],
            'accepted_chain_backing':False,'actual_source_trial_readiness':False,
            'main_positive_native_Full_operations':6,'main_genuine_Groth16_proofs':5,
            'independent_public_synthetic_C0_positive_native_Full_operations':1,
            'independent_public_synthetic_C0_genuine_proofs':1,'main_prior_output_links':5,
            'SDK_roundtrips':7,'source_sompi':metadata['source_sompi'],
            'ordinary_change_sompi':metadata['ordinary_change_sompi'],'main_all_fees_sompi':fees,
            'main_native_payouts_sompi':payouts,'main_terminal_reserve_sompi':0,
            'final_CM_count':9,'final_NF_count':11,'local_original_backup_recognition_zero_tails':True,
            'parameters_sha256':PARAMETERS_SHA,'vk_sha256':VK_SHA,
            'selected_local_proof_metadata':reports,
            'C0_not_a_main_trace_spend_and_no_main_NF_or_CM_overlap':True,
            'earlier_ordinary_funding_costs_included_here':False,
            'main_raw_Auth_NF_CFs_bodies_and_private_witnesses_exported':False,
            'new_setup_or_proof_or_RPC_or_funding_or_broadcast':False,
            'independent_cold_recovery_privacy_fee_or_production_qualified':False}
        save(t,output/'PUBLIC-SUMMARY.json',summary)
        # This private closure can bind exact unbroadcast bodies without exposing
        # them as competing public statements against future independent exits.
        save(t,output/'PRIVATE-COMPLETE.json',{'summary':summary,'main_transaction_ids':main_ids,
            'main_raw_statement_artifacts_private':True})
        return {'main_Full':6,'independent_C0_Full':1,'private_proofs_consumed':6,
                'main_reserve_sompi':0,'funding_or_broadcast':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('prepared','proofs','parameters','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(run(args.prepared,args.proofs,args.parameters,args.output),sort_keys=True))
