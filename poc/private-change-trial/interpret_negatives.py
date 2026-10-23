#!/usr/bin/env python3
"""Additive reading of the existing six reports. No execution or retest API."""
import argparse
import json
from pathlib import Path

import phase

NAMES=('partial-output-destination-mismatch','partial-auth-and-destination-rebinding',
       'partial-payout-reserve-rebinding','payment-extra-native-output',
       'payment-NF-update-order','stale-payment-current-context')
LATE=set(NAMES[1:3])
ZK='ZkIntegrity("Groth16 verification failed")'
UPSTREAM=Path('/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e')
SOURCE_FILES=('crypto/txscript/src/zk_precompiles/groth16/error.rs',
              'crypto/txscript/src/zk_precompiles/groth16/mod.rs',
              'crypto/txscript/src/zk_precompiles/mod.rs')


def interpret(result,receipt,output):
    phase.selected()
    original=phase.parse((result/'PUBLIC-SUMMARY.json').read_bytes())
    execution=phase.parse(receipt.read_bytes())
    phase.require(original['passed']==4 and original['total']==6 and execution['returncode']==1
        and [row['case'] for row in original['cases']]==list(NAMES),'preserved-original-prediction-result')
    rows=[]
    for name in NAMES:
        actual=phase.parse((result/name/'validation/native-validation.json').read_bytes())
        expected=ZK if name in LATE else 'EvalFalse' if name==NAMES[-1] else 'VerifyError'
        full='SignatureInvalid('+expected+')';engines=actual['per_input_ScriptEngine']
        phase.require(actual['Full']=={'accepted':False,'typed_error':full}
            and actual['all_input_engines_accepted'] is False and actual['isolation']=='PASS'
            and len(engines)==1 and actual['ScriptEngine']==engines[0]
            and engines[0]['accepted'] is False and engines[0]['typed_error']==expected,
            'source-confirmed-existing-typed-rejection')
        units=engines[0]['units'];allowed=engines[0]['allowed_script_units']
        phase.require(14_750_000<=units<=allowed if name in LATE else 0<=units<14_750_000,
                      'existing-metered-rejection-stage')
        rows.append({'case':name,'observed_Full_typed_failure':full,
            'observed_engine_typed_failure':expected,'rejected':True,
            'scope':'original-proof-rebinding-rejected-at-G16' if name in LATE else 'public-check-before-G16',
            'original_error_name_prediction_matched':name not in LATE})
    # These are exact pinned consensus sources, not private case/statement data.
    source_rows=[]
    for relative in SOURCE_FILES:
        raw=(UPSTREAM/relative).read_bytes()
        source_rows.append({'repository_path':relative,'bytes':len(raw),'sha256':phase.digest(raw)})
    error=(UPSTREAM/SOURCE_FILES[0]).read_text();dispatch=(UPSTREAM/SOURCE_FILES[2]).read_text()
    phase.require('#[error("Groth16 verification failed")]' in error
        and 'VerificationFailed' in error and 'TxScriptError::ZkIntegrity' in dispatch,
        'pinned-consensus-error-mapping-source')
    report={'schema':'kpx3-private-change-native-negative-interpretation/v1',
        'status':'POST_RUN_SOURCE_INTERPRETATION_NOT_RETEST','actual_native_rejections':6,
        'original_frozen_error_name_predictions_matched':4,'original_error_name_predictions_total':6,
        'original_runner_returncode':1,'original_prediction_summary_and_execution_unchanged':True,
        'harness_prediction_mismatches':2,'cases':rows,
        'consensus_repository':'kaspanet/rusty-kaspa',
        'consensus_commit':'01b532e8b553523216471682649693af92f0fd16','source_files':source_rows,
        'correction':'Two genuine-proof Auth rebindings return ZkIntegrity from failed Groth16 verification, rather than the predicted VerifyError.',
        'Native_VM_or_proof_or_setup_or_RPC_or_funding_or_broadcast_executed_here':False,
        'raw_variants_Auth_NFs_bodies_proofs_candidate_digests_or_private_paths_exported':False,
        'genuine_current_rebased_occupied_NF_proof_or_chain_freshness_claimed':False}
    phase.require(not output.exists(),'fresh-public-interpretation-file')
    with output.open('x') as file:json.dump(report,file,indent=2,sort_keys=True);file.write('\n')
    return {'actual_native_rejections':6,'original_error_name_predictions_matched':4,
            'new_VM_or_proof_executions':0,'interpretation_sha256':phase.digest(output.read_bytes())}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('result','receipt','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(interpret(args.result,args.receipt,args.output),sort_keys=True))
