#!/usr/bin/env python3
"""One bounded public synthetic native kernel comparison; no financial policy."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import time
import types

import kernel

HERE = Path(__file__).resolve().parent
NATIVE_SHA = '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061'
NODE_SHA = 'd1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c'
RUNTIME_SHA = '3ce31ae0eb8f942009a4108f9a5dbb6a08df6c7f0925f06a952315091e1bbd1c'
FAULTS = ('positive','leaf','sibling','index','occupied','truncated','trailing')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as file:
        json.dump(data,file,sort_keys=True,indent=2);file.write('\n')


def runtime(path):
    raw=path.read_bytes()
    if sha(raw)!=RUNTIME_SHA: raise ValueError('selected-normal-runtime-source')
    module=types.ModuleType('_compact_normal_runtime');module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),vars(module));return module


def run(output,native_path,node_path,runtime_path):
    if output.exists():raise ValueError('fresh-public-kernel-output')
    output.mkdir(parents=True)
    rt=runtime(runtime_path)
    rows=[];cases=[]
    for n in (4,8,16,32):
        for mode in ('baseline','subtree'):
            for fault in FAULTS:
                case,metadata=kernel.fixture(n,mode,fault)
                rows.append(metadata);cases.append(case)
    # One pinned SDK process computes all IDs before official native serde.
    with rt.TrustedExecutable(node_path,NODE_SHA) as node:
        original_cases=json.loads(json.dumps(cases))
        result=node.run([HERE/'sdk.mjs'],input_text=json.dumps(cases))
        if result.returncode:raise ValueError('public-SDK-fixture-ID-preparation')
        cases=json.loads(result.stdout)
        if type(cases) is not list or len(cases)!=56 or len(original_cases)!=56:
            raise ValueError('complete-SDK-fixture-batch-required')
        for before,after in zip(original_cases,cases):
            before['transaction']['id']=after['transaction']['id']
            if (before!=after or type(after['transaction']['id']) is not str
                    or len(after['transaction']['id'])!=64
                    or any(c not in '0123456789abcdef' for c in after['transaction']['id'])):
                raise ValueError('SDK-may-change-only-recomputed-ID')
        write(output/'NODE-RUNTIME.json',node.receipt())
    for index,(case,row) in enumerate(zip(cases,rows)):
        case['transaction']['inputs'][0]['sequence']=int(case['transaction']['inputs'][0]['sequence'])
        row['SDK_transaction_id_recomputed']=True
        target=output/f'case-{index:03d}'
        write(target/'case.json',case);write(target/'fixture.json',row)
    native=rt.TrustedExecutable(native_path,NATIVE_SHA)
    write(output/'NATIVE-RUNTIME.json',native.receipt())
    def evaluate(index):
        case_dir=output/f'case-{index:03d}';started=time.monotonic()
        completed=native.run(['validate-transaction',case_dir/'case.json',case_dir/'native'])
        if completed.returncode:raise ValueError('native-process-failed')
        report=json.loads((case_dir/'native/native-validation.json').read_bytes())
        metrics=json.loads((case_dir/'native/metrics.json').read_bytes())
        engine=report['per_input_ScriptEngine'][0]
        accepted=(report.get('isolation')=='PASS' and report['Full'].get('accepted') is True
            and report.get('all_input_engines_accepted') is True and len(report['per_input_ScriptEngine'])==1
            and engine['input_index']==0 and engine['accepted'] is True)
        expected=rows[index]['expected_native_acceptance']
        guarded_rejection=(report.get('isolation')=='PASS' and report['Full'].get('accepted') is False
            and report['Full'].get('typed_error')=='SignatureInvalid(VerifyError)'
            and engine['accepted'] is False and engine.get('typed_error')=='VerifyError')
        return {**rows[index],'actual_Full_and_engine_acceptance':accepted,
            'expected_verdict_matches':accepted if expected else guarded_rejection,
            'actual_engine_accepted':engine['accepted'],'native_units':engine['units'],
            'native_typed_error':engine.get('typed_error'),'Full':report['Full'],
            'metrics':metrics,'native_wall_seconds':time.monotonic()-started,
            'case_sha256':sha((case_dir/'case.json').read_bytes()),
            'native_report_sha256':sha((case_dir/'native/native-validation.json').read_bytes())}
    try:
        with ThreadPoolExecutor(max_workers=4) as executor:results=list(executor.map(evaluate,range(len(cases))))
    finally:native.close()
    positive=[row for row in results if row['fault']=='positive']
    for n in (4,8,16,32):
        pair=[row for row in positive if row['n']==n]
        if len(pair)!=2 or pair[0]['old_root']!=pair[1]['old_root'] or pair[0]['new_root']!=pair[1]['new_root']:
            raise ValueError('identical-tree-transition-comparison')
    summary={'schema':'kpx-compact-cm-native-kernel-results/v1','classification':'PUBLIC_UNFUNDED_MERKLE_KERNEL_ONLY',
        'cases':results,'case_count':len(results),'expected_verdicts_match':all(row['expected_verdict_matches'] for row in results),
        'positive_native_Full_and_engine_acceptances':sum(row['actual_Full_and_engine_acceptance'] for row in positive),
        'negative_cases':len(results)-len(positive),'public_SDK_IDs_recomputed':True,
        'same_input_amount_outpoint_DAA_and_tree_transition_per_positive_pair':True,
        'locking_script_hash_differs_because_compared_programs_differ':True,
        'budget512_is_generous_component_test_budget_not_payment_budget':True,
        'financial_authorization_nullifier_ownership_conservation_or_Groth16_tested':False,
        'whole_policy_fee_qualification':False,'source_hashes':{name:sha((HERE/name).read_bytes()) for name in ['kernel.py','sdk.mjs','harness.py']},
        'actual_PK_seed_setup_proof_funding_or_RPC_operations':0,'DO_NOT_FUND':True}
    write(output/'RESULTS.json',summary)
    return {'cases':len(results),'expected_verdicts_match':summary['expected_verdicts_match'],
        'positive_native_acceptances':summary['positive_native_Full_and_engine_acceptances'],
        'RESULTS_sha256':sha((output/'RESULTS.json').read_bytes())}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path);parser.add_argument('--native',type=Path,required=True)
    parser.add_argument('--node',type=Path,required=True);parser.add_argument('--runtime-source',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(run(args.output,args.native,args.node,args.runtime_source),sort_keys=True))
