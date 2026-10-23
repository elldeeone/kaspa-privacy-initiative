#!/usr/bin/env python3
"""Export only the exact reviewed signed prefix and public verification data."""
import argparse
import hashlib
import json
from pathlib import Path

import prepare as p
import prefix_stage as s
import run_local as local
import trial as t

REPORT_KEYS={'Full','ScriptEngine','all_input_engines_accepted','isolation','per_input_ScriptEngine'}
ENGINE_KEYS={'accepted','allowed_script_units','input_index','units'}
DESC_KEYS={'schema','network_id','genesis_hash_hex','domain_hex32','founding_outpoint',
           'birth_start_hash','initial_redeem_hex','vk_hex328','immutable_policy_sha256',
           'public_params_manifest_sha256'}


def export(closed,prefix,founding_result,payment_result,output):
    local.pin_packet(closed,s.LOCAL_SHA)
    t.require(not output.exists(),'fresh-prefix-public-output')
    selected=[]
    for index,(name,result) in enumerate((('founding',founding_result),('payment',payment_result))):
        prepared=prefix/(name+'-prepared')
        body_raw=(prepared/'transaction.json').read_bytes();body=t.parse_json(body_raw)
        t.require(body_raw==(closed/f'case-{index:04d}/transaction.json').read_bytes(),
                  'exact-closed-signed-prefix-body')
        contexts=p.read(prepared/'supplied-context.json');old=p.read(closed/f'case-{index:04d}/supplied-context.json')
        t.require(len(contexts)==len(old)==1,'single-prefix-input-context')
        wanted=dict(old[0],block_daa_score=contexts[0]['block_daa_score'])
        t.require(contexts==[wanted] and contexts[0]==p.context_entry(int(wanted['amount_sompi']),
            wanted['script_public_key'],wanted['block_daa_score']) and int(wanted['block_daa_score'])>0,
            'exact-public-DAA-only-context')
        report=p.read(result/'native-validation.json')
        t.require(set(report)==REPORT_KEYS and set(report['Full'])=={'accepted','fee_sompi'}
            and report['Full']['accepted'] is True and type(report['Full']['fee_sompi']) is int
            and report['all_input_engines_accepted'] is True and report['isolation']=='PASS'
            and len(report['per_input_ScriptEngine'])==1,'public-prefix-native-report')
        for engine in [report['ScriptEngine'],*report['per_input_ScriptEngine']]:
            t.require(set(engine)==ENGINE_KEYS and engine['accepted'] is True
                and engine['input_index']==0
                and all(type(engine[key]) is int and engine[key]>=0
                    for key in ('allowed_script_units','input_index','units')),'public-native-engine-fields')
        t.require(report['Full']['fee_sompi']==sum(int(row['amount_sompi']) for row in contexts)
            -sum(row['value'] for row in body['outputs'])
            and report['ScriptEngine']==report['per_input_ScriptEngine'][0],
            'public-prefix-fee-and-engine-binding')
        check=p.read(result/'local-check.json')
        keys={'body_sha256','transaction_id','profile_sha256','native_binary_sha256',
              'native_full_accepted','all_input_engines_accepted','inputs'}
        if index==0:keys.add('output0_redeem_hex')
        t.require(set(check)==keys and check['body_sha256']==t.digest(body_raw)
            and check['transaction_id']==body['id'] and check['native_binary_sha256']==p.GENERIC_SHA
            and check['native_full_accepted'] is True and check['all_input_engines_accepted'] is True
            and check['inputs']==[dict(contexts[0],outpoint=body['inputs'][0]['previousOutpoint'])]
            and len(bytes.fromhex(check['profile_sha256']))==32,'exact-public-localcheck')
        selected.extend((prepared/'transaction.json',prepared/'supplied-context.json',
                         result/'native-validation.json',result/'local-check.json'))
    descriptor=p.read(prefix/'public-descriptor.json')
    t.require(set(descriptor)==DESC_KEYS and descriptor['schema']=='kpx3-private-network-descriptor/v1'
        and descriptor['network_id']=='testnet-10' and descriptor['genesis_hash_hex']==t.GENESIS
        and descriptor['public_params_manifest_sha256']==local.PARAMETERS_SHA,
        'exact-public-descriptor-fields')
    redeem=bytes.fromhex(descriptor['initial_redeem_hex'])
    t.require(len(redeem)==24417 and redeem[10:42].hex()==descriptor['domain_hex32']
        and t.digest(redeem[114:])==descriptor['immutable_policy_sha256']
        and descriptor['founding_outpoint']=={'transactionId':p.read(closed/'case-0000/transaction.json')['id'],'index':0}
        and redeem.hex()==p.read(founding_result/'local-check.json')['output0_redeem_hex'],
        'exact-public-descriptor-initial-program')
    selections=[]
    for stage,name,result in (('founding','founding',founding_result),
                              ('private-payment','payment',payment_result)):
        release_path=prefix/(name+'-release.json');request_path=prefix/(name+'-submit-request.json')
        release=p.read(release_path);request=p.read(request_path);check=p.read(result/'local-check.json')
        t.require(release['allowed_stages']==[stage] and release['network']=='testnet-10'
            and release['genesis']==t.GENESIS and release['rpc_url']==s.RPC
            and release['authorization']=='TN10_FRESH_TRIAL_REHEARSAL'
            and release['native_binary_sha256']==p.GENERIC_SHA
            and release['bodies']=={stage:{'transaction_id':check['transaction_id'],
                'body_sha256':check['body_sha256'],'local_check_sha256':t.digest((result/'local-check.json').read_bytes())}}
            and request['op']=='submit-once' and request['stage']==stage and request['rpc_url']==s.RPC
            and request['release_sha256']==t.digest(release_path.read_bytes())
            and request['start_hash']==descriptor['birth_start_hash'],
            'exact-prefix-release-request-binding')
        receipt=p.read(result/'EXECUTION-RECEIPT.json')
        t.require(receipt['successful_launch_returncode']==0 and receipt['network']=='unshared'
            and receipt['body_changed'] is False and receipt['funding_or_broadcast'] is False,
            'successful-bounded-prefix-native-runtime')
        safe={'schema':'kpx3-public-prefix-authorization-selection/v1','stage':stage,
            'original_release_sha256':t.digest(release_path.read_bytes()),
            'original_request_sha256':t.digest(request_path.read_bytes()),
            'release_selection':{key:release[key] for key in ('authorization','profile_sha256',
                'network','genesis','rpc_url','allowed_stages','adapter_sha256','native_safe_sha256',
                'native_binary_sha256','bodies')},
            'request_selection':{key:request[key] for key in ('op','stage','rpc_url','start_hash','release_sha256')},
            'private_filesystem_paths_omitted':True}
        runtime={'schema':'kpx3-public-prefix-native-runtime-selection/v1','stage':stage,
            'original_receipt_sha256':t.digest((result/'EXECUTION-RECEIPT.json').read_bytes()),
            'original_runtime_freeze_sha256':receipt['runtime_freeze_sha256'],
            'successful_invocation_id':receipt['successful_invocation_id'],
            'successful_launch_returncode':receipt['successful_launch_returncode'],
            'network':'unshared','ordinary_systemd_env_i_bwrap_launch':True,
            'requested_CPUQuota':receipt['requested_CPUQuota'],
            'requested_MemoryMax':receipt['requested_MemoryMax'],
            'requested_MemorySwapMax':receipt['requested_MemorySwapMax'],
            'active_resource_usage_sampled':receipt['active_resource_usage_sampled'],
            'native_binary_sha256':p.GENERIC_SHA,'body_changed':False,'broadcast':False,
            'initial_launcher_attempt_failed_before_VM':stage=='founding',
            'private_filesystem_paths_omitted':True}
        selections.append((safe,runtime))
    output.mkdir(parents=True)
    for index,source in enumerate(selected):
        destination=output/f'case-{index//4:04d}'/source.name
        destination.parent.mkdir(exist_ok=True)
        with destination.open('xb') as file:file.write(source.read_bytes())
    with (output/'public-descriptor.json').open('xb') as file:file.write((prefix/'public-descriptor.json').read_bytes())
    for index,(authorization,runtime) in enumerate(selections):
        for name,value in (('authorization-selection.json',authorization),('runtime-selection.json',runtime)):
            with (output/f'case-{index:04d}'/name).open('x') as file:
                json.dump(value,file,indent=2,sort_keys=True);file.write('\n')
    (output/'source').mkdir()
    for name in ('prefix_stage.py','prefix_packet.py'):
        with (output/'source'/name).open('xb') as file:file.write(Path(__file__).with_name(name).read_bytes())
    files=[]
    for file in sorted(path for path in output.rglob('*') if path.is_file()):
        raw=file.read_bytes();files.append({'path':str(file.relative_to(output)),
            'bytes':len(raw),'sha256':t.digest(raw)})
    manifest={'schema':'kpx3-public-prefix-allowlist/v1','files':files,
        'exporter_source_sha256':t.digest(Path(__file__).read_bytes()),
        'closed_local_allowlist_sha256':s.LOCAL_SHA,'exact_signed_prefix_bodies':2,
        'actual_context_native_Full_checks':2,'chain_observations_included':False,
        'operator_exit_bodies_proofs_private_paths_or_witnesses_included':False,
        'privacy_fee_resource_or_independent_recovery_qualified':False}
    with (output/'FILE-ALLOWLIST.json').open('x') as file:json.dump(manifest,file,indent=2,sort_keys=True);file.write('\n')
    return {'public_files':len(files),'allowlist_sha256':t.digest((output/'FILE-ALLOWLIST.json').read_bytes())}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('closed','prefix','founding-result','payment-result','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(export(args.closed,args.prefix,args.founding_result,args.payment_result,args.output),sort_keys=True))
