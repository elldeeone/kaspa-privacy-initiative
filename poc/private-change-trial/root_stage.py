#!/usr/bin/env python3
"""Root-only data staging. No seed/profile-secret read, VM, RPC or submission."""
import argparse
import json
from pathlib import Path

import phase

STAGES=('founding','initial-payment','partial-cashout','change-payment','full-cashout','terminal-cashout')
RPC='wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh'
GENERIC='077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061'
HELPER='f6139cea85a30f092447efe199796f62c540b0399d63e949845423678d4bdc44'


def read(path):return phase.parse(path.read_bytes())


def stage(trial,label,body_path,context_path,report_path,case_path,genesis_path,start,output,native_sha):
    phase.selected();t,_,p=phase.helpers();trial=t.outside_git(trial)
    profile=trial/'public/identity.json';phase.require(phase.digest(profile.read_bytes())==phase.IDENTITY_SHA,'selected-public-identity')
    for file in (body_path,context_path,report_path,case_path):t.no_symlinks(file.absolute())
    phase.require(trial in body_path.resolve().parents and label in STAGES,'body-inside-selected-trial')
    raw=body_path.read_bytes();body=phase.parse(raw);contexts=read(context_path);report=read(report_path)
    phase.require(len(body['inputs'])==len(contexts)==1 and body['inputs'][0]['sequence']==(1<<64)-1,
                  'single-unlocked-stage-input')
    phase.require(all(row==p.context_entry(int(row['amount_sompi']),row['script_public_key'],row['block_daa_score'])
        for row in contexts),'strict-stage-contexts')
    entries=[{'amount':int(row['amount_sompi']),'scriptPublicKey':row['script_public_key'],
        'blockDaaScore':int(row['block_daa_score']),'isCoinbase':False,'covenantId':None} for row in contexts]
    phase.require(read(case_path)=={'transaction':body,'entries':entries},'exact-native-case-body-context')
    phase.require(report['Full']['accepted'] is True and report['all_input_engines_accepted'] is True
        and len(report['per_input_ScriptEngine'])==1
        and all(row['accepted'] is True for row in report['per_input_ScriptEngine'])
        and report['Full']['fee_sompi']==sum(int(row['amount_sompi']) for row in contexts)
            -sum(row['value'] for row in body['outputs']),'existing-exact-Full-all-input-engines-fee')
    phase.require(native_sha in (GENERIC,HELPER),'selected-native-binary-sha')
    phase.require(len(bytes.fromhex(start))==32 and bytes.fromhex(start).hex()==start,'birth-checkpoint')
    output=t.outside_git(output);phase.require(trial in output.parents and not output.exists(),'fresh-private-stage-output')
    p.mkdir(output)
    def save(name,value):
        path=output/name;t.private_write(path,t.encoded(value));return path,phase.digest(path.read_bytes())
    check={'body_sha256':phase.digest(raw),'transaction_id':body['id'],'profile_sha256':phase.IDENTITY_SHA,
        'native_binary_sha256':native_sha,'native_full_accepted':True,'all_input_engines_accepted':True,
        'inputs':[dict(row,outpoint=body['inputs'][i]['previousOutpoint']) for i,row in enumerate(contexts)]}
    if label=='founding':
        phase.require(genesis_path is not None and native_sha==GENERIC,'GN-generic-Full-and-genesis-required')
        genesis=read(genesis_path);redeem=bytes.fromhex(genesis['redeem_hex'])
        phase.require(len(redeem)==24417 and redeem[10:42].hex()==phase.selected()['domain_hex32']
            and p.pool_spk(redeem)==body['outputs'][0]['scriptPublicKey']
            and genesis['payload_hex536']==body['payload']
            and int(genesis['reserve_sompi'])==body['outputs'][0]['value'],'exact-GN-output-policy-payload')
        check['output0_redeem_hex']=redeem.hex()
    check_path,check_sha=save('local-check.json',check)
    adapter=phase.ROOT/'poc/private-change-trial/adapter.mjs';safe=adapter.with_name('native_safe.py')
    release={'authorization':'TN10_FRESH_TRIAL_REHEARSAL','profile_sha256':phase.IDENTITY_SHA,
        'network':'testnet-10','genesis':phase.GENESIS,'rpc_url':RPC,'trial_directory':str(trial),
        'allowed_stages':[label],'adapter_sha256':phase.digest(adapter.read_bytes()),
        'native_safe_sha256':phase.digest(safe.read_bytes()),'native_binary_sha256':native_sha,
        'bodies':{label:{'transaction_id':body['id'],'body_sha256':phase.digest(raw),'local_check_sha256':check_sha}}}
    release_path,release_sha=save('release.json',release)
    request={'op':'submit-once','stage':label,'rpc_url':RPC,'profile_path':str(profile),'trial_dir':str(trial),
        'body_path':str(body_path.resolve()),'context_path':str(context_path.resolve()),
        'local_check_path':str(check_path),'release_path':str(release_path),
        'release_sha256':release_sha,'start_hash':start}
    submit,submit_sha=save('submit-request.json',request)
    observe=dict(request,op='observe',min_confirmations=20)
    observe_path,observe_sha=save('observe-request.json',observe)
    return {'stage':label,'transaction_id':body['id'],'release_path':str(release_path),
        'release_sha256':release_sha,'submit_request':str(submit),'submit_request_sha256':submit_sha,
        'observe_request':str(observe_path),'observe_request_sha256':observe_sha,
        'submission_or_RPC_or_VM_performed':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trial',type=Path);parser.add_argument('--stage',choices=STAGES,required=True)
    for name in ('body','contexts','native-report','native-case','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--genesis',type=Path);parser.add_argument('--start-hash',required=True)
    parser.add_argument('--native-sha',choices=(GENERIC,HELPER),default=GENERIC)
    args=parser.parse_args()
    print(json.dumps(stage(args.trial,args.stage,args.body,args.contexts,args.native_report,args.native_case,
        args.genesis,args.start_hash,args.output,args.native_sha),sort_keys=True))
