#!/usr/bin/env python3
"""Copy one exact selected cold result into the trial; no other owner files."""
import argparse
import json
from pathlib import Path

import phase


def copy(trial,body_path,context_path,report_path,diagnostic_path,output):
    phase.selected();t,_,p=phase.helpers();trial=t.outside_git(trial)
    phase.require(phase.digest((trial/'public/identity.json').read_bytes())==phase.IDENTITY_SHA,
                  'selected-trial-public-identity')
    files=(body_path,context_path,report_path,diagnostic_path)
    for file in files:t.no_symlinks(file.absolute())
    raw=[file.read_bytes() for file in files];body,contexts,report,diagnostic=map(phase.parse,raw)
    phase.require(set(diagnostic)=={'public_native_request','returncode','stdout','stderr'}
        and diagnostic['returncode']==0,'selected-cold-native-verify-diagnostic')
    request=diagnostic['public_native_request'];verified=phase.parse(diagnostic['stdout'])
    phase.require(request['mode']=='verify' and verified['verified'] is True
        and verified['transaction']==body and verified['supplied_context']==contexts
        and verified['native_validation']==report and request['expected_quote_id']==verified['quote_id']
        and report['Full']['accepted'] is True and report['all_input_engines_accepted'] is True,
        'exact-selected-cold-body-context-Full-and-quote-binding')
    payload=bytes.fromhex(body['payload']);frame=bytes.fromhex(body['inputs'][0]['signatureScript'])
    phase.require(len(payload)==4400 and payload[:8]==b'KPX3AU01'
        and payload[8:40].hex()==phase.selected()['domain_hex32']
        and payload==(bytes.fromhex(request['auth_hex528'])+bytes.fromhex(request['cipher_hex528'])
                        +bytes.fromhex(request['public_witness_hex3344']))
        and frame[68:196].hex()==request['proof_hex128'] and frame[199:].hex()==request['current_redeem_hex']
        and len(contexts)==1 and contexts[0]==request['supplied_utxo']
        and body['inputs'][0]['previousOutpoint']==request['previous_outpoint'],
        'selected-cold-public-request-is-this-complete-body')
    phase.require(all(row==p.context_entry(int(row['amount_sompi']),row['script_public_key'],row['block_daa_score'])
        for row in contexts),'selected-cold-strict-contexts')
    output=t.outside_git(output);phase.require(trial in output.parents and not output.exists(),
                                              'fresh-selected-stage-copy-inside-trial')
    p.mkdir(output)
    for name,data in zip(('transaction.json','supplied-context.json','native-validation.json'),raw[:3]):
        t.private_write(output/name,data)
    entries=[{'amount':int(row['amount_sompi']),'scriptPublicKey':row['script_public_key'],
        'blockDaaScore':int(row['block_daa_score']),'isCoinbase':False,'covenantId':None} for row in contexts]
    t.private_write(output/'validation-case.json',t.encoded({'transaction':body,'entries':entries}))
    return {'selected_body_copy':str(output/'transaction.json'),'transaction_id':body['id'],
        'body_sha256':phase.digest(raw[0]),'selected_native_binding_checked':True,
        'private_witness_backup_profile_PK_or_other_attempt_files_read':False,
        'RPC_VM_proof_or_broadcast':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('trial',type=Path)
    for name in ('body','contexts','native-report','verify-diagnostic','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(copy(args.trial,args.body,args.contexts,args.native_report,args.verify_diagnostic,args.output),sort_keys=True))
