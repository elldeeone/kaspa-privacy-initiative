#!/usr/bin/env python3
"""Read-only full retained prefix, exact native replay and payout confirmation."""
import argparse
from pathlib import Path
from types import SimpleNamespace
import time
from replay import HERE,BASE,integer_boundary,native_case,replay,runtime_from
import sys
sys.path.insert(0,str(BASE/'bootstrap'))
from gn3_common import digest,encoded,hx,need,parse,write_new
from gn3_runtime import Runtime
from paths import HostPolicy


def confirm(a):
    started=time.monotonic();guard=HostPolicy();hx(a.expected_transaction_id,32)
    expected_case=parse(guard.read(a.expected_case,a.expected_case_sha256))
    need(expected_case['transaction']['id']==a.expected_transaction_id,'expected-CASE-ID-binding')
    output=Path(a.output);need(not output.exists(),'fresh-confirmation-output');output.mkdir(parents=True,mode=0o700)
    runtime=runtime_from(a);fetch_dir=output/'prefix'
    command=[HERE/'fetch.mjs',a.selection,a.selection_sha256,a.descriptor,a.descriptor_sha256,fetch_dir,'--sdk-dir',runtime.sdk_dir]
    for endpoint in a.rpc:command += ['--rpc',endpoint]
    runtime.executables['node'].run(command)
    raw=guard.read(fetch_dir/'fetch.json');fetch=parse(raw);fetch_sha=digest(raw)
    matching=[row for row in fetch['transactions'] if row['transaction']['id']==a.expected_transaction_id]
    need(len(matching)==1,'expected-whole-transaction-not-in-confirmed-accepted-prefix')
    need(native_case(matching[0])==expected_case,'accepted-whole-CASE-witness-budget-context-differs-from-submitted')
    replay_args=SimpleNamespace(**{**vars(a),'fetch':fetch_dir/'fetch.json','fetch_sha256':fetch_sha,
        'bundle_directory':fetch_dir,'output':output/'replay'})
    result=replay(replay_args)
    queries={q['outpoint']['transactionId']+q['outpoint']['index'].to_bytes(4,'little').hex():q for q in fetch['current_view']['queries']}
    payouts=[]
    for row in fetch['transactions'][1:]:
        case=native_case(row);body=case['transaction'];payload=hx(body['payload'])
        if payload[:8]!=b'KPXAXB01':continue
        paid=body['outputs'][-1];at=body['id']+(len(body['outputs'])-1).to_bytes(4,'little').hex()
        query=queries.get(at);need(query is not None and query['entry'] is not None,'actual-native-payout-UTXO-observation-required')
        actual=query['entry'];need(integer_boundary(actual['amount_sompi'])==paid['value']
             and actual['script_public_key']==paid['scriptPublicKey'],'exact-native-payout-value-destination-and-point')
        payouts.append(actual)
    selectors={}
    for name in ('HISTORY.json','CONTEXT.json','CURRENT-ENTRY.json','RESULTS.json'):
        path=output/'replay'/name;member=guard.read(path);selectors[name]={'path':str(path),'sha256':digest(member)}
    selectors['fetch.json']={'path':str(fetch_dir/'fetch.json'),'sha256':fetch_sha}
    handoff={'schema':'kpxa-confirmed-transition-handoff/v1','status':result['status'],
        'expected_transaction_id':a.expected_transaction_id,'expected_case_sha256':a.expected_case_sha256,
        'accepted_whole_CASE_equals_expected':True,'trial_id':result['trial_id'],
        'accepted_transactions':result['accepted_transactions'],'checkpoint':result['current_checkpoint'],
        'terminal':result['terminal'],'native_payouts_observed':payouts,'selectors':selectors,
        'observed_total_fee_sompi':result['observed_total_fee_sompi'],'wall_seconds':time.monotonic()-started,
        'transport':'TOR_SOCKS5H_TLS','submission_performed':False,'automatic_resubmission_permitted':False,
        'independent_consensus_or_continuous_currentness':False}
    write_new(output/'HANDOFF.json',encoded(handoff)+b'\n',0o400);return handoff

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('selection','descriptor','assets','parameters'):
        p.add_argument('--'+name,type=Path,required=True);p.add_argument('--'+name+'-sha256',required=True)
    for name in ('codec','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--codec-sha256',required=True);p.add_argument('--expected-transaction-id',required=True)
    p.add_argument('--expected-case',type=Path,required=True);p.add_argument('--expected-case-sha256',required=True)
    p.add_argument('--rpc',action='append',default=[])
    for name in ('crypto','node','native-validator','sdk-directory'):p.add_argument('--'+name,type=Path)
    try:
        a=p.parse_args();value=confirm(a)
        print(encoded({'status':value['status'],'output':str(a.output),'checkpoint':value['checkpoint']}).decode())
    except (ValueError,OSError,KeyError,TypeError):p.exit(2,'read-only confirmation incomplete; never retransmit\n')
