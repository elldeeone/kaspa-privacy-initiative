#!/usr/bin/env python3
"""Read-only fixed Full-prefix replay and typed current-entry/payout handoff.

This adapter has no submission method. An ambiguous prior submission is resolved
only by fetching the same expected transaction ID through this path. Financial
acceptance is provided by the unchanged fixed replay, not by a JSON status flag.
"""
import argparse
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'poc/owner-private-lifecycle/bootstrap'))
from gn3_common import digest,encoded,fields,hx,need,parse,write_new
from gn3_runtime import GENERIC,Runtime,SDK_DIR,SDK_PINS
from gn3_selection import decode
from paths import HostPolicy
from replay import SOURCES,decimals,replay,source_modules

HERE=Path(__file__).resolve().parent
PRIVATE=Path('/var/tmp/kpi-owner-private-lifecycle-01/private')


def point_key(value):
    fields(value,{'transactionId','index'},'exact-observed-point')
    hx(value['transactionId'],32)
    need(type(value['index']) is int and 0<=value['index']<1<<32,'observed-point-index')
    return value['transactionId']+value['index'].to_bytes(4,'little').hex()


def typed_entry(row):
    fields(row,{'outpoint','amount_sompi','script_public_key','block_daa_score',
                'is_coinbase','covenant_id'},'complete-current-entry')
    point_key(row['outpoint']);hx(row['script_public_key'])
    need(row['is_coinbase'] is False and row['covenant_id'] is None,
         'noncoinbase-null-covenant-current-entry')
    return {'outpoint':row['outpoint'],'entry':{
        'amount':decimals(row['amount_sompi']),'scriptPublicKey':row['script_public_key'],
        'blockDaaScore':decimals(row['block_daa_score']),'isCoinbase':False,'covenantId':None}}


def derive_observation(fetch,history,checkpoint,report,selection,expected_txid,public):
    """Convert outputs of this adapter's just-completed fixed replay.

    Pure conversion controls test this function separately; calling it alone
    never establishes that supplied objects were accepted by native consensus.
    """
    hx(expected_txid,32)
    rows=fetch['transactions']
    need(rows and rows[-1]['transaction']['id']==expected_txid,
         'expected-accepted-transaction-must-be-current-transition')
    need(report['current_checkpoint']==checkpoint==history['head'],
         'fixed-replay-history-checkpoint-agreement')
    queries={}
    for row in fetch['current_view']['queries']:
        key=point_key(row['outpoint'])
        need(key not in queries and row['queried'] is True,'unique-complete-exact-query')
        queries[key]=row
    for row in rows:
        for item in row['transaction']['inputs']:
            query=queries.get(point_key(item['previousOutpoint']))
            need(query is not None and query['entry'] is None,'accepted-input-must-be-spent')
    payout_observations=[]
    for payout in report['payouts']:
        at={'transactionId':payout['transaction_id'],'index':payout['output_index']}
        key=point_key(at);query=queries.get(key)
        need(query is not None and query['entry'] is not None,'every-native-payout-must-be-observed')
        value=typed_entry(query['entry'])
        need(value['outpoint']==at and value['entry']['amount']==payout['payout_sompi']
             and value['entry']['scriptPublicKey']==payout['script_public_key'],
             'exact-native-payout-value-destination-and-outpoint')
        payout_observations.append(value)
    if checkpoint['outpoint_hex36'] is None:
        need(checkpoint['reserve_sompi']==0 and fetch['terminal_candidate_not_yet_replay_verified'] is True,
             'explicit-terminal-zero-reserve')
        current=None
    else:
        need(checkpoint['reserve_sompi']>0,'nonterminal-positive-reserve')
        key=checkpoint['outpoint_hex36'];hx(key,36)
        query=queries.get(key)
        need(query is not None and query['entry'] is not None,'actual-current-reserve-query-required')
        current=typed_entry(query['entry'])
        need(point_key(current['outpoint'])==key,'exact-current-reserve-point')
        public.current_entry_context(history,selection.tail.hex(),current)
    return current,payout_observations


def confirm(a):
    hx(a.expected_transaction_id,32)
    guard=HostPolicy(a.exclude_old_trial,a.exclude_private_directory)
    need(PRIVATE in guard.new_directories,'whole-selected-private-parent-must-be-excluded')
    names=('selection','descriptor','parameters','sessions','source_pins')
    runtime_paths={name:getattr(a,name.replace('-','_')) for name in GENERIC
                   if getattr(a,name.replace('-','_')) is not None}
    actual_runtime={name:runtime_paths.get(name,default) for name,(default,_) in GENERIC.items()}
    sdk=a.sdk_directory or SDK_DIR
    fixed_js=[HERE/name for name in ('wire.mjs','json.mjs','selection.mjs','acquire.mjs',
                                     'fetch.mjs','verify_bundle.mjs')]
    guard.guard([*(getattr(a,name) for name in names),a.codec,*actual_runtime.values(),
                 *(sdk/name for name in SDK_PINS),*(ROOT/name for name in SOURCES),*fixed_js])
    raw={name:guard.read(getattr(a,name),getattr(a,name+'_sha256')) for name in names}
    selection=decode(raw['selection'],a.selection_sha256)
    output=Path(a.output).absolute()
    need(not output.exists() and all(not output.is_relative_to(p) for p in guard.directories),
         'fresh-public-confirmation-stage')
    output.mkdir(parents=True,mode=0o700)
    started=time.monotonic();runtime=Runtime(paths=runtime_paths,sdk_dir=sdk)
    fetch_dir=output/'prefix';fetch_args=[HERE/'fetch.mjs',a.selection,a.selection_sha256,
        a.descriptor,a.descriptor_sha256,fetch_dir,'--sdk-dir',runtime.sdk_dir]
    for endpoint in a.rpc:fetch_args+=['--rpc',endpoint]
    result=runtime.executables['node'].run(fetch_args,allow_failure=True)
    need(result.returncode==0,'read-only-full-prefix-acquisition-incomplete')
    fetch_file=fetch_dir/'fetch.json';raw_fetch=guard.read(fetch_file);fetch_sha=digest(raw_fetch)
    fetched_at=time.monotonic()
    report=replay(raw['selection'],a.selection_sha256,raw['descriptor'],a.descriptor_sha256,
        raw_fetch,fetch_sha,fetch_dir,raw['parameters'],a.parameters_sha256,a.codec,a.codec_sha256,
        raw['sessions'],a.sessions_sha256,raw['source_pins'],a.source_pins_sha256,output/'replay',
        runtime_paths=runtime_paths,sdk_directory=runtime.sdk_dir)
    paths={name:output/'replay'/name for name in ('HISTORY.json','CHECKPOINT.json','RESULTS.json')}
    guard.guard(paths.values());produced={name:guard.read(path) for name,path in paths.items()}
    history=parse(produced['HISTORY.json']);checkpoint=parse(produced['CHECKPOINT.json'])
    need(report==parse(produced['RESULTS.json'])
         and digest(produced['HISTORY.json'])==report['history_sha256'],'fixed-replay-output-identity')
    public=source_modules(raw['source_pins'],a.source_pins_sha256)
    fetch=parse(raw_fetch)
    current,payouts=derive_observation(fetch,history,checkpoint,report,selection,
                                      a.expected_transaction_id,public)
    current_file=output/'CURRENT-ENTRY.json';current_raw=encoded(current)+b'\n'
    write_new(current_file,current_raw,0o400)
    selectors={name:{'path':str(path),'sha256':digest(produced[name])} for name,path in paths.items()}
    selectors['fetch.json']={'path':str(fetch_file),'sha256':fetch_sha}
    selectors['CURRENT-ENTRY.json']={'path':str(current_file),'sha256':digest(current_raw)}
    for name in names:
        selectors[name]={'path':str(getattr(a,name)),'sha256':getattr(a,name+'_sha256')}
    pages=[*fetch['pages'],*fetch['current_view']['post_query_delta']['pages']]
    handoff={'schema':'kpx8-confirmed-transition-handoff/v1',
        'status':'RECORDED_VALIDATING_NODE_PREFIX_FINANCIAL_AND_NATIVE_PASS',
        'trial_id':parse(raw['descriptor'])['trial_id'],'financial_profile_sha256':selection.profile_sha256,
        'expected_transaction_id':a.expected_transaction_id,'accepted_transactions':len(fetch['transactions']),
        'checkpoint':checkpoint,'terminal':current is None,'native_payouts_observed':payouts,
        'selectors':selectors,'full_prefix_pages':[{'path':str(fetch_dir/p['path']),
            'sha256':p['gzip_sha256'],'bytes':p['gzip_bytes']} for p in pages],
        'fetch_wall_seconds':fetched_at-started,'total_wall_seconds':time.monotonic()-started,
        'observed_total_fee_sompi':report['observed_total_fee_sompi'],
        'automatic_resubmission_permitted':False,'submission_performed':False,
        'independent_consensus_or_continuous_currentness':False}
    write_new(output/'HANDOFF.json',encoded(handoff)+b'\n',0o400)
    return handoff


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('selection','descriptor','parameters','sessions','source-pins'):
        p.add_argument('--'+name,type=Path,required=True);p.add_argument('--'+name+'-sha256',required=True)
    for name in ('codec','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--codec-sha256',required=True);p.add_argument('--expected-transaction-id',required=True)
    for name in ('crypto','node','native-validator','sdk-directory'):p.add_argument('--'+name,type=Path)
    p.add_argument('--rpc',action='append',default=[])
    p.add_argument('--exclude-old-trial',type=Path,action='append',required=True)
    p.add_argument('--exclude-private-directory',type=Path,action='append',required=True)
    try:
        a=p.parse_args();value=confirm(a)
        print(encoded({'status':value['status'],'output':str(a.output),
            'expected_transaction_id':value['expected_transaction_id'],'checkpoint':value['checkpoint']}).decode())
    except (ValueError,OSError,KeyError,TypeError):p.exit(2,'read-only confirmation incomplete; never retransmit\n')
