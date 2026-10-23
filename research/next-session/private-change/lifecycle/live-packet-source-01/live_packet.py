#!/usr/bin/env python3
"""Export one confirmed selected transaction, then reconcile seven finite packets.

Only explicitly named public-type inputs are read. No directory discovery, keys,
backup, witness, operator alternative, RPC, VM, proving or signing operation.
Raw bodies are emitted only after exact accepted-body and durable-intent checks.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

import phase

STAGES=('ordinary-merge','founding','initial-payment','partial-cashout','change-payment','full-cashout','terminal-cashout')
GENERIC='077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061'
HELPER='f6139cea85a30f092447efe199796f62c540b0399d63e949845423678d4bdc44'
RPC='wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh'
MAX=2_870_000_000_000_000_000


def need(ok,code):
    if not ok:raise ValueError(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def hx(value,width=None):return type(value) is str and re.fullmatch('[0-9a-f]{'+str(width*2)+'}' if width else '(?:[0-9a-f]{2})*',value) is not None
def uint(value,limit=1<<64):return type(value) is int and 0<=value<limit
def decimal(value):return type(value) is str and re.fullmatch('0|[1-9][0-9]*',value) is not None and int(value)<1<<64
def point(value):return type(value) is dict and set(value)=={'transactionId','index'} and hx(value['transactionId'],32) and uint(value['index'],1<<32)
def spk(value):return type(value) is str and re.fullmatch('0000(?:20[0-9a-f]{64}ac|aa20[0-9a-f]{64}87)',value) is not None


def read(path):
    need(not any(x.is_symlink() for x in (path,*path.parents)),'input-symlink')
    raw=path.read_bytes();return raw,phase.parse(raw)


def body_types(body):
    need(type(body) is dict and set(body)=={'version','id','inputs','outputs','lockTime','subnetworkId','gas','payload','mass'}
        and body['version']==1 and body['lockTime']==body['gas']==0 and body['subnetworkId']=='00'*20
        and hx(body['id'],32) and hx(body['payload']) and len(body['payload']) in (0,1072,8800)
        and uint(body['mass']) and type(body['inputs']) is list and 1<=len(body['inputs'])<=3
        and type(body['outputs']) is list and 1<=len(body['outputs'])<=2,'strict-public-body')
    for row in body['inputs']:
        need(set(row)=={'previousOutpoint','signatureScript','sequence','computeBudget'} and point(row['previousOutpoint'])
            and row['sequence']==(1<<64)-1 and uint(row['computeBudget']) and hx(row['signatureScript'])
            and len(row['signatureScript']) in (132,49232),'strict-public-input')
    for row in body['outputs']:
        need(set(row)=={'value','scriptPublicKey','covenant'} and uint(row['value'],MAX+1) and row['value']>0
            and spk(row['scriptPublicKey']) and row['covenant'] is None,'strict-public-output')


def context_types(rows):
    need(type(rows) is list and rows,'strict-context-list')
    for row in rows:
        need(type(row) is dict and set(row)=={'amount_sompi','script_public_key','block_daa_score','is_coinbase','covenant_id'}
            and decimal(row['amount_sompi']) and 0<int(row['amount_sompi'])<=MAX
            and decimal(row['block_daa_score']) and spk(row['script_public_key'])
            and row['is_coinbase'] is False and row['covenant_id'] is None,'strict-public-context')


def canonical_body(body):
    result=dict(body);result['storageMass']=str(result.pop('mass'))
    result['lockTime']=str(result['lockTime']);result['gas']=str(result['gas'])
    result['inputs']=[dict(row,sequence=str(row['sequence'])) for row in result['inputs']]
    result['outputs']=[dict(row,value=str(row['value'])) for row in result['outputs']]
    return result


def full_body(body):
    # FullV2 carries additional public verbose fields. Only canonical transaction
    # fields below are reconstructed, checked, and ever eligible for output.
    rows=[]
    for row in body['inputs']:
        need(row.get('sigOpCount',0)==0,'v1-sigop-zero')
        rows.append({k:row[k] for k in ('previousOutpoint','signatureScript','sequence','computeBudget')})
    outputs=[]
    for row in body['outputs']:
        script=row['scriptPublicKey']
        if isinstance(script,dict):
            need(set(script)=={'version','script'} and script['version']==0,'v0-Full-script')
            script='0000'+script['script']
        outputs.append({'value':int(row['value']),'scriptPublicKey':script,'covenant':row.get('covenant')})
    result={k:body[k] for k in ('version','lockTime','subnetworkId','gas','payload')}
    result.update(id=body.get('verboseData',{}).get('transactionId',body.get('id')),inputs=rows,outputs=outputs,
        mass=int(body['storageMass'] if 'storageMass' in body else body['mass']))
    # SDK canonical strings are retained for u64 fields, as in native_safe.body.
    for row in result['inputs']:row['sequence']=int(row['sequence'])
    result['lockTime']=int(result['lockTime']);result['gas']=int(result['gas'])
    body_types(result);return canonical_body(result)


def header_types(header):
    need(type(header) is dict and set(header)=={'acceptedIdMerkleRoot','bits','blueScore','blueWork','daaScore','hash',
        'hashMerkleRoot','nonce','parentsByLevel','pruningPoint','timestamp','utxoCommitment','version'},'public-header-fields')
    for k in ('acceptedIdMerkleRoot','hash','hashMerkleRoot','pruningPoint','utxoCommitment'):need(hx(header[k],32),'public-header-hash')
    for k in ('blueScore','daaScore','nonce','timestamp'):need(decimal(header[k]),'public-header-u64')
    need(type(header['blueWork']) is str and re.fullmatch('[0-9a-f]+',header['blueWork']) is not None
        and uint(header['bits'],1<<32) and uint(header['version'],1<<16),'public-header-number')
    parents=header['parentsByLevel']
    need(type(parents) in (dict,list),'public-header-parents')
    levels=parents.values() if isinstance(parents,dict) else parents
    if isinstance(parents,dict):need(all(re.fullmatch('0|[1-9][0-9]*',k) for k in parents),'public-header-level')
    need(all(type(level) is list and all(hx(x,32) for x in level) for level in levels),'public-header-parent-hashes')


def native_types(native,contexts,body):
    need(set(native)=={'Full','ScriptEngine','all_input_engines_accepted','isolation','per_input_ScriptEngine'}
        and native['isolation']=='PASS' and native['all_input_engines_accepted'] is True
        and set(native['Full'])=={'accepted','fee_sompi'} and native['Full']['accepted'] is True
        and uint(native['Full']['fee_sompi'],MAX+1)
        and native['Full']['fee_sompi']==sum(int(x['amount_sompi']) for x in contexts)-sum(x['value'] for x in body['outputs'])
        and len(native['per_input_ScriptEngine'])==len(contexts)
        and native['ScriptEngine']==native['per_input_ScriptEngine'][0],'strict-Full-and-all-engines')
    for i,row in enumerate(native['per_input_ScriptEngine']):
        need(set(row)=={'accepted','allowed_script_units','input_index','units'} and row['accepted'] is True
            and row['input_index']==i and all(uint(row[k]) for k in ('allowed_script_units','input_index','units')),
            'strict-input-engine-fields')


def metrics_types(metrics,fee):
    ints={'actual_fee_sompi','compute_mass','estimated_bytes','mining_mass','relay_mass','storage_mass','transient_mass'}
    bools={'source_adapted_block_mass_caps','source_adapted_default_relay_fee','source_adapted_sigop_policy','standard_script_classes'}
    need(set(metrics)==ints|bools|{'P2SH_sigop_counts','quotes'} and all(uint(metrics[k]) for k in ints)
        and all(type(metrics[k]) is bool for k in bools) and metrics['actual_fee_sompi']==fee
        and type(metrics['P2SH_sigop_counts']) is list and all(uint(v) for v in metrics['P2SH_sigop_counts'])
        and type(metrics['quotes']) is list and len(metrics['quotes'])==3,'strict-official-metrics')
    for row,rate in zip(metrics['quotes'],(100,200,500)):
        need(set(row)=={'actual_sompi','passes','rate','required_sompi'} and row['rate']==rate
            and row['actual_sompi']==fee and row['required_sompi']==rate*metrics['mining_mass']
            and row['passes'] is (fee>=row['required_sompi']),'strict-official-fee-quotes')
    need(fee==100*metrics['mining_mass'],'selected-rate100-exact-fee')


def observation(value,body,contexts):
    cb=canonical_body(body);txid=body['id']
    need(value['transaction_id']==txid and value['accepted_body']==cb
        and value['accepted_body_sha256']==sha(json.dumps(value['accepted_body'],separators=(',',':'),ensure_ascii=False).encode()),
        'confirmed-exact-canonical-body')
    need(value['network']=='testnet-10' and value['expected_genesis']==phase.GENESIS
        and value['chain_delta_removed']==[] and value['post_query_related_spend_check'] is True,'confirmed-network-and-related-spend')
    header=value['accepting_block_header'];header_types(header)
    policy=value['confirmation_policy']
    need(set(policy)=={'accepting_blue_score','actual_blue_score_distance','comparison','immutable_finality',
        'min_confirmation_count','passes','sink_blue_score'} and policy['passes'] is True
        and policy['immutable_finality'] is False and type(policy['min_confirmation_count']) is int
        and policy['min_confirmation_count']>=20
        and all(decimal(policy[k]) for k in ('accepting_blue_score','actual_blue_score_distance','sink_blue_score'))
        and int(policy['actual_blue_score_distance'])==int(policy['sink_blue_score'])-int(policy['accepting_blue_score'])
        and int(policy['actual_blue_score_distance'])>policy['min_confirmation_count']
        and policy['comparison']=='sinkBlueScore-acceptingBlueScore > min'
        and policy['accepting_blue_score']==header['blueScore'],'confirmed-depth-policy')
    expected=[dict(row,outpoint=body['inputs'][i]['previousOutpoint']) for i,row in enumerate(contexts)]
    need(value['accepted_input_contexts']==expected and len(value['spent_inputs'])==len(contexts),'actual-contexts-bind-native-case')
    for row,context in zip(value['spent_inputs'],expected):
        need(set(row)=={'outpoint','queried','script_public_key','unspent'} and row['queried'] is True
            and row['unspent'] is False and row['outpoint']==context['outpoint']
            and row['script_public_key']==context['script_public_key'],'spent-source-query')
    outputs=value['current_outputs'];need(len(outputs)==len(body['outputs']),'all-output-queries')
    for i,(row,output) in enumerate(zip(outputs,body['outputs'])):
        outpoint={'transactionId':txid,'index':i}
        need(set(row)=={'amount_sompi','index','outpoint','script_public_key','utxo'} and row['index']==i
            and row['outpoint']==outpoint and row['amount_sompi']==str(output['value'])
            and row['script_public_key']==output['scriptPublicKey'],'queried-output-binding')
        entry=row['utxo'];need(type(entry) is dict and set(entry)==set(contexts[0])|{'outpoint'}
            and entry['outpoint']==outpoint and entry['amount_sompi']==str(output['value'])
            and entry['script_public_key']==output['scriptPublicKey'] and entry['block_daa_score']==header['daaScore']
            and entry['is_coinbase'] is False and entry['covenant_id'] is None,'output-unspent-at-own-observation')
    # Retain the actual selected header and canonical body, without unrelated
    # transaction rows or arbitrary nested verbose fields from FullV2 pages.
    records=0
    for page in value['pages']:
        response=page['response'];groups=response['chainBlockAcceptedTransactions']
        need(response['removedChainBlockHashes']==[] and len(groups)==len(response['addedChainBlockHashes']),'no-observed-prefix-removal')
        for group,blockhash in zip(groups,response['addedChainBlockHashes']):
            need(group['chainBlockHeader']['hash']==blockhash,'page-header-identity')
            for tx in group['acceptedTransactions']:
                if tx.get('verboseData',{}).get('transactionId',tx.get('id'))==txid:
                    need(full_body(tx)==cb and group['chainBlockHeader']==header,'selected-FullV2-acceptance')
                    records+=1
    need(records>0,'selected-acceptance-record-present')
    for k in ('start_hash','observed_sink','final_cursor'):need(hx(value[k],32),'public-observation-hash')
    need(decimal(value['virtual_daa_score']),'observed-virtual-DAA')
    return {'schema':'kpx3-private-change-selected-confirmation/v1','transaction_id':txid,
        'accepted_body':cb,'accepted_body_sha256':value['accepted_body_sha256'],
        'accepted_input_contexts':expected,'accepting_block_header':header,'confirmation_policy':policy,
        'spent_inputs':value['spent_inputs'],'current_outputs':outputs,'start_hash':value['start_hash'],
        'observed_sink':value['observed_sink'],'final_cursor':value['final_cursor'],
        'virtual_daa_score':value['virtual_daa_score'],'network':'testnet-10','expected_genesis':phase.GENESIS,
        'post_query_related_spend_check':True,'selected_acceptance_record_count':records,
        'unrelated_global_pages_or_verbose_records_exported':False,
        'headers_independently_rehashed_or_consensus_finality_claimed':False,
        'assertions_apply_at_observation_time_only':True}


def export(args):
    identity=phase.selected();names=('body','contexts','native_case','native_report','metrics','local_check','release',
        'request','observation','stage_intent','txid_intent','submission_result')
    loaded={k:read(getattr(args,k)) for k in names};raw={k:v[0] for k,v in loaded.items()};v={k:r[1] for k,r in loaded.items()}
    body,contexts,native,metrics=v['body'],v['contexts'],v['native_report'],v['metrics']
    body_types(body)
    if args.stage=='ordinary-merge':
        need(all(set(row)=={'outpoint','amount_sompi','script_public_key','block_daa_score','is_coinbase','covenant_id'}
            and row['outpoint']==body['inputs'][i]['previousOutpoint'] for i,row in enumerate(contexts)),'ordinary-context-outpoints')
        contexts=[{k:x for k,x in row.items() if k!='outpoint'} for row in contexts]
    context_types(contexts);need(len(contexts)==len(body['inputs']),'all-native-contexts')
    entries=[{'amount':int(row['amount_sompi']),'scriptPublicKey':row['script_public_key'],
        'blockDaaScore':int(row['block_daa_score']),'isCoinbase':False,'covenantId':None} for row in contexts]
    need(v['native_case']=={'transaction':body,'entries':entries},'native-case-exact-body-contexts')
    native_types(native,contexts,body);fee=native['Full']['fee_sompi'];metrics_types(metrics,fee)
    release,request,check=v['release'],v['request'],v['local_check'];label='fundingprep' if args.stage=='ordinary-merge' else args.stage
    native_sha=GENERIC if args.stage in ('ordinary-merge','founding') else HELPER
    need(check['body_sha256']==sha(raw['body']) and check['transaction_id']==body['id']
        and check['native_full_accepted'] is True and check['all_input_engines_accepted'] is True
        and check['native_binary_sha256']==native_sha
        and check['inputs']==[dict(row,outpoint=body['inputs'][i]['previousOutpoint']) for i,row in enumerate(contexts)],'root-check-exact-body-native-contexts')
    check_fields={'body_sha256','transaction_id','profile_sha256','native_binary_sha256','native_full_accepted',
        'all_input_engines_accepted','inputs'}
    if args.stage=='founding':
        need(hx(check.get('output0_redeem_hex'),24417),'GN-public-redeem');check_fields.add('output0_redeem_hex')
    # Ordinary old merge wrappers may additionally bind the selected report hash.
    if 'native_validation_sha256' in check:
        need(check['native_validation_sha256']==sha(raw['native_report']),'check-native-report-hash');check_fields.add('native_validation_sha256')
    need(set(check)==check_fields and hx(check['profile_sha256'],32),'strict-local-check-projection')
    selected_body={'body_sha256':sha(raw['body']),'transaction_id':body['id'],'local_check_sha256':sha(raw['local_check'])}
    need(release['allowed_stages']==[label] and release['bodies']=={label:selected_body}
        and release['native_binary_sha256']==native_sha and release['profile_sha256']==check['profile_sha256']
        and release['network']=='testnet-10' and release['genesis']==phase.GENESIS and release['rpc_url']==RPC
        and release['authorization']=='TN10_FRESH_TRIAL_REHEARSAL'
        and hx(release['adapter_sha256'],32) and hx(release['native_safe_sha256'],32),'one-stage-release-binds-exact-check')
    if args.stage!='ordinary-merge':
        need(release['profile_sha256']==phase.IDENTITY_SHA
            and release['adapter_sha256']==sha((phase.ROOT/'poc/private-change-trial/adapter.mjs').read_bytes())
            and release['native_safe_sha256']==sha((phase.ROOT/'poc/private-change-trial/native_safe.py').read_bytes()),'selected-fresh-live-program-and-transport')
    need(request['op']=='submit-once' and request['stage']==label and request['rpc_url']==RPC
        and request['release_sha256']==sha(raw['release']) and request['start_hash']==v['observation']['start_hash'],
        'issued-request-release-observation-binding')
    intent=v['stage_intent']
    need(intent==v['txid_intent'] and set(intent)=={'transaction_id','body_sha256','profile_sha256','stage','rpc_url',
        'release_sha256','start_hash','created_at'} and intent['transaction_id']==body['id']
        and intent['body_sha256']==sha(raw['body']) and intent['profile_sha256']==check['profile_sha256']
        and intent['stage']==label and intent['rpc_url']==RPC and intent['release_sha256']==sha(raw['release'])
        and intent['start_hash']==request['start_hash'],'both-durable-intents-bind-exact-accepted-body')
    result=v['submission_result'];need(set(result)=={'transaction_id','status','response','submission_attempted'}
        and result['transaction_id']==body['id'] and result['status']=='RPC_ACK_ONLY'
        and result['submission_attempted'] is True and result['response']=={'transactionId':body['id']},'single-submit-RPC-ack')
    selected=observation(v['observation'],body,contexts)
    effect={'reserve_before_sompi':0,'reserve_after_sompi':0,'native_payout_sompi':0,'CM_count_after':0,'NF_count_after':0}
    if args.stage=='ordinary-merge':need(len(body['inputs'])==3 and len(body['outputs'])==1 and body['payload']=='','ordinary-three-input-one-output')
    elif args.stage=='founding':
        need(len(body['inputs'])==1 and len(body['outputs'])==2 and body['payload'].startswith(b'KPX2GN01'.hex()),'whole-note-GN-only')
        effect['reserve_after_sompi']=body['outputs'][0]['value']
    else:
        auth=bytes.fromhex(body['payload']);need(len(auth)==4400 and auth[:8]==b'KPX3AU01' and auth[8:40].hex()==identity['domain_hex32'],'fresh-Auth528')
        R=int.from_bytes(auth[188:196],'little');f=int.from_bytes(auth[196:204],'little')
        after=int.from_bytes(auth[476:484],'little');P=int.from_bytes(auth[484:492],'little')
        need(R==int(contexts[0]['amount_sompi']) and f==fee and R==after+P+f,'Auth-reserve-payout-fee-conservation')
        p0=args.stage in ('initial-payment','change-payment');terminal=args.stage=='terminal-cashout'
        need((P==0 if p0 else P>=10_000_000) and (after==0 if terminal else after>0)
            and len(body['outputs'])==(1 if p0 or terminal else 2),'selected-public-action-mode')
        if after:need(body['outputs'][0]['value']==after,'actual-reserve-output')
        if P:need(body['outputs'][-1]['value']==P and body['outputs'][-1]['scriptPublicKey']==auth[492:528].hex(),'actual-native-payout')
        effect={'reserve_before_sompi':R,'reserve_after_sompi':after,'native_payout_sompi':P,
            'CM_count_after':int.from_bytes(auth[436:440],'little'),'NF_count_after':int.from_bytes(auth[472:476],'little')}
    authorization={'schema':'kpx3-private-change-public-once-authorization/v1','stage':args.stage,
        'original_release_sha256':sha(raw['release']),'original_request_sha256':sha(raw['request']),
        'original_stage_intent_sha256':sha(raw['stage_intent']),'original_txid_intent_sha256':sha(raw['txid_intent']),
        'selected_body':selected_body,'release_selection':{k:release[k] for k in ('authorization','profile_sha256','network',
            'genesis','rpc_url','adapter_sha256','native_safe_sha256','native_binary_sha256')},
        'request_selection':{k:request[k] for k in ('op','rpc_url','start_hash','release_sha256')},
        'both_once_markers_equal_and_bound':True,'private_filesystem_paths_or_owner_maps_exported':False}
    summary={'schema':'kpx3-private-change-confirmed-stage/v1','stage':args.stage,'transaction_id':body['id'],
        'body_sha256':sha(raw['body']),'input_sum_sompi':sum(int(x['amount_sompi']) for x in contexts),
        'output_sum_sompi':sum(x['value'] for x in body['outputs']),'fee_sompi':fee,'mining_mass':metrics['mining_mass'],
        **effect,'confirmed_accepted_exact_body':True,'original_public_input_identities':{k:{'sha256':sha(b),'bytes':len(b)} for k,b in raw.items()},
        'selected_node_observation_not_current_now_or_independent_consensus':True,
        'unbroadcast_alternatives_owner_maps_backup_witness_PK_or_paths_exported':False,
        'export_RPC_VM_proof_signing_or_broadcast_operations':0}
    payloads={'transaction.json':raw['body'],'supplied-context.json':raw['contexts'],'validation-case.json':raw['native_case'],
        'native-validation.json':raw['native_report'],'metrics.json':raw['metrics'],'local-check.json':raw['local_check'],
        'authorization-selection.json':encoded(authorization),'submission-result.json':encoded(result),
        'selected-confirmation.json':encoded(selected),'CONFIRMED-STAGE.json':encoded(summary)}
    output=args.output;need(not output.exists() and not any(x.is_symlink() for x in (output,*output.parents)),'fresh-public-output')
    # Every nested public container is checked before the first output write.
    output.mkdir(parents=True)
    for name,blob in payloads.items():
        with (output/name).open('xb') as file:file.write(blob)
    files=[{'path':k,'sha256':sha(b),'bytes':len(b)} for k,b in sorted(payloads.items())]
    manifest={'schema':'kpx3-private-change-live-stage-allowlist/v1','stage':args.stage,'files':files,
        'exporter_source_sha256':sha(Path(__file__).read_bytes()),'only_actual_confirmed_selected_body_exported':True}
    with (output/'FILE-ALLOWLIST.json').open('xb') as file:file.write(encoded(manifest))
    return {'stage':args.stage,'public_payloads':len(files),'allowlist_sha256':sha(encoded(manifest))}


def ledger(packets,output):
    need(len(packets)==7,'seven-confirmed-finite-packets');rows=[];bodies=[];observations=[]
    for expected,directory in zip(STAGES,packets):
        _,manifest=read(directory/'FILE-ALLOWLIST.json');need(manifest['stage']==expected,'ordered-stages')
        for row in manifest['files']:
            need(type(row['path']) is str and '/' not in row['path'] and row['path']!='FILE-ALLOWLIST.json','finite-payload-name')
            raw,_=read(directory/row['path']);need(sha(raw)==row['sha256'] and len(raw)==row['bytes'],'sealed-stage-payload')
        _,summary=read(directory/'CONFIRMED-STAGE.json');_,body=read(directory/'transaction.json')
        _,obs=read(directory/'selected-confirmation.json');need(summary['stage']==expected and summary['confirmed_accepted_exact_body'] is True,'confirmed-stage-summary')
        rows.append(summary);bodies.append(body);observations.append(obs)
    for index in range(1,7):
        need(bodies[index]['inputs'][0]['previousOutpoint']=={'transactionId':bodies[index-1]['id'],'index':0}
            and observations[index]['accepted_input_contexts']==[observations[index-1]['current_outputs'][0]['utxo']],
            'actual-accepted-context-and-output-link')
    source=rows[0]['input_sum_sompi'];ordinary_change=bodies[1]['outputs'][1]['value']
    fees=sum(x['fee_sompi'] for x in rows);payouts=sum(x['native_payout_sompi'] for x in rows)
    need(source==286_604_800 and rows[-1]['reserve_after_sompi']==0
        and rows[-1]['CM_count_after']==9 and rows[-1]['NF_count_after']==11
        and source==ordinary_change+payouts+fees,'whole-source-no-hidden-tail-reconciliation')
    result={'schema':'kpx3-private-change-actual-live-financial-closure/v1','classification':'CONFIRMED_TESTNET_FUNCTIONAL_SMALLER_PILOT',
        'source_sompi':source,'ordinary_change_sompi':ordinary_change,'native_payouts_sompi':payouts,'all_seven_fees_sompi':fees,
        'terminal_reserve_sompi':0,'CM_count_after':9,'NF_count_after':11,'accepted_stage_count':7,'actual_prior_output_links':6,
        'stage_fees_sompi':[row['fee_sompi'] for row in rows],'transaction_ids':[body['id'] for body in bodies],
        'original_10KAS_local_workload_or_privacy_fee_denominators_rescored':False,
        'independent_backup_recovery_and_current_head_evidence_in_separate_wallet_network_packets':True,
        'privacy_fee_production_or_independent_consensus_qualification_claimed':False,
        'unbroadcast_main_alternatives_or_private_owner_maps_exported':False}
    need(not output.exists() and not any(x.is_symlink() for x in (output,*output.parents)),'fresh-ledger-output')
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('xb') as file:file.write(encoded(result))
    return {'ledger_sha256':sha(encoded(result)),'source_sompi':source,'reconciled':True}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='op',required=True)
    one=sub.add_parser('stage');one.add_argument('--stage',choices=STAGES,required=True)
    for name in ('body','contexts','native-case','native-report','metrics','local-check','release','request','observation','stage-intent','txid-intent','submission-result','output'):
        one.add_argument('--'+name,type=Path,required=True)
    all_=sub.add_parser('ledger');all_.add_argument('packets',type=Path,nargs=7);all_.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(export(args) if args.op=='stage' else ledger(args.packets,args.output),sort_keys=True))
