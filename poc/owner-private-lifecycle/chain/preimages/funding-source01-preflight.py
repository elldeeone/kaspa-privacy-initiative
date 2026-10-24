#!/usr/bin/env python3
"""Fixed selected financial/native checks before a single TN10 submission."""
import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'poc/owner-private-lifecycle/bootstrap'))
from gn3 import validate_genesis
from gn3_common import digest,encoded,fields,hx,need,parse,uint,uuid_text,write_new
from gn3_runtime import Executable,GENERIC,Runtime,SDK_DIR,SDK_PINS
from gn3_selection import decode
from paths import HostPolicy
from replay import SOURCES,bundle_public_paths,replay,verify_native

PROFILE_SHA='69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f'
DOMAIN='be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480'
PRIVATE=Path('/var/tmp/kpi-owner-private-lifecycle-01/private')


def ordinary_consolidation(case,trial_id):
    body,entries=case['transaction'],case['entries']
    need(type(body['inputs']) is list and body['inputs']
         and len(body['inputs'])==len(entries) and len(body['outputs'])==1,
         'ordinary-consolidation-input-output-layout')
    payload=hx(body['payload'],88)
    import uuid
    need(payload[:8]==b'KPX8MF01' and payload[8:40].hex()==DOMAIN
         and payload[40:56]==uuid.UUID(trial_id).bytes,'ordinary-new-trial-identity')
    output=body['outputs'][0];amount=uint(output['value'])
    need(amount>=2_100_000_000 and output['covenant'] is None,'ordinary-own-positive-self-output')
    spk=hx(output['scriptPublicKey'],36)
    need(spk[:3]==b'\0\0\x20' and spk[-1:]==b'\xac','ordinary-funding-P2PK-self-output')
    for item,e in zip(body['inputs'],entries):
        need(e['scriptPublicKey']==spk.hex() and e['isCoinbase'] is True
             and e['covenantId'] is None and item['computeBudget']==10,
             'same-owner-coinbase-consolidation')
        sig=hx(item['signatureScript'],66)
        need(sig[:1]==b'\x41' and sig[-1:]==b'\x01','ordinary-ALL-signature')


def run(a):
    uuid_text(a.trial_id)
    guard=HostPolicy(a.exclude_old_trial,a.exclude_private_directory)
    need(PRIVATE in guard.new_directories,'whole-selected-private-parent-must-be-excluded')
    selected_paths=[a.selection,a.case,ROOT/'poc/owner-private-lifecycle/financial-profile.json',
                    *[(getattr(a,name.replace('-','_')) or default) for name,(default,_) in GENERIC.items()],
                    *((a.sdk_directory or SDK_DIR)/n for n in SDK_PINS)]
    if a.mode=='lifecycle':
        need(all(getattr(a,n) is not None for n in ('parameters','parameters_sha256','codec',
             'sessions','sessions_sha256','source_pins','source_pins_sha256','descriptor',
             'descriptor_sha256','fetch','fetch_sha256','bundle_directory')),
             'complete-fixed-accepted-prefix-inputs-required')
        selected_paths += [a.parameters,a.codec,a.sessions,a.source_pins,a.descriptor,a.fetch,
                           *(ROOT/source for source in SOURCES)]
    guard.guard(selected_paths)
    profile=parse(guard.read(ROOT/'poc/owner-private-lifecycle/financial-profile.json',PROFILE_SHA))
    need(profile['schema']=='kpx8-owner-private-financial-profile/v1'
         and profile['domain_hex32']==DOMAIN and profile['selected'] is True,
         'root-selected-financial-profile')
    raw_selection=guard.read(a.selection,a.selection_sha256)
    selected=decode(raw_selection,a.selection_sha256)
    need(selected.profile_sha256==PROFILE_SHA
         and digest(selected.tail)==profile['selected_public_binaries_and_native_policy']['immutable_native_tail']['sha256'],
         'GN3-selection-must-match-root-selected-financial-profile')
    raw_case=guard.read(a.case,a.case_sha256);case=parse(raw_case)
    fields(case,{'transaction','entries'},'exact-native-case')
    body=case['transaction'];need(body['version']==1 and type(body['version']) is int
         and body['lockTime']==0 and body['gas']==0 and body['subnetworkId']=='00'*20,
         'canonical-testnet-native-header')
    output=Path(a.output);need(not output.exists(),'fresh-public-native-preflight')
    output.mkdir(parents=True,mode=0o700)
    runtime_paths={name:getattr(a,name.replace('-','_')) for name in GENERIC
                   if getattr(a,name.replace('-','_')) is not None}
    runtime=Runtime(paths=runtime_paths,sdk_dir=a.sdk_directory)
    normalized,metrics=runtime.normalize(case,output/'native-normalization')
    need(normalized==case and metrics['actual_fee_sompi']==100*metrics['mining_mass'],
         'exact-native-ID-storage-mass-and-reference-rate100-fee')
    checked=verify_native(runtime,case,output/'native-Full')
    need(checked==metrics,'native-Full-and-quote-agreement')
    checkpoint=None
    if a.mode=='genesis':
        validate_genesis(case,selected,a.trial_id,required_fee=metrics['actual_fee_sompi'],signed=True)
        runtime.roundtrip(case)
    elif a.mode=='consolidate':
        ordinary_consolidation(case,a.trial_id)
    else:
        raw={name:guard.read(getattr(a,name),getattr(a,name+'_sha256')) for name in
             ('parameters','sessions','source_pins','descriptor','fetch')}
        guard.guard(bundle_public_paths(parse(raw['fetch']),a.bundle_directory))
        parameters=parse(raw['parameters'])
        fields(parameters,{'outer_image_hex32','component_profile_sha256','exit_vk_hex328'},
               'exact-selected-native-parameters')
        need(parameters['outer_image_hex32']==profile['outer_image_hex32']
             and parameters['component_profile_sha256']==profile['component_profile_sha256']
             and digest(hx(parameters['exit_vk_hex328'],328))==profile['roles']['exit']['vk_sha256'],
             'native-parameters-must-match-root-profile')
        codec_sha=profile['selected_public_binaries_and_native_policy']['native_codec']['sha256']
        history=replay(raw_selection,a.selection_sha256,raw['descriptor'],a.descriptor_sha256,
            raw['fetch'],a.fetch_sha256,a.bundle_directory,raw['parameters'],a.parameters_sha256,
            a.codec,codec_sha,raw['sessions'],a.sessions_sha256,raw['source_pins'],a.source_pins_sha256,
            output/'accepted-prefix-replay',runtime_paths=runtime_paths,sdk_directory=runtime.sdk_dir)
        checkpoint=history['current_checkpoint']
        parsed=parse(Executable(a.codec,codec_sha).run(request={'operation':'body','case':case,**parameters}).stdout)
        payload=hx(body['payload']);point=body['inputs'][0]['previousOutpoint']
        need(len(body['inputs'])==1 and body['inputs'][0]['computeBudget']==profile['compute_budget']
             and point['transactionId']+point['index'].to_bytes(4,'little').hex()==checkpoint['outpoint_hex36']
             and payload[148:260].hex()==checkpoint['state_hex112']
             and int.from_bytes(payload[260:268],'little')==checkpoint['reserve_sompi'],
             'actual-current-accepted-prefix-and-native-candidate-must-agree')
        need(parsed['case']==case,'exact-native-candidate-policy-and-financial-effects')
    sdk_body,sdk_contexts=runtime.sdk_body(case)
    result={'schema':'kpx8-public-submit-candidate/v1','network_id':'testnet-10',
        'genesis_hash_hex':'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
        'mode':a.mode,'stage':a.stage,'trial_id':a.trial_id,'financial_profile_sha256':PROFILE_SHA,
        'selection_file_sha256':a.selection_sha256,'case_sha256':a.case_sha256,
        'transaction':sdk_body,'contexts':sdk_contexts,'actual_native_Full_passed':True,
        'exact_reference_fee_sompi':metrics['actual_fee_sompi'],'recorded_accepted_checkpoint':checkpoint,
        'node_pin':GENERIC['node'][1],'broadcast_performed':False,'spend_authorized_by_host_report':False}
    write_new(output/'SDK-CANDIDATE.json',encoded(result)+b'\n',0o400)
    return {'status':'NATIVE_FINANCIAL_PREFLIGHT_PASS_PENDING_EXACT_LIVE_INPUT_QUERY',
            'candidate_sha256':digest(encoded(result)+b'\n'),'output':str(output)}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',choices=('consolidate','genesis','lifecycle'),required=True)
    for name in ('selection','case','output'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('selection-sha256','case-sha256','trial-id','stage'):p.add_argument('--'+name,required=True)
    for name in ('parameters','sessions','source-pins','descriptor','fetch'):
        p.add_argument('--'+name,type=Path);p.add_argument('--'+name+'-sha256')
    p.add_argument('--codec',type=Path);p.add_argument('--bundle-directory',type=Path)
    for name in ('crypto','node','native-validator','sdk-directory'):
        p.add_argument('--'+name,type=Path)
    p.add_argument('--exclude-old-trial',type=Path,action='append',required=True)
    p.add_argument('--exclude-private-directory',type=Path,action='append',required=True)
    try:print(encoded(run(p.parse_args())).decode())
    except (ValueError,OSError,TypeError,KeyError):p.exit(1,'fixed native preflight incomplete\n')
