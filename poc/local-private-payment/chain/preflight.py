#!/usr/bin/env python3
"""Exact native Full + financial/current-prefix preflight. No network or signing."""
import argparse
from pathlib import Path
import sys
from types import SimpleNamespace
from replay import BASE,HERE,modules,replay,runtime_from
sys.path.insert(0,str(BASE/'bootstrap'))
from gn3 import validate_genesis
from gn3_common import ROOT,digest,encoded,fields,hx,need,parse,uint,uuid_text,write_new
from gn3_runtime import GENERIC,Runtime
from gn3_selection import decode
from paths import HostPolicy


def ordinary(case,trial_id):
    body=case['transaction'];need(len(body['outputs'])==1 and body['inputs'],'ordinary-own-output-layout')
    out=body['outputs'][0];spk=hx(out['scriptPublicKey'],36)
    need(out['value']>=2_100_000_000 and out['covenant'] is None and spk[:3]==b'\0\0\x20' and spk[-1:]==b'\xac','ordinary-own-self-output')
    payload=hx(body['payload'],88)
    import uuid
    need(payload[:8]==b'KPXAMF01' and payload[8:40].hex()=='b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
         and payload[40:56]==uuid.UUID(trial_id).bytes and payload[56:]==bytes(32),'fresh-ordinary-testnet-trial-payload')
    for item,entry in zip(body['inputs'],case['entries']):
        need(entry['scriptPublicKey']==spk.hex() and entry['isCoinbase'] is True and entry['covenantId'] is None
             and item['computeBudget']==10,'same-owner-coinbase-inputs')
        sig=hx(item['signatureScript'],66);need(sig[:1]==b'\x41' and sig[-1:]==b'\x01','ordinary-ALL-signature')


def run(a):
    guard=HostPolicy();uuid_text(a.trial_id)
    raw_selection=guard.read(a.selection,a.selection_sha256);selection=decode(raw_selection,a.selection_sha256)
    case=parse(guard.read(a.case,a.case_sha256));fields(case,{'transaction','entries'},'whole-native-CASE')
    body=case['transaction'];need(body['version']==1 and type(body['version']) is int and body['lockTime']==0
        and body['gas']==0 and body['subnetworkId']=='00'*20,'canonical-native-testnet-header')
    output=Path(a.output);need(not output.exists(),'fresh-public-preflight');output.mkdir(parents=True,mode=0o700)
    runtime=runtime_from(a);normalized,metrics=runtime.normalize(case,output/'normalization')
    need(normalized==case and metrics['actual_fee_sompi']==100*metrics['mining_mass'],'exact-ID-storage-mass-reference100fee')
    _,checked=runtime.validate(case,output/'native-Full');need(checked==metrics,'actual-Full-and-quote-agreement')
    sdk_body,contexts=runtime.sdk_body(case)
    roundtrip=parse(runtime.executables['node'].run([HERE/'roundtrip.mjs',runtime.sdk_dir],request={
        'network_id':'testnet-10','genesis_hash_hex':'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
        'transaction':sdk_body,'contexts':contexts}).stdout)
    need(roundtrip=={'transaction':sdk_body,'contexts':contexts,'lossless_safe_roundtrip':True,
         'network_or_broadcast':False},'official-SDK-whole-CASE-roundtrip')
    checkpoint=None
    if a.mode=='genesis':validate_genesis(case,selection,a.trial_id,required_fee=metrics['actual_fee_sompi'],signed=True)
    elif a.mode=='consolidate':ordinary(case,a.trial_id)
    else:
        need(all(getattr(a,name,None) is not None for name in ('descriptor','descriptor_sha256','fetch','fetch_sha256',
             'bundle_directory','assets','assets_sha256','parameters','parameters_sha256','codec','codec_sha256')),'complete-actual-accepted-prefix-required')
        descriptor=parse(guard.read(a.descriptor,a.descriptor_sha256));need(descriptor['trial_id']==a.trial_id,'actual-trial-identity')
        accepted=replay(SimpleNamespace(**{**vars(a),'output':output/'accepted-prefix'}))
        checkpoint=accepted['current_checkpoint']
        need(checkpoint['outpoint_hex36'] is not None and len(body['inputs'])==1,'actual-live-single-reserve-required')
        point=body['inputs'][0]['previousOutpoint'];payload=hx(body['payload'])
        need(point['transactionId']+point['index'].to_bytes(4,'little').hex()==checkpoint['outpoint_hex36']
            and payload[148:260].hex()==checkpoint['state_hex112']
            and int.from_bytes(payload[260:268],'little')==checkpoint['reserve_sompi'],'exact-current-prefix-head-binding')
        support,_,codec_module=modules(guard);parameters=parse(guard.read(a.parameters,a.parameters_sha256))
        codec=codec_module.NativeCodec(a.codec,a.codec_sha256)
        projected,_,_,_=codec_module.project(codec,case,hx(parameters['outer_image_hex32'],32),
            hx(parameters['component_profile_sha256'],32),hx(parameters['exit_vk_hex328'],328))
        need(projected==case,'exact-whole-CASE-native-policy')
    sdk_body,contexts=runtime.sdk_body(case)
    result={'schema':'kpxa-public-submit-candidate/v1','network_id':'testnet-10',
        'genesis_hash_hex':'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
        'mode':a.mode,'stage':a.stage,'trial_id':a.trial_id,'financial_profile_sha256':selection.profile_sha256,
        'selection_file_sha256':a.selection_sha256,'case_sha256':a.case_sha256,'transaction':sdk_body,'contexts':contexts,
        'actual_native_Full_passed':True,'exact_reference_fee_sompi':metrics['actual_fee_sompi'],
        'recorded_accepted_checkpoint':checkpoint,'node_pin':GENERIC['node'][1],
        'broadcast_performed':False,'spend_authorized_by_host_report':False}
    raw=encoded(result)+b'\n';write_new(output/'SDK-CANDIDATE.json',raw,0o400)
    return {'status':'NATIVE_FINANCIAL_PREFLIGHT_PASS_PENDING_EXACT_LIVE_INPUT_QUERY','candidate_sha256':digest(raw),'output':str(output)}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--mode',choices=('consolidate','genesis','lifecycle'),required=True)
    for name in ('selection','case','output'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('selection-sha256','case-sha256','trial-id','stage'):p.add_argument('--'+name,required=True)
    for name in ('assets','parameters','descriptor','fetch'):
        p.add_argument('--'+name,type=Path);p.add_argument('--'+name+'-sha256')
    p.add_argument('--codec',type=Path);p.add_argument('--codec-sha256');p.add_argument('--bundle-directory',type=Path)
    # Legacy caller flags accepted only for CLI compatibility; fixed public guard is always used.
    for name in ('exclude-old-trial','exclude-private-directory'):p.add_argument('--'+name,action='append',default=[])
    for name in ('crypto','node','native-validator','sdk-directory','sessions','sessions-sha256','source-pins','source-pins-sha256'):p.add_argument('--'+name)
    try:print(encoded(run(p.parse_args())).decode())
    except (ValueError,OSError,TypeError,KeyError):p.exit(1,'exact native financial preflight incomplete\n')
