#!/usr/bin/env python3
"""Fixed GN3/native accepted-prefix replay. No owner seed, signer or PK access."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[3]
BOOTSTRAP=ROOT/'poc/owner-private-lifecycle/bootstrap'
sys.path.insert(0,str(BOOTSTRAP))
from gn3 import validate_accepted_genesis
from gn3_common import digest, encoded, fields, hx, need, parse, public_bytes, uint, write_new
from gn3_runtime import Executable, GENERIC, Runtime, SDK_DIR, SDK_PINS
from gn3_selection import decode as decode_selection
from paths import HostPolicy

SOURCES=('poc/owner-private-lifecycle/integration/trees.py',
         'poc/owner-private-lifecycle/integration/public.py',
         'poc/owner-private-lifecycle/integration/construction/codec.py',
         'poc/owner-private-lifecycle/verification/wire.py')
PARAMETERS={'outer_image_hex32','component_profile_sha256','exit_vk_hex328'}


def bundle_public_paths(value,bundle_directory):
    """Enumerate page paths without opening, hashing or decompressing a page."""
    root=Path(bundle_directory).absolute()
    pages=[*value['pages'],*value['current_view']['post_query_delta']['pages']]
    result=[]
    for record in pages:
        relative=record['path'];need(type(relative) is str,'canonical-retained-page-path')
        path=Path(relative)
        need(not path.is_absolute() and '..' not in path.parts
             and str(path)==relative and relative not in ('','.'),'canonical-retained-page-path')
        result.append(root/path)
    need(len(result)==len(set(result)),'distinct-retained-page-paths')
    return tuple(result)


def decimals(value,bits=64):
    need(type(value) is str and value.isascii() and value.isdecimal()
         and (value=='0' or not value.startswith('0')),'canonical-decimal-sompi-boundary')
    return uint(int(value),bits)


def native_case(row):
    """Convert canonical RPC strings once, before any Python integer comparison."""
    value=copy.deepcopy(row['transaction'])
    value['mass']=decimals(value.pop('storageMass'))
    value['lockTime']=decimals(value['lockTime']);value['gas']=decimals(value['gas'])
    for item in value['inputs']:item['sequence']=decimals(item['sequence'])
    for item in value['outputs']:item['value']=decimals(item['value'])
    need(type(row['accepted_input_contexts']) is list
         and len(row['accepted_input_contexts'])==len(value['inputs']),'populated-context-count')
    entries=[]
    for index,context in enumerate(row['accepted_input_contexts']):
        need(context['outpoint']==value['inputs'][index]['previousOutpoint'],
             'populated-context-exact-outpoint')
        entries.append({'amount':decimals(context['amount_sompi']),
            'scriptPublicKey':context['script_public_key'],
            'blockDaaScore':decimals(context['block_daa_score']),
            'isCoinbase':context['is_coinbase'],'covenantId':context['covenant_id']})
    need(len(entries)==len(value['inputs']),'populated-context-count')
    return {'transaction':value,'entries':entries}


def source_modules(raw_pins,expected):
    need(digest(raw_pins)==expected,'selected-replay-source-pins')
    pins=parse(raw_pins);fields(pins,set(SOURCES),'exact-selected-replay-source-set')
    for name in SOURCES:
        hx(pins[name],32)
        need(digest(public_bytes(ROOT/name))==pins[name],'selected-public-replay-source')
    integration=ROOT/'poc/owner-private-lifecycle/integration'
    # Only fixed, independently hash-selected application sources can execute.
    sys.path.insert(0,str(integration))
    name='_kpx8_chain_public_history'
    spec=importlib.util.spec_from_file_location(name,integration/'public.py')
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module


def verify_native(runtime,case,output):
    output.mkdir(parents=True,exist_ok=False,mode=0o700)
    source=output/'case.json';write_new(source,encoded(case)+b'\n')
    runtime.executables['native-validator'].run(['validate-transaction',source,output/'native'])
    report=parse((output/'native/native-validation.json').read_bytes())
    metrics=parse((output/'native/metrics.json').read_bytes())
    need(report['isolation']=='PASS' and report['Full']['accepted'] is True
         and report['all_input_engines_accepted'] is True
         and len(report['per_input_ScriptEngine'])==len(case['transaction']['inputs'])
         and all(row['accepted'] is True for row in report['per_input_ScriptEngine']),
         'actual-native-Full-and-all-input-engines-required')
    return metrics


def replay(raw_selection,selection_sha,raw_descriptor,descriptor_sha,raw_fetch,fetch_sha,
           bundle_directory,raw_parameters,parameters_sha,codec_path,codec_sha,
           raw_sessions,sessions_sha,raw_source_pins,source_pins_sha,output,*,
           runtime_paths=None,sdk_directory=None):
    """Financial/native semantics after the independent SDK Full-page stage.

    The caller must freshly acquire and requery immediately before signing or
    submitting. This replays a recorded validating-node observation; it is not
    an independent PoW/GHOSTDAG or continuously current chain proof.
    """
    selection=decode_selection(raw_selection,selection_sha)
    for raw,expected in ((raw_descriptor,descriptor_sha),(raw_fetch,fetch_sha),
                         (raw_parameters,parameters_sha),(raw_sessions,sessions_sha)):
        hx(expected,32);need(digest(raw)==expected,'external-public-replay-input-pin')
    output=Path(output);need(not output.exists(),'fresh-fixed-replay-output')
    output.mkdir(parents=True,mode=0o700)
    public_files={}
    for name,raw in (('selection',raw_selection),('descriptor',raw_descriptor),('fetch',raw_fetch)):
        path=output/(name+'.json');write_new(path,raw,0o400);public_files[name]=path
    runtime=Runtime(paths=runtime_paths,sdk_dir=sdk_directory)
    sdk_output=output/'SDK-VERIFICATION.json'
    runtime.executables['node'].run([ROOT/'poc/owner-private-lifecycle/chain/verify_bundle.mjs',
        public_files['selection'],selection_sha,public_files['descriptor'],descriptor_sha,
        public_files['fetch'],fetch_sha,bundle_directory,sdk_output,runtime.sdk_dir])
    sdk=parse(sdk_output.read_bytes())
    need(sdk['status']=='PUBLIC_EVIDENCE_CONSISTENCY_PASS'
         and sdk['financial_profile_sha256']==selection.profile_sha256
         and sdk['selection_file_sha256']==selection_sha,'fixed-independent-SDK-stage')
    fetch=parse(raw_fetch);descriptor=parse(raw_descriptor)
    parameters=parse(raw_parameters);fields(parameters,PARAMETERS,'fixed-native-codec-parameters')
    hx(parameters['outer_image_hex32'],32);hx(parameters['component_profile_sha256'],32)
    hx(parameters['exit_vk_hex328'],328)
    sessions=parse(raw_sessions);need(type(sessions) is list,'public-session-list')
    session_map={}
    for session in sessions:
        identity=digest(encoded(session)+b'\n')
        need(identity not in session_map,'distinct-public-sessions')
        session_map[identity]=session
    construction=source_modules(raw_source_pins,source_pins_sha)
    codec=Executable(codec_path,codec_sha)
    rows=fetch['transactions'];need(type(rows) is list and rows,'accepted-founding-required')
    cases=[native_case(row) for row in rows]
    genesis=validate_accepted_genesis(cases[0],selection,descriptor['trial_id'])
    need(genesis['founding_outpoint']==descriptor['founding_outpoint']
         and genesis['redeem_hex']==descriptor['initial_redeem_hex'],'strict-founding-selected-descriptor')
    emitted=parse(codec.run(request={'operation':'emit','state_hex112':genesis['state_hex112'],
                                    **parameters}).stdout)
    need(emitted['immutable_tail_hex']==selection.tail.hex()
         and emitted['redeem_hex']==genesis['redeem_hex'],'profile-native-emitter-exact-selected-tail')
    history=construction.genesis([hx(row,496) for row in genesis['records_hex496']],
                                 genesis['outpoint_hex36'])
    need(history['head']=={key:genesis[key] for key in
                          ('state_hex112','reserve_sompi','outpoint_hex36')},'independent-genesis-trees')
    reports=[];total_fee=0;payouts=[]
    for index,case in enumerate(cases):
        metrics=verify_native(runtime,case,output/('native-'+str(index).zfill(4)))
        total_fee+=metrics['actual_fee_sompi']
        reports.append({'transaction_id':case['transaction']['id'],'metrics':metrics,
                        'native_full_and_all_input_engines_passed':True})
        if index==0:continue
        value=parse(codec.run(request={'operation':'body','case':case,**parameters}).stdout)
        need(value['case']==case,'exact-accepted-body-and-context-codec')
        point=case['transaction']['inputs'][0]['previousOutpoint']
        expected_point=point['transactionId']+point['index'].to_bytes(4,'little').hex()
        body=bytes.fromhex(case['transaction']['payload'])
        need(expected_point==history['head']['outpoint_hex36']
             and body[148:260].hex()==history['head']['state_hex112']
             and int.from_bytes(body[260:268],'little')==history['head']['reserve_sompi'],
             'exact-native-history-lineage-and-state')
        remaining=int.from_bytes(body[380:388],'little')
        successor=case['transaction']['id']+'00000000' if remaining else None
        transition={'kind':'batch' if value['mode']=='mixed' else 'exit',
            'projection_hex':value['financial_projection_hex'],'successor_outpoint_hex36':successor}
        if value['mode']=='mixed':
            identity=body[48:80].hex();need(identity in session_map,'accepted-batch-public-session-required')
            transition['session']=session_map[identity]
        else:
            witness=hx(case['transaction']['inputs'][0]['signatureScript'])
            need(witness[:2]==b'\x4c\x80' and len(witness)>=130,'canonical-native-Exit-proof-frame')
            transition['proof_hex128']=witness[2:130].hex()
            payouts.append({'transaction_id':case['transaction']['id'],
                'output_index':len(case['transaction']['outputs'])-1,
                'payout_sompi':int.from_bytes(body[396:404],'little'),
                'script_public_key':body[404:440].hex()})
        history=construction.extend(history,transition)
    _,checkpoint=construction.reconstruct(history)
    head=sdk['discovered_head']
    need(checkpoint['outpoint_hex36']==(None if head is None else
        head['transactionId']+head['index'].to_bytes(4,'little').hex()),'SDK-and-financial-head-agreement')
    need((checkpoint['reserve_sompi']==0)==sdk['terminal_candidate'],'SDK-and-financial-terminal-agreement')
    report={'schema':'kpx8-accepted-native-replay/v1',
        'status':'RECORDED_VALIDATING_NODE_PREFIX_FINANCIAL_AND_NATIVE_PASS',
        'financial_profile_sha256':selection.profile_sha256,'selection_file_sha256':selection_sha,
        'descriptor_sha256':descriptor_sha,'fetch_sha256':fetch_sha,
        'genesis_rederived_from_public_notes_and_native_backing':True,
        'all_native_Full_and_input_engines_executed':True,
        'current_checkpoint':checkpoint,'transactions':reports,'payouts':payouts,
        'observed_total_fee_sompi':total_fee,'history_sha256':digest(encoded(history)+b'\n'),
        'independent_consensus_or_continuous_currentness':False,'spend_authorized':False,
        'trust':'SELECTED_SOFTWARE_HOST_VALIDATING_NODE_TRANSPORT_AND_RETAINED_PUBLIC_DATA'}
    write_new(output/'HISTORY.json',encoded(history)+b'\n',0o400)
    write_new(output/'CHECKPOINT.json',encoded(checkpoint)+b'\n',0o400)
    write_new(output/'RESULTS.json',encoded(report)+b'\n',0o400)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('selection','descriptor','fetch','parameters','sessions','source-pins'):
        p.add_argument('--'+name,type=Path,required=True)
        p.add_argument('--'+name+'-sha256',required=True)
    for name in ('bundle-directory','codec','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--codec-sha256',required=True)
    for name in ('crypto','node','native-validator','sdk-directory'):
        p.add_argument('--'+name,type=Path)
    p.add_argument('--exclude-old-trial',type=Path,action='append',required=True)
    p.add_argument('--exclude-private-directory',type=Path,action='append',required=True)
    try:
        a=p.parse_args();guard=HostPolicy(a.exclude_old_trial,a.exclude_private_directory)
        need(Path('/var/tmp/kpi-owner-private-lifecycle-01/private') in guard.new_directories,
             'whole-selected-private-parent-must-be-excluded')
        names=('selection','descriptor','fetch','parameters','sessions','source_pins')
        fixed_js=tuple((ROOT/'poc/owner-private-lifecycle/chain'/name) for name in
                       ('wire.mjs','json.mjs','selection.mjs','acquire.mjs','verify_bundle.mjs'))
        runtime_paths={name:getattr(a,name.replace('-','_')) for name in GENERIC
                       if getattr(a,name.replace('-','_')) is not None}
        actual_runtime={name:runtime_paths.get(name,default) for name,(default,_) in GENERIC.items()}
        sdk_directory=a.sdk_directory or SDK_DIR
        guard.guard([*(getattr(a,key) for key in names),a.codec,*(ROOT/source for source in SOURCES),
                     *fixed_js,*actual_runtime.values(),
                     *(sdk_directory/name for name in SDK_PINS)])
        raw={key:guard.read(getattr(a,key),getattr(a,key+'_sha256')) for key in names}
        guard.guard(bundle_public_paths(parse(raw['fetch']),a.bundle_directory))
        result=replay(raw['selection'],a.selection_sha256,raw['descriptor'],a.descriptor_sha256,
            raw['fetch'],a.fetch_sha256,a.bundle_directory,raw['parameters'],a.parameters_sha256,
            a.codec,a.codec_sha256,raw['sessions'],a.sessions_sha256,
            raw['source_pins'],a.source_pins_sha256,a.output,
            runtime_paths=runtime_paths,sdk_directory=sdk_directory)
        print(encoded({'status':result['status'],'output':str(a.output),
                       'checkpoint':result['current_checkpoint']}).decode())
    except (ValueError,OSError,KeyError,TypeError):p.exit(2,'accepted native prefix replay incomplete\n')
