#!/usr/bin/env python3
"""Whole accepted CASE replay: retained SDK pages + genuine proofs + native Full.

A selected validating node and its retained confirmed prefix are assumptions;
this does not establish independent consensus or continuous currentness.
"""
import argparse
import copy
import importlib.util
from pathlib import Path
import sys

HERE=Path(__file__).absolute().parent
BASE=HERE.parent
sys.path.insert(0,str(BASE/'bootstrap'))
from gn3 import validate_accepted_genesis
from gn3_common import ROOT,digest,encoded,fields,hx,need,parse,uint,write_new
from gn3_runtime import Executable,Runtime
from gn3_selection import decode
from paths import HostPolicy
import cache_common


def selected_module(path,name,guard):
    raw=guard.read(path);module=importlib.util.module_from_spec(importlib.util.spec_from_loader(name,loader=None))
    module.__file__=str(path);sys.modules[name]=module
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def modules(guard):
    support=selected_module(BASE/'wallet/support.py','support',guard)
    history=selected_module(BASE/'recovery/history.py','_kpxa_chain_history',guard)
    codec=selected_module(BASE/'verification/native_case.py','_kpxa_chain_codec',guard)
    return support,history,codec


def integer_boundary(value):
    need(type(value) is str and value.isascii() and value.isdecimal()
         and (value=='0' or not value.startswith('0')),'canonical-decimal-boundary')
    return uint(int(value))


def native_case(row):
    """Exactly one representation in native CASE: integer sompi and DAA."""
    body=copy.deepcopy(row['transaction']);contexts=row['accepted_input_contexts']
    need(len(body['inputs'])==len(contexts),'complete-populated-contexts')
    for item in body['inputs']:item['sequence']=integer_boundary(item['sequence'])
    for item in body['outputs']:item['value']=integer_boundary(item['value'])
    for name in ('lockTime','gas'):body[name]=integer_boundary(body[name])
    body['mass']=integer_boundary(body.pop('storageMass'))
    entries=[]
    for item,context in zip(body['inputs'],contexts):
        need(context['outpoint']==item['previousOutpoint'],'exact-input-context-outpoint')
        entries.append({'amount':integer_boundary(context['amount_sompi']),
            'scriptPublicKey':context['script_public_key'],'blockDaaScore':integer_boundary(context['block_daa_score']),
            'isCoinbase':context['is_coinbase'],'covenantId':context['covenant_id']})
    return {'transaction':body,'entries':entries}


def runtime_from(a):
    paths={name:getattr(a,name.replace('-','_')) for name in ('crypto','node','native-validator')
           if getattr(a,name.replace('-','_'),None) is not None}
    return Runtime(paths=paths,sdk_dir=getattr(a,'sdk_directory',None))


def replay(a):
    cache_common.authenticate(a);guard=HostPolicy();out=Path(a.output).absolute();need(not out.exists(),'fresh-replay-output');out.mkdir(parents=True,mode=0o700)
    raw={name:guard.read(getattr(a,name),getattr(a,name+'_sha256')) for name in ('selection','descriptor','fetch','assets','parameters')}
    selection=decode(raw['selection'],a.selection_sha256);descriptor=parse(raw['descriptor']);fetch=parse(raw['fetch'])
    need(descriptor['trial_id']==fetch['descriptor']['trial_id'],'actual-trial-descriptor')
    runtime=runtime_from(a);guard.guard([a.codec])
    sdk=runtime.executables['node'].run([HERE/'verify_bundle_cached.mjs',a.selection,a.selection_sha256,
        a.descriptor,a.descriptor_sha256,a.fetch,a.fetch_sha256,a.bundle_directory,out/'SDK-VERIFICATION.json',runtime.sdk_dir,*cache_common.arguments(a)])
    verified=parse(guard.read(out/'SDK-VERIFICATION.json'))
    need(verified['status']=='PUBLIC_EVIDENCE_CONSISTENCY_PASS','retained-full-SDK-history-required')
    rows=fetch['transactions'];need(type(rows) is list and rows,'complete-genesis-and-transition-history')
    cases=[native_case(row) for row in rows]
    first=validate_accepted_genesis(cases[0],selection,descriptor['trial_id'])
    need(first['founding_outpoint']==descriptor['founding_outpoint'] and first['redeem_hex']==descriptor['initial_redeem_hex'],
         'actual-native-funding-CASE-and-descriptor')
    support,history_module,codec_module=modules(guard)
    assets=support.Assets(raw['assets'],a.assets_sha256)
    parameters=parse(raw['parameters']);fields(parameters,{'outer_image_hex32','component_profile_sha256','exit_vk_hex328'},'native-parameters')
    need(assets.tail==selection.tail and parameters['exit_vk_hex328']==assets.relation.parameters['exit'][1]['vk_hex328'],
         'same-selected-native-tail-and-exitVK')
    codec=codec_module.NativeCodec(Path(a.codec),a.codec_sha256)
    genesis={name:first[name] for name in ('state_hex112','reserve_sompi','outpoint_hex36','outputs_hex520','deposit_sompi')}
    transitions=[];observed_fee=0;native_reports=[]
    for index,case in enumerate(cases):
        normalized,metrics=runtime.normalize(case,out/('normalize-'+str(index)))
        need(normalized==case,'accepted-whole-CASE-native-ID-storage-mass')
        report,full_metrics=runtime.validate(case,out/('Full-'+str(index)))
        need(full_metrics==metrics,'whole-CASE-Full-metrics-agree')
        observed_fee+=metrics['actual_fee_sompi'];native_reports.append({'transaction_id':case['transaction']['id'],'metrics':metrics})
        if not index:continue
        _,projection,_,projected=codec_module.project(codec,case,hx(parameters['outer_image_hex32'],32),
            hx(parameters['component_profile_sha256'],32),hx(parameters['exit_vk_hex328'],328))
        mixed=projected['mode']=='mixed';parsed=assets.wire.parse_projection(projection) if mixed else assets.wire.parse_exit_projection(projection)
        remaining=parsed.body.new_reserve
        transition={'kind':'payment' if mixed else 'exit','projection_hex':projection.hex(),
            'successor_outpoint_hex36':case['transaction']['id']+'00000000' if remaining else None}
        if not mixed:transition['proof_hex128']=hx(case['transaction']['inputs'][0]['signatureScript'])[2:130].hex()
        transitions.append(transition)
    last=genesis if not transitions else {'state_hex112':parsed.body.new_state.raw.hex(),'reserve_sompi':remaining,
        'outpoint_hex36':transitions[-1]['successor_outpoint_hex36']}
    checkpoint={key:last[key] for key in ('state_hex112','reserve_sompi','outpoint_hex36')}
    history={'schema':'kpxa-local-private-history/v1','domain_hex32':selection.domain.hex(),
        'genesis':genesis,'transitions':transitions,'head':checkpoint}
    genesis_sha=digest(encoded(genesis));loaded=history_module.load(encoded(history),checkpoint,genesis_sha,assets)
    queries={q['outpoint']['transactionId']+q['outpoint']['index'].to_bytes(4,'little').hex():q for q in fetch['current_view']['queries']}
    current=None
    if loaded.point is not None:
        need(loaded.point.hex() in queries and queries[loaded.point.hex()]['entry'] is not None,'actual-current-reserve-UTXO-required')
        current=queries[loaded.point.hex()]['entry'];need(integer_boundary(current['amount_sompi'])==loaded.reserve
            and current['script_public_key']==assets.wire.state_spk(loaded.state.state(),assets.tail).hex(),
            'actual-current-reserve-amount-and-policy')
    else:need(loaded.reserve==0,'terminal-zero-reserve')
    # Every observed direct exit is checked against its actual native payout output.
    for index,transition in enumerate(transitions,1):
        if transition['kind']!='exit':continue
        projection=assets.wire.parse_exit_projection(bytes.fromhex(transition['projection_hex']));body=projection.body
        paid=cases[index]['transaction']['outputs'][-1]
        need(paid['value']==body.payout and paid['scriptPublicKey']==body.payout_spk.hex(),'actual-native-payout-effect')
    write_new(out/'HISTORY.json',encoded(history)+b'\n',0o400)
    context={'schema':'kpxa-selected-history-context/v1','domain_hex32':selection.domain.hex(),
        'genesis_sha256':genesis_sha,'checkpoint':checkpoint}
    write_new(out/'CONTEXT.json',encoded(context)+b'\n',0o400)
    write_new(out/'CURRENT-ENTRY.json',encoded(current)+b'\n',0o400)
    result={'schema':'kpxa-accepted-native-replay/v1','status':'RECORDED_VALIDATING_NODE_PREFIX_FINANCIAL_AND_NATIVE_PASS',
        'trial_id':descriptor['trial_id'],'selection_sha256':a.selection_sha256,'fetch_sha256':a.fetch_sha256,
        'accepted_transactions':len(cases),'current_checkpoint':checkpoint,'terminal':loaded.point is None,
        'history_sha256':digest(encoded(history)+b'\n'),'context_sha256':digest(encoded(context)+b'\n'),
        'observed_total_fee_sompi':observed_fee,'whole_CASE_native_Full_reports':native_reports,
        'independent_consensus_or_continuous_currentness':False,'submission_performed':False}
    write_new(out/'RESULTS.json',encoded(result)+b'\n',0o400);return result


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('selection','descriptor','fetch','assets','parameters'):
        p.add_argument('--'+name,type=Path,required=True);p.add_argument('--'+name+'-sha256',required=True)
    for name in ('codec','bundle-directory','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--codec-sha256',required=True)
    for name in ('crypto','node','native-validator','sdk-directory'):p.add_argument('--'+name,type=Path)
    cache_common.flags(p)
    return p

if __name__=='__main__':
    p=parser()
    try:print(encoded(replay(p.parse_args())).decode())
    except (ValueError,OSError,KeyError,TypeError):p.exit(2,'complete accepted native replay incomplete\n')
