#!/usr/bin/env python3
"""Frozen pure metadata checks; no module body, archive or Original API executes."""
import ast
import copy
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import runpy
from types import SimpleNamespace

ROOT=Path('/var/tmp/kpi-terminal-audit-two-checker-fix-01')
DATA=Path('/var/tmp/kpi-local-private-payment-01/publication-release/terminal-final-data-01')
CORE='53a8cb735d8063425cdc3e02046e4dcac581806b44cf92c792907619c93abeec'
BRIDGE='137d39dd614134f7f9e94fa3c05468c465777ee1434f6959886b2039425dfefe'
OLD='3e989a03efeeef6054aff924cd007ffb3b669c3e1d1760882c935dc173979d4c'
PRODUCER='fbc565020ec0c4a2adfd787f1805ff40210ebde4fa159cf8a62dd76a61ef5274'
INDEX='29d8ce3354da58afc9b4382a2111e6e44dc3701988374fb9ee4b890c139a3bf1'
PLAN='cf5b6b7c210a2e85abdc76ae0aa17f3ecb70878449429902886728d8cbd2a281'
PREPARATION='826e8359006f0bb9924217247036dd55ff3812dfcb8bec2460c54f7fae116780'
BASE='147bd10d3d901929220d6b082cedc4191c85749186d809b576742600fbf6b8c4'


def definitions(raw,namespace,names=None):
    nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and (names is None or n.name in names)]
    if names is not None:assert {n.name for n in nodes}==set(names)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<frozen-pure-function-definitions>','exec'),namespace)
    return namespace


def main():
    read=runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    # The exact domain is selected from the source's literal, never from an input override.
    raw=read(str(ROOT/'publication_batch_audit_path_fix.py'),CORE)
    tree=ast.parse(raw)
    domain=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign)
                and any(isinstance(t,ast.Name) and t.id=='DOMAIN' for t in n.targets))
    env={'hashlib':hashlib,'json':json,'math':math,'Path':Path,'PurePosixPath':PurePosixPath,
         're':re,'PRODUCER':PRODUCER,'DOMAIN':domain}
    core=definitions(raw,env)
    a=SimpleNamespace(**{k:v for k,v in core.items() if callable(v)})
    exemptions=frozenset(('45ae6cd5110b09466c19de8c1f0cf89ec93f6c0d853f232773801e19bd0d62bd',
        '887573cf53559e969007857cd50284db9948204390389fc6e85dd75644b1241d',
        'fc531fcdb192dba2123bb13a02f78aa019cd5299e6905ad7ab4a5c6afdf481b1'))
    bridge=definitions(read(str(ROOT/'prepare_terminal_audit_two_checker_fix.py'),BRIDGE),
        {'a':a,'EXEMPT_PK_SHAS':exemptions},('scanned_candidate','complete_preparation_checked'))
    old=definitions(read(str(ROOT/'PREIMAGE-publication-batch-audit-3e989.py.txt'),OLD),
        {'fields':core['fields'],'need':core['need'],'uint':core['uint'],'PRODUCER':PRODUCER},
        ('producer_preparation_checked',))
    prep=json.loads(read(str(DATA/'LOCAL-COMPLETE-PREPARATION.json'),PREPARATION))
    index=json.loads(read(str(DATA/'GLOBAL-CANDIDATE-INDEX.json'),INDEX))
    plan=json.loads(read(str(DATA/'BATCH-PLAN.json'),PLAN))
    descriptor=json.loads(read(str(DATA/'BASE-BATCH.json'),BASE))
    assert core['sha'](core['encoded'](index))==INDEX and core['sha'](core['encoded'](plan))==PLAN
    results=[]
    def passed(name):results.append({'name':name,'status':'PASS'})
    def authority(p):return {'source_sha256':PRODUCER,'result':p,'raw_archive_member_aliases_reverified':True}
    def reject(name,call,reason):
        try:call()
        except ValueError as e:
            assert str(e)==reason,(name,str(e),reason)
            passed(name)
        else:raise AssertionError('unexpected-accept:'+name)
    core['index_checked'](index);passed('actual_index_strict_archive_shape')
    core['plan_checked'](plan,index,INDEX);passed('actual_plan_complete_whole_page_partition')
    core['descriptor_checked'](descriptor,plan['batches'][0],index,INDEX,PLAN);passed('actual_BASE_descriptor')
    core['materialization_checked'](prep['base_verification'],plan['batches'][0],descriptor,
        prep['base_verification']['descriptor'],INDEX,PLAN);passed('actual_BASE_materialization_receipt')
    badindex=copy.deepcopy(index);badindex['archive']['path']='other.tar'
    reject('index_cannot_override_canonical_path',lambda:core['index_checked'](badindex),'archive-identity')
    reject('preserved_old_core_reproduces_actual_refusal',
        lambda:old['producer_preparation_checked'](authority(prep),index,INDEX,plan,PLAN),
        'full-producer-output-archive-and-complete-decoded-join')
    checkers={'bridge':lambda p:bridge['complete_preparation_checked'](p,index,plan),
        'core':lambda p:core['producer_preparation_checked'](authority(p),index,INDEX,plan,PLAN)}
    join_reason={'bridge':'complete-producer-count-and-archive-join','core':'full-producer-output-archive-and-complete-decoded-join'}
    field_reason={'bridge':'complete-reviewed-producer-result-required','core':'actual-producer-preparation-fields'}
    mutations=[('archive_wrong_path',('archive','path'),'other.tar'),
        ('archive_traversal',('archive','path'),'../data.tar'),
        ('archive_wrong_bytes',('archive','bytes'),prep['archive']['bytes']+1),
        ('archive_wrong_members',('archive','members'),450),
        ('archive_wrong_sha',('archive','sha256'),'00'*32)]
    for key in ('global_index_sha256','batch_plan_sha256','base_batch_sha256'):
        mutations.append(('wrong_'+key,(key,),'00'*32))
    for key in ('global_candidates','whole_decoded_pages','decoded_batches','decoded_bytes_verified'):
        mutations.append(('wrong_'+key,(key,),prep[key]+1))
    for key in ('decoded_bytes_retained','raw_member_physical_copies_created'):
        mutations.append(('nonzero_'+key,(key,),1))
    mutations += [('supplemental_must_remain_required',('public_descriptor_supplemental_audit_required',),False),
                  ('no_private_execution_marker',('private_original_worker_network_or_publication_executed',),True)]
    for name,check in checkers.items():
        check(prep);passed(name+'_actual_full_producer_record_accepts')
        for label,path,value in mutations:
            p=copy.deepcopy(prep);parent=p
            for key in path[:-1]:parent=parent[key]
            parent[path[-1]]=value
            reject(name+'_'+label,lambda p=p:check(p),join_reason[name])
        p=copy.deepcopy(prep);del p['archive']['path']
        reject(name+'_missing_canonical_path',lambda:check(p),join_reason[name])
        p=copy.deepcopy(prep);p['archive']['extra']=0
        reject(name+'_no_extra_archive_fields',lambda:check(p),join_reason[name])
        p=copy.deepcopy(prep);p['decoded_batches']=True
        reject(name+'_bool_not_integer',lambda:check(p),'exact-nonnegative-integer')
        p=copy.deepcopy(prep);p['extra']=0
        reject(name+'_no_extra_producer_fields',lambda:check(p),field_reason[name])
    for key,value in [('source_sha256','00'*32),('raw_archive_member_aliases_reverified',False)]:
        v=authority(prep);v[key]=value
        reject('core_'+key,lambda v=v:core['producer_preparation_checked'](v,index,INDEX,plan,PLAN),
            'selected-producer-raw-alias-reverification')
    print(json.dumps({'schema':'kpxa-two-producer-checker-pure-controls/v1','status':'PASS','count':len(results),
        'checks':results,'fixed_core_sha256':CORE,'fixed_bridge_sha256':BRIDGE,
        'actual_public_preparation_sha256':PREPARATION,'actual_index_sha256':INDEX,'actual_plan_sha256':PLAN,
        'full_module_import_or_Original_API_or_bulk_or_producer_or_packet_or_worker_executed':False,
        'raw_alias_flag_test_is_metadata_contract_not_a_new_raw_verification':True},sort_keys=True,indent=2))


if __name__=='__main__':main()
