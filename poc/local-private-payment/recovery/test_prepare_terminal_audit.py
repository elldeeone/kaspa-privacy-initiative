"""Public metadata model only. No accepted history/proof, Original or bulk I/O.

The existing producer/scope/native authorities are not replaced in production.
Tests that compose artifacts use explicit metadata identity/gate oracles; they
are evidence about closed selectors/order/joins, not financial validation.
"""
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import publication_batch_audit as a
import prepare_terminal_audit as b
from test_publication_batch_audit import fixture


def base_model():
    # Reuse the exact reviewed path/member/page predicates, without invoking the
    # producer, decoder, terminal preparation or any private/namespace routine.
    import prepare_data_packet_batched as producer
    return producer.pinned_preimage()


def model():
    f=fixture();selected=a.parse(bytes.fromhex(f['coverage']['selection']['raw_hex']))
    roles={name:copy.deepcopy(next(row for row in selected['files'] if row['path']==path))
        for name,path in selected['roles'].items()}
    for row in roles.values():row['kind']='public-metadata'
    fetch=a.parse(bytes.fromhex(f['coverage']['fetch']['raw_hex']))
    for page in [*fetch['pages'],*fetch['current_view']['post_query_delta']['pages']]:
        page.update(request={'known_public_metadata_model':True},encoding='KNOWN_PUBLIC_OPAQUE_PAGE_MODEL')
    candidate={'schema':'kpxa-second-source-candidate/v1','files':[
        {'path':'source/a.py','source':'/known-public/source-a.py','bytes':17,'sha256':'11'*32},
        {'path':'source/b.py','source':'/known-public/source-b.py','bytes':19,'sha256':'22'*32}]}
    request={'schema':'kpxa-terminal-public-audit-bridge-request/v1','domain_hex32':a.DOMAIN,'roles':roles,
        'additional_data_files':[],'publication_candidate':{'path':'/known-public/CANDIDATE.json','sha256':'33'*32},
        'publication_paths':['source/a.py'],'prior_public_files':[],
        'creation_template':{'path':'/known-public/CREATION.json','sha256':'44'*32},
        'canary_assets':f['canary_assets'],'originals':f['originals'],'decoded_budget_bytes':2**30,'run_label':'public-model'}
    return f,roles,fetch,candidate,request


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.base=base_model()

    def test_exact_both_array_page_selection_without_opening_pages(self):
        _,roles,fetch,_,_=model();selected=b.selection_rows(roles,[],fetch,self.base)
        pages=[v for v in selected['files'] if v['kind']=='full-source-page']
        self.assertEqual(len(pages),2)
        self.assertEqual({r['path'] for r in pages},{'chain/a.json.gz','chain/post/b.json.gz'})
        for change in [lambda f:f.pop('pages'),lambda f:f['current_view']['post_query_delta'].pop('pages'),
            lambda f:f['pages'][0].update(path='../private.gz'),lambda f:f['pages'][0].update(gzip_bytes=True),
            lambda f:f['current_view']['post_query_delta']['pages'][0].update(decoded_bytes=True),
            lambda f:f['current_view']['post_query_delta']['pages'].__setitem__(0,copy.deepcopy(f['pages'][0]))]:
            with self.subTest(change=change):
                f=copy.deepcopy(fetch);change(f)
                with self.assertRaises((ValueError,KeyError)):b.selection_rows(roles,[],f,self.base)
        bad=copy.deepcopy(roles);bad['history']['path']=bad['context']['path']
        with self.assertRaises(ValueError):b.selection_rows(bad,[],fetch,self.base)
        bad=copy.deepcopy(roles);bad['fetch']['path']='wrong/fetch.json'
        with self.assertRaises(ValueError):b.selection_rows(bad,[],fetch,self.base)
        with self.assertRaises(ValueError):b.selection_rows(roles,[dict(pages[0])],fetch,self.base)

    def test_metadata_route_needs_supplied_ctime_and_exact_policy(self):
        *_,request=model();self.assertIs(b.request_checked(request),request)
        changes=[lambda v:v['originals'][0].pop('ctime_ns'),lambda v:v['originals'][0].update(ctime_ns=True),
            lambda v:v['originals'][0].update(device=True),lambda v:v['originals'][7].update(expected_second_kind='received'),
            lambda v:v['originals'].pop(),lambda v:v['originals'].__setitem__(0,copy.deepcopy(v['originals'][1])),
            lambda v:v.update(decoded_budget_bytes=True),lambda v:v.update(schema='old-schema')]
        for change in changes:
            with self.subTest(change=change):
                v=copy.deepcopy(request);change(v)
                with self.assertRaises((ValueError,KeyError)):b.request_checked(v)

    def test_publication_subset_and_prior_asset_identity_boundaries(self):
        _,_,_,candidate,_=model()
        prior={'source':'/known-public/PUBLISHED-OPAQUE.bin','path':'published/large-opaque.bin','bytes':3*2**30,'sha256':'55'*32}
        result=b.publication_extras(candidate,['source/a.py'],[prior],self.base)
        self.assertEqual(len(result['files']),2);self.assertEqual(next(r for r in result['files'] if r['source']==prior['source'])['bytes'],3*2**30)
        for paths,assets in [([],[]),(['missing.py'],[]),(['source/a.py']*2,[]),
            (['source/a.py'],[{**prior,'source':'/known-public/exit.pk'}]),
            (['source/a.py'],[{**prior,'path':'published/opaque.pk'}]),
            (['source/a.py'],[{**prior,'source':'/var/tmp/kpi-local-original-metadata-01/ORIGINALS.json'}]),
            (['source/a.py'],[{**prior,'source':str(a.PRIVATE/'controller/STATE.json')}]),
            (['source/a.py'],[{**prior,'source':'/known-public/raw.log'}]),
            (['source/a.py'],[{**prior,'bytes':True}]),
            (['source/a.py'],[{**prior,'path':'publication/source/a.py'}])]:
            with self.subTest(paths=paths,assets=assets):
                with self.assertRaises(ValueError):b.publication_extras(candidate,paths,assets,self.base)

    def test_every_selected_nineteen_case_identity_is_explicit(self):
        accounting={'actual_native_Full_reports':[{'case_path':f'/known-public/case-{i:02d}.json',
            'case_sha256':f'{i+1:064x}'} for i in range(19)]}
        rows=[{'source':r['case_path'],'path':f'evidence/case-{i:02d}.json','bytes':17,
            'sha256':r['case_sha256'],'kind':'public-evidence'} for i,r in enumerate(accounting['actual_native_Full_reports'])]
        b.accounting_case_coverage(accounting,rows)
        for changed in [rows[:-1],rows+[copy.deepcopy(rows[0])],
            [{**r,'sha256':'ff'*32} if i==0 else r for i,r in enumerate(rows)],
            [{**r,'kind':'public-source'} if i==0 else r for i,r in enumerate(rows)]]:
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):b.accounting_case_coverage(accounting,changed)
        changed=copy.deepcopy(accounting);changed['actual_native_Full_reports'][0]['case_path']=changed['actual_native_Full_reports'][1]['case_path']
        with self.assertRaises(ValueError):b.accounting_case_coverage(changed,rows)

    def test_complete_producer_output_not_nested_base_marker(self):
        f=fixture();result=copy.deepcopy(f['batches'][0]['producer_preparation']['result'])
        b.complete_preparation_checked(result,f['index'],f['plan'])
        with self.assertRaises(ValueError):b.complete_preparation_checked(result['base_verification'],f['index'],f['plan'])
        changes=[lambda v:v['archive'].update(sha256='ff'*32),lambda v:v.update(global_candidates=True),
            lambda v:v.update(whole_decoded_pages=1),lambda v:v.update(decoded_bytes_verified=1),
            lambda v:v.update(raw_member_physical_copies_created=1),lambda v:v.update(decoded_bytes_retained=1),
            lambda v:v.update(private_original_worker_network_or_publication_executed=True),
            lambda v:v.update(public_descriptor_supplemental_audit_required=False)]
        for change in changes:
            with self.subTest(change=change):
                v=copy.deepcopy(result);change(v)
                with self.assertRaises(ValueError):b.complete_preparation_checked(v,f['index'],f['plan'])

    def test_scope_keeps_all_twelve_original_roles_and_separate_portable_assets(self):
        f,roles,*_=model();scope=b.accepted_scope(roles)
        self.assertEqual(set(scope['roles']),set(b.ROLES));self.assertEqual(scope['roles']['assets']['mount'],'/public/final-provenance/assets.json')
        self.assertNotEqual(scope['roles']['assets']['sha256'],f['canary_assets']['sha256'])
        self.assertIs(scope['accepted_backing_or_recovery_authority'],False)
        self.assertEqual(scope['candidate_manifest_sha256'],a.sha(a.encoded([])))

    def test_selected_metadata_sha_refusal_precedes_any_materialization(self):
        _,roles,_,_,_=model();row=copy.deepcopy(roles['history']);row['bytes']=3
        with patch.object(b.a,'guarded',return_value=b'{}'):
            with self.assertRaises(ValueError):b.public_read(row,self.base)
        row['source']=str(a.PRIVATE/'BCK/BACKUP.json')
        with patch.object(b.a,'guarded') as read:
            with self.assertRaises(ValueError):b.public_read(row,self.base)
            read.assert_not_called()

    def test_packet_is_exact_reviewed_api_call_with_no_original_arguments(self):
        recipe={'code':{'producer':{'path':'/known-public/fbc.py','sha256':a.PRODUCER}},
            'root_selection':{'path':'/known-public/DATA.json','sha256':'11'*32},
            'base_extras':{'path':'/known-public/EXTRAS.json','sha256':'22'*32},'decoded_budget_bytes':2**30}
        calls=[];result={'KNOWN_PUBLIC_METADATA_API_MODEL':True}
        def prepare(*args):calls.append(args);return result
        with patch.object(b,'recipe_checked',return_value=recipe),patch.object(b,'selected_module',return_value=SimpleNamespace(prepare=prepare)), \
            patch.object(b.a,'save',return_value={'path':'/known-public/result','sha256':'33'*32}) as save:
            out=b.packet({'path':'/known-public/RECIPE.json','sha256':'44'*32},Path('/known-public/PACKET'))
        self.assertEqual(calls,[(Path('/known-public/DATA.json'),'11'*32,Path('/known-public/PACKET'),2**30,Path('/known-public/EXTRAS.json'),'22'*32)])
        self.assertIs(out['actual_Original_worker_executed'],False);self.assertIs(save.call_args.args[1],result)

    def test_each_page_array_byte_omission_fails_selected_metadata_identity(self):
        _,roles,fetch,_,_=model();raw=a.encoded(fetch);row=dict(roles['fetch'],bytes=len(raw),sha256=a.sha(raw))
        for group in ('primary','post'):
            with self.subTest(group=group):
                changed=copy.deepcopy(fetch)
                if group=='primary':changed['pages'].clear()
                else:changed['current_view']['post_query_delta']['pages'].clear()
                def oracle(selector):
                    candidate=a.encoded(changed)
                    if a.sha(candidate)!=selector['sha256']:raise ValueError('public-metadata-SHA-mismatch')
                    return candidate
                with patch.object(b.a,'guarded',side_effect=oracle):
                    with self.assertRaises(ValueError):b.public_read(row,self.base)

    def test_every_role_context_substitution_refused_against_selected_dataset(self):
        f,*_=model()
        for role in b.ROLES:
            with self.subTest(role=role):
                ctx=copy.deepcopy(f['contexts']['actual02']);target=b.role_target(role)
                ctx['scope_document']['roles'][role]['sha256']='ff'*32
                next(r for r in ctx['sources'] if r['mount']==target)['sha256']='ff'*32
                scope=a.encoded(ctx['scope_document'])
                next(r for r in ctx['sources'] if r['mount']=='/public/CANARY-CONTEXT-SCOPE.json').update(bytes=len(scope),sha256=a.sha(scope))
                a.context_checked(ctx)
                with self.assertRaises(ValueError):a.actual_context_checked(ctx,f['coverage'],f['canary_assets'])

    def test_public_gate_refusal_before_any_packet_or_output(self):
        _,roles,fetch,_,request=model();docs={}
        for role,row in roles.items():
            raw=a.encoded(fetch if role=='fetch' else {'known_public_metadata_only':role})
            row.update(bytes=len(raw),sha256=a.sha(raw));docs[row['source']]=raw
        request_row={'path':'/known-public/REQUEST.json','sha256':a.sha(a.encoded(request))};docs[request_row['path']]=a.encoded(request)
        def oracle(row):
            raw=docs[row['path']]
            if a.sha(raw)!=row['sha256']:raise ValueError('identity')
            return raw
        base=dict(self.base)
        def refuse(*_):raise ValueError('KNOWN_PUBLIC_NONTERMINAL_GATE')
        base['terminal_shape']=refuse
        producer=SimpleNamespace(pinned_preimage=lambda:base,prepare=lambda *_:(_ for _ in ()).throw(AssertionError('packet must not run')))
        launcher=SimpleNamespace(final_scope=lambda *_:(_ for _ in ()).throw(AssertionError('scope must not run')))
        with patch.object(b,'code_rows',return_value={'producer':{},'launcher':{}}),             patch.object(b,'selected_module',side_effect=[producer,launcher]),             patch.object(b.a,'guarded',side_effect=oracle),patch.object(b,'fresh_output') as write:
            with self.assertRaisesRegex(ValueError,'KNOWN_PUBLIC_NONTERMINAL_GATE'):b.selectors(request_row,Path('/known-public/out'))
            write.assert_not_called()

    def test_plan_uses_complete_preparation_and_only_public_old_loader(self):
        f=fixture();prep=copy.deepcopy(f['batches'][0]['producer_preparation']['result'])
        selector={'path':'/known-public/PREP.json','sha256':a.sha(a.encoded(prep))}
        recipe={'code':{k:{'path':'/known-public/'+k+'.py','sha256':'aa'*32} for k in ('producer','launcher','prepared_launcher','positive_worker','controller')},
            'root_selection':f['coverage']['selection']['row'],'base_extras':{'path':'/known-public/EXTRAS.json','sha256':'bb'*32},
            'canary_assets':f['canary_assets'],'originals':f['originals'],'decoded_budget_bytes':f['plan']['operator_decoded_budget_bytes'],
            'run_label':'metadata-model','context_templates':{k:{'path':'/known-public/'+k+'.json','sha256':'cc'*32} for k in ('creation','actual02')}}
        docs={selector['path']:a.encoded(prep),'/known-public/GLOBAL-CANDIDATE-INDEX.json':a.encoded(f['index']),
            '/known-public/BATCH-PLAN.json':a.encoded(f['plan']),'/known-public/BASE-BATCH.json':a.encoded(f['batches'][0]['descriptor'])}
        calls=[];saved=[]
        def save(path,v):
            saved.append(v);return {'path':str(path),'sha256':a.sha(a.encoded(v))}
        with patch.object(b,'recipe_checked',return_value=recipe),patch.object(b.a,'guarded',side_effect=lambda row:docs[row['path']]),             patch.object(b,'fresh_output',return_value=Path('/known-public/OUT')),patch.object(b.a,'save',side_effect=save),             patch.object(b,'selected_module',return_value=SimpleNamespace(load_plan=lambda row:calls.append(row))):
            result=b.plan({'path':'/known-public/RECIPE.json','sha256':'dd'*32},selector,Path('/known-public/OUT'))
        self.assertEqual(len(calls),1);self.assertEqual(saved[0]['base_materialization'],selector)
        self.assertEqual(saved[0]['context_templates'],recipe['context_templates'])
        self.assertIs(result['actual_Original_worker_executed'],False)
        self.assertIs(result['Original_content_or_metadata_discovered'],False)


    def test_recipe_cannot_substitute_request_routes_pages_sources_or_assets(self):
        for change in ('none','route','assets','budget','creation','page','publication','static','role','scope','code','terminal-gate','case-gate'):
            with self.subTest(change=change):
                f,roles,fetch,candidate,request=model();docs={}
                fetch_raw=a.encoded(fetch);roles['fetch'].update(bytes=len(fetch_raw),sha256=a.sha(fetch_raw));docs[roles['fetch']['source']]=fetch_raw
                request['publication_candidate']['sha256']=a.sha(a.encoded(candidate));docs[request['publication_candidate']['path']]=a.encoded(candidate)
                creation={'schema':'kpxa-publication-audit-release/v1','domain_hex32':a.DOMAIN,'files':[],
                    'sources':f['contexts']['creation']['sources']}
                request['creation_template']['sha256']=a.sha(a.encoded(creation));docs[request['creation_template']['path']]=a.encoded(creation)
                request_row={'path':'/known-public/REQUEST.json','sha256':a.sha(a.encoded(request))};docs[request_row['path']]=a.encoded(request)
                dataset=b.selection_rows(roles,[],fetch,self.base)
                extras=b.publication_extras(candidate,request['publication_paths'],[],self.base)
                static=[r for r in creation['sources'] if r['mount'] not in ('/public/HISTORY.json','/public/CONTEXT.json','/public/CANARY-CONTEXT-SCOPE.json')]
                scope=b.accepted_scope(roles)
                actual={'schema':'kpxa-publication-audit-release/v1','domain_hex32':a.DOMAIN,'files':[],
                    'sources':copy.deepcopy(static)+[{'source':r['source'],'mount':b.role_target(k),'bytes':r['bytes'],'sha256':r['sha256'],'mode':'0400'} for k,r in roles.items()]+[
                        {'source':'/known-public/SCOPE.json','mount':'/public/CANARY-CONTEXT-SCOPE.json','bytes':len(a.encoded(scope)),'sha256':a.sha(a.encoded(scope)),'mode':'0400'}]}
                code={'producer':{'path':'/known-public/producer.py','sha256':a.PRODUCER},'launcher':{'path':'/known-public/launcher.py','sha256':a.LAUNCHER}}
                recipe={'schema':'kpxa-terminal-public-audit-recipe/v1','request':request_row,'code':copy.deepcopy(code),
                    'root_selection':{'path':'/known-public/DATA.json','sha256':'11'*32},'base_extras':{'path':'/known-public/EXTRAS.json','sha256':'22'*32},
                    'context_templates':{'creation':request['creation_template'],'actual02':{'path':'/known-public/ACTUAL.json','sha256':'33'*32}},
                    'canary_assets':copy.deepcopy(request['canary_assets']),'originals':copy.deepcopy(request['originals']),
                    'decoded_budget_bytes':request['decoded_budget_bytes'],'run_label':request['run_label']}
                if change=='route':recipe['originals'][0]['inode']+=100
                if change=='assets':recipe['canary_assets']['sha256']='ff'*32
                if change=='budget':recipe['decoded_budget_bytes']+=1
                if change=='creation':recipe['context_templates']['creation']={'path':'/known-public/other.json','sha256':'ff'*32}
                if change=='page':dataset['files'].pop()
                if change=='publication':extras['files'].clear()
                if change=='static':actual['sources'][0]['source']='/known-public/other-source.py'
                if change=='role':next(r for r in actual['sources'] if r['mount']=='/public/HISTORY.json')['sha256']='ff'*32
                if change=='scope':actual['sources'][-1]['sha256']='ff'*32
                if change=='code':recipe['code']['producer']['sha256']='ff'*32
                for selector,data in [(recipe['root_selection'],dataset),(recipe['base_extras'],extras),(recipe['context_templates']['actual02'],actual)]:
                    raw=a.encoded(data);selector['sha256']=a.sha(raw);docs[selector['path']]=raw
                recipe_row={'path':'/known-public/RECIPE.json','sha256':a.sha(a.encoded(recipe))};docs[recipe_row['path']]=a.encoded(recipe)
                def oracle(row):
                    raw=docs[row['path']]
                    if a.sha(raw)!=row['sha256']:raise ValueError('metadata identity')
                    return raw
                with patch.object(b,'code_rows',return_value=code),patch.object(b.a,'guarded',side_effect=oracle),                     patch.object(b,'selected_module',return_value=SimpleNamespace(pinned_preimage=lambda:self.base)), \
                    patch.object(b,'metadata_documents',**({'side_effect':ValueError('known-nonterminal-gate')} if change=='terminal-gate' else {'return_value':({}, {'fetch':fetch,'accounting':{}})})) as gate, \
                    patch.object(b,'accounting_case_coverage',**({'side_effect':ValueError('known-missing-case')} if change=='case-gate' else {'return_value':None})):
                    if change=='none':self.assertEqual(b.recipe_checked(recipe_row),recipe)
                    else:
                        with self.assertRaises(ValueError):b.recipe_checked(recipe_row)


    def test_exact_exempt_PK_shas_and_raw_PK_targets_refused_without_key_IO(self):
        _,roles,_,candidate,_=model()
        for sha in sorted(b.EXEMPT_PK_SHAS):
            with self.subTest(sha=sha):
                renamed={'source':'/known-public/renamed.bin','path':'public/renamed.bin','bytes':1,'sha256':sha}
                with self.assertRaises(ValueError):b.publication_extras(candidate,['source/a.py'],[renamed],self.base)
                data={**renamed,'kind':'public-evidence'}
                with self.assertRaises(ValueError):b.data_file(data,self.base)
                changed=copy.deepcopy(candidate);changed['files'][0].update(sha256=sha,bytes=1)
                with self.assertRaises(ValueError):b.publication_extras(changed,['source/a.py'],[],self.base)
        ordinary={'source':'/known-public/ordinary.bin','path':'public/ordinary.bin','bytes':3*2**30,'sha256':'55'*32}
        self.assertEqual(next(r for r in b.publication_extras(candidate,['source/a.py'],[ordinary],self.base)['files'] if r['source']==ordinary['source']),ordinary)
        with self.assertRaises(ValueError):b.data_file({**ordinary,'path':'public/ordinary.pk','kind':'public-evidence'},self.base)

    def test_metadata_helper_repeats_all_original_public_gates_in_order(self):
        _,roles,_,_,request=model();docs={}
        for key,row in roles.items():
            raw=a.encoded({'KNOWN_PUBLIC_METADATA_MODEL':key});row.update(bytes=len(raw),sha256=a.sha(raw));docs[row['source']]=raw
        calls=[];base=dict(self.base);base['terminal_shape']=lambda d,r:calls.append('terminal')
        launcher=SimpleNamespace(final_scope=lambda *_:calls.append('scope'))
        def oracle(row):
            raw=docs[row['path']]
            if a.sha(raw)!=row['sha256']:raise ValueError('metadata identity')
            return raw
        with patch.object(b.a,'guarded',side_effect=oracle),patch.object(b,'accounting_join',side_effect=lambda *_:calls.append('accounting')):
            raw,parsed=b.metadata_documents(request,base,launcher)
        self.assertEqual(calls,['terminal','accounting','scope']);self.assertEqual(len(raw),12);self.assertEqual(len(parsed),12)
        # This is an API delegation oracle, not an accepted-ledger fixture.


    def test_known_PK_identity_cannot_enter_either_decoded_array_or_global_index(self):
        for sha in sorted(b.EXEMPT_PK_SHAS):
            for group in ('primary','post','global'):
                with self.subTest(sha=sha,group=group):
                    if group=='global':
                        f=fixture();f['index']['candidates'][-1]['sha256']=sha
                        with self.assertRaisesRegex(ValueError,'exact-setup-PK-exemption'):
                            b.complete_preparation_checked(f['batches'][0]['producer_preparation']['result'],f['index'],f['plan'])
                    else:
                        _,roles,fetch,_,_=model()
                        records=fetch['pages'] if group=='primary' else fetch['current_view']['post_query_delta']['pages']
                        records[0]['decoded_sha256']=sha;records[0]['decoded_bytes']=1
                        with self.assertRaisesRegex(ValueError,'exact-setup-PK-exemption'):
                            b.selection_rows(roles,[],fetch,self.base)



if __name__=='__main__':unittest.main()
