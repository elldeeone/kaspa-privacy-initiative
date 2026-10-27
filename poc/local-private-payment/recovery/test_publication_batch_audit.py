"""Public synthetic joins only: no Original stat, byte read, worker, or network."""
import copy
import unittest

import publication_batch_audit as a

H = '12' * 32
PREPARED = '80bc8027ccda4ae8178254413e92de27980581d9e9cc43d77482563c518f8953'


def snapshot(path, value):
    raw = a.encoded(value)
    return {'row': {'path': path, 'sha256': a.sha(raw)}, 'raw_hex': raw.hex()}


def context(cohort):
    scope = {'schema': 'kpxa-canary-final-accepted-history-context/v1',
             'candidate_manifest_sha256': H, 'roles': {'synthetic_public_scope': H}} if cohort == 'actual02' else {
             'schema': 'kpxa-canary-nonchain-creation-context/v1', 'synthetic_public_scope': True}
    rows = []
    for name, pin in [('recovery/publication_literal.py', a.LITERAL),
                      ('recovery/publication_derived.py', a.DERIVED),
                      ('ASSETS.json', '21'*32), ('HISTORY.json', ('31' if cohort == 'creation' else '32')*32),
                      ('CONTEXT.json', ('41' if cohort == 'creation' else '42')*32)]:
        rows.append({'source': '/known-public/' + cohort + '/' + name, 'mount': '/public/' + name,
                     'bytes': 17, 'sha256': pin, 'mode': '0400'})
    raw = a.encoded(scope)
    rows.append({'source': '/known-public/' + cohort + '/SCOPE.json', 'mount': '/public/CANARY-CONTEXT-SCOPE.json',
                 'bytes': len(raw), 'sha256': a.sha(raw), 'mode': '0400'})
    return {'sources': rows, 'scope_document': scope}


def release(files, ctx, bid, cohort):
    scope = a.encoded(a.batch_scope(ctx, files));sources = copy.deepcopy(ctx['sources'])
    for row in sources:
        if row['mount'] == '/public/CANARY-CONTEXT-SCOPE.json':
            row.update(source='/LOCAL-UNPUBLISHED/' + bid + '/' + cohort + '-scope.json',
                       bytes=len(scope), sha256=a.sha(scope))
    value = {'schema': 'kpxa-publication-audit-release/v1', 'domain_hex32': a.DOMAIN, 'files': files, 'sources': sources}
    return {'release': value, 'row': {'path': '/LOCAL-UNPUBLISHED/' + bid + '/' + cohort + '-release.json',
                                     'sha256': a.sha(a.encoded(value))}}


def worker(kind, files):
    value = {'schema': 'kpxa-' + ('literal-seed-export' if kind == 'literal' else 'derived-export') + '-result/v1',
        'status': 'PASS', 'candidate_count': len(files)+1,
        'candidate_bytes': sum(f['bytes'] for f in files)+len(a.encoded({'schema':
            'kpx8-new-owner-seed-export-allowlist/v1' if kind=='literal' else 'kpxa-derived-export-candidates/v1',
            'files':a.candidate_manifest(files)})),
        'matched_candidate_count': 0, 'scope': 'LITERAL_SEED_CANARY_ONLY_NOT_SECURITY_OR_PRIVACY_PROOF' if kind == 'literal'
            else 'FINITE_RECOVERABLE_DERIVED_BYTES_ONLY_NOT_ALL_SECRETS_OR_PRIVACY_PROOF'}
    if kind == 'derived':value['literal_seed_coverage'] = False
    return value


def preparation(files,releases):
    return {'source_sha256':PREPARED,'provenance':{
        'schema':'kpxa-prepared-publication-public-admission/v1','base_launcher_sha256':a.LAUNCHER,
        'prepared_launcher_source_sha256':PREPARED,'candidate_manifest_sha256':a.sha(a.encoded(a.candidate_manifest(files))),
        'candidate_files':len(files),'candidate_bytes':sum(f['bytes'] for f in files),
        'context_releases':{k:r['row']['sha256'] for k,r in releases.items()},
        'large_direct_readonly_views':sum(f['bytes']>=1024*1024 for f in files),
        'small_candidate_staged_bytes':sum(f['bytes'] for f in files if f['bytes']<1024*1024),
        'public_source_stage_bytes':sum(f['bytes'] for r in releases.values() for f in r['release']['sources']),
        'largest_transient_candidate_bytes':max(f['bytes'] for f in files),
        'public_candidate_set_admitted_once':True,'public_PASS_markers_used_as_authority':False,
        'sealed_storage_or_hostile_host_protection':False,'trusted_host_no_concurrent_mutation_required':True,
        'worker_whole_candidate_authentication_before_each_private_read':True,
        'original_content_read_or_hashed_by_preparer':False,'original_fds_opened_or_cached_by_preparer':False,
        'public_admission_wall_seconds':1.25}}


def invocation(original, record, contexts, ix, pl):
    cohort = original['cohort'];rel = record['releases'][cohort];files = record['descriptor']['files']
    summary = {'schema': 'kpxa-one-leaf-publication-audit/v1', 'release_sha256': rel['row']['sha256'],
        'candidate_manifest_sha256': a.sha(a.encoded(a.candidate_manifest(files))),
        'candidate_file_count': len(files), 'candidate_bytes': sum(f['bytes'] for f in files),
        'source_files': len(rel['release']['sources']), 'literal_status': 'PASS', 'derived_status': 'PASS',
        'actual_original_check_executed': True, 'one_original_leaf_read_only_per_namespace': True,
        'parent_sibling_root_or_home_mounted': False, 'original_content_read_or_hashed_by_controller': False,
        'literal_and_derived_are_separate': True, 'private_values_paths_hashes_or_indices_exported': False,
        'future_material_covered': False, 'context_kind': 'ACCEPTED_HISTORY' if cohort == 'actual02' else 'NONCHAIN_CREATION_ONLY',
        'own_historical_payout_keys_checked': cohort == 'actual02'}
    return {'schema': 'kpxa-publication-batch-audit-invocation/v1', 'global_index_sha256': ix,
        'batch_plan_sha256': pl, 'batch_id': record['descriptor']['batch_id'],
        'batch_descriptor': record['descriptor_row'], 'original': copy.deepcopy(original), 'release': rel['row'],
        'launcher_sha256': a.LAUNCHER, 'source_core_sha256': a.sha(a.encoded(a.core_sources(contexts[cohort]['sources']))),
        'scope_sha256': a.sources_checked(rel['release']['sources'])['/public/CANARY-CONTEXT-SCOPE.json']['sha256'],
        'prepared_launcher_sha256':PREPARED,
        'public_preparation_sha256':a.sha(a.encoded(record['preparation']['provenance'])),
        'summary': summary, 'workers': {k: worker(k, files) for k in ('literal', 'derived')},
        'worker_receipts': {k:{**worker(k,files),'sha256':a.sha(a.encoded(worker(k,files))),
            'bytes':len(a.encoded(worker(k,files))),
            'candidate_manifest_sha256':summary['candidate_manifest_sha256']} for k in ('literal','derived')}}


def fixture():
    roles = ['terminalhandoff', 'activation', 'history', 'context', 'currententry', 'replayresults',
             'fetch', 'selection', 'descriptor', 'assets', 'parameters', 'accounting']
    pages = [{'path': 'a.json.gz', 'gzip_bytes': 8, 'gzip_sha256': '51'*32, 'decoded_bytes': 64, 'decoded_sha256': '61'*32},
             {'path': 'post/b.json.gz', 'gzip_bytes': 9, 'gzip_sha256': '52'*32, 'decoded_bytes': 80, 'decoded_sha256': '62'*32}]
    fetch = {'schema': 'kpxa-gn3-network-fetch/v1', 'pages': pages[:1],
             'current_view': {'post_query_delta': {'pages': pages[1:]}}}
    fs = snapshot('/known-public/fetch.json', fetch)
    files = [];role_paths = {}
    for role in roles:
        path = 'chain/fetch.json' if role == 'fetch' else 'metadata/' + role + '.json';role_paths[role] = path
        files.append({'source': fs['row']['path'] if role == 'fetch' else '/known-public/' + path,
            'path': path, 'bytes': len(bytes.fromhex(fs['raw_hex'])) if role == 'fetch' else 17,
            'sha256': fs['row']['sha256'] if role == 'fetch' else H, 'kind': 'metadata'})
    for page in pages:files.append({'source': '/known-public/' + page['path'], 'path': 'chain/' + page['path'],
        'bytes': page['gzip_bytes'], 'sha256': page['gzip_sha256'], 'kind': 'full-source-page'})
    selection = {'schema': 'kpxa-root-public-recovery-data-selection/v1', 'domain_hex32': a.DOMAIN,
                 'roles': role_paths, 'files': files}
    ss = snapshot('/known-public/ROOT-SELECTION.json', selection)
    inventory = {'schema': 'kpxa-public-recovery-data-inventory/v1', 'domain_hex32': a.DOMAIN,
        'files': [{k: f[k] for k in ('path', 'bytes', 'sha256', 'kind')} for f in files],
        'file_count': len(files), 'payload_bytes': sum(f['bytes'] for f in files)}
    inv = snapshot('/known-public/packet/DATA-INVENTORY.json', inventory)
    packet = {'schema': 'kpxa-public-recovery-data-packet/v1', 'domain_hex32': a.DOMAIN,
        'archive': {'bytes': 10240, 'sha256': '71'*32, 'members': len(files)+1},
        'roles': {role: {k: next(f for f in files if f['path'] == path)[k] for k in ('path', 'bytes', 'sha256')}
                  for role, path in role_paths.items()},
        'pages': [{'packet_path': 'chain/'+p['path'], **{k:p[k] for k in ('gzip_bytes','gzip_sha256','decoded_bytes','decoded_sha256')}} for p in pages]}
    pkt = snapshot('/known-public/packet/PACKET.json', packet)
    raw = []
    for name, size, pin in [('data.tar',10240,'71'*32),('PACKET.json',len(bytes.fromhex(pkt['raw_hex'])),pkt['row']['sha256']),
                          ('DATA-INVENTORY.json',len(bytes.fromhex(inv['raw_hex'])),inv['row']['sha256']),('SHA256SUMS',128,'81'*32)]:
        raw.append({'path':'raw/'+name,'bytes':size,'sha256':pin,'kind':'raw','source':'/known-public/packet/'+name,'gzip':None})
    for f in files:raw.append({'path':'members/'+f['path'],'bytes':f['bytes'],'sha256':f['sha256'],'kind':'raw','source':f['source'],'gzip':None})
    raw.append({'path':'members/DATA-INVENTORY.json','bytes':len(bytes.fromhex(inv['raw_hex'])),
                'sha256':inv['row']['sha256'],'kind':'raw','source':inv['row']['path'],'gzip':None})
    decoded = [{'path':'decoded-gzip/chain/'+p['path'],'bytes':p['decoded_bytes'],'sha256':p['decoded_sha256'],
        'kind':'decoded','source':None,'gzip':{'source':'/known-public/'+p['path'],'bytes':p['gzip_bytes'],'sha256':p['gzip_sha256']}} for p in pages]
    candidates = sorted(raw,key=lambda f:f['path'])+decoded
    candidates = [{'index':n,**v} for n,v in enumerate(candidates)]
    index = {'schema':'kpxa-publication-global-candidate-index/v1','domain_hex32':a.DOMAIN,
        'root_selection_sha256':ss['row']['sha256'],'archive':{'bytes':10240,'sha256':'71'*32},'candidates':candidates}
    ix = a.sha(a.encoded(index));rn=len(raw)
    plan = {'schema':'kpxa-publication-whole-page-batch-plan/v1','domain_hex32':a.DOMAIN,'global_index_sha256':ix,
        'operator_decoded_budget_bytes':100,'batches':[{'batch_id':'BASE','candidate_indices':list(range(rn)),
        'bytes':sum(f['bytes'] for f in raw)}, {'batch_id':'D000001','candidate_indices':[rn],'bytes':64},
        {'batch_id':'D000002','candidate_indices':[rn+1],'bytes':80}]}
    pl=a.sha(a.encoded(plan));contexts={c:context(c) for c in ('creation','actual02')};records=[]
    actual=contexts['actual02'];actual['scope_document']['roles']={}
    for name,path in role_paths.items():
        f=next(f for f in selection['files'] if f['path']==path)
        mount='/public/'+name.upper()+'.json' if name in ('history','context') else '/public/final-provenance/'+name+'.json'
        actual['scope_document']['roles'][name]={'mount':mount,'sha256':f['sha256']}
        old=next((r for r in actual['sources'] if r['mount']==mount),None)
        if old is None:actual['sources'].append({'source':f['source'],'mount':mount,'bytes':f['bytes'],'sha256':f['sha256'],'mode':'0400'})
        else:old.update(source=f['source'],bytes=f['bytes'],sha256=f['sha256'])
    scope_raw=a.encoded(actual['scope_document'])
    next(r for r in actual['sources'] if r['mount']=='/public/CANARY-CONTEXT-SCOPE.json').update(bytes=len(scope_raw),sha256=a.sha(scope_raw))
    canary_assets={k:a.sources_checked(actual['sources'])['/public/ASSETS.json'][k] for k in ('source','bytes','sha256')}
    for batch in plan['batches']:
        files=[{'source':candidates[n]['source'] or '/dev/shm/known-public/'+str(n),
            **{k:candidates[n][k] for k in ('path','bytes','sha256')}} for n in batch['candidate_indices']]
        desc={'schema':'kpxa-publication-audit-batch/v1','domain_hex32':a.DOMAIN,'global_index_sha256':ix,
            'batch_plan_sha256':pl,'batch_id':batch['batch_id'],'candidate_indices':batch['candidate_indices'],'files':files}
        dr={'path':'/known-public/'+batch['batch_id']+'-BATCH.json','sha256':a.sha(a.encoded(desc))}
        proof={'schema':'kpxa-publication-batch-materialization/v1','global_index_sha256':ix,
            'batch_plan_sha256':pl,'batch_id':batch['batch_id'],'descriptor':dr,'verified_candidate_indices':batch['candidate_indices'],
            'whole_decoded_pages':batch['batch_id']!='BASE','gzip_and_decoded_identities_verified':True}
        if batch['batch_id']=='BASE':proof['raw_archive_and_member_aliases_verified']=True
        records.append({'descriptor':desc,'descriptor_row':dr,'materialization':proof,
            'releases':{c:release(files,contexts[c],batch['batch_id'],c) for c in contexts}})
        records[-1]['preparation']=preparation(files,records[-1]['releases'])
        records[-1]['producer_preparation']=None
    records[0]['producer_preparation']={'source_sha256':a.PRODUCER,'raw_archive_member_aliases_reverified':True,
        'result':{'schema':'kpxa-public-recovery-data-batched-preparation/v1','archive':packet['archive'],
            'global_index_sha256':ix,'batch_plan_sha256':pl,'base_batch_sha256':records[0]['descriptor_row']['sha256'],
            'global_candidates':len(candidates),'base_verification':copy.deepcopy(records[0]['materialization']),
            'whole_decoded_pages':2,'decoded_batches':2,'decoded_bytes_verified':144,'decoded_bytes_retained':0,
            'raw_member_physical_copies_created':0,'public_descriptor_supplemental_audit_required':True,
            'private_original_worker_network_or_publication_executed':False}}
    meta=[{'source':x['descriptor_row']['path'],'path':'public-meta/'+str(n)+'.json',
           'bytes':len(a.encoded(x['descriptor'])),'sha256':x['descriptor_row']['sha256']} for n,x in enumerate(records)]
    for name,doc,pin in [('INDEX',index,ix),('PLAN',plan,pl)]:meta.append({'source':'/known-public/'+name+'.json',
        'path':'public-meta/'+name+'.json','bytes':len(a.encoded(doc)),'sha256':pin})
    stage={'batch_id':'DESCRIPTORS','files':meta,'required_public_metadata':{
        'index':{'path':'/known-public/INDEX.json','sha256':ix},'plan':{'path':'/known-public/PLAN.json','sha256':pl}},
        'releases':{c:release(meta,contexts[c],'DESCRIPTORS',c) for c in contexts}}
    stage['supplemental_public_metadata']=[]
    sr=a.sha(a.encoded(stage));stage['release_sha256']=sr
    stage['preparation']=preparation(meta,stage['releases'])
    ds={'descriptor':{'schema':'kpxa-publication-audit-batch/v1','domain_hex32':a.DOMAIN,'global_index_sha256':ix,
        'batch_plan_sha256':pl,'batch_id':'DESCRIPTORS','candidate_indices':[],'files':meta},
        'descriptor_row':{'path':'/LOCAL-UNPUBLISHED/DESCRIPTORS','sha256':sr},'releases':stage['releases'],
        'preparation':stage['preparation']}
    originals=[]
    for n in range(1,10):originals.append({'original_id':'O'+str(n).zfill(2),'cohort':'creation' if n<7 else 'actual02',
        'path':str(a.PRIVATE/'KNOWN-PUBLIC-MODEL'/str(n)/'BACKUP.json'),'device':1,'inode':100+n,'bytes':168,'ctime_ns':100000+n,
        'expected_second_kind':None if n<7 else 'change' if n==8 else 'received'})
    jobs=[invocation(o,r,contexts,ix,pl) for r in [*records,ds] for o in originals]
    positives=[{'schema':'kpxa-publication-batch-positive-invocation/v1','global_index_sha256':ix,'batch_plan_sha256':pl,
        'original':copy.deepcopy(o),'source_core_sha256':a.sha(a.encoded(a.core_sources(contexts['actual02']['sources']))),
        'positive_source_sha256':a.POSITIVE,'result':{'schema':'kpxa-own-final-workload-and-exit-key-attestation/v1','status':'PASS',
        'approved_own_workload_matched':True,'approved_historical_exit_key_coverage':True}} for o in originals if o['cohort']=='actual02']
    return dict(index=index,index_sha=ix,plan=plan,plan_sha=pl,originals=originals,contexts=contexts,batches=records,
        descriptor_stage=stage,invocations=jobs,positives=positives,descriptor_release_sha=sr,
        coverage={'selection':ss,'fetch':fs,'packet':pkt,'inventory':inv,'extra_files':[]},canary_assets=canary_assets,prepared_source_sha=PREPARED)


class Controls(unittest.TestCase):
    def test_complete_public_model(self):
        value=a.aggregate(**fixture())
        self.assertTrue(value['every_nine_originals_every_batch_literal_and_derived_passed'])
        self.assertTrue(value['descriptor_stage_checked'])
        self.assertNotIn('originals',value)

    def test_grid_source_context_and_result_negatives(self):
        changes={
            'missing-original-batch':lambda f:f['invocations'].pop(),
            'duplicate-original-batch':lambda f:f['invocations'].__setitem__(-1,copy.deepcopy(f['invocations'][0])),
            'foreign-batch':lambda f:f['invocations'][0].update(batch_id='D999999'),
            'wrong-original':lambda f:f['invocations'][0]['original'].update(inode=9999),
            'wrong-launcher':lambda f:f['invocations'][0].update(launcher_sha256=H),
            'wrong-prepared-source':lambda f:f['invocations'][0].update(prepared_launcher_sha256=H),
            'wrong-prepared-receipt':lambda f:f['invocations'][0].update(public_preparation_sha256=H),
            'false-sealed-storage-claim':lambda f:f['batches'][0]['preparation']['provenance'].update(sealed_storage_or_hostile_host_protection=True),
            'public-PASS-cache-authority':lambda f:f['batches'][0]['preparation']['provenance'].update(public_PASS_markers_used_as_authority=True),
            'unbound-producer-source':lambda f:f['batches'][0]['producer_preparation'].update(source_sha256=H),
            'wrong-producer-archive':lambda f:f['batches'][0]['producer_preparation']['result']['archive'].update(sha256=H),
            'raw-archive-not-rechecked':lambda f:f['batches'][0]['producer_preparation'].update(raw_archive_member_aliases_reverified=False),
            'partial-producer-page-coverage':lambda f:f['batches'][0]['producer_preparation']['result'].update(decoded_bytes_verified=64),
            'worker-receipt-bool-alias':lambda f:f['invocations'][0]['worker_receipts']['literal'].update(matched_candidate_count=False),
            'worker-receipt-SHA-substitution':lambda f:f['invocations'][0]['worker_receipts']['literal'].update(sha256=H),
            'Original-metadata-bool-alias':lambda f:f['invocations'][0]['original'].update(device=True),
            'wrong-local-manifest-vs-global':lambda f:f['invocations'][0]['summary'].update(candidate_manifest_sha256=f['index_sha']),
            'suppressed-derived-result':lambda f:f['invocations'][0]['workers'].pop('derived'),
            'matched-secret':lambda f:f['invocations'][0]['workers']['literal'].update(matched_candidate_count=1),
            'false-worker-PASS':lambda f:f['invocations'][0]['workers']['derived'].update(status='FAIL'),
            'bool-count':lambda f:f['invocations'][0]['workers']['derived'].update(candidate_count=True),
            'changed-source-context':lambda f:f['invocations'][0].update(source_core_sha256=H),
            'changed-scope':lambda f:f['invocations'][0].update(scope_sha256=H),
            'missing-decoded-verification':lambda f:f['batches'][1]['materialization'].pop('gzip_and_decoded_identities_verified'),
            'false-decoded-verification':lambda f:f['batches'][1]['materialization'].update(gzip_and_decoded_identities_verified=False),
            'partial-decoded-indices':lambda f:f['batches'][1]['materialization'].update(verified_candidate_indices=[]),
            'missing-raw-alias-verification':lambda f:f['batches'][0]['materialization'].update(raw_archive_and_member_aliases_verified=False),
            'wrong-descriptor-release':lambda f:f.update(descriptor_release_sha=H),
            'missing-descriptor-Original':lambda f:f['invocations'].pop(-3),
            'duplicate-descriptor-file':lambda f:f['descriptor_stage']['files'].append(copy.deepcopy(f['descriptor_stage']['files'][0])),
            'omitted-positive':lambda f:f['positives'].pop(),
            'duplicate-positive':lambda f:f['positives'].__setitem__(-1,copy.deepcopy(f['positives'][0])),
            'positive-H-C-context-substitution':lambda f:f['positives'][0].update(source_core_sha256=H),
            'positive-bool-alias':lambda f:f['positives'][0]['result'].update(approved_historical_exit_key_coverage=1),
            'wrong-positive-worker':lambda f:f['positives'][0].update(positive_source_sha256=H),
            'wrong-global-index-SHA':lambda f:f.update(index_sha=H),
            'wrong-plan-SHA':lambda f:f.update(plan_sha=H),
            'wrong-external-portable-assets':lambda f:f['canary_assets'].update(sha256=H),
            'wrong-received-change-distribution':lambda f:f['originals'][7].update(expected_second_kind='received'),
        }
        for name,change in changes.items():
            with self.subTest(name=name):
                f=fixture();change(f)
                with self.assertRaises((ValueError,KeyError,TypeError)):a.aggregate(**f)

    def test_global_coverage_cannot_omit_postpage_with_self_consistent_new_index(self):
        f=fixture();index=copy.deepcopy(f['index']);index['candidates'].pop()
        # The new index remains structurally valid; its fresh digest is not
        # authority to omit the Root-selected post-query decoded page.
        a.index_checked(index)
        with self.assertRaises(ValueError):a.coverage_checked(f['coverage'],index)

    def test_partition_boundaries(self):
        for change in [lambda p:p['batches'][1].update(candidate_indices=[True]),
                       lambda p:p['batches'][2].update(candidate_indices=p['batches'][1]['candidate_indices']),
                       lambda p:p['batches'].pop(), lambda p:p.update(operator_decoded_budget_bytes=63)]:
            f=fixture();change(f['plan'])
            with self.assertRaises(ValueError):a.plan_checked(f['plan'],f['index'],f['index_sha'])

    def test_alternate_context_cannot_pass_current_dataset_join(self):
        f=fixture();other=copy.deepcopy(f['contexts']['actual02'])
        for r in other['sources']:
            if r['mount']=='/public/HISTORY.json':r['sha256']='99'*32
        other['scope_document']['roles']['history']['sha256']='99'*32
        scope=a.encoded(other['scope_document'])
        next(r for r in other['sources'] if r['mount']=='/public/CANARY-CONTEXT-SCOPE.json').update(bytes=len(scope),sha256=a.sha(scope))
        a.context_checked(other)
        with self.assertRaises(ValueError):a.actual_context_checked(other,f['coverage'],f['canary_assets'])

    def test_primary_checkpoint_has_no_supplemental_PASS(self):
        f=fixture();keys=('index','index_sha','plan','plan_sha','originals','contexts','batches','coverage','canary_assets','prepared_source_sha')
        args={k:f[k] for k in keys};args['invocations']=[v for v in f['invocations'] if v['batch_id']!='DESCRIPTORS']
        self.assertIs(a.primary_checked(**args),True)
        args['invocations'].pop()
        with self.assertRaises(ValueError):a.primary_checked(**args)
        # Primary cells cannot be silently counted as DESCRIPTORS or positives.
        f['invocations']=[v for v in f['invocations'] if v['batch_id']!='DESCRIPTORS']
        with self.assertRaises(ValueError):a.aggregate(**f)

    def test_explicit_extra_metadata_cannot_replace_mandatory_descriptor(self):
        f=fixture();stage=copy.deepcopy(f['descriptor_stage'])
        for k in ('release_sha256','preparation'):stage.pop(k)
        extra={'source':'/known-public/DATA-PARTS.json','path':'public-meta/DATA-PARTS.json','bytes':64,'sha256':H}
        stage['supplemental_public_metadata']=[extra];stage['files'].append(extra)
        stage['releases']={c:release(stage['files'],f['contexts'][c],'DESCRIPTORS',c) for c in f['contexts']}
        args=(f['index'],f['index_sha'],f['plan'],f['plan_sha'],f['batches'],f['contexts'])
        self.assertEqual(a.descriptor_stage_checked(stage,*args,a.sha(a.encoded(stage)))['files'][-1],extra)
        stage['files'].pop(0)
        with self.assertRaises(ValueError):a.descriptor_stage_checked(stage,*args,a.sha(a.encoded(stage)))

    def test_finite_time_metadata_keeps_integer_predicates_strict(self):
        self.assertEqual(a.parse_metadata(b'{"seconds":1.25}'),{'seconds':1.25})
        for raw in (b'{"seconds":NaN}',b'{"x":1,"x":2}',b'{"seconds":1e999}'):
            with self.assertRaises(ValueError):a.parse_metadata(raw)
        f=fixture();f['batches'][0]['preparation']['provenance']['candidate_files']=1.0
        with self.assertRaises(ValueError):a.aggregate(**f)



if __name__=='__main__':unittest.main()
