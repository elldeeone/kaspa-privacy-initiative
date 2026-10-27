#!/usr/bin/env python3
"""Bounded, serial publication audit controller; no daemon or Original cache.

Only --execute may invoke private-leaf workers, after a separately selected
local execution plan. All public batch bytes are authenticated before unchanged
c465 performs metadata checks and creates each one-leaf namespace. This module
never opens, hashes, copies or shares an Original file descriptor.
"""
import argparse
import copy
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

import publication_batch_audit as audit

CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
SCOPE_MOUNT = '/public/CANARY-CONTEXT-SCOPE.json'


def selected_module(selector, name):
    raw = audit.guarded(selector)
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader=None))
    module.__file__ = selector['path'];sys.modules[name] = module
    exec(compile(raw, selector['path'], 'exec'), module.__dict__)
    return module


def load_plan(selector):
    value = audit.parse(audit.guarded(selector))
    audit.fields(value, ('schema', 'domain_hex32', 'index', 'batch_plan', 'root_selection', 'canary_assets', 'extra_candidates', 'producer', 'launcher', 'prepared_launcher',
        'positive_worker', 'context_templates', 'originals', 'base_materialization', 'run_label'), 'execution-plan-fields')
    audit.need(value['schema'] == 'kpxa-publication-batch-execution-plan/v1'
        and value['domain_hex32'] == audit.DOMAIN, 'execution-plan-domain')
    for name in ('index', 'batch_plan', 'root_selection', 'producer', 'launcher', 'prepared_launcher', 'positive_worker', 'base_materialization'):
        audit.row(value[name])
    audit.need(value['launcher']['sha256'] == audit.LAUNCHER
         and value['positive_worker']['sha256'] == audit.POSITIVE
         and value['producer']['sha256'] == audit.PRODUCER, 'unchanged-selected-launcher-and-positive')
    audit.need(type(value['run_label']) is str and re.fullmatch('[a-z0-9-]{1,20}', value['run_label']), 'neutral-local-run-label')
    audit.originals_checked(value['originals'])  # Metadata values only: no stat/open.
    index = audit.index_checked(audit.parse(audit.guarded(value['index'])))
    plan = audit.plan_checked(audit.parse(audit.guarded(value['batch_plan'])), index, value['index']['sha256'])
    audit.fields(value['context_templates'], ('creation', 'actual02'), 'context-template-selectors')
    contexts = {}
    for cohort, selector in value['context_templates'].items():
        release = audit.parse(audit.guarded(selector))
        audit.fields(release, ('schema', 'domain_hex32', 'files', 'sources'), 'template-old-release-fields')
        audit.need(release['schema'] == 'kpxa-publication-audit-release/v1'
             and release['domain_hex32'] == audit.DOMAIN, 'same-template-domain')
        mounts = audit.sources_checked(release['sources']);scope_row = mounts[SCOPE_MOUNT]
        scope = audit.parse(audit.guarded({'path': scope_row['source'], 'sha256': scope_row['sha256']}))
        contexts[cohort] = audit.context_checked({'sources': release['sources'], 'scope_document': scope})
        expected = 'kpxa-canary-final-accepted-history-context/v1' if cohort == 'actual02' else 'kpxa-canary-nonchain-creation-context/v1'
        audit.need(scope['schema'] == expected, 'cohort-scope-must-not-be-substituted')
    def snapshot(selected):
        return {'row': selected, 'raw_hex': audit.guarded(selected).hex()}
    raw_candidates = {v['path']: v for v in index['candidates'] if v['kind'] == 'raw'}
    selection_snapshot = snapshot(value['root_selection'])
    selection = audit.parse(bytes.fromhex(selection_snapshot['raw_hex']))
    fetch = next(f for f in selection['files'] if f['path'] == selection['roles']['fetch'])
    extras = []
    if value['extra_candidates'] is not None:
        extra = audit.parse(audit.guarded(value['extra_candidates']))
        audit.fields(extra, ('schema', 'domain_hex32', 'files'), 'explicit-base-extra-allowlist')
        audit.need(extra['schema'] == 'kpxa-publication-base-extra-candidates/v1'
             and extra['domain_hex32'] == audit.DOMAIN, 'same-extra-domain')
        extras = extra['files']
    coverage = {'selection': selection_snapshot,
        'fetch': snapshot({'path': fetch['source'], 'sha256': fetch['sha256']}),
        'packet': snapshot({'path': raw_candidates['raw/PACKET.json']['source'], 'sha256': raw_candidates['raw/PACKET.json']['sha256']}),
        'inventory': snapshot({'path': raw_candidates['raw/DATA-INVENTORY.json']['source'], 'sha256': raw_candidates['raw/DATA-INVENTORY.json']['sha256']}),
        'extra_files': extras}
    audit.coverage_checked(coverage, index)
    audit.actual_context_checked(contexts['actual02'], coverage, value['canary_assets'])
    assets_raw = audit.guarded({'path': value['canary_assets']['source'], 'sha256': value['canary_assets']['sha256']})
    audit.need(len(assets_raw) == value['canary_assets']['bytes'], 'exact-portable-canary-assets-bytes')
    return value, index, plan, contexts, coverage


def materialize(producer, index_row, plan_row, batch, output):
    audit.guarded(producer)
    command = ['/usr/bin/python3', '-B', producer['path'], 'materialize',
        '--index', index_row['path'], '--index-sha256', index_row['sha256'],
        '--plan', plan_row['path'], '--plan-sha256', plan_row['sha256'],
        '--batch-id', batch['batch_id'], '--output', str(output)]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=CLEAN, close_fds=True)
    audit.need(result.returncode == 0 and not result.stderr, 'public-whole-page-materialization-failed')
    return audit.parse(result.stdout)


def release_for(output, bid, cohort, files, context):
    scope = audit.batch_scope(context, files)
    scope_row = audit.save(output / 'local-scopes' / bid / (cohort + '.json'), scope)
    scope_bytes = len(audit.encoded(scope))
    sources = [dict(v) for v in context['sources']]
    for source in sources:
        if source['mount'] == SCOPE_MOUNT:
            source.update(source=scope_row['path'], bytes=scope_bytes, sha256=scope_row['sha256'])
    release = {'schema': 'kpxa-publication-audit-release/v1', 'domain_hex32': audit.DOMAIN,
               'files': files, 'sources': sources}
    row = audit.save(output / 'local-releases' / bid / (cohort + '.json'), release)
    return {'release': release, 'row': row}


def original_options(original):
    # These are exact Root-selected metadata. The unchanged launcher alone stats
    # the leaf; the coordinator does not even discover private directory entries.
    result = ['--original', original['path']]
    for name in ('device', 'inode', 'bytes', 'ctime_ns'):
        result += ['--original-' + name.replace('_', '-'), str(original[name])]
    return result


def audit_one(value, original, descriptor, descriptor_row, record, context, output, prepared, preparation):
    from types import SimpleNamespace
    bid = descriptor['batch_id'];identity = 'audit-' + value['run_label'] + '-' + bid.lower() + '-' + original['original_id'].lower()
    args = SimpleNamespace(original=original['path'], original_device=original['device'],
        original_inode=original['inode'], original_bytes=original['bytes'], original_ctime_ns=original['ctime_ns'])
    before = time.monotonic_ns()
    result = prepared.execute(args, original['cohort'], identity)
    audit.need(result['public_preparation_provenance'] == preparation['provenance'], 'same-prepared-object-all-nine')
    workers = {};receipts = result['workers']
    for kind in ('literal', 'derived'):
        workers[kind] = {k:v for k,v in receipts[kind].items()
                        if k not in ('sha256','bytes','candidate_manifest_sha256')}
    scope = audit.sources_checked(record['release']['sources'])[SCOPE_MOUNT]
    envelope = {'schema': 'kpxa-publication-batch-audit-invocation/v1',
        'global_index_sha256': value['index']['sha256'], 'batch_plan_sha256': value['batch_plan']['sha256'],
        'batch_id': bid, 'batch_descriptor': descriptor_row, 'original': copy.deepcopy(original),
        'release': record['row'], 'launcher_sha256': value['launcher']['sha256'],
        'prepared_launcher_sha256': value['prepared_launcher']['sha256'],
        'public_preparation_sha256': audit.sha(audit.encoded(preparation['provenance'])),
        'source_core_sha256': audit.sha(audit.encoded(audit.core_sources(context['sources']))),
        'scope_sha256': scope['sha256'], 'summary': result['summary'], 'workers': workers,
        'worker_receipts': receipts}
    audit.invocation_checked(envelope, original, descriptor, descriptor_row, record['release'],
        record['row'], context, value['index']['sha256'], value['batch_plan']['sha256'],
        preparation, value['prepared_launcher']['sha256'])
    audit.save(output / 'local-invocations' / bid / (original['original_id'] + '.json'), envelope)
    audit.save(output / 'local-timing' / bid / (original['original_id'] + '.json'),
               {'elapsed_nanoseconds': time.monotonic_ns() - before,
                'worker_pair_nanoseconds': round(result['worker_pair_wall_seconds'] * 1_000_000_000)})
    return envelope


def prepare_snapshot(value, descriptor, releases, prepared_api):
    selected = {cohort: {'source': record['row']['path'],
        'bytes': len(audit.encoded(record['release'])), 'sha256': record['row']['sha256']}
        for cohort, record in releases.items()}
    raw_base = audit.guarded(value['launcher'])
    base_row = {'source': value['launcher']['path'], 'bytes': len(raw_base), 'sha256': audit.LAUNCHER}
    runtime = Path('/var/tmp/kpi-local-private-payment-01/publication-audits') / (
        'prepared-' + value['run_label'] + '-' + descriptor['batch_id'].lower())
    prepared = prepared_api.prepare(descriptor['files'], selected, runtime, base_row)
    record = {'source_sha256': value['prepared_launcher']['sha256'],
              'provenance': prepared.public_preparation_provenance}
    audit.preparation_checked(record, releases, descriptor['files'], value['prepared_launcher']['sha256'])
    return prepared, record


def runpy_read_public(path):
    import runpy
    return runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'](str(path))


def cleanup_public_payloads(runtime, identity):
    """Only c465's fresh job public copies, after both workers have exited PASS."""
    audit.need(runtime.parent == Path('/var/tmp/kpi-local-private-payment-01/publication-audits')
         and runtime.name == identity, 'only-own-public-job-stage')
    for name in ('sources', 'candidates'):
        path = runtime / name
        if path.exists():
            audit.need(path.is_dir() and not path.is_symlink(), 'public-stage-directory-only')
            shutil.rmtree(path)


def positive_one(value, original, context, output, launcher):
    """One new namespace; unchanged positive b812 and its original e4c imports.

    The public source/context closure is the same as every actual02 batch, apart
    from the batch-specific scope and the explicitly pinned positive entry.
    No Original descriptor is opened or passed by this parent.
    """
    files = []
    record = release_for(output, 'POSITIVE-' + original['original_id'], 'actual02', files, context)
    sources = []
    for source in record['release']['sources']:
        raw = audit.guarded({'path': source['source'], 'sha256': source['sha256']})
        audit.need(len(raw) == source['bytes'], 'positive-public-source-size')
        sources.append((source, raw))
    selected = {r['mount']: raw for r, raw in sources}
    scope = launcher.final_scope(selected, audit.sha(audit.encoded([])))
    audit.need(scope['context_kind'] == 'ACCEPTED_HISTORY', 'positive-needs-same-accepted-context')
    positive_raw = audit.guarded(value['positive_worker'])
    positive_mount = '/public/recovery/optional_volume_final.py'
    audit.need(positive_mount not in selected, 'positive-entry-not-ambiguous')
    from types import SimpleNamespace
    args = SimpleNamespace(original=original['path'], original_device=original['device'],
        original_inode=original['inode'], original_bytes=original['bytes'], original_ctime_ns=original['ctime_ns'])
    owner, before = launcher.original_metadata(args)
    runtime = output / 'local-positive-stage' / original['original_id'];runtime.mkdir(parents=True, mode=0o700)
    out = runtime / 'out';out.mkdir(mode=0o700)
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/candidates',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8']
    pins = {}
    for n, (source, raw) in enumerate(sources):
        path = runtime / 'sources' / (str(n) + '.bin');launcher.save(path, raw, int(source['mode'], 8))
        command += ['--ro-bind', str(path), source['mount']];pins[source['mount']] = source['sha256']
    entry = runtime / 'positive.py';launcher.save(entry, positive_raw)
    command += ['--ro-bind', str(entry), positive_mount, '--ro-bind', str(owner), '/BACKUP.json',
        '--bind', str(out), '/out', '/usr/bin/python3', '-B', positive_mount,
        '--owner', '/BACKUP.json', '--output', '/out/RESULTS.json',
        '--expected-second-kind', original['expected_second_kind']]
    for name, mount in (('assets', '/public/ASSETS.json'), ('history', '/public/HISTORY.json'), ('context', '/public/CONTEXT.json')):
        command += ['--' + name, mount, '--' + name + '-sha256', pins[mount]]
    audit.need(launcher.attributes(launcher.original_metadata(args)[1])==launcher.attributes(before),'positive-current-Original-before-namespace')
    process = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, env=CLEAN, close_fds=True)
    audit.need(process.returncode == 0 and launcher.attributes(launcher.original_metadata(args)[1])
         == launcher.attributes(before), 'positive-one-leaf-check-failed')
    result = audit.parse(runpy_read_public(out / 'RESULTS.json'))
    envelope = {'schema': 'kpxa-publication-batch-positive-invocation/v1',
        'global_index_sha256': value['index']['sha256'], 'batch_plan_sha256': value['batch_plan']['sha256'],
        'original': copy.deepcopy(original), 'source_core_sha256': audit.sha(audit.encoded(audit.core_sources(context['sources']))),
        'positive_source_sha256': audit.POSITIVE, 'result': result}
    audit.positive_checked(envelope, original, context, value['index']['sha256'], value['batch_plan']['sha256'])
    audit.save(output / 'local-positive-results' / (original['original_id'] + '.json'), envelope)
    return envelope


def fresh_control_output(output):
    output=Path(output)
    audit.absolute(str(output))
    audit.need(output.is_relative_to('/var/tmp/kpi-local-private-payment-01/publication-audits')
        and not output.exists() and not any(p.is_symlink() for p in (output,*output.parents)),
        'fresh-owned-public-control-output')
    output.mkdir(parents=True,mode=0o700)
    return output


def checkpoint_checked(selector, execution_plan):
    value,index,plan,contexts,coverage=load_plan(execution_plan)
    primary=audit.parse_metadata(audit.guarded(selector))
    audit.fields(primary,('schema','execution_plan_value','index','plan','contexts','coverage','batches','invocations','descriptor_release'),'primary-checkpoint-fields')
    audit.need(primary['schema']=='kpxa-publication-primary-audit-checkpoint/v1'
        and primary['execution_plan_value']==value and primary['index']==index and primary['plan']==plan
        and primary['contexts']==contexts and primary['coverage']==coverage,'same-selected-primary-checkpoint')
    audit.primary_checked(index,value['index']['sha256'],plan,value['batch_plan']['sha256'],value['originals'],
        contexts,primary['batches'],primary['invocations'],coverage,value['canary_assets'],value['prepared_launcher']['sha256'])
    return value,index,plan,contexts,coverage,primary


def prepare_supplemental(selector,output):
    """Public-only; Root still externally selects the resulting release to resume.

    Extra metadata is explicitly pinned in this input. It is appended to the
    mandatory descriptor set, never substituted for it. No primary Original
    cell is rerun to create this supplemental selection.
    """
    selected=audit.parse(audit.guarded(selector))
    audit.fields(selected,('schema','execution_plan','primary_journal','extra_metadata'),'supplemental-preparation-selector')
    audit.need(selected['schema']=='kpxa-publication-descriptor-preparation/v1','explicit-supplemental-preparation')
    value,index,plan,contexts,coverage,primary=checkpoint_checked(selected['primary_journal'],selected['execution_plan'])
    extras=selected['extra_metadata'];audit.need(type(extras) is list,'explicit-public-extra-metadata')
    mandatory=[value['index'],value['batch_plan'],*[r['descriptor_row'] for r in primary['batches']]]
    files=[]
    for n,row in enumerate(mandatory):
        raw=audit.guarded(row);files.append({'source':row['path'],'path':'public-descriptors/'+str(n).zfill(6)+'.json',
            'bytes':len(raw),'sha256':row['sha256']})
    for file in extras:
        audit.file_row(file)
        audit.need(len(audit.guarded({'path':file['source'],'sha256':file['sha256']}))==file['bytes'],'selected-extra-metadata-bytes')
    files += extras
    output=fresh_control_output(output)
    releases={c:release_for(output,'DESCRIPTORS',c,files,context) for c,context in contexts.items()}
    stage={'batch_id':'DESCRIPTORS','files':files,'required_public_metadata':{'index':value['index'],'plan':value['batch_plan']},
        'supplemental_public_metadata':extras,'releases':releases}
    row=audit.save(output/'LOCAL-UNPUBLISHED-DESCRIPTOR-RELEASE.json',stage)
    audit.descriptor_stage_checked(stage,index,value['index']['sha256'],plan,value['batch_plan']['sha256'],
        primary['batches'],contexts,row['sha256'])
    audit.save(output/'LOCAL-UNPUBLISHED-SUPPLEMENTAL-HANDOFF.json',{'descriptor_release':row,
        'primary_journal':selected['primary_journal'],'execution_plan':selected['execution_plan']})
    return {'supplemental_release_prepared':True,'external_Root_selection_required':True,
        'actual_original_workers_invoked':False,'global_audit_complete':False}


def execute(value, index, plan, contexts, coverage, output):
    output=fresh_control_output(output)
    launcher = selected_module(value['launcher'], 'reviewed_c465_batch_launcher')
    prepared_api = selected_module(value['prepared_launcher'], 'reviewed_prepared_public_audit_launcher')
    producer_api = selected_module(value['producer'], 'reviewed_whole_page_public_materializer')
    shm_base = Path(producer_api.pinned_preimage()['SHM_OUTPUT_BASE'])
    base_result = audit.parse(audit.guarded(value['base_materialization']))
    base_proof=base_result['base_verification']
    # Independently re-run the selected producer's exact USTAR/member alias
    # comparison once, before any Original metadata/worker operation. Full
    # producer stdout also binds archive, both-page coverage and all counts.
    import runpy
    read=runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    archive_started=time.monotonic_ns()
    archive_row=next(c for c in index['candidates'] if c['path']=='raw/data.tar')
    archive=read(archive_row['source'],archive_row['sha256'])
    audit.need(len(archive)==archive_row['bytes'],'whole-raw-archive-identity')
    aliases={c['path'][len('members/'):]:c for c in index['candidates'] if c['path'].startswith('members/')}
    producer_api.verify_member_aliases(producer_api.pinned_preimage(),read,archive,aliases)
    del archive
    audit.save(output/'local-timing'/'BASE-archive-revalidation.json',
        {'stage':'PUBLIC_RAW_USTAR_AND_MEMBER_ALIAS_REVALIDATION',
         'elapsed_nanoseconds':time.monotonic_ns()-archive_started,
         'archive_bytes':index['archive']['bytes'],'producer_source_sha256':value['producer']['sha256']})
    base_authority={'source_sha256':value['producer']['sha256'],'result':base_result,
        'raw_archive_member_aliases_reverified':True}
    audit.producer_preparation_checked(base_authority,index,value['index']['sha256'],plan,value['batch_plan']['sha256'])
    records, invocations = [], []
    for batch in plan['batches']:
        bid = batch['batch_id'];temporary = None
        if bid == 'BASE':
            proof = base_proof
        else:
            temporary = shm_base / ('batch-' + value['run_label'] + '-' + bid.lower())
            audit.need(not temporary.exists(), 'fresh-owned-decoded-shm-directory')
            proof = materialize(value['producer'], value['index'], value['batch_plan'], batch, temporary)
        descriptor_row = proof['descriptor'];descriptor = audit.parse(audit.guarded(descriptor_row))
        audit.descriptor_checked(descriptor, batch, index, value['index']['sha256'], value['batch_plan']['sha256'])
        audit.materialization_checked(proof, batch, descriptor, descriptor_row, value['index']['sha256'], value['batch_plan']['sha256'])
        releases = {cohort: release_for(output, bid, cohort, descriptor['files'], context) for cohort, context in contexts.items()}
        prepared, preparation = prepare_snapshot(value, descriptor, releases, prepared_api)
        record = {'descriptor': descriptor, 'descriptor_row': descriptor_row, 'materialization': proof,
                  'releases': releases, 'preparation': preparation,
                  'producer_preparation':base_authority if bid=='BASE' else None}
        records.append(record)
        for original in value['originals']:
            cohort = original['cohort']
            invocations.append(audit_one(value, original, descriptor, descriptor_row,
                releases[cohort], contexts[cohort], output, prepared, preparation))
        prepared.close()
        if temporary is not None:
            # Every namespace has exited. Remove only this controller-created
            # decoded subtree; durable public descriptors and all audit evidence
            # stay outside it. A failed check leaves the current tree intact.
            audit.need(temporary.parent == shm_base and temporary.name.startswith('batch-' + value['run_label'] + '-'), 'owned-shm-cleanup-only')
            shutil.rmtree(temporary)
    metadata = [value['index'], value['batch_plan'], *[r['descriptor_row'] for r in records]]
    files = []
    for n, selected in enumerate(metadata):
        raw = audit.guarded(selected)
        files.append({'source': selected['path'], 'path': 'public-descriptors/' + str(n).zfill(6) + '.json',
                      'bytes': len(raw), 'sha256': selected['sha256']})
    releases = {cohort: release_for(output, 'DESCRIPTORS', cohort, files, context) for cohort, context in contexts.items()}
    descriptor_stage = {'batch_id': 'DESCRIPTORS', 'files': files,
        'required_public_metadata': {'index': value['index'], 'plan': value['batch_plan']},
        'supplemental_public_metadata':[], 'releases': releases}
    descriptor_release = audit.save(output / 'LOCAL-UNPUBLISHED-DESCRIPTOR-RELEASE.json', descriptor_stage)
    descriptor_stage['release_sha256'] = descriptor_release['sha256']
    descriptor = {'schema': 'kpxa-publication-audit-batch/v1', 'domain_hex32': audit.DOMAIN,
        'global_index_sha256': value['index']['sha256'], 'batch_plan_sha256': value['batch_plan']['sha256'],
        'batch_id': 'DESCRIPTORS', 'candidate_indices': [], 'files': files}
    descriptor_row = {'path': '/LOCAL-UNPUBLISHED/DESCRIPTORS', 'sha256': descriptor_release['sha256']}
    audit.primary_checked(index, value['index']['sha256'], plan, value['batch_plan']['sha256'],
        value['originals'], contexts, records, invocations, coverage, value['canary_assets'], value['prepared_launcher']['sha256'])
    journal = {'schema':'kpxa-publication-primary-audit-checkpoint/v1','execution_plan_value':value,
        'index':index,'plan':plan,'contexts':contexts,'coverage':coverage,'batches':records,
        'invocations':invocations,'descriptor_release':descriptor_release}
    journal_row = audit.save(output / 'LOCAL-UNPUBLISHED-PRIMARY-JOURNAL.json',journal)
    # Public batch selectors did not exist before their materialization. Stop:
    # Root externally selects this exact supplemental release before any new
    # Original is used for DESCRIPTORS or the three positives. This is not PASS.
    result={'primary_checks_complete':True,'descriptor_stage_checked':False,
            'global_audit_complete':False,'external_descriptor_release_required':True}
    audit.save(output / 'PRIMARY-ONLY-BOOLEAN-CHECKPOINT.json',result)
    audit.save(output / 'LOCAL-UNPUBLISHED-RESUME-HANDOFF.json',{'primary_journal':journal_row,
        'descriptor_release':descriptor_release,'actual_Original_workers_after_this_boundary':False})
    return result


def resume_descriptors(release_selector, output):
    selected=audit.parse(audit.guarded(release_selector))
    audit.fields(selected,('schema','execution_plan','primary_journal','descriptor_release'),'external-descriptor-resume-fields')
    audit.need(selected['schema']=='kpxa-publication-descriptor-resume-release/v1','explicit-Root-descriptor-release')
    value,index,plan,contexts,coverage,primary=checkpoint_checked(selected['primary_journal'],selected['execution_plan'])
    records,invocations=primary['batches'],primary['invocations']
    stage=audit.parse(audit.guarded(selected['descriptor_release']))
    audit.descriptor_stage_checked(stage,index,value['index']['sha256'],plan,value['batch_plan']['sha256'],records,contexts,selected['descriptor_release']['sha256'])
    for file in stage['files']:
        audit.need(len(audit.guarded({'path':file['source'],'sha256':file['sha256']}))==file['bytes'],'exact-supplemental-public-file')
    output=fresh_control_output(output)
    prepared_api=selected_module(value['prepared_launcher'],'reviewed_descriptor_prepared_launcher')
    launcher=selected_module(value['launcher'],'reviewed_positive_c465_launcher')
    descriptor={'schema':'kpxa-publication-audit-batch/v1','domain_hex32':audit.DOMAIN,
        'global_index_sha256':value['index']['sha256'],'batch_plan_sha256':value['batch_plan']['sha256'],
        'batch_id':'DESCRIPTORS','candidate_indices':[],'files':stage['files']}
    descriptor_row={'path':'/LOCAL-UNPUBLISHED/DESCRIPTORS','sha256':selected['descriptor_release']['sha256']}
    # A distinct resume label keeps every job/runtime fresh; primary cells are
    # reused only as exact local checked receipts, never executed a second time.
    runtime_value=dict(value);runtime_value['run_label']=value['run_label']+'-meta'
    prepared,preparation=prepare_snapshot(runtime_value,descriptor,stage['releases'],prepared_api)
    stage['release_sha256']=selected['descriptor_release']['sha256'];stage['preparation']=preparation
    all_invocations=list(invocations)
    for original in value['originals']:
        cohort=original['cohort'];all_invocations.append(audit_one(runtime_value,original,descriptor,descriptor_row,
            stage['releases'][cohort],contexts[cohort],output,prepared,preparation))
    prepared.close()
    positives=[positive_one(value,o,contexts['actual02'],output,launcher) for o in value['originals'] if o['cohort']=='actual02']
    journal={'index':index,'index_sha':value['index']['sha256'],'plan':plan,'plan_sha':value['batch_plan']['sha256'],
        'originals':value['originals'],'contexts':contexts,'batches':records,'descriptor_stage':stage,
        'invocations':all_invocations,'positives':positives,'descriptor_release_sha':selected['descriptor_release']['sha256'],
        'coverage':coverage,'canary_assets':value['canary_assets'],'prepared_source_sha':value['prepared_launcher']['sha256']}
    result=audit.aggregate(**journal)
    audit.save(output/'LOCAL-UNPUBLISHED-COMPLETE-JOURNAL.json',journal)
    audit.save(output/'BOOLEAN-RESULT.json',result)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    modes=p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--execution-plan',type=Path)
    modes.add_argument('--resume-descriptors',type=Path)
    modes.add_argument('--prepare-supplemental',type=Path)
    p.add_argument('--selection-sha256',required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--execute',action='store_true')
    a=p.parse_args()
    selector={'path':str(a.execution_plan or a.resume_descriptors or a.prepare_supplemental),'sha256':a.selection_sha256}
    if a.execution_plan:
        value,index,plan,contexts,coverage=load_plan(selector)
        result=execute(value,index,plan,contexts,coverage,a.output) if a.execute else {
            'public_preflight_passed':True,'actual_original_workers_invoked':False}
    elif a.prepare_supplemental:
        audit.need(not a.execute,'supplemental-preparation-never-executes-Originals')
        result=prepare_supplemental(selector,a.output)
    else:
        audit.need(a.execute,'descriptor-resume-requires-explicit-execute')
        result=resume_descriptors(selector,a.output)
    print(audit.encoded(result).decode().strip())


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Batched publication audit refused; no private result exported.')
