#!/usr/bin/env python3
"""Whole-page audit scheduling and strict local result joins.

No Original is opened by this coordinator. Execution is an explicit separate
operation; unchanged c465 supplies the one-Original/two-namespace boundary.
Local route/journal/release files are not publication candidates. Public index,
plan and batch descriptors receive their own all-nine supplemental audit.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import math

DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
LAUNCHER = 'c465c8e6c77b80a9d4f3928cbbe97704751104ec96488fcf9516efe007ceff42'
LITERAL = '0d3d7cbed85da8288040407df8c6038fe58c14782d9af8f1ad8dcc748b1f1c52'
DERIVED = 'e4c466cdbcb849d2249832f4c42efab97ea7d43039a55095948888710b67a489'
PRODUCER = 'fbc565020ec0c4a2adfd787f1805ff40210ebde4fa159cf8a62dd76a61ef5274'
POSITIVE = 'b8127aabd90ba738fa521cfc023e40e0dd50c7d8cd8b7cc385b664b4212e0e9c'
PRIVATE = Path('/var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def fields(value, names, reason):
    need(type(value) is dict and set(value) == set(names), reason)


def uint(value, positive=False):
    need(type(value) is int and value >= (1 if positive else 0), 'exact-nonnegative-integer')
    return value


def pin(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'canonical-sha256')
    return value


def absolute(value):
    need(type(value) is str and value.startswith('/') and not value.startswith('//')
         and str(PurePosixPath(value)) == value and '..' not in PurePosixPath(value).parts
         and '\\' not in value and '\0' not in value, 'canonical-absolute-path')
    return value


def relative(value):
    need(type(value) is str and value and not value.startswith('/')
         and str(PurePosixPath(value)) == value and '..' not in PurePosixPath(value).parts
         and '\\' not in value and '\0' not in value, 'canonical-relative-path')
    return value


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def pairs(rows):
        out = {}
        for key, value in rows:
            need(key not in out, 'duplicate-json-key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs, parse_float=lambda _: need(False, 'float-refused'),
                      parse_constant=lambda _: need(False, 'nonfinite-refused'))


def parse_metadata(raw):
    # Only neutral elapsed-time fields use finite floats. Integer predicates
    # below still require type(value) is int, excluding bool and float aliases.
    def pairs(rows):
        out = {}
        for key,value in rows:
            need(key not in out, 'duplicate-json-key');out[key]=value
        return out
    def number(value):
        result=float(value);need(math.isfinite(result),'nonfinite-refused');return result
    return json.loads(raw,object_pairs_hook=pairs,parse_float=number,
        parse_constant=lambda _:need(False,'nonfinite-refused'))


def row(value):
    fields(value, ('path', 'sha256'), 'selector-fields')
    absolute(value['path']);pin(value['sha256'])
    return value


def file_row(value):
    fields(value, ('source', 'path', 'bytes', 'sha256'), 'candidate-file-fields')
    absolute(value['source']);relative(value['path']);uint(value['bytes']);pin(value['sha256'])
    return value


def guarded(value):
    row(value)
    return runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'](value['path'], value['sha256'])


def save(path, value):
    path = Path(path)
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'output-symlink')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw = encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw);out.flush();os.fsync(out.fileno())
    return {'path': str(path.absolute()), 'sha256': sha(raw)}


def index_checked(value):
    fields(value, ('schema', 'domain_hex32', 'root_selection_sha256', 'archive', 'candidates'), 'global-index-fields')
    need(value['schema'] == 'kpxa-publication-global-candidate-index/v1'
         and value['domain_hex32'] == DOMAIN, 'global-index-domain')
    pin(value['root_selection_sha256'])
    fields(value['archive'], ('bytes', 'sha256'), 'archive-identity')
    uint(value['archive']['bytes'], True);pin(value['archive']['sha256'])
    need(type(value['candidates']) is list and value['candidates'], 'nonempty-global-candidates')
    paths = set()
    for n, candidate in enumerate(value['candidates']):
        fields(candidate, ('index', 'path', 'bytes', 'sha256', 'kind', 'source', 'gzip'), 'global-candidate-fields')
        need(uint(candidate['index']) == n, 'contiguous-global-indices')
        relative(candidate['path']);uint(candidate['bytes']);pin(candidate['sha256'])
        need(candidate['path'] not in paths, 'unique-global-path');paths.add(candidate['path'])
        need(candidate['kind'] in ('raw', 'decoded'), 'candidate-kind')
        if candidate['kind'] == 'raw':
            absolute(candidate['source']);need(candidate['gzip'] is None, 'raw-has-no-gzip-selector')
        else:
            need(candidate['source'] is None, 'decoded-source-is-materialized-only')
            fields(candidate['gzip'], ('source', 'bytes', 'sha256'), 'decoded-gzip-selector')
            absolute(candidate['gzip']['source']);uint(candidate['gzip']['bytes'], True);pin(candidate['gzip']['sha256'])
            uint(candidate['bytes'], True)
    return value


def plan_checked(value, index, index_sha):
    fields(value, ('schema', 'domain_hex32', 'global_index_sha256', 'operator_decoded_budget_bytes', 'batches'), 'batch-plan-fields')
    need(value['schema'] == 'kpxa-publication-whole-page-batch-plan/v1'
         and value['domain_hex32'] == DOMAIN and value['global_index_sha256'] == pin(index_sha), 'batch-plan-binding')
    budget = uint(value['operator_decoded_budget_bytes'], True)
    need(type(value['batches']) is list and value['batches'], 'nonempty-batches')
    seen = set()
    for n, batch in enumerate(value['batches']):
        fields(batch, ('batch_id', 'candidate_indices', 'bytes'), 'batch-plan-row')
        need(batch['batch_id'] == ('BASE' if n == 0 else 'D' + str(n).zfill(6)), 'deterministic-batch-id')
        ids = batch['candidate_indices']
        need(type(ids) is list and ids and all(type(i) is int for i in ids)
             and ids == sorted(set(ids)) and all(0 <= i < len(index['candidates']) for i in ids), 'whole-unique-batch-indices')
        need(not (seen & set(ids)), 'batch-overlap');seen.update(ids)
        candidates = [index['candidates'][i] for i in ids]
        need(all(c['kind'] == ('raw' if n == 0 else 'decoded') for c in candidates), 'base-versus-decoded-partition')
        need(uint(batch['bytes']) == sum(c['bytes'] for c in candidates), 'exact-batch-byte-sum')
        if n:
            need(batch['bytes'] <= budget, 'whole-page-budget-not-silent-split-or-overrun')
    need(seen == set(range(len(index['candidates']))), 'exact-global-candidate-union')
    return value


def descriptor_checked(value, batch, index, index_sha, plan_sha):
    fields(value, ('schema', 'domain_hex32', 'global_index_sha256', 'batch_plan_sha256', 'batch_id', 'candidate_indices', 'files'), 'batch-descriptor-fields')
    need(value['schema'] == 'kpxa-publication-audit-batch/v1' and value['domain_hex32'] == DOMAIN
         and value['global_index_sha256'] == index_sha and value['batch_plan_sha256'] == plan_sha
         and value['batch_id'] == batch['batch_id'] and value['candidate_indices'] == batch['candidate_indices']
         and all(type(i) is int for i in value['candidate_indices']), 'batch-descriptor-identity')
    need(type(value['files']) is list and len(value['files']) == len(batch['candidate_indices']), 'complete-batch-files')
    for file, n in zip(value['files'], batch['candidate_indices']):
        file_row(file);candidate = index['candidates'][n]
        need(all(file[k] == candidate[k] for k in ('path', 'bytes', 'sha256')), 'whole-global-candidate-identity')
        if candidate['kind'] == 'raw':
            need(file['source'] == candidate['source'], 'raw-source-exact')
    return value


def materialization_checked(value, batch, descriptor, descriptor_row, index_sha, plan_sha):
    common = {'schema', 'global_index_sha256', 'batch_plan_sha256', 'batch_id', 'descriptor',
              'verified_candidate_indices', 'whole_decoded_pages', 'gzip_and_decoded_identities_verified'}
    fields(value, common | ({'raw_archive_and_member_aliases_verified'} if batch['batch_id'] == 'BASE' else set()), 'materialization-proof-fields')
    need(value['schema'] == 'kpxa-publication-batch-materialization/v1'
         and value['global_index_sha256'] == index_sha and value['batch_plan_sha256'] == plan_sha
         and value['batch_id'] == batch['batch_id'] and value['descriptor'] == descriptor_row
         and value['verified_candidate_indices'] == batch['candidate_indices']
         and all(type(i) is int for i in value['verified_candidate_indices'])
         and value['gzip_and_decoded_identities_verified'] is True
         and value['whole_decoded_pages'] is (batch['batch_id'] != 'BASE'), 'explicit-complete-decoded-verification')
    if batch['batch_id'] == 'BASE':
        need(value['raw_archive_and_member_aliases_verified'] is True, 'raw-member-alias-identity-verification')


def original_checked(value):
    fields(value, ('original_id', 'cohort', 'path', 'device', 'inode', 'bytes', 'ctime_ns', 'expected_second_kind'), 'local-original-route-fields')
    need(type(value['original_id']) is str and re.fullmatch('O[0-9]{2}', value['original_id']), 'neutral-original-id')
    absolute(value['path']);p = Path(value['path'])
    need(p.is_relative_to(PRIVATE) and p.name == 'BACKUP.json', 'approved-original-prefix')
    for k in ('device', 'inode', 'bytes', 'ctime_ns'):
        uint(value[k], True)
    need(value['cohort'] in ('creation', 'actual02'), 'explicit-original-cohort')
    need(value['expected_second_kind'] in ('received', 'change') if value['cohort'] == 'actual02'
         else value['expected_second_kind'] is None, 'local-positive-policy-routing')
    return value


def originals_checked(values):
    need(type(values) is list and len(values) == 9, 'exact-nine-originals')
    for value in values:
        original_checked(value)
    for key in ('original_id', 'path'):
        need(len({v[key] for v in values}) == 9, 'duplicate-original-route')
    need(len({(v['device'], v['inode']) for v in values}) == 9, 'duplicate-original-inode')
    need(sum(v['cohort'] == 'actual02' for v in values) == 3, 'exact-three-actual02-positive-originals')
    need(sorted(v['expected_second_kind'] for v in values if v['cohort'] == 'actual02')
         == ['change', 'received', 'received'], 'approved-two-received-one-change-policy')
    return {v['original_id']: v for v in values}


def sources_checked(values):
    need(type(values) is list and values, 'nonempty-public-source-context-closure')
    mounts = {}
    for value in values:
        fields(value, ('source', 'mount', 'bytes', 'sha256', 'mode'), 'source-context-row')
        absolute(value['source']);absolute(value['mount']);uint(value['bytes']);pin(value['sha256'])
        need(PurePosixPath(value['mount']).is_relative_to('/public')
             and value['mount'] not in mounts and value['mode'] in ('0400', '0500'), 'source-context-mount')
        mounts[value['mount']] = value
    required = {'/public/recovery/publication_literal.py': LITERAL,
                '/public/recovery/publication_derived.py': DERIVED}
    need(all(mounts.get(k, {}).get('sha256') == v for k, v in required.items()), 'unchanged-literal-derived-workers')
    need(all('/public/' + k + '.json' in mounts for k in ('ASSETS', 'HISTORY', 'CONTEXT', 'CANARY-CONTEXT-SCOPE')), 'complete-context-assets')
    return mounts


def core_sources(values):
    sources_checked(values)
    return [v for v in values if v['mount'] != '/public/CANARY-CONTEXT-SCOPE.json']


def context_checked(value):
    fields(value, ('sources', 'scope_document'), 'context-template-fields')
    mounts = sources_checked(value['sources'])
    scope = mounts['/public/CANARY-CONTEXT-SCOPE.json']
    raw = encoded(value['scope_document'])
    need(scope['sha256'] == sha(raw) and scope['bytes'] == len(raw), 'exact-context-scope-template-bytes')
    return value


def batch_scope(context, files):
    context_checked(context)
    scope = dict(context['scope_document'])
    if scope.get('schema') == 'kpxa-canary-final-accepted-history-context/v1':
        scope['candidate_manifest_sha256'] = sha(encoded(candidate_manifest(files)))
    else:
        need(scope.get('schema') == 'kpxa-canary-nonchain-creation-context/v1', 'approved-context-scope-kind')
    return scope


def candidate_manifest(files):
    return [{'path': f['path'], 'bytes': f['bytes'], 'sha256': f['sha256']} for f in files]


def coverage_checked(value, index):
    """Rebuild the global universe from separately Root-selected public bytes.

    A structurally valid GLOBAL and its fresh SHA are insufficient: both fetch
    page arrays must map exactly to decoded candidates and raw source members.
    Raw hex here is PUBLIC metadata only and stays in the local journal.
    """
    fields(value, ('selection', 'fetch', 'packet', 'inventory', 'extra_files'), 'public-coverage-inputs')
    docs, selected = {}, {}
    for name in ('selection', 'fetch', 'packet', 'inventory'):
        item = value[name];fields(item, ('row', 'raw_hex'), 'public-document-snapshot')
        row(item['row']);need(type(item['raw_hex']) is str and re.fullmatch('(?:[0-9a-f]{2})+', item['raw_hex']), 'public-document-raw-bytes')
        raw = bytes.fromhex(item['raw_hex']);need(sha(raw) == item['row']['sha256'], 'public-document-SHA')
        def number(text):
            result = float(text);need(math.isfinite(result), 'finite-public-metadata');return result
        # Existing public fetch metadata can contain finite timing floats. No
        # count or monetary predicate below uses float equality.
        def pairs(rows):
            out = {}
            for k, v in rows:need(k not in out, 'duplicate-public-metadata-key');out[k] = v
            return out
        docs[name] = json.loads(raw, object_pairs_hook=pairs, parse_float=number,
            parse_constant=lambda _: need(False, 'nonfinite-public-metadata'))
        selected[name] = (item['row'], len(raw))
    selection = docs['selection']
    fields(selection, ('schema', 'domain_hex32', 'roles', 'files'), 'Root-selection-shape')
    need(selection['schema'] == 'kpxa-root-public-recovery-data-selection/v1'
         and selection['domain_hex32'] == DOMAIN
         and selected['selection'][0]['sha256'] == index['root_selection_sha256'], 'Root-selected-global-universe')
    roles = {'terminalhandoff', 'activation', 'history', 'context', 'currententry', 'replayresults',
             'fetch', 'selection', 'descriptor', 'assets', 'parameters', 'accounting'}
    fields(selection['roles'], roles, 'all-twelve-root-roles')
    need(type(selection['files']) is list and selection['files'], 'Root-selected-files')
    raw_files = {}
    for f in selection['files']:
        fields(f, ('source', 'path', 'bytes', 'sha256', 'kind'), 'Root-file-row')
        file_row({k: f[k] for k in ('source', 'path', 'bytes', 'sha256')})
        need(f['path'] not in raw_files, 'unique-Root-file-path');raw_files[f['path']] = f
    need(all(path in raw_files for path in selection['roles'].values())
         and len(set(selection['roles'].values())) == 12, 'distinct-covered-root-roles')
    fetch_file = raw_files[selection['roles']['fetch']]
    need(selection['roles']['fetch'] == 'chain/fetch.json'
         and selected['fetch'][0] == {'path': fetch_file['source'], 'sha256': fetch_file['sha256']}
         and selected['fetch'][1] == fetch_file['bytes'], 'same-Root-fetch-bytes')
    packet, inventory = docs['packet'], docs['inventory']
    need(packet['schema'] == 'kpxa-public-recovery-data-packet/v1' and packet['domain_hex32'] == DOMAIN
         and inventory['schema'] == 'kpxa-public-recovery-data-inventory/v1'
         and inventory['domain_hex32'] == DOMAIN, 'same-public-packet-inventory-domain')
    expected_inventory = [{k: f[k] for k in ('path', 'bytes', 'sha256', 'kind')} for f in selection['files']]
    need(inventory['files'] == expected_inventory and uint(inventory['file_count']) == len(raw_files)
         and uint(inventory['payload_bytes']) == sum(f['bytes'] for f in raw_files.values()), 'complete-inventory-Root-join')
    need({k: packet['archive'][k] for k in ('bytes', 'sha256')} == index['archive']
         and uint(packet['archive']['members']) == len(raw_files) + 1, 'complete-raw-archive-identity')
    expected_roles = {name: {k: raw_files[path][k] for k in ('path', 'bytes', 'sha256')}
                      for name, path in selection['roles'].items()}
    need(packet['roles'] == expected_roles, 'packet-twelve-role-identities')
    by_path = {f['path']: f for f in index['candidates']}
    required_raw = {'raw/' + n for n in ('data.tar', 'DATA-INVENTORY.json', 'PACKET.json', 'SHA256SUMS')}
    need(required_raw <= set(by_path), 'all-four-raw-objects')
    for name, key in (('PACKET.json', 'packet'), ('DATA-INVENTORY.json', 'inventory')):
        f = by_path['raw/' + name]
        need(f['source'] == selected[key][0]['path'] and f['sha256'] == selected[key][0]['sha256']
             and f['bytes'] == selected[key][1], 'exact-raw-public-metadata')
    need({k: by_path['raw/data.tar'][k] for k in ('bytes', 'sha256')} == index['archive'], 'entire-raw-archive-candidate')
    aliases = {**raw_files, 'DATA-INVENTORY.json': {'source': selected['inventory'][0]['path'],
        'bytes': selected['inventory'][1], 'sha256': selected['inventory'][0]['sha256']}}
    for name, f in aliases.items():
        candidate = by_path.get('members/' + name)
        need(candidate is not None and candidate['kind'] == 'raw'
             and all(candidate[k] == f[k] for k in ('source', 'bytes', 'sha256')), 'all-raw-member-aliases-covered')
    extras = value['extra_files'];need(type(extras) is list, 'explicit-base-extra-candidates')
    for f in extras:
        file_row(f);candidate = by_path.get('extras/' + f['path'])
        need(candidate is not None and all(candidate[k] == f[k] for k in ('source', 'bytes', 'sha256')), 'approved-base-extra-candidate')
    expected_raw = required_raw | {'members/' + name for name in aliases} | {'extras/' + f['path'] for f in extras}
    need({f['path'] for f in index['candidates'] if f['kind'] == 'raw'} == expected_raw, 'no-missing-or-foreign-raw-candidates')
    fetch = docs['fetch'];need(fetch['schema'] == 'kpxa-gn3-network-fetch/v1', 'root-fetch-schema')
    pages = list(fetch['pages']) + list(fetch['current_view']['post_query_delta']['pages']);expected_decoded = {};packet_pages = []
    for page in pages:
        path = 'chain/' + relative(page['path']);need(path not in expected_decoded, 'duplicate-full-page-selector')
        f = raw_files.get(path);need(f is not None and f['kind'] == 'full-source-page'
            and f['bytes'] == uint(page['gzip_bytes'], True) and f['sha256'] == pin(page['gzip_sha256']), 'every-primary-and-post-gzip-member')
        expected_decoded[path] = {'path': 'decoded-gzip/' + path, 'bytes': uint(page['decoded_bytes'], True),
            'sha256': pin(page['decoded_sha256']), 'kind': 'decoded', 'source': None,
            'gzip': {'source': f['source'], 'bytes': f['bytes'], 'sha256': f['sha256']}}
        packet_pages.append({'packet_path': path, **{k: page[k] for k in ('gzip_bytes', 'gzip_sha256', 'decoded_bytes', 'decoded_sha256')}})
    need({f['path'] for f in raw_files.values() if f['kind'] == 'full-source-page'} == set(expected_decoded), 'complete-selected-gzip-union')
    actual_decoded = [{k: v for k, v in f.items() if k != 'index'} for f in index['candidates'] if f['kind'] == 'decoded']
    need(actual_decoded == [expected_decoded[k] for k in sorted(expected_decoded)], 'complete-two-fetch-array-decoded-union')
    need(packet['pages'] == sorted(packet_pages, key=lambda f: f['packet_path']), 'packet-decoded-coverage-identities')
    return value


def actual_context_checked(context, coverage, canary_assets):
    """Bind current H/C and every scope role to the externally selected dataset.

    Portable canary ASSETS can use /public paths while the packet retains the
    original asset manifest bytes. Its separate Root selector is explicit; the
    packet asset role still has to match the original bytes exactly.
    """
    context_checked(context)
    fields(canary_assets, ('source', 'bytes', 'sha256'), 'external-canary-assets-selector')
    absolute(canary_assets['source']);uint(canary_assets['bytes']);pin(canary_assets['sha256'])
    selection = json.loads(bytes.fromhex(coverage['selection']['raw_hex']))
    by_path = {f['path']: f for f in selection['files']}
    mounts = sources_checked(context['sources']);scope = context['scope_document']
    need(scope.get('schema') == 'kpxa-canary-final-accepted-history-context/v1', 'actual02-accepted-scope')
    role_names = set(selection['roles']);fields(scope['roles'], role_names, 'same-twelve-current-scope-roles')
    for name in role_names:
        expected = by_path[selection['roles'][name]]
        target = '/public/' + name.upper() + '.json' if name in ('history', 'context') else '/public/final-provenance/' + name + '.json'
        need(scope['roles'][name] == {'mount': target, 'sha256': expected['sha256']}
             and mounts.get(target, {}).get('sha256') == expected['sha256']
             and mounts[target]['bytes'] == expected['bytes'], 'same-Root-selected-role-source-bytes')
    assets = mounts['/public/ASSETS.json']
    need(all(assets[k] == canary_assets[k] for k in ('source', 'bytes', 'sha256')), 'same-external-canary-assets')


def worker_report_checked(value, kind, files):
    fields(value, {'schema', 'status', 'candidate_count', 'candidate_bytes', 'matched_candidate_count', 'scope'}
           | ({'literal_seed_coverage'} if kind == 'derived' else set()), 'unchanged-worker-result-fields')
    need(value['schema'] == 'kpxa-' + ('literal-seed-export' if kind == 'literal' else 'derived-export') + '-result/v1'
         and value['status'] == 'PASS' and uint(value['matched_candidate_count']) == 0
         and uint(value['candidate_count']) == len(files) + 1
         and uint(value['candidate_bytes']) == sum(f['bytes'] for f in files)
             + len(encoded({'schema': 'kpx8-new-owner-seed-export-allowlist/v1' if kind == 'literal'
                           else 'kpxa-derived-export-candidates/v1',
                           'files': candidate_manifest(files)})), 'complete-all-pass-worker-result')
    need(value['scope'] == ('LITERAL_SEED_CANARY_ONLY_NOT_SECURITY_OR_PRIVACY_PROOF' if kind == 'literal'
         else 'FINITE_RECOVERABLE_DERIVED_BYTES_ONLY_NOT_ALL_SECRETS_OR_PRIVACY_PROOF'), 'unchanged-worker-scope')
    if kind == 'derived':
        need(value['literal_seed_coverage'] is False, 'literal-and-derived-separate')


def preparation_checked(value, releases, files, expected_source):
    fields(value, ('source_sha256', 'provenance'), 'explicit-prepared-source-and-provenance')
    need(value['source_sha256'] == pin(expected_source), 'actual-prepared-source-pin')
    p = value['provenance']
    fields(p, ('schema', 'base_launcher_sha256', 'prepared_launcher_source_sha256',
        'candidate_manifest_sha256', 'candidate_files', 'candidate_bytes', 'context_releases',
        'large_direct_readonly_views', 'small_candidate_staged_bytes', 'public_source_stage_bytes',
        'largest_transient_candidate_bytes', 'public_candidate_set_admitted_once',
        'public_PASS_markers_used_as_authority', 'sealed_storage_or_hostile_host_protection',
        'trusted_host_no_concurrent_mutation_required', 'worker_whole_candidate_authentication_before_each_private_read',
        'original_content_read_or_hashed_by_preparer', 'original_fds_opened_or_cached_by_preparer',
        'public_admission_wall_seconds'), 'prepared-public-provenance-fields')
    need(p['schema'] == 'kpxa-prepared-publication-public-admission/v1'
         and p['base_launcher_sha256'] == LAUNCHER
         and p['prepared_launcher_source_sha256'] == expected_source
         and p['candidate_manifest_sha256'] == sha(encoded(candidate_manifest(files)))
         and uint(p['candidate_files']) == len(files)
         and uint(p['candidate_bytes']) == sum(f['bytes'] for f in files)
         and p['context_releases'] == {k:r['row']['sha256'] for k,r in releases.items()}, 'same-admitted-public-batch-contexts')
    threshold = 1024 * 1024
    need(uint(p['large_direct_readonly_views']) == sum(f['bytes'] >= threshold for f in files)
         and uint(p['small_candidate_staged_bytes']) == sum(f['bytes'] for f in files if f['bytes'] < threshold)
         and uint(p['public_source_stage_bytes']) == sum(f['bytes'] for r in releases.values() for f in r['release']['sources'])
         and uint(p['largest_transient_candidate_bytes']) == max(f['bytes'] for f in files), 'honest-public-stage-resource-counts')
    for name, expected in (('public_candidate_set_admitted_once',True),('public_PASS_markers_used_as_authority',False),
        ('sealed_storage_or_hostile_host_protection',False),('trusted_host_no_concurrent_mutation_required',True),
        ('worker_whole_candidate_authentication_before_each_private_read',True),
        ('original_content_read_or_hashed_by_preparer',False),('original_fds_opened_or_cached_by_preparer',False)):
        need(p[name] is expected, 'prepared-boundary-and-worker-authentication')
    need(type(p['public_admission_wall_seconds']) in (int,float)
         and math.isfinite(p['public_admission_wall_seconds']) and p['public_admission_wall_seconds'] >= 0,
         'finite-neutral-public-admission-time')
    return sha(encoded(p))


def invocation_checked(value, original, descriptor, descriptor_row, release, release_row,
                       context, index_sha, plan_sha, preparation, prepared_source_sha, launcher_sha=LAUNCHER):
    original_checked(value['original'])
    fields(value, ('schema', 'global_index_sha256', 'batch_plan_sha256', 'batch_id', 'batch_descriptor',
        'original', 'release', 'launcher_sha256', 'source_core_sha256', 'scope_sha256',
        'prepared_launcher_sha256', 'public_preparation_sha256', 'summary', 'workers', 'worker_receipts'), 'local-invocation-envelope')
    need(value['schema'] == 'kpxa-publication-batch-audit-invocation/v1'
         and value['global_index_sha256'] == index_sha and value['batch_plan_sha256'] == plan_sha
         and value['batch_id'] == descriptor['batch_id'] and value['batch_descriptor'] == descriptor_row
         and value['original'] == original and value['release'] == release_row
         and value['launcher_sha256'] == launcher_sha == LAUNCHER, 'batch-original-launcher-release-join')
    need(value['prepared_launcher_sha256'] == prepared_source_sha
         and value['public_preparation_sha256'] == sha(encoded(preparation['provenance'])), 'same-actual-prepared-snapshot')
    fields(release, ('schema', 'domain_hex32', 'files', 'sources'), 'unchanged-c465-release-schema')
    need(release['schema'] == 'kpxa-publication-audit-release/v1' and release['domain_hex32'] == DOMAIN
         and release['files'] == descriptor['files'] and sha(encoded(release)) == release_row['sha256']
         and core_sources(release['sources']) == core_sources(context['sources']), 'same-candidate-and-source-context')
    actual = sources_checked(release['sources']);scope = actual['/public/CANARY-CONTEXT-SCOPE.json']
    scope_raw = encoded(batch_scope(context, descriptor['files']))
    need(value['source_core_sha256'] == sha(encoded(core_sources(context['sources'])))
         and value['scope_sha256'] == scope['sha256'] == sha(scope_raw)
         and scope['bytes'] == len(scope_raw), 'same-H-C-assets-source-and-batch-scope')
    summary = value['summary'];files = descriptor['files']
    need(type(summary) is dict and summary['schema'] == 'kpxa-one-leaf-publication-audit/v1'
         and summary['release_sha256'] == release_row['sha256']
         and summary['candidate_manifest_sha256'] == sha(encoded(candidate_manifest(files)))
         and uint(summary['candidate_file_count']) == len(files)
         and uint(summary['candidate_bytes']) == sum(f['bytes'] for f in files)
         and uint(summary['source_files']) == len(release['sources'])
         and summary['literal_status'] == summary['derived_status'] == 'PASS'
         and summary['actual_original_check_executed'] is True
         and summary['one_original_leaf_read_only_per_namespace'] is True
         and summary['parent_sibling_root_or_home_mounted'] is False
         and summary['original_content_read_or_hashed_by_controller'] is False
         and summary['literal_and_derived_are_separate'] is True
         and summary['private_values_paths_hashes_or_indices_exported'] is False
         and summary['future_material_covered'] is False, 'complete-unchanged-launcher-pass')
    need(summary['context_kind'] == ('ACCEPTED_HISTORY' if original['cohort'] == 'actual02' else 'NONCHAIN_CREATION_ONLY')
         and summary['own_historical_payout_keys_checked'] is (original['cohort'] == 'actual02'), 'same-original-context-cohort')
    fields(value['workers'], ('literal', 'derived'), 'both-worker-results-required')
    fields(value['worker_receipts'], ('literal', 'derived'), 'both-raw-worker-receipts-required')
    for kind in ('literal', 'derived'):
        worker_report_checked(value['workers'][kind], kind, files)
        result = value['workers'][kind];receipt = value['worker_receipts'][kind]
        fields(receipt,set(result)|{'sha256','bytes','candidate_manifest_sha256'},'raw-worker-receipt-fields')
        worker_report_checked({k:v for k,v in receipt.items() if k in result},kind,files)
        uint(receipt['bytes']);pin(receipt['sha256']);pin(receipt['candidate_manifest_sha256'])
        need(receipt == {'sha256':sha(encoded(result)), 'bytes':len(encoded(result)),
                        'candidate_manifest_sha256':sha(encoded(candidate_manifest(files))), **result},
             'exact-raw-worker-result-identity')


def positive_checked(value, original, context, index_sha, plan_sha):
    original_checked(value['original'])
    fields(value, ('schema', 'global_index_sha256', 'batch_plan_sha256', 'original',
        'source_core_sha256', 'positive_source_sha256', 'result'), 'positive-envelope-fields')
    need(value['schema'] == 'kpxa-publication-batch-positive-invocation/v1'
         and value['global_index_sha256'] == index_sha and value['batch_plan_sha256'] == plan_sha
         and value['original'] == original and original['cohort'] == 'actual02'
         and value['source_core_sha256'] == sha(encoded(core_sources(context['sources'])))
         and value['positive_source_sha256'] == POSITIVE, 'same-three-positive-original-and-context-join')
    result = value['result']
    fields(result, ('schema', 'status', 'approved_own_workload_matched', 'approved_historical_exit_key_coverage'), 'unchanged-positive-result')
    need(result['schema'] == 'kpxa-own-final-workload-and-exit-key-attestation/v1'
         and result['status'] == 'PASS' and result['approved_own_workload_matched'] is True
         and result['approved_historical_exit_key_coverage'] is True, 'positive-workload-and-three-exit-key-coverage')


def producer_preparation_checked(value,index,index_sha,plan,plan_sha):
    fields(value,('source_sha256','result','raw_archive_member_aliases_reverified'),'producer-BASE-authority')
    need(value['source_sha256']==PRODUCER and value['raw_archive_member_aliases_reverified'] is True,'selected-producer-raw-alias-reverification')
    p=value['result']
    fields(p,('schema','archive','global_index_sha256','batch_plan_sha256','base_batch_sha256','global_candidates',
        'base_verification','whole_decoded_pages','decoded_batches','decoded_bytes_verified','decoded_bytes_retained',
        'raw_member_physical_copies_created','public_descriptor_supplemental_audit_required',
        'private_original_worker_network_or_publication_executed'),'actual-producer-preparation-fields')
    decoded=[c for c in index['candidates'] if c['kind']=='decoded']
    need(p['schema']=='kpxa-public-recovery-data-batched-preparation/v1' and p['archive']=={'path':'data.tar',**index['archive'],
        'members':sum(c['path'].startswith('members/') for c in index['candidates'])}
        and p['global_index_sha256']==index_sha and p['batch_plan_sha256']==plan_sha
        and p['base_batch_sha256']==p['base_verification']['descriptor']['sha256']
        and uint(p['global_candidates'])==len(index['candidates']) and uint(p['whole_decoded_pages'])==len(decoded)
        and uint(p['decoded_batches'])==len(plan['batches'])-1
        and uint(p['decoded_bytes_verified'])==sum(c['bytes'] for c in decoded)
        and uint(p['decoded_bytes_retained'])==0 and uint(p['raw_member_physical_copies_created'])==0
        and p['public_descriptor_supplemental_audit_required'] is True
        and p['private_original_worker_network_or_publication_executed'] is False,'full-producer-output-archive-and-complete-decoded-join')


def primary_checked(index, index_sha, plan, plan_sha, originals, contexts, batches,
                    invocations, coverage, canary_assets, prepared_source_sha):
    """Validate a primary checkpoint without manufacturing supplemental PASS."""
    need(sha(encoded(index)) == pin(index_sha) and sha(encoded(plan)) == pin(plan_sha), 'exact-primary-index-plan-SHA')
    index_checked(index);coverage_checked(coverage,index);plan_checked(plan,index,index_sha)
    expected_originals=originals_checked(originals)
    fields(contexts,('creation','actual02'),'primary-contexts')
    for context in contexts.values():context_checked(context)
    actual_context_checked(contexts['actual02'],coverage,canary_assets)
    need(type(batches) is list and len(batches)==len(plan['batches']),'complete-primary-batch-checkpoint')
    expected={}
    for batch,record in zip(plan['batches'],batches):
        fields(record,('descriptor','descriptor_row','materialization','releases','preparation','producer_preparation'),'primary-batch-fields')
        descriptor_checked(record['descriptor'],batch,index,index_sha,plan_sha)
        row(record['descriptor_row']);need(sha(encoded(record['descriptor']))==record['descriptor_row']['sha256'],'primary-descriptor-SHA')
        materialization_checked(record['materialization'],batch,record['descriptor'],record['descriptor_row'],index_sha,plan_sha)
        if batch['batch_id']=='BASE':
            producer_preparation_checked(record['producer_preparation'],index,index_sha,plan,plan_sha)
            need(record['producer_preparation']['result']['base_verification']==record['materialization'],'same-actual-BASE-receipt')
        else:need(record['producer_preparation'] is None,'decoded-batch-has-no-foreign-BASE-proof')
        fields(record['releases'],('creation','actual02'),'primary-release-contexts')
        preparation_checked(record['preparation'],record['releases'],record['descriptor']['files'],prepared_source_sha)
        expected[batch['batch_id']]=record
    need(type(invocations) is list and len(invocations)==9*len(expected),'all-nine-every-primary-batch')
    seen=set()
    for value in invocations:
        oid=value.get('original',{}).get('original_id');bid=value.get('batch_id');key=(oid,bid)
        need(oid in expected_originals and bid in expected and key not in seen,'primary-wrong-Original-or-duplicate-batch')
        seen.add(key);record=expected[bid];original=expected_originals[oid];release=record['releases'][original['cohort']]
        fields(release,('release','row'),'primary-release-record')
        invocation_checked(value,original,record['descriptor'],record['descriptor_row'],release['release'],release['row'],
            contexts[original['cohort']],index_sha,plan_sha,record['preparation'],prepared_source_sha)
    need(seen=={(o,b) for o in expected_originals for b in expected},'primary-exact-crossproduct')
    return True


def descriptor_stage_checked(stage,index,index_sha,plan,plan_sha,batches,contexts,release_sha):
    """Mandatory descriptors plus explicitly Root-selected supplemental metadata.

    The selection is local/unpublished, avoiding a recursive self-audit claim.
    Extra public metadata (including multipart maps) cannot displace a mandatory
    GLOBAL, PLAN, BASE or decoded-batch descriptor.
    """
    required_fields={'batch_id','files','required_public_metadata','supplemental_public_metadata','releases'}
    fields(stage,required_fields|({'release_sha256','preparation'} if 'preparation' in stage else set()),'descriptor-stage-fields')
    core={k:stage[k] for k in required_fields}
    need(stage['batch_id']=='DESCRIPTORS' and sha(encoded(core))==pin(release_sha),'external-descriptor-release-SHA')
    if 'preparation' in stage:need(stage['release_sha256']==release_sha,'same-external-descriptor-release')
    selectors=stage['required_public_metadata'];fields(selectors,('index','plan'),'required-index-plan-selectors')
    row(selectors['index']);row(selectors['plan'])
    need(selectors['index']['sha256']==index_sha and selectors['plan']['sha256']==plan_sha,'required-index-plan-pins')
    mandatory=[{'source':r['descriptor_row']['path'],'bytes':len(encoded(r['descriptor'])),
                'sha256':r['descriptor_row']['sha256']} for r in batches]
    mandatory += [{'source':selectors['index']['path'],'bytes':len(encoded(index)),'sha256':index_sha},
                  {'source':selectors['plan']['path'],'bytes':len(encoded(plan)),'sha256':plan_sha}]
    extras=stage['supplemental_public_metadata'];need(type(extras) is list,'explicit-supplemental-list')
    for file in extras:file_row(file)
    files=stage['files'];need(type(files) is list and files,'nonempty-descriptor-files')
    for file in files:file_row(file)
    def identities(rows):return {(f['source'],f['bytes'],f['sha256']) for f in rows}
    need(len({f['source'] for f in files})==len(files) and len({f['path'] for f in files})==len(files)
        and len({f['source'] for f in mandatory+extras})==len(mandatory)+len(extras)
        and identities(files)==identities(mandatory+extras),'all-mandatory-and-explicit-supplemental-metadata')
    fields(stage['releases'],('creation','actual02'),'descriptor-two-context-releases')
    for cohort,record in stage['releases'].items():
        fields(record,('release','row'),'descriptor-release-record');row(record['row'])
        rel=record['release'];fields(rel,('schema','domain_hex32','files','sources'),'descriptor-release-shape')
        need(rel['schema']=='kpxa-publication-audit-release/v1' and rel['domain_hex32']==DOMAIN
             and rel['files']==files and sha(encoded(rel))==record['row']['sha256']
             and core_sources(rel['sources'])==core_sources(contexts[cohort]['sources']),'same-descriptor-public-context')
        scope=sources_checked(rel['sources'])['/public/CANARY-CONTEXT-SCOPE.json']
        raw=encoded(batch_scope(contexts[cohort],files))
        need(scope['sha256']==sha(raw) and scope['bytes']==len(raw),'same-descriptor-batch-scope')
    return {'schema':'kpxa-publication-audit-batch/v1','domain_hex32':DOMAIN,'global_index_sha256':index_sha,
        'batch_plan_sha256':plan_sha,'batch_id':'DESCRIPTORS','candidate_indices':[],'files':files}


def aggregate(index, index_sha, plan, plan_sha, originals, contexts, batches, descriptor_stage,
              invocations, positives, descriptor_release_sha, coverage, canary_assets, prepared_source_sha):
    """Trusted-local invocation receipts; never a public cryptographic attestation."""
    need(sha(encoded(index)) == pin(index_sha) and sha(encoded(plan)) == pin(plan_sha), 'exact-canonical-index-and-plan-SHA')
    index_checked(index);coverage_checked(coverage, index)
    plan_checked(plan, index, index_sha);expected_originals = originals_checked(originals)
    fields(contexts, ('creation', 'actual02'), 'two-explicit-context-closures')
    for value in contexts.values():context_checked(value)
    actual_context_checked(contexts['actual02'], coverage, canary_assets)
    need(type(batches) is list and len(batches) == len(plan['batches']), 'all-planned-batch-records')
    expected = {}
    for batch, record in zip(plan['batches'], batches):
        fields(record, ('descriptor', 'descriptor_row', 'materialization', 'releases', 'preparation', 'producer_preparation'), 'batch-record-fields')
        descriptor_checked(record['descriptor'], batch, index, index_sha, plan_sha)
        row(record['descriptor_row']);need(sha(encoded(record['descriptor'])) == record['descriptor_row']['sha256'], 'per-batch-descriptor-SHA-not-global-index-SHA')
        materialization_checked(record['materialization'], batch, record['descriptor'], record['descriptor_row'], index_sha, plan_sha)
        if batch['batch_id']=='BASE':
            producer_preparation_checked(record['producer_preparation'],index,index_sha,plan,plan_sha)
            need(record['producer_preparation']['result']['base_verification']==record['materialization'],'same-actual-BASE-receipt')
        else:need(record['producer_preparation'] is None,'decoded-batch-has-no-foreign-BASE-proof')
        fields(record['releases'], ('creation', 'actual02'), 'both-context-releases')
        preparation_checked(record['preparation'], record['releases'], record['descriptor']['files'], prepared_source_sha)
        expected[batch['batch_id']] = record
    descriptor = descriptor_stage_checked(descriptor_stage,index,index_sha,plan,plan_sha,batches,contexts,descriptor_release_sha)
    files=descriptor['files']
    preparation_checked(descriptor_stage['preparation'],descriptor_stage['releases'],files,prepared_source_sha)
    expected['DESCRIPTORS'] = {'descriptor': descriptor,
        'descriptor_row': {'path': '/LOCAL-UNPUBLISHED/DESCRIPTORS', 'sha256': descriptor_release_sha},
        'releases': descriptor_stage['releases'], 'preparation': descriptor_stage['preparation']}
    need(type(invocations) is list and len(invocations) == 9 * len(expected), 'every-nine-original-times-every-batch')
    seen = set()
    for value in invocations:
        need(type(value) is dict and type(value.get('original')) is dict, 'invocation-shape')
        oid = value['original'].get('original_id');bid = value.get('batch_id');key = (oid, bid)
        need(oid in expected_originals and bid in expected and key not in seen, 'wrong-original-foreign-or-duplicate-batch')
        seen.add(key);record = expected[bid];cohort = expected_originals[oid]['cohort'];release_record = record['releases'][cohort]
        fields(release_record, ('release', 'row'), 'release-record')
        invocation_checked(value, expected_originals[oid], record['descriptor'], record['descriptor_row'],
            release_record['release'], release_record['row'], contexts[cohort], index_sha, plan_sha,
            record['preparation'], prepared_source_sha)
    need(seen == {(o, b) for o in expected_originals for b in expected}, 'exact-all-original-batch-crossproduct')
    actual = {k: v for k, v in expected_originals.items() if v['cohort'] == 'actual02'}
    need(type(positives) is list and len(positives) == 3, 'exact-three-positive-checks-once')
    found = set()
    for value in positives:
        oid = value.get('original', {}).get('original_id')
        need(oid in actual and oid not in found, 'positive-original-mismatch-or-duplicate');found.add(oid)
        positive_checked(value, actual[oid], contexts['actual02'], index_sha, plan_sha)
    need(found == set(actual), 'same-three-positive-nine-exit-coverage-join')
    return {'schema': 'kpxa-batched-publication-audit-boolean-result/v1',
        'global_index_sha256': index_sha, 'batch_plan_sha256': plan_sha,
        'descriptor_release_sha256': descriptor_release_sha,
        'prepared_launcher_source_sha256': prepared_source_sha, 'base_launcher_source_sha256': LAUNCHER,
        'exact_global_candidate_union_checked': True,
        'every_nine_originals_every_batch_literal_and_derived_passed': True,
        'descriptor_stage_checked': True, 'same_three_positive_nine_exit_coverage_joined': True,
        'all_H_C_assets_sources_unchanged': True, 'private_original_contents_read_by_coordinator': False,
        'private_original_routes_or_values_exported': False, 'future_material_covered': False,
        'accepted_backing_or_recovery_authority': False, 'general_privacy_or_security_proved': False}
