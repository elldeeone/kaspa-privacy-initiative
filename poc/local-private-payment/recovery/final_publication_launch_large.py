#!/usr/bin/env python3
"""Large-leaf resource sibling of reviewed final scope launcher bfe8.

Established campaign_cached finite_mounts pattern (586a8852bff9b5dbfce13d0f16a70546d9f94d39553d9a4bc1df85d6ce655bd8):
authenticate one whole public leaf via helper09, stage small files, and bind each
large canonical public source read-only. Root selected 1MiB for nonexecuted
candidate artifacts; executable/source staging remains unchanged. No complete candidate payload list is
retained. Host administration/concurrent host mutation remains outside the threat
model; per-file metadata and unchanged worker hashes are still checked.

Execution requires root's exact release selection and independent review GO.
The controller reads only guard-admitted public files and original metadata.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import stat
import subprocess

DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
GUARD = '/var/tmp/kpi-root-guard-helper-09.py'
ORIGINAL_PREFIX = Path('/var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01')
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def need(value):
    if not value:
        raise ValueError('finite-publication-audit-refused')


def parse(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value)
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_float=lambda _: need(False), parse_constant=lambda _: need(False))


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def attributes(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode',
        'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def original_metadata(a):
    path = Path(a.original)
    need(path.is_absolute() and '..' not in path.parts and path.name == 'BACKUP.json')
    # Exact prefix was released by root; this does not discover new originals.
    need(path.is_relative_to(ORIGINAL_PREFIX))
    need(not any(p.is_symlink() for p in (path, *path.parents)))
    info = path.lstat()  # Metadata only. Never open/hash/copy this original.
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o600
         and (info.st_dev, info.st_ino, info.st_size, info.st_ctime_ns) ==
             (a.original_device, a.original_inode, a.original_bytes, a.original_ctime_ns))
    return path, info


def save(path, raw, mode=0o400):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), mode)
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())



# Minimal scope extension of launcher1bd; no checker or private-leaf logic changes.
ROLES = frozenset(('terminalhandoff', 'activation', 'history', 'context', 'currententry',
                   'replayresults', 'fetch', 'selection', 'descriptor', 'assets',
                   'parameters', 'accounting'))
ROLE_MOUNTS = {role: '/public/final-provenance/' + role + '.json' for role in ROLES}
ROLE_MOUNTS.update({'history': '/public/HISTORY.json', 'context': '/public/CONTEXT.json'})
HEX = re.compile('[0-9a-f]{64}')


def metadata_json(raw):
    # Timings may be finite floats. Monetary/count predicates below still require
    # exact integers or the existing canonical decimal-string boundary.
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value)
            value[key] = item
        return value
    def number(text):
        value = float(text)
        need(math.isfinite(value))
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_float=number,
                      parse_constant=lambda _: need(False))


def terminal_checkpoint(value):
    need(type(value) is dict and set(value) == {'state_hex112', 'reserve_sompi', 'outpoint_hex36'}
         and type(value['reserve_sompi']) is int and value['reserve_sompi'] == 0
         and value['outpoint_hex36'] is None
         and type(value['state_hex112']) is str and re.fullmatch('[0-9a-f]{224}', value['state_hex112']))
    state = bytes.fromhex(value['state_hex112'])
    need(state[:8] == b'KPXAST01' and state[8:40].hex() == DOMAIN
         and int.from_bytes(state[72:76], 'little') == 15
         and int.from_bytes(state[108:112], 'little') == 16)


def observed_sompi(value):
    need(type(value) is str and value.isascii() and value.isdecimal()
         and (value == '0' or not value.startswith('0')))
    amount = int(value)
    need(10_000_000 <= amount <= 2_870_000_000_000_000_000)
    return amount


def accepted_scope(scope, sources, candidate_sha):
    need(set(scope) == {'schema', 'classification', 'original_cohort', 'roles',
         'candidate_manifest_sha256', 'accepted_backing_or_recovery_authority',
         'own_historical_payout_keys_required', 'future_material_covered'}
         and scope['schema'] == 'kpxa-canary-final-accepted-history-context/v1'
         and scope['classification'] == 'CANARY_ONLY_ROOT_SELECTED_ACCEPTED_HISTORY_AND_OWN_PAYOUT_KEYS'
         and scope['original_cohort'] == 'actual02'
         and scope['candidate_manifest_sha256'] == candidate_sha
         and scope['accepted_backing_or_recovery_authority'] is False
         and scope['own_historical_payout_keys_required'] is True
         and scope['future_material_covered'] is False
         and type(scope['roles']) is dict and set(scope['roles']) == ROLES)
    documents, pins = {}, {}
    for role in sorted(ROLES):
        row = scope['roles'][role]
        need(type(row) is dict and set(row) == {'mount', 'sha256'}
             and row['mount'] == ROLE_MOUNTS[role]
             and type(row['sha256']) is str and HEX.fullmatch(row['sha256'])
             and row['mount'] in sources and sha(sources[row['mount']]) == row['sha256'])
        pins[role] = row['sha256']
        # All twelve identities bind exact bytes. Opaque roles are not reinterpreted.
        if role in ('terminalhandoff', 'history', 'context', 'currententry',
                    'replayresults', 'fetch', 'descriptor'):
            documents[role] = metadata_json(sources[row['mount']])
    h, history, context, replay, fetch = (documents[role] for role in
        ('terminalhandoff', 'history', 'context', 'replayresults', 'fetch'))
    need(h['schema'] == 'kpxa-confirmed-transition-handoff/v1'
         and type(h['accepted_transactions']) is int and h['accepted_transactions'] == 16
         and h['terminal'] is True and h['accepted_whole_CASE_equals_expected'] is True
         and type(h['native_payouts_observed']) is list and len(h['native_payouts_observed']) == 9)
    need(history['schema'] == 'kpxa-local-private-history/v1' and history['domain_hex32'] == DOMAIN
         and type(history['transitions']) is list and len(history['transitions']) == 15
         and [row['kind'] for row in history['transitions']] == ['payment'] * 6 + ['exit'] * 9)
    initial = history['genesis']
    need(type(initial['outputs_hex520']) is list and len(initial['outputs_hex520']) == 3
         and type(initial['deposit_sompi']) is int and initial['deposit_sompi'] == 2_000_000_000
         and type(initial['reserve_sompi']) is int and initial['reserve_sompi'] == 6_000_000_000)
    need(context['schema'] == 'kpxa-selected-history-context/v1' and context['domain_hex32'] == DOMAIN
         and context['genesis_sha256'] == sha(json.dumps(initial, sort_keys=True,
             separators=(',', ':'), allow_nan=False).encode()))
    terminal_checkpoint(history['head'])
    need(history['head'] == context['checkpoint'] == h['checkpoint'] == replay['current_checkpoint']
         and documents['currententry'] is None)
    need(replay['schema'] == 'kpxa-accepted-native-replay/v1'
         and h['status'] == replay['status'] == 'RECORDED_VALIDATING_NODE_PREFIX_FINANCIAL_AND_NATIVE_PASS'
         and type(replay['accepted_transactions']) is int and replay['accepted_transactions'] == 16
         and replay['terminal'] is True and type(replay['whole_CASE_native_Full_reports']) is list
         and len(replay['whole_CASE_native_Full_reports']) == 16)
    need(fetch['schema'] == 'kpxa-gn3-network-fetch/v1' and fetch['status'] == 'FETCHED_PENDING_REPLAY'
         and type(fetch['transactions']) is list and len(fetch['transactions']) == 16)
    ids = [row['transaction']['id'] for row in fetch['transactions']]
    need(all(type(txid) is str and HEX.fullmatch(txid) for txid in ids) and len(set(ids)) == 16
         and [row['transaction_id'] for row in replay['whole_CASE_native_Full_reports']] == ids
         and h['expected_transaction_id'] == ids[-1]
         and h['trial_id'] == replay['trial_id'] == documents['descriptor']['trial_id'] == fetch['descriptor']['trial_id'])
    for role, field in [('history', 'history_sha256'), ('context', 'context_sha256'),
                        ('fetch', 'fetch_sha256'), ('selection', 'selection_sha256')]:
        need(replay[field] == pins[role])
    for role, selector in [('history', 'HISTORY.json'), ('context', 'CONTEXT.json'),
                           ('currententry', 'CURRENT-ENTRY.json'), ('replayresults', 'RESULTS.json'),
                           ('fetch', 'fetch.json')]:
        need(h['selectors'][selector]['sha256'] == pins[role])
    # Scope-only joins; the unchanged derived worker performs genuine financial
    # replay and own payout-key reconciliation. These checks create no chain truth.
    for transition, observed in zip(history['transitions'][6:], h['native_payouts_observed']):
        raw = transition['projection_hex']
        need(type(raw) is str and len(raw) in (1824 * 2, 1872 * 2)
             and re.fullmatch('[0-9a-f]+', raw))
        body = bytes.fromhex(raw)[-1632:]
        need(body[:8] == b'KPXAXB01' and body[16:48].hex() == DOMAIN
             and type(observed) is dict
             and observed_sompi(observed['amount_sompi']) == int.from_bytes(body[396:404], 'little')
             and observed['script_public_key'] == body[404:440].hex())
    return {'context_kind': 'ACCEPTED_HISTORY', 'original_cohort': 'actual02',
        'canary_context_classification': scope['classification'],
        'accepted_backing_or_recovery_authority': False,
        'own_historical_payout_keys_checked': False,
        'public_protocol_transactions': 16, 'public_payment_transitions': 6,
        'public_exit_transitions': 9, 'future_material_covered': False,
        'scope_binds_all_twelve_root_selected_roles': True}


def final_scope(sources, candidate_sha):
    scope = parse(sources['/public/CANARY-CONTEXT-SCOPE.json'])
    if scope.get('schema') == 'kpxa-canary-final-accepted-history-context/v1':
        return accepted_scope(scope, sources, candidate_sha)
    # Original NONCHAIN scope and predicates are unchanged from launcher1bd.
    need(set(scope) == {'schema', 'classification', 'creation_output_count',
        'deposit_sompi', 'accepted_backing', 'recovery_or_signing_authority',
        'actual_payout_key_material_covered', 'future_material_covered'}
        and scope['schema'] == 'kpxa-canary-nonchain-creation-context/v1'
        and scope['classification'] == 'CANARY_ONLY_NONCHAIN_GENUINE_CREATION_OUTPUTS'
        and type(scope['creation_output_count']) is int and scope['creation_output_count'] == 9
        and type(scope['deposit_sompi']) is int and scope['deposit_sompi'] == 2_000_000_000
        and scope['accepted_backing'] is False and scope['recovery_or_signing_authority'] is False
        and type(scope['actual_payout_key_material_covered']) is int
        and scope['actual_payout_key_material_covered'] == 0
        and scope['future_material_covered'] is False)
    audit_history = parse(sources['/public/HISTORY.json'])
    need(audit_history['transitions'] == []
         and len(audit_history['genesis']['outputs_hex520']) == scope['creation_output_count']
         and audit_history['genesis']['deposit_sompi'] == scope['deposit_sompi'])
    return {'context_kind': 'NONCHAIN_CREATION_ONLY',
        'canary_context_classification': scope['classification'],
        'accepted_backing_or_recovery_authority': False,
        'own_historical_payout_keys_checked': False,
        'actual_payout_key_material_covered': 0, 'future_material_covered': False}



LARGE_PUBLIC_LEAF = 1024 * 1024


def candidate_entry(guard, row, index, runtime):
    """One guard-authenticated public leaf; never retain a complete payload set."""
    value = row['source']
    need(type(value) is str and Path(value).is_absolute() and '..' not in Path(value).parts
         and str(Path(value)) == value and type(row['bytes']) is int and row['bytes'] >= 0
         and type(row['sha256']) is str and HEX.fullmatch(row['sha256']))
    guard['refresh']()
    path, before = guard['m'].GUARD.metadata(Path(value))
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and before.st_size == row['bytes']
         and not any(part.is_symlink() for part in (path, *path.parents)))
    # This is the existing helper09 whole-byte authority, not a new stream API.
    # Only this one leaf's bytes exist transiently in the controller.
    raw = guard['read'](str(path), row['sha256'])
    _, after = guard['m'].GUARD.metadata(path)
    need(len(raw) == row['bytes'] and attributes(before) == attributes(after))
    direct = len(raw) >= LARGE_PUBLIC_LEAF
    if direct:
        selected = path
    elif runtime is not None:
        selected = runtime / 'candidates' / (str(index) + '.bin')
        save(selected, raw)
    else:
        selected = None  # Preflight performs no staging, as in bfe8.
    del raw
    return selected, path, attributes(after), direct


def check_candidate_metadata(guard, candidates):
    """Check immutable public identities before/after each one-leaf worker."""
    guard['refresh']()
    for _, path, expected, _ in candidates:
        selected, info = guard['m'].GUARD.metadata(path)
        need(selected == path and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and not any(part.is_symlink() for part in (path, *path.parents))
             and attributes(info) == expected)


def execute(a):
    guard = runpy.run_path(GUARD)
    read = guard['read']
    runtime = None
    value = parse(read(str(a.release), a.release_sha256))
    need(type(value) is dict and set(value) == {'schema', 'domain_hex32', 'files', 'sources'}
         and value['schema'] == 'kpxa-publication-audit-release/v1'
         and value['domain_hex32'] == DOMAIN and type(value['files']) is list
         and value['files'] and type(value['sources']) is list and value['sources'])
    if a.execute:
        need(re.fullmatch('audit-[a-z0-9-]{1,64}', a.identity))
        runtime = Path('/var/tmp/kpi-local-private-payment-01/publication-audits') / a.identity
        need(not runtime.exists() and not any(p.is_symlink() for p in (runtime, *runtime.parents)))
        runtime.mkdir(parents=True, mode=0o700)
    rows, candidates, sources, names, mounts = [], [], [], set(), set()
    for index, row in enumerate(value['files']):
        need(type(row) is dict and set(row) == {'source', 'path', 'bytes', 'sha256'})
        name = PurePosixPath(row['path'])
        need(type(row['path']) is str and str(name) == row['path'] and not name.is_absolute()
             and name.parts and '..' not in name.parts and '\\' not in row['path']
             and '\0' not in row['path'] and row['path'] not in names)
        names.add(row['path'])
        entry = candidate_entry(guard, row, index, runtime)
        rows.append({key: row[key] for key in ('path', 'bytes', 'sha256')})
        candidates.append(entry)
    for row in value['sources']:
        need(type(row) is dict and set(row) == {'source', 'mount', 'bytes', 'sha256', 'mode'})
        path = PurePosixPath(row['mount'])
        need(type(row['mount']) is str and str(path) == row['mount']
             and path.is_relative_to('/public') and '..' not in path.parts
             and path != PurePosixPath('/public') and '\\' not in row['mount']
             and '\0' not in row['mount']
             and row['mount'] not in mounts and row['mode'] in ('0400', '0500'))
        mounts.add(row['mount'])
        raw = read(row['source'], row['sha256'])
        need(type(row['bytes']) is int and len(raw) == row['bytes'])
        sources.append((row, raw))
    required = {'/public/recovery/publication_literal.py', '/public/recovery/publication_derived.py',
                '/public/ASSETS.json', '/public/HISTORY.json', '/public/CONTEXT.json',
                '/public/CANARY-CONTEXT-SCOPE.json'}
    need(required <= mounts)
    selected_sources = {row['mount']: raw for row, raw in sources}
    need(sha(selected_sources['/public/recovery/publication_literal.py'])
         == '0d3d7cbed85da8288040407df8c6038fe58c14782d9af8f1ad8dcc748b1f1c52'
         and sha(selected_sources['/public/recovery/publication_derived.py'])
         == 'e4c466cdbcb849d2249832f4c42efab97ea7d43039a55095948888710b67a489')
    scope_summary = final_scope(selected_sources, sha(encoded(rows)))
    owner, before = original_metadata(a)
    # All public bytes are authenticated before a child can receive the leaf.
    summary = {'schema': 'kpxa-one-leaf-publication-audit/v1', 'release_sha256': a.release_sha256,
        'candidate_file_count': len(rows), 'candidate_bytes': sum(row['bytes'] for row in rows),
        'source_files': len(sources), 'original_content_read_or_hashed_by_controller': False,
        'actual_original_check_executed': False, 'literal_and_derived_are_separate': True,
        'candidate_manifest_sha256': sha(encoded(rows)),
        'large_candidate_direct_readonly_mounts': sum(entry[3] for entry in candidates),
        'small_candidate_staged_mounts': sum(not entry[3] for entry in candidates),
        'small_candidate_bytes_per_job': sum(row['bytes'] for row in rows if row['bytes'] < LARGE_PUBLIC_LEAF),
        'nine_job_small_candidate_copy_bytes': 9 * sum(row['bytes'] for row in rows if row['bytes'] < LARGE_PUBLIC_LEAF),
        'source_stage_bytes_per_job': sum(len(raw) for _, raw in sources),
        'largest_transient_candidate_payload_bytes': max(row['bytes'] for row in rows),
        'additional_large_candidate_copy_bytes_per_job': 0,
        'complete_candidate_payload_list_retained': False,
        'trusted_host_mutation_outside_model': True, **scope_summary}
    if not a.execute:
        return summary
    common = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
        '--clearenv', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
        '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
        '--ro-bind', '/etc/alternatives', '/etc/alternatives', '--proc', '/proc',
        '--dev', '/dev', '--tmpfs', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'LANG', 'C.UTF-8']
    for index, (selected, _, _, _) in enumerate(candidates):
        need(selected is not None)
        common += ['--ro-bind', str(selected), '/candidates/' + str(index) + '.bin']
    by_mount = {}
    for index, (row, raw) in enumerate(sources):
        selected = runtime / 'sources' / (str(index) + '.bin')
        save(selected, raw, int(row['mode'], 8))
        common += ['--ro-bind', str(selected), row['mount']]
        by_mount[row['mount']] = row['sha256']
    for kind, schema, result_schema in (
        ('literal', 'kpx8-new-owner-seed-export-allowlist/v1', 'kpxa-literal-seed-export-result/v1'),
        ('derived', 'kpxa-derived-export-candidates/v1', 'kpxa-derived-export-result/v1')):
        check_candidate_metadata(guard, candidates)
        need(attributes(original_metadata(a)[1]) == attributes(before))
        raw_manifest = encoded({'schema': schema, 'files': rows})
        manifest = runtime / (kind + '-ALLOWLIST.json')
        save(manifest, raw_manifest)
        out = runtime / (kind + '-out')
        out.mkdir(mode=0o700)
        command = common + ['--ro-bind', str(owner), '/BACKUP.json',
            '--ro-bind', str(manifest), '/ALLOWLIST.json', '--bind', str(out), '/out',
            '/usr/bin/python3', '-B', '/public/recovery/publication_' + kind + '.py',
            '--owner', '/BACKUP.json', '--allowlist', '/ALLOWLIST.json',
            '--allowlist-sha256', sha(raw_manifest), '--candidates', '/candidates',
            '--output', '/out/RESULTS.json']
        if kind == 'derived':
            for option, mount in [('assets', '/public/ASSETS.json'), ('history', '/public/HISTORY.json'),
                                  ('context', '/public/CONTEXT.json')]:
                command += ['--' + option, mount, '--' + option + '-sha256', by_mount[mount]]
        process = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, env=CLEAN)
        need(process.returncode == 0)
        result = parse(read(str(out / 'RESULTS.json')))
        expected_fields = {'schema', 'status', 'candidate_count', 'candidate_bytes',
                           'matched_candidate_count', 'scope'}
        if kind == 'derived':
            expected_fields.add('literal_seed_coverage')
        need(set(result) == expected_fields and result['schema'] == result_schema
             and result['status'] == 'PASS' and type(result['matched_candidate_count']) is int
             and result['matched_candidate_count'] == 0
             and result['candidate_count'] == len(rows) + 1
             and result['candidate_bytes'] == summary['candidate_bytes'] + len(raw_manifest))
        if kind == 'derived':
            need(result['literal_seed_coverage'] is False
                 and result['scope'] == 'FINITE_RECOVERABLE_DERIVED_BYTES_ONLY_NOT_ALL_SECRETS_OR_PRIVACY_PROOF')
        else:
            need(result['scope'] == 'LITERAL_SEED_CANARY_ONLY_NOT_SECURITY_OR_PRIVACY_PROOF')
        check_candidate_metadata(guard, candidates)
        need(attributes(original_metadata(a)[1]) == attributes(before))
        summary[kind + '_status'] = result['status']
    summary['own_historical_payout_keys_checked'] = scope_summary['context_kind'] == 'ACCEPTED_HISTORY'
    summary.update({'actual_original_check_executed': True, 'one_original_leaf_read_only_per_namespace': True,
                    'parent_sibling_root_or_home_mounted': False, 'private_values_paths_hashes_or_indices_exported': False})
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--release', required=True, type=Path)
    p.add_argument('--release-sha256', required=True)
    p.add_argument('--original', required=True)
    for name in ('device', 'inode', 'bytes', 'ctime-ns'):
        p.add_argument('--original-' + name, required=True, type=int)
    p.add_argument('--identity')
    p.add_argument('--execute', action='store_true')
    try:
        print(json.dumps(execute(p.parse_args()), sort_keys=True))
    except Exception:
        p.exit(2, 'Finite publication audit refused; no private material exported.\n')


if __name__ == '__main__':
    main()
