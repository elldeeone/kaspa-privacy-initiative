#!/usr/bin/env python3
"""Preserve the pinned public packet; defer whole decoded pages to bounded batches.

No original, private context, worker, network, publication or deletion operation
exists here. Public descriptor coverage is a separate externally pinned audit.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import tarfile

GUARD = '/var/tmp/kpi-root-guard-helper-09.py'
PREIMAGE_SHA = 'e958bd50cf77a8f69c8064c2aa3c8d61c69d54e9796ea41b42ee9cc8e510d584'
INDEX_SCHEMA = 'kpxa-publication-global-candidate-index/v1'
PLAN_SCHEMA = 'kpxa-publication-whole-page-batch-plan/v1'
BATCH_SCHEMA = 'kpxa-publication-audit-batch/v1'


def need(condition, label):
    if not condition:
        raise ValueError(label)


def pinned_preimage():
    source = Path(__file__).absolute().with_name('prepare_data_packet_tmpfs.py')
    raw = runpy.run_path(GUARD)['read'](str(source), PREIMAGE_SHA)
    value = {'__name__': '_pinned_opaque_packet_preimage', '__file__': str(source)}
    exec(compile(raw, str(source), 'exec'), value)
    return value


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(row):
    return {key: row[key] for key in ('path', 'bytes', 'sha256')}


def authenticate_selection(base, read, selection, selection_sha):
    need(type(selection_sha) is str and base['HEX'].fullmatch(selection_sha), 'external-selection-SHA-required')
    selected = base['parse'](read(str(base['public_source'](str(selection))), selection_sha))
    need(type(selected) is dict and set(selected) == {'schema', 'domain_hex32', 'roles', 'files'}
         and selected['schema'] == 'kpxa-root-public-recovery-data-selection/v1'
         and selected['domain_hex32'] == base['DOMAIN'] and type(selected['roles']) is dict
         and set(selected['roles']) == base['ROLES'], 'exact-root-selection-schema')
    rows = base['file_rows'](selected['files'])
    by_path = {row['path']: row for row in rows}
    need(len(set(selected['roles'].values())) == len(base['ROLES']), 'distinct-semantic-role-paths-required')
    role_rows = {}
    for role, name in selected['roles'].items():
        base['relative'](name)
        need(name in by_path and by_path[name]['kind'] != 'full-source-page', 'explicit-role-row-required')
        role_rows[role] = by_path[name]
    need(selected['roles']['fetch'] == 'chain/fetch.json', 'canonical-fetch-placement')
    documents = {}
    for row in rows:
        raw = read(str(base['public_source'](row['source'])), row['sha256'])
        need(len(raw) == row['bytes'], 'whole-selected-public-file-length')
        for role, role_row in role_rows.items():
            if role_row is row:
                documents[role] = base['parse'](raw)
    base['terminal_shape'](documents, role_rows)
    pages = base['page_contract'](documents['fetch'], rows)
    return rows, role_rows, pages


def extra_rows(base, read, path=None, expected=None):
    if path is None:
        need(expected is None, 'extra-path-and-pin-required-together')
        return []
    need(type(expected) is str and base['HEX'].fullmatch(expected), 'external-extra-pin-required')
    value = base['parse'](read(str(base['public_source'](str(path))), expected))
    need(type(value) is dict and set(value) == {'schema', 'domain_hex32', 'files'}
         and value['schema'] == 'kpxa-publication-base-extra-candidates/v1'
         and value['domain_hex32'] == base['DOMAIN'] and type(value['files']) is list,
         'exact-base-extra-schema')
    rows = []
    for row in value['files']:
        need(type(row) is dict and set(row) == {'source', 'path', 'bytes', 'sha256'}, 'exact-base-extra-row')
        base['relative'](row['path']); base['uint'](row['bytes'])
        need(type(row['sha256']) is str and base['HEX'].fullmatch(row['sha256']), 'extra-row-SHA')
        raw = read(str(base['public_source'](row['source'])), row['sha256'])
        need(len(raw) == row['bytes'], 'extra-row-byte-identity')
        rows.append(dict(row))
    base['member_paths']([row['path'] for row in rows])
    return sorted(rows, key=lambda row: row['path'])


def decode_verify_discard(base, read, rows, pages):
    """Verify every member of every gzip, retaining no decoded byte object."""
    by_path = {row['path']: row for row in rows}
    result = []
    for index, (name, record) in enumerate(sorted(pages.items())):
        row = by_path[name]
        raw = read(str(base['public_source'](row['source'])), row['sha256'])
        for _chunk in base['decoded_chunks'](raw, record):
            pass
        result.append({'packet_path': name, 'gzip_bytes': record['gzip_bytes'],
            'gzip_sha256': record['gzip_sha256'], 'decoded_bytes': record['decoded_bytes'],
            'decoded_sha256': record['decoded_sha256'], 'audit_path': 'decoded/page-%05d.bin' % index})
    return result


def verify_member_aliases(base, read, raw_archive, aliases):
    """Authenticate exact canonical member bytes against existing public leaves.

    This avoids physically extracting a second copy of the raw member set.
    The archive is read through guard09; no filesystem content read bypasses it.
    """
    names = sorted(aliases)
    base['member_paths'](names)
    offset = 0
    with tarfile.open(fileobj=io.BytesIO(raw_archive), mode='r:') as archive:
        members = archive.getmembers()
        need([member.name for member in members] == names, 'exact-alias-member-name-order')
        for member in members:
            row = aliases[member.name]
            raw = read(str(base['public_source'](row['source'])), row['sha256'])
            need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'alias-whole-byte-identity')
            header = base['tar_member'](member.name, raw).tobuf(format=tarfile.USTAR_FORMAT)
            need(member.offset == offset and member.offset_data == offset + 512
                 and raw_archive[offset:offset + 512] == header
                 and member.type == tarfile.REGTYPE and not member.pax_headers
                 and archive.extractfile(member).read() == raw, 'canonical-member-alias-equality')
            offset += 512 + ((len(raw) + 511) // 512) * 512
    trailer_bytes = 1024 + (-(offset + 1024) % tarfile.RECORDSIZE)
    need(len(raw_archive) == offset + trailer_bytes and not any(raw_archive[offset:]),
         'exact-canonical-zero-trailer')


def write_packet(base, read, rows, role_rows, decoded_rows, output):
    """The four public release object bytes match immutable e958 exactly."""
    inventory_rows = [{key: row[key] for key in ('path', 'bytes', 'sha256', 'kind')} for row in rows]
    inventory = {'schema': 'kpxa-public-recovery-data-inventory/v1', 'domain_hex32': base['DOMAIN'],
        'files': inventory_rows, 'file_count': len(rows), 'payload_bytes': sum(row['bytes'] for row in rows),
        'all_payload_members_regular_mode0400': True,
        'proving_key_or_runtime_executable_roles_supported': False, 'private_owner_inputs_selected': False}
    inventory_raw = encoded(inventory)
    base['write_new'](output / 'DATA-INVENTORY.json', inventory_raw)
    archive_path = output / 'data.tar'
    with archive_path.open('xb') as destination:
        with tarfile.open(fileobj=destination, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            members = [(row['path'], row) for row in rows] + [('DATA-INVENTORY.json', None)]
            for name, row in sorted(members):
                raw = inventory_raw if row is None else read(str(base['public_source'](row['source'])), row['sha256'])
                need(row is None or len(raw) == row['bytes'], 'public-file-changed-before-archive')
                archive.addfile(base['tar_member'](name, raw), io.BytesIO(raw))
        destination.flush(); os.fsync(destination.fileno())
    archive_path.chmod(0o400)
    archive_raw = read(str(archive_path))
    aliases = {row['path']: dict(row) for row in rows}
    aliases['DATA-INVENTORY.json'] = {'source': str(output / 'DATA-INVENTORY.json'),
        'path': 'DATA-INVENTORY.json', 'bytes': len(inventory_raw), 'sha256': sha(inventory_raw)}
    verify_member_aliases(base, read, archive_raw, aliases)
    packet = {'schema': 'kpxa-public-recovery-data-packet/v1', 'domain_hex32': base['DOMAIN'],
        'classification': 'OPAQUE_PUBLIC_BYTE_CONTAINER_WITH_METADATA_SHAPE_PREFLIGHT_ONLY',
        'inventory': {'path': 'DATA-INVENTORY.json', 'bytes': len(inventory_raw), 'sha256': sha(inventory_raw)},
        'archive': {'path': 'data.tar', 'bytes': len(archive_raw), 'sha256': sha(archive_raw), 'members': len(rows) + 1},
        'roles': {role: {key: role_rows[role][key] for key in ('path', 'bytes', 'sha256')} for role in sorted(base['ROLES'])},
        'pages': [{key: row[key] for key in ('packet_path', 'gzip_bytes', 'gzip_sha256', 'decoded_bytes', 'decoded_sha256')}
                  for row in decoded_rows],
        'declared_terminal_shape': {'accepted_protocol_transactions': 16, 'payments': 6, 'native_exits': 9,
            'reserve_sompi': 0, 'head_outpoint': None},
        'source_bytes_reserialized': False, 'decoded_pages_in_archive': False,
        'chain_native_or_cryptographic_acceptance_verified_by_packager': False,
        'currentness_independent_administration_or_offhost_execution_claimed': False,
        'private_original_backups_or_owner_inputs_read': False}
    packet_raw = encoded(packet)
    base['write_new'](output / 'PACKET.json', packet_raw)
    sums = ''.join(pin + '  ' + name + '\n' for pin, name in
                   [(sha(archive_raw), 'data.tar'), (sha(inventory_raw), 'DATA-INVENTORY.json'),
                    (sha(packet_raw), 'PACKET.json')]).encode()
    base['write_new'](output / 'SHA256SUMS', sums)
    return aliases, packet


def candidate_index(base, read, rows, pages, aliases, packet, output, selection_sha, extras=()):
    raw_rows = []
    for name in ('data.tar', 'DATA-INVENTORY.json', 'PACKET.json', 'SHA256SUMS'):
        source = output / name
        raw = read(str(base['public_source'](str(source))))
        raw_rows.append({'path': 'raw/' + name, 'bytes': len(raw), 'sha256': sha(raw),
                         'kind': 'raw', 'source': str(source), 'gzip': None})
    for name, row in aliases.items():
        raw_rows.append({'path': 'members/' + name, 'bytes': row['bytes'], 'sha256': row['sha256'],
                         'kind': 'raw', 'source': row['source'], 'gzip': None})
    for row in extras:
        raw_rows.append({'path': 'extras/' + row['path'], 'bytes': row['bytes'], 'sha256': row['sha256'],
                         'kind': 'raw', 'source': row['source'], 'gzip': None})
    by_path = {row['path']: row for row in rows}
    decoded = []
    for name, record in sorted(pages.items()):
        row = by_path[name]
        decoded.append({'path': 'decoded-gzip/' + name, 'bytes': record['decoded_bytes'],
            'sha256': record['decoded_sha256'], 'kind': 'decoded', 'source': None,
            'gzip': {'source': row['source'], 'bytes': row['bytes'], 'sha256': row['sha256']}})
    candidates = [*sorted(raw_rows, key=lambda row: row['path']), *decoded]
    for index, row in enumerate(candidates):
        row['index'] = index
    value = {'schema': INDEX_SCHEMA, 'domain_hex32': base['DOMAIN'], 'root_selection_sha256': selection_sha,
             'archive': {key: packet['archive'][key] for key in ('bytes', 'sha256')}, 'candidates': candidates}
    validate_index(base, value)
    return value


def validate_index(base, value):
    need(type(value) is dict and set(value) == {'schema', 'domain_hex32', 'root_selection_sha256', 'archive', 'candidates'}
         and value['schema'] == INDEX_SCHEMA and value['domain_hex32'] == base['DOMAIN'], 'exact-global-index-schema')
    need(type(value['root_selection_sha256']) is str and base['HEX'].fullmatch(value['root_selection_sha256']), 'root-selection-pin')
    archive = value['archive']
    need(type(archive) is dict and set(archive) == {'bytes', 'sha256'}
         and type(archive['sha256']) is str and base['HEX'].fullmatch(archive['sha256']), 'global-archive-identity')
    base['uint'](archive['bytes'])
    rows = value['candidates']
    need(type(rows) is list and rows, 'nonempty-global-candidates')
    for index, row in enumerate(rows):
        need(type(row) is dict and set(row) == {'index', 'path', 'bytes', 'sha256', 'kind', 'source', 'gzip'}
             and type(row['index']) is int and row['index'] == index, 'exact-contiguous-global-row')
        base['relative'](row['path']); base['uint'](row['bytes'])
        need(type(row['sha256']) is str and base['HEX'].fullmatch(row['sha256']), 'candidate-SHA')
        if row['kind'] == 'raw':
            need(row['gzip'] is None, 'raw-candidate-gzip-null')
            base['public_source'](row['source'])
        else:
            need(row['kind'] == 'decoded' and row['source'] is None, 'decoded-candidate-source-null')
            gzip = row['gzip']
            need(type(gzip) is dict and set(gzip) == {'source', 'bytes', 'sha256'}
                 and type(gzip['sha256']) is str and base['HEX'].fullmatch(gzip['sha256']), 'exact-decoded-gzip-selector')
            base['uint'](gzip['bytes']); base['public_source'](gzip['source'])
    base['member_paths']([row['path'] for row in rows])
    ordered = [*sorted((row for row in rows if row['kind'] == 'raw'), key=lambda row: row['path']),
               *sorted((row for row in rows if row['kind'] == 'decoded'), key=lambda row: row['path'])]
    need(rows == ordered and any(row['kind'] == 'raw' for row in rows)
         and any(row['kind'] == 'decoded' for row in rows), 'raw-prefix-then-decoded-deterministic-order')
    by_path = {row['path']: row for row in rows}
    need(all('raw/' + name in by_path for name in ('data.tar', 'DATA-INVENTORY.json', 'PACKET.json', 'SHA256SUMS'))
         and {key: by_path['raw/data.tar'][key] for key in ('bytes', 'sha256')} == archive,
         'all-four-raw-artifacts-and-whole-archive-join')
    for row in rows:
        if row['kind'] != 'decoded':
            continue
        need(row['path'].startswith('decoded-gzip/chain/'), 'decoded-original-artifact-path-required')
        member = by_path.get('members/' + row['path'][len('decoded-gzip/'):])
        need(member is not None and member['kind'] == 'raw'
             and {key: member[key] for key in ('source', 'bytes', 'sha256')} == row['gzip'],
             'decoded-gzip-exact-raw-member-alias-join')


def batch_plan(base, index, index_sha, budget):
    validate_index(base, index)
    need(type(index_sha) is str and base['HEX'].fullmatch(index_sha), 'external-index-pin')
    need(base['uint'](budget) > 0, 'positive-operator-decoded-budget')
    raw = [row for row in index['candidates'] if row['kind'] == 'raw']
    decoded = [row for row in index['candidates'] if row['kind'] == 'decoded']
    batches = [{'batch_id': 'BASE', 'candidate_indices': [row['index'] for row in raw],
                'bytes': sum(row['bytes'] for row in raw)}]
    chosen, total = [], 0
    for row in decoded:
        need(row['bytes'] <= budget, 'whole-decoded-page-exceeds-operator-budget')
        if chosen and total + row['bytes'] > budget:
            batches.append({'batch_id': 'D%06d' % len(batches), 'candidate_indices': chosen, 'bytes': total})
            chosen, total = [], 0
        chosen.append(row['index']); total += row['bytes']
    if chosen:
        batches.append({'batch_id': 'D%06d' % len(batches), 'candidate_indices': chosen, 'bytes': total})
    return {'schema': PLAN_SCHEMA, 'domain_hex32': base['DOMAIN'], 'global_index_sha256': index_sha,
            'operator_decoded_budget_bytes': budget, 'batches': batches}


def validate_plan(base, index, index_sha, plan):
    need(type(plan) is dict and set(plan) == {'schema', 'domain_hex32', 'global_index_sha256',
         'operator_decoded_budget_bytes', 'batches'}, 'exact-batch-plan-schema')
    need(type(plan['batches']) is list and plan['batches'], 'nonempty-typed-batches')
    for batch in plan['batches']:
        need(type(batch) is dict and set(batch) == {'batch_id', 'candidate_indices', 'bytes'}
             and type(batch['batch_id']) is str and type(batch['candidate_indices']) is list
             and batch['candidate_indices'] and all(type(number) is int and number >= 0
             for number in batch['candidate_indices']), 'exact-typed-nonempty-batch')
        base['uint'](batch['bytes'])
    expected = batch_plan(base, index, index_sha, plan['operator_decoded_budget_bytes'])
    need(plan == expected, 'exact-deterministic-whole-page-partition')


def descriptor(base, index, index_sha, plan, plan_sha, selected, sources):
    need(type(plan_sha) is str and base['HEX'].fullmatch(plan_sha), 'external-plan-pin')
    files = []
    for number in selected['candidate_indices']:
        row = index['candidates'][number]
        base['public_source'](sources[number])
        files.append({'source': sources[number], **identity(row)})
    return {'schema': BATCH_SCHEMA, 'domain_hex32': base['DOMAIN'], 'global_index_sha256': index_sha,
            'batch_plan_sha256': plan_sha, 'batch_id': selected['batch_id'],
            'candidate_indices': list(selected['candidate_indices']), 'files': files}


def prepare(selection, selection_sha, output, budget, extra_allowlist=None, extra_sha=None):
    base = pinned_preimage(); read = runpy.run_path(GUARD)['read']
    rows, role_rows, pages = authenticate_selection(base, read, selection, selection_sha)
    extras = extra_rows(base, read, extra_allowlist, extra_sha)
    need(base['uint'](budget) > 0 and all(record['decoded_bytes'] <= budget for record in pages.values()),
         'whole-page-fit-required-before-output')
    decoded = decode_verify_discard(base, read, rows, pages)
    output = base['output_path'](output)
    output.mkdir(mode=0o700)
    aliases, packet = write_packet(base, read, rows, role_rows, decoded, output)
    index = candidate_index(base, read, rows, pages, aliases, packet, output, selection_sha, extras)
    index_raw = encoded(index); index_sha = sha(index_raw)
    plan = batch_plan(base, index, index_sha, budget)
    plan_raw = encoded(plan); plan_sha = sha(plan_raw)
    base['write_new'](output / 'GLOBAL-CANDIDATE-INDEX.json', index_raw)
    base['write_new'](output / 'BATCH-PLAN.json', plan_raw)
    sources = {row['index']: row['source'] for row in index['candidates'] if row['kind'] == 'raw'}
    base_raw = encoded(descriptor(base, index, index_sha, plan, plan_sha, plan['batches'][0], sources))
    base['write_new'](output / 'BASE-BATCH.json', base_raw)
    return {'schema': 'kpxa-public-recovery-data-batched-preparation/v1',
        'archive': packet['archive'], 'global_index_sha256': index_sha, 'batch_plan_sha256': plan_sha,
        'base_batch_sha256': sha(base_raw), 'global_candidates': len(index['candidates']),
        'base_verification': {'schema': 'kpxa-publication-batch-materialization/v1',
            'global_index_sha256': index_sha, 'batch_plan_sha256': plan_sha, 'batch_id': 'BASE',
            'descriptor': {'path': str(output / 'BASE-BATCH.json'), 'sha256': sha(base_raw)},
            'verified_candidate_indices': plan['batches'][0]['candidate_indices'],
            'whole_decoded_pages': False, 'gzip_and_decoded_identities_verified': True,
            'raw_archive_and_member_aliases_verified': True},
        'whole_decoded_pages': len(decoded), 'decoded_batches': len(plan['batches']) - 1,
        'decoded_bytes_verified': sum(row['decoded_bytes'] for row in decoded),
        'decoded_bytes_retained': 0, 'raw_member_physical_copies_created': 0,
        'public_descriptor_supplemental_audit_required': True,
        'private_original_worker_network_or_publication_executed': False}


def materialize(index_path, index_sha, plan_path, plan_sha, batch_id, output):
    base = pinned_preimage(); read = runpy.run_path(GUARD)['read']
    for expected in (index_sha, plan_sha):
        need(type(expected) is str and base['HEX'].fullmatch(expected), 'external-descriptor-pin')
    index_path, plan_path = Path(index_path), Path(plan_path)
    need(index_path.name == 'GLOBAL-CANDIDATE-INDEX.json' and plan_path.name == 'BATCH-PLAN.json'
         and index_path.parent == plan_path.parent, 'same-prepared-descriptor-parent')
    index = base['parse'](read(str(base['public_source'](str(index_path))), index_sha))
    plan = base['parse'](read(str(base['public_source'](str(plan_path))), plan_sha))
    validate_index(base, index); validate_plan(base, index, index_sha, plan)
    matches = [row for row in plan['batches'] if row['batch_id'] == batch_id]
    need(len(matches) == 1 and batch_id != 'BASE', 'one-decoded-batch-required')
    selected = matches[0]
    output = base['output_path'](output)
    need(output.parent == base['SHM_OUTPUT_BASE'], 'decoded-batch-exact-public-tmpfs-only')
    descriptor_path = index_path.parent / (batch_id + '-BATCH.json')
    base['public_source'](str(descriptor_path))
    need(not descriptor_path.exists(), 'fresh-batch-descriptor-required')
    output.mkdir(mode=0o700)
    sources = {}
    for number in selected['candidate_indices']:
        row = index['candidates'][number]; gzip = row['gzip']
        need(row['kind'] == 'decoded', 'whole-decoded-candidate-only')
        raw = read(str(base['public_source'](gzip['source'])), gzip['sha256'])
        record = {'gzip_bytes': gzip['bytes'], 'gzip_sha256': gzip['sha256'],
                  'decoded_bytes': row['bytes'], 'decoded_sha256': row['sha256']}
        target = output / ('candidate-%06d.bin' % number)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, 'wb') as destination:
            for chunk in base['decoded_chunks'](raw, record):
                destination.write(chunk)
            destination.flush(); os.fsync(destination.fileno())
        # Only the complete, exactly verified page becomes a mounted candidate.
        sources[number] = str(target)
    value = descriptor(base, index, index_sha, plan, plan_sha, selected, sources)
    raw_descriptor = encoded(value)
    base['write_new'](descriptor_path, raw_descriptor)
    return {'schema': 'kpxa-publication-batch-materialization/v1', 'batch_id': batch_id,
        'global_index_sha256': index_sha, 'batch_plan_sha256': plan_sha,
        'descriptor': {'path': str(descriptor_path), 'sha256': sha(raw_descriptor)},
        'verified_candidate_indices': selected['candidate_indices'],
        'whole_decoded_pages': True, 'gzip_and_decoded_identities_verified': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    p = commands.add_parser('prepare')
    p.add_argument('--selection', required=True, type=Path)
    p.add_argument('--selection-sha256', required=True)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--decoded-budget-bytes', required=True, type=int)
    p.add_argument('--base-extra-allowlist', type=Path)
    p.add_argument('--base-extra-allowlist-sha256')
    p = commands.add_parser('materialize')
    p.add_argument('--index', required=True, type=Path)
    p.add_argument('--index-sha256', required=True)
    p.add_argument('--plan', required=True, type=Path)
    p.add_argument('--plan-sha256', required=True)
    p.add_argument('--batch-id', required=True)
    p.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.operation == 'prepare':
            result = prepare(args.selection, args.selection_sha256, args.output, args.decoded_budget_bytes,
                             args.base_extra_allowlist, args.base_extra_allowlist_sha256)
        else:
            result = materialize(args.index, args.index_sha256, args.plan, args.plan_sha256, args.batch_id, args.output)
        print(json.dumps(result, sort_keys=True))
    except Exception:
        parser.exit(2, 'Batched public packet refused; no private operation or publication performed.\n')


if __name__ == '__main__':
    main()
