#!/usr/bin/env python3
"""Opaque public recovery-data container; no financial verification or execution.

Actual inputs must be root-frozen and independently audited before publication.
This producer never selects a directory tree, private owner, program or key.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import tarfile
import zlib

GUARD = '/var/tmp/kpi-root-guard-helper-09.py'
OUTPUT_BASE = Path('/var/tmp/kpi-local-private-payment-01/publication-release')
LOCAL_ONLY_PREFIXES = (
    Path('/var/tmp/kpi-owner-private-lifecycle-01/private'),
    Path('/var/tmp/kpi-local-original-metadata-01'),
    Path('/var/tmp/kpi-local-private-payment-01/publication-contexts'),
)
DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
ROLES = frozenset({'terminalhandoff', 'activation', 'history', 'context', 'currententry',
                  'replayresults', 'fetch', 'selection', 'descriptor', 'assets',
                  'parameters', 'accounting'})
KINDS = frozenset({'public-metadata', 'public-source', 'public-evidence', 'full-source-page'})
RESERVED_FILES = frozenset({'DATA-INVENTORY.json', 'PACKET.json', 'data.tar', 'SHA256SUMS'})
HEX = re.compile(r'[0-9a-f]{64}')


class Refused(ValueError):
    pass


def need(condition, label):
    if not condition:
        raise Refused(label)


def parse(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate-JSON-field')
            value[key] = item
        return value
    def finite_float(value):
        parsed = float(value)
        need(math.isfinite(parsed), 'nonfinite-JSON-number')
        return parsed
    def invalid(_):
        raise Refused('nonfinite-JSON-number')
    # Operational timing telemetry can be finite floats; amount/count fields
    # remain explicit type(value) is int checks below. Raw bytes are preserved.
    return json.loads(raw, object_pairs_hook=pairs, parse_float=finite_float, parse_constant=invalid)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def uint(value):
    need(type(value) is int and 0 <= value < 1 << 64, 'unsigned-integer-required')
    return value


def relative(value):
    need(type(value) is str and value and re.fullmatch(r'[A-Za-z0-9_./-]+', value),
         'canonical-relative-path-required')
    path = PurePosixPath(value)
    need(not path.is_absolute() and path.parts and str(path) == value
         and all(part not in ('.', '..') and not part.startswith('.') for part in path.parts),
         'unsafe-relative-path')
    return value


def public_source(value):
    need(type(value) is str and '\0' not in value and '\\' not in value,
         'absolute-public-source-required')
    path = Path(value)
    need(path.is_absolute() and '..' not in path.parts and str(path) == value, 'unsafe-public-source')
    need(not any(path.is_relative_to(prefix) for prefix in LOCAL_ONLY_PREFIXES),
         'known-local-only-source-forbidden')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'unsafe-public-source')
    lowered = [part.lower() for part in path.parts]
    need(not any(part in ('private', 'owner', 'controller', 'local-bookkeeping', 'truth', 'events')
                 for part in lowered), 'private-source-forbidden')
    name = path.name.lower()
    need(name not in ('owner.json', '.env')
         and not name.startswith(('originals', 'backup', 'owner', 'private-plan', 'private_plan',
                                  'privateplan', 'invoice', 'rawlog', 'raw-log',
                                  'raw_log', 'viewseal', 'view-seal', 'view_seal'))
         and not name.endswith(('.pk', '.log', '.stdout', '.stderr', '.stdout.txt', '.stderr.txt')),
         'backup-key-plan-map-or-raw-log-source-forbidden')
    return path


def member_paths(names):
    selected = set()
    for name in names:
        relative(name)
        need(name not in selected, 'duplicate-member-path')
        selected.add(name)
    for name in selected:
        need(all(str(parent) not in selected for parent in PurePosixPath(name).parents
                 if str(parent) != '.'), 'regular-member-ancestor-collision')


def file_rows(value):
    need(type(value) is list and value, 'explicit-nonempty-public-file-list-required')
    result, names = [], set()
    for row in value:
        need(type(row) is dict and set(row) == {'source', 'path', 'bytes', 'sha256', 'kind'},
             'exact-public-row-fields')
        name = relative(row['path'])
        need(name not in names and name not in RESERVED_FILES
             and PurePosixPath(name).parts[0] != 'audit-only',
             'duplicate-or-reserved-packet-path')
        need(row['kind'] in KINDS and type(row['sha256']) is str
             and HEX.fullmatch(row['sha256']), 'public-row-kind-or-SHA')
        uint(row['bytes'])
        public_source(row['source'])
        names.add(name)
        result.append(dict(row))
    member_paths([*names, *RESERVED_FILES])
    return sorted(result, key=lambda row: row['path'])


def page_contract(fetch, rows):
    """Exact main and post-query page closure, preserving fetch-relative paths."""
    need(type(fetch) is dict and type(fetch.get('pages')) is list and fetch['pages']
         and type(fetch.get('current_view')) is dict
         and type(fetch['current_view'].get('post_query_delta')) is dict
         and type(fetch['current_view']['post_query_delta'].get('pages')) is list,
         'both-retained-page-lists-required')
    pages = [*fetch['pages'], *fetch['current_view']['post_query_delta']['pages']]
    need(pages, 'nonempty-complete-main-prefix-pages-required')
    files = {row['path']: row for row in rows}
    expected = {}
    for record in pages:
        need(type(record) is dict and set(record) == {'path', 'request', 'decoded_sha256',
             'decoded_bytes', 'gzip_sha256', 'gzip_bytes', 'encoding'}, 'exact-fetch-page-fields')
        name = 'chain/' + relative(record['path'])
        need(name not in expected, 'duplicate-fetch-relative-page')
        for field in ('decoded_sha256', 'gzip_sha256'):
            need(type(record[field]) is str and HEX.fullmatch(record[field]), 'page-SHA-required')
        for field in ('decoded_bytes', 'gzip_bytes'):
            uint(record[field])
        need(type(record['encoding']) is str and record['encoding'], 'page-encoding-required')
        row = files.get(name)
        need(row is not None and row['kind'] == 'full-source-page'
             and row['sha256'] == record['gzip_sha256'] and row['bytes'] == record['gzip_bytes'],
             'missing-or-inconsistent-main-or-post-query-page')
        expected[name] = dict(record)
    need({row['path'] for row in rows if row['kind'] == 'full-source-page'} == set(expected),
         'extra-or-missing-full-source-page')
    return expected


def decoded_chunks(raw, record):
    """All gzip members are decoded unchanged; non-gzip trailing data refuses."""
    need(len(raw) == record['gzip_bytes'] and sha(raw) == record['gzip_sha256'],
         'compressed-page-byte-identity')
    count, digest = 0, hashlib.sha256()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as source:
            while True:
                chunk = source.read(1 << 20)
                if not chunk:
                    break
                count += len(chunk)
                need(count <= record['decoded_bytes'], 'decoded-page-larger-than-selected-identity')
                digest.update(chunk)
                yield chunk
    except (OSError, EOFError, zlib.error) as error:
        raise Refused('invalid-or-incomplete-gzip-page') from error
    need(count == record['decoded_bytes'] and digest.hexdigest() == record['decoded_sha256'],
         'decoded-page-byte-identity')


def checkpoint(value):
    need(type(value) is dict and set(value) == {'state_hex112', 'reserve_sompi', 'outpoint_hex36'},
         'exact-checkpoint-fields')
    need(type(value['state_hex112']) is str and re.fullmatch(r'[0-9a-f]{224}', value['state_hex112'])
         and uint(value['reserve_sompi']) == 0 and value['outpoint_hex36'] is None,
         'terminal-zero-reserve-null-head-required')
    state = bytes.fromhex(value['state_hex112'])
    need(state[:8] == b'KPXAST01' and state[8:40].hex() == DOMAIN
         and int.from_bytes(state[72:76], 'little') == 15
         and int.from_bytes(state[108:112], 'little') == 16, 'terminal-CM15-NF16-shape')


def replay_pin_joins(replay, role_rows):
    for role, field in [('history', 'history_sha256'), ('context', 'context_sha256'),
                        ('fetch', 'fetch_sha256'), ('selection', 'selection_sha256')]:
        need(replay[field] == role_rows[role]['sha256'], 'replay-selected-byte-identity')


def terminal_shape(documents, role_rows):
    """Metadata consistency only: this does not verify a chain, proof or native VM."""
    h, history, context, replay, fetch = (documents[name] for name in
                                        ('terminalhandoff', 'history', 'context', 'replayresults', 'fetch'))
    need(h['schema'] == 'kpxa-confirmed-transition-handoff/v1'
         and type(h['accepted_transactions']) is int and h['accepted_transactions'] == 16
         and h['terminal'] is True and h['accepted_whole_CASE_equals_expected'] is True
         and type(h['native_payouts_observed']) is list and len(h['native_payouts_observed']) == 9,
         'complete-terminal-handoff-shape-required')
    need(history['schema'] == 'kpxa-local-private-history/v1' and history['domain_hex32'] == DOMAIN
         and type(history['transitions']) is list and len(history['transitions']) == 15
         and [row['kind'] for row in history['transitions']] == ['payment'] * 6 + ['exit'] * 9,
         'six-payments-nine-exits-required')
    need(type(history['genesis']['outputs_hex520']) is list
         and len(history['genesis']['outputs_hex520']) == 3
         and uint(history['genesis']['deposit_sompi']) == 2_000_000_000
         and uint(history['genesis']['reserve_sompi']) == 6_000_000_000,
         'three-note-CV20-native60-genesis-metadata-shape')
    need(context['schema'] == 'kpxa-selected-history-context/v1' and context['domain_hex32'] == DOMAIN,
         'selected-terminal-context-required')
    checkpoint(history['head'])
    need(history['head'] == context['checkpoint'] == h['checkpoint'] == replay['current_checkpoint'],
         'exact-terminal-checkpoint-join')
    # The existing context hashes canonical compact JSON without a newline.
    genesis_raw = json.dumps(history['genesis'], sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    need(context['genesis_sha256'] == sha(genesis_raw), 'context-genesis-identity')
    need(documents['currententry'] is None, 'terminal-current-entry-must-be-null')
    need(replay['schema'] == 'kpxa-accepted-native-replay/v1'
         and h['status'] == replay['status'] == 'RECORDED_VALIDATING_NODE_PREFIX_FINANCIAL_AND_NATIVE_PASS'
         and type(replay['accepted_transactions']) is int and replay['accepted_transactions'] == 16
         and replay['terminal'] is True and type(replay['whole_CASE_native_Full_reports']) is list
         and len(replay['whole_CASE_native_Full_reports']) == 16,
         'complete-public-replay-report-shape')
    need(fetch['schema'] == 'kpxa-gn3-network-fetch/v1' and fetch['status'] == 'FETCHED_PENDING_REPLAY'
         and type(fetch['transactions']) is list and len(fetch['transactions']) == 16,
         'sixteen-retained-accepted-protocol-transactions')
    ids = [row['transaction']['id'] for row in fetch['transactions']]
    need(len(set(ids)) == 16 and [row['transaction_id'] for row in replay['whole_CASE_native_Full_reports']] == ids,
         'retained-prefix-and-native-report-ID-order-join')
    need(h['expected_transaction_id'] == ids[-1], 'terminal-handoff-last-transaction-ID-join')
    need(h['trial_id'] == replay['trial_id'] == documents['descriptor']['trial_id'] == fetch['descriptor']['trial_id'],
         'same-actual-trial-metadata')
    replay_pin_joins(replay, role_rows)
    for role, selector in [('history', 'HISTORY.json'), ('context', 'CONTEXT.json'),
                           ('currententry', 'CURRENT-ENTRY.json'), ('replayresults', 'RESULTS.json'),
                           ('fetch', 'fetch.json')]:
        need(h['selectors'][selector]['sha256'] == role_rows[role]['sha256'], 'handoff-selected-byte-identity')
    need(type(documents['accounting']) is dict and documents['accounting'], 'explicit-final-public-accounting-required')


def tar_member(name, raw):
    info = tarfile.TarInfo(relative(name))
    info.size, info.mode = len(raw), 0o400
    info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = ''
    # Fail before writing if this name cannot be represented by canonical USTAR.
    info.tobuf(format=tarfile.USTAR_FORMAT, encoding='utf-8', errors='strict')
    return info


def canonical_tar(payloads):
    """Pure known-public-byte control API; production uses the streaming writer."""
    need(type(payloads) is dict and payloads, 'nonempty-payload-map')
    member_paths(payloads)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(payloads.items()):
            need(type(raw) is bytes, 'byte-payload-required')
            archive.addfile(tar_member(name, raw), io.BytesIO(raw))
    return stream.getvalue()


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def prepare(selection_path, selection_sha256, output):
    read = runpy.run_path(GUARD)['read']
    need(type(selection_sha256) is str and HEX.fullmatch(selection_sha256), 'external-selection-SHA-required')
    selected = parse(read(str(public_source(str(selection_path))), selection_sha256))
    need(type(selected) is dict and set(selected) == {'schema', 'domain_hex32', 'roles', 'files'}
         and selected['schema'] == 'kpxa-root-public-recovery-data-selection/v1'
         and selected['domain_hex32'] == DOMAIN and type(selected['roles']) is dict
         and set(selected['roles']) == ROLES, 'exact-root-selection-schema')
    rows = file_rows(selected['files'])
    by_path = {row['path']: row for row in rows}
    need(len(set(selected['roles'].values())) == len(ROLES), 'distinct-semantic-role-paths-required')
    role_rows = {}
    for role, name in selected['roles'].items():
        relative(name)
        need(name in by_path and by_path[name]['kind'] != 'full-source-page', 'each-role-must-select-one-explicit-row')
        role_rows[role] = by_path[name]
    need(selected['roles']['fetch'] == 'chain/fetch.json', 'canonical-fetch-placement-chain-fetch-json')
    documents = {}
    # Authenticate the entire selected set before producing any container.
    for row in rows:
        raw = read(str(public_source(row['source'])), row['sha256'])
        need(len(raw) == row['bytes'], 'whole-selected-public-file-length')
        for role, role_row in role_rows.items():
            if role_row is row:
                documents[role] = parse(raw)
    terminal_shape(documents, role_rows)
    pages = page_contract(documents['fetch'], rows)
    output = Path(output)
    need(output.is_absolute() and output.parent == OUTPUT_BASE and not output.exists()
         and not any(p.is_symlink() for p in (output, *output.parents)), 'fresh-public-output-required')
    output.mkdir(parents=True, mode=0o700)
    decoded_rows = []
    for index, (name, record) in enumerate(sorted(pages.items())):
        row = by_path[name]
        raw = read(str(public_source(row['source'])), row['sha256'])
        audit_name = 'decoded/page-%05d.bin' % index
        target = output / 'audit-only' / audit_name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, 'wb') as stream:
            for chunk in decoded_chunks(raw, record):
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        decoded_rows.append({'packet_path': name, 'gzip_bytes': record['gzip_bytes'],
            'gzip_sha256': record['gzip_sha256'], 'decoded_bytes': record['decoded_bytes'],
            'decoded_sha256': record['decoded_sha256'], 'audit_path': audit_name})
    inventory_rows = [{key: row[key] for key in ('path', 'bytes', 'sha256', 'kind')} for row in rows]
    inventory = {'schema': 'kpxa-public-recovery-data-inventory/v1', 'domain_hex32': DOMAIN,
        'files': inventory_rows, 'file_count': len(rows), 'payload_bytes': sum(row['bytes'] for row in rows),
        'all_payload_members_regular_mode0400': True,
        'proving_key_or_runtime_executable_roles_supported': False,
        'private_owner_inputs_selected': False}
    inventory_raw = encoded(inventory)
    write_new(output / 'DATA-INVENTORY.json', inventory_raw)
    archive_path = output / 'data.tar'
    with archive_path.open('xb') as destination:
        with tarfile.open(fileobj=destination, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            members = [(row['path'], row) for row in rows] + [('DATA-INVENTORY.json', None)]
            for name, row in sorted(members):
                raw = inventory_raw if row is None else read(str(public_source(row['source'])), row['sha256'])
                if row is not None:
                    need(len(raw) == row['bytes'], 'public-file-changed-before-archive')
                archive.addfile(tar_member(name, raw), io.BytesIO(raw))
        destination.flush()
        os.fsync(destination.fileno())
    archive_path.chmod(0o400)
    archive_raw = read(str(archive_path))
    packet = {'schema': 'kpxa-public-recovery-data-packet/v1', 'domain_hex32': DOMAIN,
        'classification': 'OPAQUE_PUBLIC_BYTE_CONTAINER_WITH_METADATA_SHAPE_PREFLIGHT_ONLY',
        'inventory': {'path': 'DATA-INVENTORY.json', 'bytes': len(inventory_raw), 'sha256': sha(inventory_raw)},
        'archive': {'path': 'data.tar', 'bytes': len(archive_raw), 'sha256': sha(archive_raw), 'members': len(rows) + 1},
        'roles': {role: {key: role_rows[role][key] for key in ('path', 'bytes', 'sha256')} for role in sorted(ROLES)},
        'pages': [{key: row[key] for key in ('packet_path', 'gzip_bytes', 'gzip_sha256', 'decoded_bytes', 'decoded_sha256')}
                  for row in decoded_rows],
        'declared_terminal_shape': {'accepted_protocol_transactions': 16, 'payments': 6, 'native_exits': 9,
            'reserve_sompi': 0, 'head_outpoint': None},
        'source_bytes_reserialized': False, 'decoded_pages_in_archive': False,
        'chain_native_or_cryptographic_acceptance_verified_by_packager': False,
        'currentness_independent_administration_or_offhost_execution_claimed': False,
        'private_original_backups_or_owner_inputs_read': False}
    packet_raw = encoded(packet)
    write_new(output / 'PACKET.json', packet_raw)
    audit_map = {'schema': 'kpxa-public-recovery-data-decoded-audit-map/v1', 'domain_hex32': DOMAIN,
        'classification': 'LOCAL_AUDIT_OBJECTS_NOT_UPLOAD_MEMBERS', 'pages': decoded_rows,
        'JSON_reserialized': False, 'all_gzip_members_decoded': True,
        'non_gzip_trailing_bytes_rejected': True}
    write_new(output / 'audit-only' / 'DECODED-AUDIT-MAP.json', encoded(audit_map))
    sums = ''.join(pin + '  ' + name + '\n' for pin, name in
                   [(sha(archive_raw), 'data.tar'), (sha(inventory_raw), 'DATA-INVENTORY.json'),
                    (sha(packet_raw), 'PACKET.json')]).encode()
    write_new(output / 'SHA256SUMS', sums)
    return {'schema': 'kpxa-public-recovery-data-preparation-result/v1',
        'archive_sha256': sha(archive_raw), 'archive_bytes': len(archive_raw),
        'inventory_sha256': sha(inventory_raw), 'packet_sha256': sha(packet_raw),
        'payload_files': len(rows), 'archive_members': len(rows) + 1,
        'source_pages': len(decoded_rows), 'root_selection_sha256': selection_sha256,
        'classification': 'PENDING_ROOT_AUDIT_RELEASE_AND_FRESH_NETWORK_RETRIEVAL',
        'private_owner_worker_network_or_publication_executed': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--selection', required=True, type=Path)
    p.add_argument('--selection-sha256', required=True)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    try:
        print(json.dumps(prepare(a.selection, a.selection_sha256, a.output), sort_keys=True))
    except Exception:
        p.exit(2, 'Public data container refused; no private operation or publication performed.\n')


if __name__ == '__main__':
    main()
