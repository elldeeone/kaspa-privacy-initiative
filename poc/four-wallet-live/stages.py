#!/usr/bin/env python3
"""Finite public request/prefix/copy/bundle joins; no runtime or signing.

All eight original backup inodes and whole owner directories are excluded
before public ingress. These pure joins create no financial authority: actual
accepted replay and owner/outer verification must validate every proposed byte.
"""
import argparse
from pathlib import Path
import re

from prepare_runtime import Exclusions, PROFILE_SHA
from public import (ROOT, amount, case_summary, checked, digest, encoded, fields,
                    need, parse, sha, trial, write_new)

GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
PROFILE_ID = '68312927-f203-4317-9816-c47c020eed16'
DOMAIN = '2630ed4a338afa60d3e1747a0d8875ba05f4b6694eefc345a977def800c4b89e'


def hexbytes(value, count):
    need(type(value) is str and re.fullmatch('[0-9a-f]{' + str(2 * count) + '}', value),
         'canonical-selected-public-hex-width')
    return bytes.fromhex(value)


def fresh_output(path, excluded):
    path = checked(path)
    need(not path.exists() and not path.is_relative_to(ROOT)
         and all(not path.is_relative_to(folder) for folder in excluded.directories),
         'fresh-public-join-output-outside-code-and-owner-trees')
    path.mkdir(parents=True, mode=0o700)
    return path


def selected_profile(raw, expected):
    need(expected == PROFILE_SHA and digest(raw) == expected, 'selected-financial-profile-pin')
    value = parse(raw)
    need(value['schema'] == 'kpx6-four-wallet-financial-profile/v1'
         and value['financial_profile_id'] == PROFILE_ID
         and value['network_id'] == 'testnet-10' and value['genesis_hash_hex'] == GENESIS
         and value['child_domain_hex32'] == DOMAIN, 'selected-financial-request-domain')
    return value


def request(raw_sizing, raw_recipient, profile, trial_id):
    """Use only the accepted quote adapter's computed credit, never a CLI credit."""
    trial(trial_id)
    sizing, recipient = parse(raw_sizing), parse(raw_recipient)
    need(sizing['schema'] == 'kpx6-four-wallet-public-sizing/v1'
         and sizing['classification'] == 'INVALID_PUBLIC_RECORD_SIZING_NOT_QUOTE_OR_SETTLEMENT_AUTHORITY'
         and sizing['financial_profile_sha256'] == PROFILE_SHA
         and sizing['trial_id'] == trial_id and sizing['public_source_kind'] == 'accepted'
         and sizing['net_principal_sompi'] == 1_000_000_000
         and type(sizing['net_principal_sompi']) is int
         and sizing['reference_rate'] == 100 and type(sizing['reference_rate']) is int
         and sizing['genuine_body_requote_and_exact_fee_reconciliation_required'] is True
         and sizing['private_witness_PK_proof_native_Full_chain_acceptance_or_fee_qualification'] is False
         and sizing['sizing_grants_spend_authority'] is False,
         'accepted-provisional-sizing-with-fresh-trial-and-exact-net-rate')
    sha(sizing['descriptor_sha256']); sha(sizing['fetch_sha256'])
    fields(sizing['accepted_point'], ('transactionId', 'index'), 'accepted-sizing-point')
    sha(sizing['accepted_point']['transactionId'])
    need(type(sizing['accepted_point']['index']) is int and sizing['accepted_point']['index'] == 0
         and type(sizing['actual_DAA']) is int and 0 <= sizing['actual_DAA'] < 1 << 64,
         'accepted-sizing-head-and-DAA')
    credit = amount(sizing['recipient_exit_credit_sompi'], positive=True)
    amount(1_000_000_000 + credit, positive=True)
    need(recipient['schema'] == 'kpx6-owner-initial-public/v1'
         and recipient['trial_id'] == trial_id and recipient['role'] in ('B', 'D')
         and recipient['financial_profile_id'] == profile['financial_profile_id']
         and recipient['domain_hex32'] == profile['child_domain_hex32']
         and recipient['network_id'] == 'testnet-10' and recipient['genesis_hash_hex'] == GENESIS,
         'same-live-trial-public-recipient')
    return sizing, recipient


def component(raw, profile):
    """Structural extraction only; a record is still unverified public input."""
    value = parse(raw)
    fields(value, ('schema', 'classification', 'role', 'fee_context', 'auth_hex528',
                   'payload_hex', 'proof_hex128', 'public_case'), 'exact-public-component-fields')
    need(value['schema'] == 'kpx4-selected-public-payment-component/v1'
         and value['classification'] == 'UNVERIFIED_COMPONENT_EXTERNAL_SETTLEMENT_POLICY_REQUIRED'
         and value['role'] == 'compact2'
         and value['fee_context'] == 'PROPOSED_VIRTUAL_NEW_POLICY_REQUIRED',
         'proposed-compact-P0-component-scope')
    auth = hexbytes(value['auth_hex528'], 528)
    payload = hexbytes(value['payload_hex'], 3920)
    proof = hexbytes(value['proof_hex128'], 128)
    need(payload[:528] == auth and auth[:8] == b'KPX4AU01'
         and auth[8:40].hex() == profile['child_domain_hex32'] and proof != bytes(128),
         'component-auth-domain-payload-proof-width-join')
    case_summary(value['public_case'])
    body = value['public_case']['transaction']
    need(len(body['inputs']) == len(value['public_case']['entries']) == len(body['outputs']) == 1
         and body['payload'] == payload.hex() and body['inputs'][0]['computeBudget'] == 1600
         and value['public_case']['entries'][0]['blockDaaScore'] == 0,
         'proposed-one-input-one-output-virtual-public-case')
    item = body['inputs'][0]
    point = item['previousOutpoint']
    need(auth[40:76] == bytes.fromhex(point['transactionId']) + point['index'].to_bytes(4, 'little'),
         'component-authorization-point')
    frame = bytes.fromhex(item['signatureScript'])
    need(len(frame) > 313 and frame[:68] == b'\x41' + bytes(65) + b'\x4c\x80'
         and frame[68:196] == proof and frame[196:197] == b'\x4d'
         and len(frame) == 199 + int.from_bytes(frame[197:199], 'little')
         and frame[199:201] == b'\x4c\x70' and frame[201:313] == auth[76:188],
         'component-exact-public-proof-slot-and-state-frame')
    # The public component supplies no verified trial/sender identity. The
    # owner and outer adapter must replay these ordered records from the
    # selected accepted GN2 head and verify genuine G16/NF/CM/value effects.
    return (payload + proof).hex()


def bundle(args, excluded):
    """Copy pinned fetch/pages unchanged; never decompress or accept history."""
    sha(args.fetch_sha256)
    excluded.guard((args.fetch,))
    fetched = excluded.read(args.fetch, args.fetch_sha256)
    value = parse(fetched)
    need(type(value) is dict and value.get('schema') == 'kpx5-gn2-network-fetch/v1'
         and value.get('status') == 'FETCHED_PENDING_REPLAY', 'pending-public-fetch-metadata-only')
    first = value['pages']
    second = value['current_view']['post_query_delta']['pages']
    need(type(first) is list and type(second) is list, 'finite-base-and-postquery-page-lists')
    source_root = checked(args.bundle_directory)
    rows, paths, names = [*first, *second], [], set()
    for row in rows:
        fields(row, ('path', 'request', 'decoded_sha256', 'decoded_bytes',
                     'gzip_sha256', 'gzip_bytes', 'encoding'), 'strict-public-page-metadata')
        name = row['path']
        need(type(name) is str and name not in ('', '.', 'fetch.json', 'RESULTS.json')
             and '\\' not in name and '\0' not in name and not Path(name).is_absolute()
             and '..' not in Path(name).parts and str(Path(name)) == name
             and name not in names, 'canonical-unique-relative-page-path')
        names.add(name)
        sha(row['gzip_sha256']); sha(row['decoded_sha256'])
        need(type(row['gzip_bytes']) is int and row['gzip_bytes'] > 0
             and type(row['decoded_bytes']) is int and row['decoded_bytes'] >= 0
             and type(row['encoding']) is str,
             'canonical-page-length-and-encoding-metadata')
        fields(row['request'], ('startHash', 'dataVerbosityLevel', 'minConfirmationCount'),
               'strict-Full-page-request-metadata')
        sha(row['request']['startHash'])
        need(row['request']['dataVerbosityLevel'] == 'Full'
             and type(row['request']['minConfirmationCount']) is int
             and 0 <= row['request']['minConfirmationCount'] < 1 << 64,
             'Full-page-request-metadata-only')
        path = checked(source_root / name)
        need(path != source_root and path.is_relative_to(source_root), 'page-within-public-bundle')
        paths.append(path)
    # Complete metadata exclusion for all base AND post-query pages precedes
    # the first page byte/hash/copy. Each later open also checks its inode
    # before reading, then stable exact SHA/length bytes are copied read-only.
    excluded.guard(paths)
    output = fresh_output(args.output, excluded)
    write_new(output / 'fetch.json', fetched); (output / 'fetch.json').chmod(0o400)
    total = 0
    for row, path in zip(rows, paths):
        raw = excluded.read(path, row['gzip_sha256'])
        need(len(raw) == row['gzip_bytes'], 'selected-public-page-exact-length')
        target = output / row['path']
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, raw); target.chmod(0o400)
        total += len(raw)
    return output, {'schema': 'kpx6-four-wallet-public-bundle-copy/v1',
        'public_file_count': 1 + len(rows), 'public_page_count': len(rows),
        'public_bytes': len(fetched) + total, 'fetch_sha256': args.fetch_sha256,
        'copied_fetch_bytes_unchanged': True, 'relative_page_layout_preserved': True,
        'page_decompression_SDK_native_replay_or_currentness_authority': False}


def run(args):
    excluded = Exclusions(args.exclude_trial_directory)
    if args.operation == 'bundle':
        output, result = bundle(args, excluded)
    elif args.operation == 'copy-public':
        need(len(args.file) == len(args.file_sha256) > 0, 'finite-pinned-public-copy-list')
        paths, pins = args.file, args.file_sha256
    else:
        paths, pins = [args.financial_profile], [args.financial_sha256]
        if args.operation == 'request':
            paths += [args.sizing, args.recipient]
            pins += [args.sizing_sha256, args.recipient_sha256]
        else:
            need(len(args.component) == len(args.component_sha256) <= 2,
                 'zero-one-or-two-pinned-components')
            paths += args.component; pins += args.component_sha256
    if args.operation != 'bundle':
        for pin in pins:
            sha(pin)
        excluded.guard(paths)  # Every listed metadata check precedes the first byte.
        raw = [excluded.read(path, pin) for path, pin in zip(paths, pins)]
        output = fresh_output(args.output, excluded)
    if args.operation == 'bundle':
        pass
    elif args.operation == 'copy-public':
        for index, value in enumerate(raw):
            name = 'public-' + str(index).zfill(3) + '.bin'
            write_new(output / name, value); (output / name).chmod(0o400)
        result = {'schema': 'kpx6-four-wallet-public-copy-counts/v1',
                  'public_file_count': len(raw), 'public_bytes': sum(map(len, raw))}
    else:
        profile = selected_profile(raw[0], args.financial_sha256)
        if args.operation == 'request':
            sizing, recipient = request(raw[1], raw[2], profile, args.trial_id)
            invoice = recipient['invoices_hex208'][str(args.invoice_index)]
            hexbytes(invoice, 208)
            value = {'schema': 'kpx4-single-invoice-payment-request/v1',
                'domain_hex32': profile['child_domain_hex32'], 'recipient_invoice_hex208': invoice,
                'net_principal_sompi': 1_000_000_000,
                'recipient_exit_credit_sompi': sizing['recipient_exit_credit_sompi']}
            name, count = 'request.json', 1
        else:
            records = [component(value, profile) for value in raw[1:]]
            need(len(records) == len(set(records)), 'distinct-proposed-component-records')
            value = {'schema': 'kpx6-four-wallet-proposed-prefix/v1',
                     'financial_profile_sha256': args.financial_sha256, 'record_hex4048': records}
            name, count = 'prefix.json', len(records)
        serialized = encoded(value) + b'\n'
        write_new(output / name, serialized); (output / name).chmod(0o400)
        result = {'schema': 'kpx6-four-wallet-public-stage-join/v1',
            'financial_profile_sha256': args.financial_sha256,
            'public_item_count': count, 'result_sha256': digest(serialized)}
    result.update({'operation': args.operation, 'excluded_backup_file_count': 8,
        'excluded_whole_owner_directory_count': 8,
        'backup_key_witness_PK_or_native_proof_network_read_or_execution': False,
        'financial_proof_or_currentness_verified': False,
        'spend_authority_or_trial_readiness': False})
    write_new(output / 'RESULTS.json', result); (output / 'RESULTS.json').chmod(0o400)
    return result


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest='operation', required=True)
    for name in ('request', 'prefix', 'copy-public', 'bundle'):
        sub = commands.add_parser(name)
        sub.add_argument('--exclude-trial-directory', required=True, action='append', type=Path)
        sub.add_argument('--output', required=True, type=Path)
        if name == 'bundle':
            sub.add_argument('--fetch', required=True, type=Path)
            sub.add_argument('--fetch-sha256', required=True)
            sub.add_argument('--bundle-directory', required=True, type=Path)
        elif name == 'copy-public':
            sub.add_argument('--file', required=True, action='append', type=Path)
            sub.add_argument('--file-sha256', required=True, action='append')
        else:
            sub.add_argument('--financial-profile', required=True, type=Path)
            sub.add_argument('--financial-sha256', required=True)
        if name == 'request':
            sub.add_argument('--trial-id', required=True)
            for item in ('sizing', 'recipient'):
                sub.add_argument('--' + item, required=True, type=Path)
                sub.add_argument('--' + item + '-sha256', required=True)
            sub.add_argument('--invoice-index', type=int, choices=(0, 1), default=1)
        if name == 'prefix':
            sub.add_argument('--component', action='append', type=Path, default=[])
            sub.add_argument('--component-sha256', action='append', default=[])
    return p


if __name__ == '__main__':
    p = parser()
    try:
        result = run(p.parse_args())
        keys = ('operation', 'public_item_count', 'public_file_count', 'public_page_count', 'public_bytes',
                'excluded_backup_file_count', 'excluded_whole_owner_directory_count')
        print(encoded({key: result[key] for key in keys if key in result}).decode())
    except (ValueError, OSError, KeyError, TypeError, IndexError, OverflowError):
        p.exit(2, 'public stage join incomplete; no proof, private read or submission\n')
