#!/usr/bin/env python3
"""Restore externally selected PUBLIC bytes; establish no financial authority."""
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import urllib.parse


ROOT = Path(__file__).resolve().parents[2]
TRANSPORT = ROOT / 'poc/current-wrapper-runtime/transport'
TRANSPORT_PINS = {
    'public_fetch.py': '37f1a3aa6a7b0c9e4f5363ffb15f2deebde087295c49b60d1cd9b2b9f6eb32ae',
    'trusted_util.py': '78633b9e62a57796d609b600139cea77f4e1866ec362aa5bdd2588516baad9a6',
    'vendor/capsule.py': 'ba6fba072eb00e54297e47473c61ce7ef2230356183c9dfd60d0a8741cc492d2',
    'vendor/chunk_public.py': 'c713a4871079acd040f5c434ceed47c4d6f71885c8e5256199a86488a5f724aa',
}
KINDS = {'public_parameters', 'parameter_manifest', 'software_archive',
         'software_member_inventory', 'software_inventory', 'software_source',
         'descriptor', 'public_history', 'selection', 'other_public_metadata'}
IDENTIFIER = re.compile(r'[a-z][a-z0-9_-]{0,79}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
HOST = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*'
                  r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


class Refused(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise Refused(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(rows):
    result = {}
    for key, value in rows:
        need(key not in result, 'duplicate-json-key')
        result[key] = value
    return result


def parse(raw):
    def no_number(_):
        raise Refused('non-integer-json-number')
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_float=no_number, parse_constant=no_number)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Refused('invalid-json') from error


def utc(value):
    need(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value),
         'canonical-utc-time')
    try:
        return datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(
            tzinfo=datetime.timezone.utc)
    except ValueError as error:
        raise Refused('invalid-utc-time') from error


def host(value):
    need(type(value) is str and len(value) <= 253 and HOST.fullmatch(value),
         'canonical-dns-host')
    return value


def public_url(value):
    need(type(value) is str and value.isascii()
         and all(0x20 < ord(c) < 0x7f for c in value), 'public-url-string')
    try:
        split = urllib.parse.urlsplit(value)
        need(split.scheme == 'https' and split.hostname is not None
             and split.username is None and split.password is None
             and split.port in (None, 443) and not split.query and not split.fragment,
             'anonymous-https-origin-url')
        return host(split.hostname)
    except ValueError as error:
        if isinstance(error, Refused):
            raise
        raise Refused('invalid-public-url') from error


def selection(raw, expected_sha256):
    need(type(raw) is bytes and type(expected_sha256) is str and SHA256.fullmatch(expected_sha256)
         and digest(raw) == expected_sha256, 'external-publication-selection-pin')
    value = parse(raw)
    need(type(value) is dict and set(value) == {
        'schema', 'profile_reference_sha256', 'providers', 'assets'}
         and value['schema'] == 'four-wallet-public-recovery-selection/v1'
         and type(value['profile_reference_sha256']) is str
         and SHA256.fullmatch(value['profile_reference_sha256']), 'selection-schema')
    need(type(value['providers']) is list and value['providers'], 'provider-list')
    providers = {}
    for row in value['providers']:
        need(type(row) is dict and set(row) == {'id', 'reported_infrastructure',
            'reported_administration', 'reported_deletion_control', 'allowed_hosts',
            'reported_retention_until_utc', 'reported_policy_sha256'}, 'provider-fields')
        identifier = row['id']
        need(type(identifier) is str and IDENTIFIER.fullmatch(identifier)
             and identifier not in providers, 'unique-provider-id')
        for key in ('reported_infrastructure', 'reported_administration',
                    'reported_deletion_control'):
            need(type(row[key]) is str and 0 < len(row[key]) <= 200
                 and row[key].isascii() and row[key].isprintable(), 'reported-control-label')
        need(type(row['allowed_hosts']) is list and row['allowed_hosts']
             and all(type(h) is str for h in row['allowed_hosts'])
             and len(set(row['allowed_hosts'])) == len(row['allowed_hosts']), 'provider-host-list')
        for entry in row['allowed_hosts']:
            host(entry)
        if row['reported_retention_until_utc'] is not None:
            utc(row['reported_retention_until_utc'])
        policy = row['reported_policy_sha256']
        need(policy is None or (type(policy) is str and SHA256.fullmatch(policy)),
             'reported-policy-sha256')
        providers[identifier] = row
    need(type(value['assets']) is list and value['assets'], 'nonempty-asset-list')
    asset_ids = set()
    for row in value['assets']:
        need(type(row) is dict and set(row) == {'id', 'kind', 'bytes', 'sha256', 'replicas'},
             'asset-fields')
        identifier = row['id']
        need(type(identifier) is str and IDENTIFIER.fullmatch(identifier)
             and identifier not in asset_ids, 'unique-asset-id')
        asset_ids.add(identifier)
        need(type(row['kind']) is str and row['kind'] in KINDS
             and type(row['bytes']) is int and row['bytes'] > 0
             and type(row['sha256']) is str and SHA256.fullmatch(row['sha256']), 'asset-identity')
        need(type(row['replicas']) is list and row['replicas'], 'asset-replicas')
        seen = set()
        for replica in row['replicas']:
            need(type(replica) is dict and set(replica) == {'provider_id', 'url'},
                 'replica-fields')
            provider_id = replica['provider_id']
            need(type(provider_id) is str and provider_id in providers
                 and provider_id not in seen, 'known-unique-replica-provider')
            seen.add(provider_id)
            need(public_url(replica['url']) in providers[provider_id]['allowed_hosts'],
                 'replica-origin-in-provider-hosts')
    return value, providers


def new_output(path):
    path = Path(path)
    need('..' not in path.parts, 'canonical-output-path')
    path = path.absolute()
    need(not path.exists() and not path.is_symlink(), 'fresh-output-required')
    need(all(not p.is_symlink() for p in path.parents), 'output-parent-symlink')
    need(not path.is_relative_to(ROOT), 'downloaded-payload-outside-Git')
    return path


def read_selected_file(path, expected_bytes, expected_sha256):
    need(not path.is_symlink() and all(not p.is_symlink() for p in path.parents),
         'public-file-symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size == expected_bytes, 'regular-whole-public-file')
        hasher = hashlib.sha256()
        length = 0
        with os.fdopen(os.dup(fd), 'rb') as source:
            while raw := source.read(1024 * 1024):
                length += len(raw)
                hasher.update(raw)
        after = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(tuple(getattr(before, k) for k in keys) == tuple(getattr(after, k) for k in keys)
             and length == expected_bytes and hasher.hexdigest() == expected_sha256,
             'whole-public-object-integrity')
        return tuple(getattr(after, k) for k in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns'))
    finally:
        os.close(fd)


class HTTPSFetcher:
    """Unchanged trusted transport. Its redirect query strings are not exported."""
    def __init__(self):
        for name, expected in TRANSPORT_PINS.items():
            path = TRANSPORT / name
            need(not path.is_symlink() and all(not p.is_symlink() for p in path.parents)
                 and digest(path.read_bytes()) == expected, 'trusted-transport-source')

    def __call__(self, replica, asset, hosts, output):
        command = [sys.executable, '-B', str(TRANSPORT / 'public_fetch.py'),
                   '--url', replica['url'], '--expected-bytes', str(asset['bytes']),
                   '--expected-sha256', asset['sha256'], '--output', str(output)]
        for entry in sorted(hosts):
            command.extend(('--allowed-host', entry))
        process = subprocess.run(command, capture_output=True, text=True,
                                 env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        need(process.returncode == 0, 'selected-public-HTTPS-object-incomplete')
        receipt = parse(process.stdout)
        # Preserve only exact identity and the generic transport's aggregate data.
        # Never echo a command, URL, redirect capability or untrusted stderr.
        return {'transport': 'PINNED_VERIFIED_HTTPS',
                'receipt_sha256': digest(process.stdout.encode()),
                'generic_transport_reported_success': isinstance(receipt, dict)}


def assessment(providers, used, excluded, observed_at):
    now = utc(observed_at)
    excluded_admins = {providers[p]['reported_administration'] for p in excluded}
    excluded_delete = {providers[p]['reported_deletion_control'] for p in excluded}
    reports = []
    for identifier in sorted(used):
        row = providers[identifier]
        retention = row['reported_retention_until_utc']
        reports.append({'provider_id': identifier,
            'same_reported_administration_as_excluded': row['reported_administration'] in excluded_admins,
            'same_reported_deletion_control_as_excluded': row['reported_deletion_control'] in excluded_delete,
            'reported_retention_until_utc': retention,
            'retention_claim_status': ('NO_CLAIM' if retention is None else
                'UNVERIFIED_FUTURE_CLAIM' if utc(retention) > now else 'UNVERIFIED_EXPIRED_CLAIM')})
    return {'provider_reports': reports, 'provider_labels_are_unverified_claims': True,
            'independent_administration_demonstrated': False,
            'retention_guarantee_demonstrated': False,
            'separate_external_operator_and_policy_evidence_required': True}


def restore(raw, expected_sha256, output, *, excluded=(), denied_hosts=(), fetch=None,
            observed_at=None):
    value, providers = selection(raw, expected_sha256)
    excluded = frozenset(excluded)
    need(excluded <= providers.keys(), 'known-excluded-provider-ids')
    denied_hosts = frozenset(host(h) for h in denied_hosts)
    output = new_output(output)
    observed_at = observed_at or datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    utc(observed_at)
    fetch = fetch or HTTPSFetcher()
    output.mkdir(parents=True, mode=0o700)
    objects = output / 'objects'
    objects.mkdir(mode=0o700)
    attempts, restored, used = [], [], set()
    for asset in value['assets']:
        success = False
        for replica in asset['replicas']:
            identifier = replica['provider_id']
            if identifier in excluded:
                continue
            hosts = frozenset(providers[identifier]['allowed_hosts']) - denied_hosts
            if public_url(replica['url']) not in hosts:
                attempts.append({'asset_id': asset['id'], 'provider_id': identifier,
                                 'status': 'DENIED_HOST_NO_REQUEST'})
                continue
            temporary = objects / (asset['id'] + '--' + identifier + '.candidate')
            final = objects / (asset['id'] + '--' + asset['sha256'])
            linked = False
            try:
                transport = fetch(replica, asset, hosts, temporary)
                identity = read_selected_file(temporary, asset['bytes'], asset['sha256'])
                os.link(temporary, final, follow_symlinks=False)
                linked = True
                final_info = final.lstat()
                need(stat.S_ISREG(final_info.st_mode)
                     and tuple(getattr(final_info, k) for k in
                               ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns')) == identity,
                     'final-public-object-inode-binding')
                temporary.unlink()
                attempts.append({'asset_id': asset['id'], 'provider_id': identifier,
                                 'status': 'EXACT_BYTES_RESTORED', 'transport': transport})
                restored.append({'asset_id': asset['id'], 'kind': asset['kind'],
                    'bytes': asset['bytes'], 'sha256': asset['sha256'],
                    'provider_id': identifier, 'relative_path': str(final.relative_to(output))})
                used.add(identifier)
                success = True
                break
            except (OSError, Refused) as error:
                if linked:
                    # This invocation created this name in its fresh private
                    # output. Remove its failed publication, retaining the
                    # failed candidate rather than exporting unverified bytes.
                    final.unlink()
                attempts.append({'asset_id': asset['id'], 'provider_id': identifier,
                    'status': 'INCOMPLETE', 'reason': str(error) if isinstance(error, Refused)
                    else 'public-object-io-incomplete'})
        if not success:
            break
    result = {'schema': 'four-wallet-public-recovery-restore/v1',
        'external_selection_sha256': expected_sha256,
        'profile_reference_sha256': value['profile_reference_sha256'],
        'observed_at_utc': observed_at,
        'status': 'ALL_SELECTED_BYTES_RESTORED' if len(restored) == len(value['assets']) else 'INCOMPLETE',
        'required_objects': len(value['assets']), 'restored_objects': restored,
        'excluded_provider_ids': sorted(excluded), 'denied_hosts': sorted(denied_hosts),
        'attempts': attempts, 'control_assessment': assessment(providers, used, excluded, observed_at),
        'financial_authority_setup_honesty_backing_currentness_or_spend_readiness': False,
        'downloaded_software_executed_or_imported': False,
        'PK_loaded_or_backup_seed_witness_read': False}
    (output / 'RESULT.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--exclude-provider', action='append', default=[])
    parser.add_argument('--deny-host', action='append', default=[])
    args = parser.parse_args()
    try:
        result = restore(args.selection.read_bytes(), args.selection_sha256, args.output,
                         excluded=args.exclude_provider, denied_hosts=args.deny_host)
        print(json.dumps(result, sort_keys=True))
        raise SystemExit(0 if result['status'] == 'ALL_SELECTED_BYTES_RESTORED' else 2)
    except Refused as error:
        print(json.dumps({'status': 'REFUSED', 'reason': str(error)}))
        raise SystemExit(2)
