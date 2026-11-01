#!/usr/bin/env python3
"""Audit-only preflight evidence for a future Testnet research trial.

Serialized evidence never authorizes a network action. The source assembler
remains fail closed; only a future selected parent consuming both live
``BatchPrivacyPassAuthority`` and ``PreNetworkSafetyAuthority`` may launch.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

import private_worker
import wallet_history


SOURCE_SCHEMA = 'kpb-testnet-activation-preflight-source/v1'
RECEIPT_SCHEMA = 'kpb-testnet-preflight-audit-evidence/v1'
EXPECTED_KINDS = ('genesis', 'payment', 'payment')
FIELDS = (
    'schema', 'scope', 'bootstrap_trial_id', 'bootstrap_trial',
    'funding_identity_sha256', 'component_profile_sha256', 'tail_sha256',
    'source_contract', 'history', 'cases', 'privacy_acceptance_sha256',
    'registered_driver_result_sha256',
    'launch_authorized', 'authority_admitted',
    'serialized_receipt_is_authority',
    'complete_terminal_lifecycle_observed',
    'testnet_trial_readiness_claimed', 'mainnet_or_production_authorized',
)


def need(value, category):
    if not value:
        raise ValueError('activation-preflight-' + category)


def fields(value, names, category='exact-fields'):
    need(type(value) is dict and set(value) == set(names), category)


def word(value, category='canonical-sha256'):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), category)
    return value


def record(value):
    fields(value, ('path', 'sha256'), 'exact-public-record')
    path = Path(value['path'])
    need(path.is_absolute() and '..' not in path.parts,
         'absolute-public-record')
    word(value['sha256'])
    return value


def load_json(read, value):
    value = record(value)
    return private_worker.parse(read(Path(value['path']), value['sha256']))


def validate_audit_receipt(value, args, read):
    """Validate the generated receipt's exact audit scope.

    This structural check is not a producer. ``verify_audit_receipt`` also
    rebuilds the value from its exact source contract; neither can launch.
    """
    fields(value, FIELDS, 'receipt-fields')
    need(value['schema'] == RECEIPT_SCHEMA
         and value['scope'] == wallet_history.SCOPE,
         'receipt-schema-scope')
    for name in ('bootstrap_trial', 'source_contract', 'history'):
        record(value[name])
    trial = load_json(read, value['bootstrap_trial'])
    trial_id = value['bootstrap_trial_id']
    need(type(trial_id) is str and str(uuid.UUID(trial_id)) == trial_id
         and trial.get('trial_id') == trial_id,
         'same-fresh-trial')
    expected_trial = {'path': str(Path(args.trial).absolute()),
                      'sha256': args.trial_sha256}
    need(value['bootstrap_trial'] == expected_trial
         and value['funding_identity_sha256'] == args.identity_sha256
         and value['component_profile_sha256'] ==
             args.component_profile_sha256
         and value['tail_sha256'] == args.tail_sha256,
         'same-activation-inputs')
    for name in ('funding_identity_sha256', 'component_profile_sha256',
                 'tail_sha256', 'privacy_acceptance_sha256'):
        word(value[name], name)
    drivers = value['registered_driver_result_sha256']
    need(type(drivers) is list and len(drivers) == 2
         and len(set(drivers)) == 2,
         'two-distinct-registered-driver-results')
    for item in drivers:
        word(item, 'registered-driver-result-sha256')
    cases = value['cases']
    need(type(cases) is list and len(cases) == 3
         and tuple(item.get('kind') for item in cases) == EXPECTED_KINDS,
         'genesis-and-two-payment-cases')
    identities = []
    paths = []
    for item in cases:
        fields(item, ('kind', 'path', 'sha256'), 'case-record-fields')
        record({'path': item['path'], 'sha256': item['sha256']})
        identities.append((item['path'], item['sha256']))
        paths.append(item['path'])
    need(len(set(identities)) == 3 and len(set(paths)) == 3,
         'three-distinct-cases')
    need(value['launch_authorized'] is False
         and value['authority_admitted'] is False
         and value['serialized_receipt_is_authority'] is False
         and value['complete_terminal_lifecycle_observed'] is False
         and value['testnet_trial_readiness_claimed'] is False
         and value['mainnet_or_production_authorized'] is False,
         'audit-only-never-authority-or-readiness')
    return value


def assemble(source, source_ref, read):
    """Future exact producer; deliberately blocked on typed-driver export.

    The registered driver currently exposes only a process-local
    ``DriverCompletionAuthority`` and no immutable reviewed R1/R2 receipt
    schema.  Inventing a JSON success shape here would recreate the forbidden
    caller-Boolean authority, so no receipt can be assembled yet.
    """
    del source, source_ref, read
    need(False, 'registered-driver-completion-receipt-not-implemented')


def rebuild(read, source_ref):
    source = load_json(read, source_ref)
    return assemble(source, source_ref, read)


def verify_audit_receipt(value, args, read):
    validate_audit_receipt(value, args, read)
    need(rebuild(read, value['source_contract']) == value,
         'source-contract-rebuild')
    return value


def verify_audit(args, read, receipt_path, receipt_sha256, output):
    """Rebuild exact audit evidence without admitting network authority."""
    receipt_path = Path(receipt_path).absolute()
    value = private_worker.parse(read(receipt_path, receipt_sha256))
    verify_audit_receipt(value, args, read)
    output = Path(output).absolute()
    need(not output.exists(), 'fresh-verification-output')
    output.mkdir(parents=True, mode=0o700)
    result = {
        'schema': 'kpb-verified-testnet-preflight-audit-evidence/v1',
        'scope': wallet_history.SCOPE,
        'preflight_receipt_sha256': receipt_sha256,
        'bootstrap_trial_id': value['bootstrap_trial_id'],
        'funding_identity_sha256': value['funding_identity_sha256'],
        'component_profile_sha256': value['component_profile_sha256'],
        'tail_sha256': value['tail_sha256'],
        'privacy_acceptance_sha256': value['privacy_acceptance_sha256'],
        'registered_driver_result_sha256':
            value['registered_driver_result_sha256'],
        'cases': value['cases'], 'case_count': 3,
        'launch_authorized': False,
        'authority_admitted': False,
        'serialized_receipt_is_authority': False,
        'complete_terminal_lifecycle_observed': False,
        'testnet_trial_readiness_claimed': False,
        'mainnet_or_production_authorized': False,
        'network_funding_or_broadcast_performed': False,
    }
    write_new(output / 'RESULT.json', result)
    return result


def read_guarded(path, expected=None):
    raw = Path(path).read_bytes()
    if expected is not None:
        need(hashlib.sha256(raw).hexdigest() == expected, 'selected-input')
    return raw


def write_new(path, value):
    path = Path(path).absolute()
    raw = private_worker.encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    return hashlib.sha256(raw).hexdigest()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    source_ref = {'path': str(Path(args.source).absolute()),
                  'sha256': word(args.source_sha256)}
    value = rebuild(read_guarded, source_ref)
    print(json.dumps({'schema': RECEIPT_SCHEMA,
                      'sha256': write_new(args.output, value)}, sort_keys=True))


if __name__ == '__main__':
    main()
