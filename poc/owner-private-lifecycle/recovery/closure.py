#!/usr/bin/env python3
"""Restore an externally selected PUBLIC lifecycle dependency closure.

This module authenticates byte identities and an explicitly declared dependency
graph. It does not decide which software or financial profile is trustworthy,
validate accepted history, load parameters, read a wallet, or execute restored
code. The selected owner client must perform those separate checks.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys


ROOT = Path(__file__).resolve().parents[3]
STORAGE_SOURCE = ROOT / 'poc/four-wallet-storage/restore.py'
STORAGE_SHA256 = '68a0d7ca0e5cdc7b3a6b5ca06e334d8abdf6545794e9522f36af76d39608a343'
HEX32 = re.compile(r'[0-9a-f]{64}\Z')
LIFECYCLE_DOMAIN = 'be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480'
REQUIRED_ROLES = frozenset({
    'profile', 'native-policy', 'wallet-software', 'software-inventory',
    'public-codec', 'relation-prover',
    'spend-manifest', 'spend-proving-key', 'spend-verification-key',
    'output-manifest', 'output-proving-key', 'output-verification-key',
    'exit-manifest', 'exit-proving-key', 'exit-verification-key',
    'founding-descriptor', 'accepted-history-index', 'accepted-checkpoint',
})


class Refused(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def storage_module():
    """Authenticate the existing, unchanged local transport adapter first."""
    need(not STORAGE_SOURCE.is_symlink()
         and all(not item.is_symlink() for item in STORAGE_SOURCE.parents),
         'trusted-storage-source-symlink')
    fd = os.open(STORAGE_SOURCE, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
             'trusted-storage-source-file')
        with os.fdopen(os.dup(fd), 'rb') as source:
            raw = source.read()
        after = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(tuple(getattr(before, k) for k in keys)
             == tuple(getattr(after, k) for k in keys)
             and digest(raw) == STORAGE_SHA256,
             'trusted-storage-source-pin')
    finally:
        os.close(fd)
    # Execute the bytes just authenticated rather than reopening the pathname.
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(
        'lifecycle_pinned_public_storage', loader=None))
    module.__file__ = str(STORAGE_SOURCE)
    exec(compile(raw, str(STORAGE_SOURCE), 'exec'), module.__dict__)
    return module


def graph_order(dependencies, roots):
    """Validate a finite declared graph without recursion or inferred edges."""
    todo = [(identifier, False) for identifier in sorted(roots)]
    visiting, complete, order = set(), set(), []
    while todo:
        identifier, finishing = todo.pop()
        need(identifier in dependencies, 'dependency-missing')
        if finishing:
            visiting.remove(identifier)
            complete.add(identifier)
            order.append(identifier)
        elif identifier not in complete:
            need(identifier not in visiting, 'dependency-cycle')
            visiting.add(identifier)
            todo.append((identifier, True))
            todo.extend((child, False) for child in dependencies[identifier])
    need(complete == set(dependencies), 'undeclared-or-unreachable-extra-object')
    return order


def validate(raw, expected_sha256, selection_raw, *, storage=None):
    storage = storage or storage_module()
    need(type(raw) is bytes and type(expected_sha256) is str
         and HEX32.fullmatch(expected_sha256)
         and digest(raw) == expected_sha256, 'external-closure-pin')
    try:
        manifest = storage.parse(raw)
    except storage.Refused as error:
        raise Refused(str(error)) from error
    need(type(manifest) is dict and set(manifest) == {
        'schema', 'domain_hex32', 'profile_reference_sha256',
        'transport_selection_sha256', 'required_roles', 'dependencies'}
         and manifest['schema'] == 'owner-private-lifecycle-public-closure/v1',
         'closure-schema')
    for key in ('domain_hex32', 'profile_reference_sha256',
                'transport_selection_sha256'):
        need(type(manifest[key]) is str and HEX32.fullmatch(manifest[key]),
             'canonical-closure-digest')
    need(manifest['domain_hex32'] == LIFECYCLE_DOMAIN, 'selected-lifecycle-domain')
    try:
        selection, providers = storage.selection(
            selection_raw, manifest['transport_selection_sha256'])
    except storage.Refused as error:
        raise Refused(str(error)) from error
    need(selection['profile_reference_sha256']
         == manifest['profile_reference_sha256'], 'closure-selection-profile')
    assets = {item['id']: item for item in selection['assets']}
    roles = manifest['required_roles']
    need(type(roles) is dict and set(roles) == REQUIRED_ROLES,
         'complete-lifecycle-role-set')
    need(all(type(identifier) is str and identifier in assets
             for identifier in roles.values()), 'required-role-object-missing')
    dependencies = manifest['dependencies']
    need(type(dependencies) is dict and set(dependencies) == set(assets),
         'exact-dependency-object-set')
    for children in dependencies.values():
        need(type(children) is list
             and all(type(child) is str and child in assets for child in children)
             and len(children) == len(set(children)), 'canonical-dependency-edges')
    graph_order(dependencies, set(roles.values()))
    # A profile role may not silently name unrelated public bytes. Other role
    # semantics and source/parameter dependency completeness need root review.
    need(assets[roles['profile']]['sha256']
         == manifest['profile_reference_sha256'], 'profile-object-pin')
    return manifest, selection, providers, storage


def restore(raw, expected_sha256, selection_raw, output, *, excluded,
            denied_hosts, fetch=None, observed_at=None):
    manifest, selection, providers, storage = validate(
        raw, expected_sha256, selection_raw)
    excluded = frozenset(excluded)
    need(bool(excluded) and excluded <= set(providers),
         'issuer-exclusion-required')
    forbidden = {name for identifier in excluded
                 for name in providers[identifier]['allowed_hosts']}
    need(forbidden <= set(denied_hosts), 'all-excluded-provider-hosts-denied')
    try:
        result = storage.restore(selection_raw,
            manifest['transport_selection_sha256'], output,
            excluded=excluded, denied_hosts=denied_hosts, fetch=fetch,
            observed_at=observed_at)
    except storage.Refused as error:
        raise Refused(str(error)) from error
    ready = result['status'] == 'ALL_SELECTED_BYTES_RESTORED'
    paths = {item['asset_id']: item for item in result['restored_objects']}
    roles = {}
    reauthenticated = 0
    final_error = None
    if ready:
        try:
            for item in paths.values():
                storage.read_selected_file(Path(output) / item['relative_path'],
                                           item['bytes'], item['sha256'])
                reauthenticated += 1
        except (OSError, storage.Refused) as error:
            ready = False
            final_error = (str(error) if isinstance(error, storage.Refused)
                           else 'public-object-io-incomplete')
        if ready:
            roles = {role: {key: paths[identifier][key] for key in (
                        'asset_id', 'relative_path', 'bytes', 'sha256')}
                     for role, identifier in manifest['required_roles'].items()}
    handoff = {
        'schema': 'owner-private-lifecycle-public-recovery-handoff/v1',
        'status': 'DECLARED_CLOSURE_RESTORED' if ready else 'INCOMPLETE',
        'external_closure_sha256': expected_sha256,
        'transport_selection_sha256': manifest['transport_selection_sha256'],
        'domain_hex32': manifest['domain_hex32'],
        'profile_reference_sha256': manifest['profile_reference_sha256'],
        'roles': roles,
        'required_objects': result['required_objects'],
        'restored_objects': len(result['restored_objects']),
        'handoff_reauthenticated_objects': reauthenticated,
        'handoff_reauthentication_error': final_error,
        'issuer_provider_ids_excluded': sorted(excluded),
        'issuer_hosts_denied': sorted(denied_hosts),
        'transport_result_sha256': digest((Path(output) / 'RESULT.json').read_bytes()),
        'control_assessment': result['control_assessment'],
        'declared_role_and_dependency_semantics_require_external_review': True,
        'accepted_history_replayed_or_current_chain_reconciled': False,
        'restored_software_executed_or_parameters_loaded': False,
        'wallet_backup_seed_witness_or_owner_map_read': False,
        'financial_authority_setup_honesty_or_spend_readiness': False,
    }
    handoff_raw = encoded(handoff)
    fd = os.open(Path(output) / 'HANDOFF.json',
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as target:
        target.write(handoff_raw)
        target.flush()
        os.fsync(target.fileno())
    handoff['handoff_sha256'] = digest(handoff_raw)
    return handoff


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--closure', required=True, type=Path)
    parser.add_argument('--closure-sha256', required=True)
    parser.add_argument('--selection', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--exclude-provider', action='append', default=[])
    parser.add_argument('--deny-host', action='append', default=[])
    args = parser.parse_args()
    try:
        handoff = restore(args.closure.read_bytes(), args.closure_sha256,
            args.selection.read_bytes(), args.output,
            excluded=args.exclude_provider, denied_hosts=args.deny_host)
        print(json.dumps(handoff, sort_keys=True))
        return 0 if handoff['status'] == 'DECLARED_CLOSURE_RESTORED' else 2
    except (Refused, OSError) as error:
        print(json.dumps({'status': 'INCOMPLETE', 'reason':
            str(error) if isinstance(error, Refused) else 'public-recovery-io'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
