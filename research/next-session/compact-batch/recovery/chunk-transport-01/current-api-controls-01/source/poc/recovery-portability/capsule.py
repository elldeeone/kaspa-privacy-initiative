#!/usr/bin/env python3
"""Public CAS transport only. This module never authorizes or broadcasts a spend.

Installed software authenticates TrustedSelection independently of the capsule.
Copied files rely on the ADR0054 trusted host/private-stage premise during use;
the selected prover must still authenticate its entire owned PK before a seed.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType

GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
PROGRAM = 'AUTH528_COMPACT_BATCH/v1'
AUTH_MAGIC = b'KPX4AU01'.hex()
KINDS = frozenset({'descriptor', 'history', 'parameters_manifest',
                   'public_parameters', 'software_inventory'})
SMALL_KINDS = KINDS - {'public_parameters'}
U64_MAX = (1 << 64) - 1
SELECTION_FIELDS = frozenset({'schema', 'network_id', 'genesis_hash_hex',
    'domain_hex32', 'program_label', 'role', 'auth_magic_hex8',
    'descriptor_sha256', 'parameters_manifest_sha256', 'public_parameters_sha256',
    'public_parameters_bytes', 'vk_sha256', 'software_inventory_sha256'})


class Invalid(ValueError):
    """Fixed public category; no actual unexpected digest/path/private data."""


class Incomplete(Invalid):
    """Required matching public material unavailable; never a zero balance."""


def need(condition, code):
    if not condition:
        raise Invalid(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def exact(value, names, code):
    need(type(value) is dict and set(value) == set(names), code)


def hx(value, length, code):
    need(type(value) is str and re.fullmatch('[0-9a-f]{' + str(2 * length) + '}', value)
         is not None, code)
    return bytes.fromhex(value)


def uint(value, code, *, positive=False):
    need(type(value) is int and (1 if positive else 0) <= value <= U64_MAX, code)
    return value


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(Invalid('json-constant')))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise Invalid('invalid-json') from None
    need(encoded(value) == raw, 'noncanonical-json')
    return value


@dataclass(frozen=True)
class TrustedSelection:
    """Public policy selected OUTSIDE the mirror, not a self-authentication API."""
    network_id: str
    genesis_hash_hex: str
    domain_hex32: str
    program_label: str
    role: str
    auth_magic_hex8: str
    descriptor_sha256: str
    parameters_manifest_sha256: str
    public_parameters_sha256: str
    public_parameters_bytes: int
    vk_sha256: str
    software_inventory_sha256: str

    def __post_init__(self):
        need(self.network_id == 'testnet-10' and self.genesis_hash_hex == GENESIS,
             'selection-network')
        need(self.program_label == PROGRAM and self.role == 'compact2'
             and self.auth_magic_hex8 == AUTH_MAGIC, 'selection-profile-role')
        need(hx(self.domain_hex32, 32, 'selection-domain') != bytes(32), 'selection-domain')
        for value in (self.descriptor_sha256, self.parameters_manifest_sha256,
                      self.public_parameters_sha256, self.vk_sha256,
                      self.software_inventory_sha256):
            hx(value, 32, 'selection-digest')
        uint(self.public_parameters_bytes, 'selection-PK-length', positive=True)

    @classmethod
    def from_dict(cls, value):
        exact(value, SELECTION_FIELDS, 'selection-fields')
        need(value['schema'] == 'kpx4-recovery-capsule-selection/v1', 'selection-schema')
        return cls(**{name: value[name] for name in SELECTION_FIELDS - {'schema'}})


def _path(path):
    path = Path(path).absolute()
    need('..' not in path.parts and path.name not in ('', '.', '..'), 'unsafe-path')
    return path


def _metadata_forbidden(paths):
    result = set()
    for name in paths:
        path = _path(name)
        try:
            for part in (path, *path.parents):
                need(not part.is_symlink(), 'forbidden-input-symlink')
            info = path.lstat()
        except OSError:
            raise Invalid('forbidden-input-metadata-unavailable') from None
        need(stat.S_ISREG(info.st_mode), 'forbidden-input-not-regular')
        result.add((info.st_dev, info.st_ino))
    return frozenset(result)


def _open_public(path, forbidden):
    """Walk directory FDs with NOFOLLOW; fstat/alias check BEFORE any content read."""
    path = _path(path)
    directory = file_fd = None
    try:
        directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for part in path.parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                          | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = nxt
        # Metadata-only guard precedes even the content-open operation. Repeat
        # after opening to detect substitution before any byte can be read.
        selected = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        need(stat.S_ISREG(selected.st_mode), 'public-object-not-regular')
        need((selected.st_dev, selected.st_ino) not in forbidden,
             'public-private-inode-alias')
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                          | os.O_NONBLOCK, dir_fd=directory)
        info = os.fstat(file_fd)
        need(stat.S_ISREG(info.st_mode), 'public-object-not-regular')
        need((info.st_dev, info.st_ino) not in forbidden, 'public-private-inode-alias')
        need((selected.st_dev, selected.st_ino) == (info.st_dev, info.st_ino),
             'public-object-substituted')
        stream = os.fdopen(file_fd, 'rb')
        file_fd = None
        return stream, info
    except OSError:
        raise Invalid('public-object-path-unavailable') from None
    finally:
        if directory is not None:
            os.close(directory)
        if file_fd is not None:
            os.close(file_fd)


def read_public(path, forbidden_paths=(), *, maximum=None):
    forbidden = _metadata_forbidden(forbidden_paths)
    stream, before = _open_public(path, forbidden)
    with stream:
        # This limit is structural for the fixed small selection/index schema,
        # not a cap on PK/history/trial sizes.
        need(maximum is None or before.st_size <= maximum, 'public-index-too-large')
        raw = stream.read()
        after = os.fstat(stream.fileno())
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
          before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
          after.st_mtime_ns, after.st_ctime_ns), 'public-object-changed')
    return raw


def _identity(value, selection, code):
    need(value['network_id'] == selection.network_id
         and value['genesis_hash_hex'] == selection.genesis_hash_hex
         and value['domain_hex32'] == selection.domain_hex32, code)


def _descriptor(raw, selection):
    value = parse(raw)
    exact(value, {'schema', 'network_id', 'genesis_hash_hex', 'domain_hex32',
        'founding_outpoint', 'birth_start_hash', 'initial_redeem_hex',
        'compact_vk_hex328', 'wide_vk_hex328', 'immutable_policy_sha256',
        'compact_public_params_manifest_sha256', 'wide_public_params_manifest_sha256'},
        'descriptor-fields')
    need(value['schema'] == 'kpx4-compact-batch-descriptor/v1', 'descriptor-schema')
    _identity(value, selection, 'descriptor-identity')
    exact(value['founding_outpoint'], {'transactionId', 'index'}, 'founding-point-fields')
    hx(value['founding_outpoint']['transactionId'], 32, 'founding-point-id')
    need(type(value['founding_outpoint']['index']) is int
         and value['founding_outpoint']['index'] == 0, 'founding-point-index')
    hx(value['birth_start_hash'], 32, 'birth-anchor')
    compact = hx(value['compact_vk_hex328'], 328, 'descriptor-compact-VK')
    hx(value['wide_vk_hex328'], 328, 'descriptor-wide-VK')
    for key in ('immutable_policy_sha256', 'compact_public_params_manifest_sha256',
                'wide_public_params_manifest_sha256'):
        hx(value[key], 32, 'descriptor-digest')
    need(value['compact_public_params_manifest_sha256'] == selection.parameters_manifest_sha256
         and sha(compact) == selection.vk_sha256, 'descriptor-compact-selection')
    redeem = value['initial_redeem_hex']
    need(type(redeem) is str and len(redeem) >= 228 and len(redeem) % 2 == 0
         and re.fullmatch('[0-9a-f]+', redeem) is not None, 'descriptor-redeem')
    redeem = bytes.fromhex(redeem)
    need(redeem[:2] == b'\x4c\x70' and redeem[2:10] == b'KPX2ST01'
         and redeem[10:42].hex() == selection.domain_hex32
         and sha(redeem[114:]) == value['immutable_policy_sha256'], 'descriptor-policy-identity')
    # Full approved-code/role-dispatch verification is the installed lifecycle
    # implementation's responsibility; a matching substring is not that gate.
    return value


def _parameters(raw, selection, descriptor):
    value = parse(raw)
    exact(value, {'schema', 'role', 'output_arity', 'auth_magic_hex8', 'program_label',
        'trial_id', 'network_id', 'genesis_hash_hex', 'domain_hex32', 'format',
        'pk_bytes', 'pk_sha256', 'vk_hex328', 'vk_sha256', 'core_source_identity',
        'compiled_build_identity_sha256', 'constraint_shape', 'queries',
        'setup_provenance'}, 'parameter-manifest-fields')
    _identity(value, selection, 'parameter-manifest-identity')
    need(value['schema'] == 'kpx4-public-proving-parameters/v1'
         and value['role'] == selection.role and type(value['output_arity']) is int
         and value['output_arity'] == 2 and value['auth_magic_hex8'] == selection.auth_magic_hex8
         and value['program_label'] == selection.program_label
         and value['format'] == 'arkworks0.6-bn254-uncompressed', 'parameter-manifest-role')
    need(type(value['trial_id']) is str and 0 < len(value['trial_id']) <= 128,
         'parameter-manifest-trial')
    need(value['pk_bytes'] == selection.public_parameters_bytes
         and type(value['pk_bytes']) is int and value['pk_sha256'] == selection.public_parameters_sha256
         and value['vk_sha256'] == selection.vk_sha256
         and value['vk_hex328'] == descriptor['compact_vk_hex328'], 'parameter-manifest-selection')
    hx(value['compiled_build_identity_sha256'], 32, 'parameter-build-digest')
    exact(value['core_source_identity'], {'lib_rs_sha256', 'circuit_rs_sha256',
        'exact_sha256_rs_sha256', 'request_rs_sha256', 'parameters_rs_sha256',
        'main_rs_sha256', 'setup_rs_sha256', 'build_rs_sha256'}, 'parameter-source-fields')
    exact(value['setup_provenance'], {'executable_sha256', 'source_freeze_sha256',
        'public_setup_report_sha256'}, 'parameter-provenance-fields')
    for key in ('core_source_identity', 'setup_provenance'):
        for digest in value[key].values():
            hx(digest, 32, 'parameter-source-digest')
    exact(value['constraint_shape'], {'constraints', 'witness_variables',
        'instances_including_one', 'matrix_sha256', 'fft_domain_size'}, 'parameter-shape-fields')
    exact(value['queries'], {'a', 'b_g1', 'b_g2', 'l', 'h', 'instances_including_one'},
          'parameter-query-fields')
    hx(value['constraint_shape']['matrix_sha256'], 32, 'parameter-matrix-digest')
    for key, number in value['constraint_shape'].items():
        if key != 'matrix_sha256':
            uint(number, 'parameter-shape-integer', positive=True)
    for number in value['queries'].values():
        uint(number, 'parameter-query-integer', positive=True)
    need(value['constraint_shape']['instances_including_one'] == 3
         and value['queries']['instances_including_one'] == 3
         and value['queries']['h'] + 1 == value['constraint_shape']['fft_domain_size']
         and value['constraint_shape']['fft_domain_size'] & (value['constraint_shape']['fft_domain_size'] - 1) == 0
         and value['constraint_shape']['fft_domain_size'] >= value['constraint_shape']['constraints'] + 3
         and all(value['queries'][key] == value['constraint_shape']['witness_variables'] + 3
                 for key in ('a', 'b_g1', 'b_g2'))
         and value['queries']['l'] == value['constraint_shape']['witness_variables'],
         'parameter-dimension-claims')
    # These are authenticated manifest claims, not actual Ark decoding.
    return value


def _history(raw, selection):
    value = parse(raw)
    exact(value, {'schema', 'classification', 'descriptor_sha256', 'records'}, 'history-fields')
    need(value['schema'] == 'kpx4-compact-batch-history/v1'
         and value['descriptor_sha256'] == selection.descriptor_sha256,
         'history-descriptor-binding')
    need(value['classification'] in ('SYNTHETIC_NATIVE_VALID_CONTEXTS_NOT_ACCEPTED',
         'SELECTED_NODE_ACCEPTED_HISTORY', 'PUBLIC_STRUCTURE_ONLY_DO_NOT_FUND'),
         'history-classification')
    need(type(value['records']) is list and bool(value['records']), 'history-records')
    for row in value['records']:
        exact(row, {'transaction', 'entries'}, 'history-record-fields')
        exact(row['transaction'], {'version', 'id', 'inputs', 'outputs', 'lockTime',
            'subnetworkId', 'gas', 'payload', 'mass'}, 'history-native-body-fields')
        tx = row['transaction']
        need(type(tx['version']) is int and tx['version'] == 1, 'history-native-version')
        hx(tx['id'], 32, 'history-native-id')
        hx(tx['subnetworkId'], 20, 'history-native-subnetwork')
        for key in ('lockTime', 'gas', 'mass'):
            uint(tx[key], 'history-native-integer')
        need(type(tx['payload']) is str and len(tx['payload']) % 2 == 0
             and re.fullmatch('[0-9a-f]*', tx['payload']) is not None, 'history-native-payload')
        need(type(row['entries']) is list and type(row['transaction']['inputs']) is list
             and len(row['entries']) == len(row['transaction']['inputs']), 'history-context-dimensions')
        for item in tx['inputs']:
            exact(item, {'previousOutpoint', 'signatureScript', 'sequence', 'computeBudget'},
                  'history-native-input-fields')
            exact(item['previousOutpoint'], {'transactionId', 'index'}, 'history-native-input-point')
            hx(item['previousOutpoint']['transactionId'], 32, 'history-native-input-id')
            need(type(item['previousOutpoint']['index']) is int
                 and 0 <= item['previousOutpoint']['index'] < 1 << 32, 'history-native-input-index')
            need(type(item['signatureScript']) is str and len(item['signatureScript']) % 2 == 0
                 and re.fullmatch('[0-9a-f]*', item['signatureScript']) is not None,
                 'history-native-signature')
            uint(item['sequence'], 'history-native-sequence')
            need(type(item['computeBudget']) is int and 0 <= item['computeBudget'] < 1 << 16,
                 'history-native-budget')
        need(type(tx['outputs']) is list, 'history-native-outputs')
        for item in tx['outputs']:
            exact(item, {'value', 'scriptPublicKey', 'covenant'}, 'history-native-output-fields')
            uint(item['value'], 'history-native-value')
            need(type(item['scriptPublicKey']) is str and len(item['scriptPublicKey']) >= 4
                 and len(item['scriptPublicKey']) % 2 == 0
                 and re.fullmatch('[0-9a-f]+', item['scriptPublicKey']) is not None
                 and item['covenant'] is None, 'history-native-output-script')
        for entry in row['entries']:
            exact(entry, {'amount', 'scriptPublicKey', 'blockDaaScore',
                'isCoinbase', 'covenantId'}, 'history-native-entry-fields')
            uint(entry['amount'], 'history-native-entry-amount', positive=True)
            uint(entry['blockDaaScore'], 'history-native-entry-score')
            need(type(entry['scriptPublicKey']) is str and len(entry['scriptPublicKey']) >= 4
                 and len(entry['scriptPublicKey']) % 2 == 0
                 and re.fullmatch('[0-9a-f]+', entry['scriptPublicKey']) is not None
                 and type(entry['isCoinbase']) is bool and entry['covenantId'] is None,
                 'history-native-entry-context')
    # No semantic, acceptance, coverage, spentness or sparse-position assertion
    # comes from this structural/public-container check.
    return value


def _software(raw, selection):
    value = parse(raw)
    exact(value, {'schema', 'program_label', 'source_base_commit',
        'source_freeze_sha256', 'components'}, 'software-inventory-fields')
    need(value['schema'] == 'kpx4-recovery-software-inventory/v1'
         and value['program_label'] == selection.program_label, 'software-inventory-profile')
    hx(value['source_base_commit'], 20, 'software-base-commit')
    hx(value['source_freeze_sha256'], 32, 'software-source-digest')
    need(type(value['components']) is list and bool(value['components']), 'software-components')
    seen = set()
    for row in value['components']:
        exact(row, {'component', 'sha256'}, 'software-component-fields')
        need(type(row['component']) is str and re.fullmatch('[a-z0-9_]{1,64}', row['component'])
             is not None and row['component'] not in seen, 'software-component-name')
        seen.add(row['component'])
        hx(row['sha256'], 32, 'software-component-digest')
    return value


@dataclass(frozen=True)
class StagedCapsule:
    """Owned small bytes plus readonly staged paths, never a current-state token."""
    receipt: object
    owned_json: object
    staged_paths: object

    def public_receipt(self):
        return json.loads(json.dumps(dict(self.receipt)))


def stage_capsule(manifest_path, expected_capsule_sha256, selection, mirror_roots,
                  new_output_directory, forbidden_paths=(), *, mode='spend_material'):
    forbidden_paths = tuple(forbidden_paths)
    need(type(selection) is TrustedSelection, 'trusted-selection-required')
    need(mode in ('recognition', 'spend_material'), 'staging-mode')
    hx(expected_capsule_sha256, 32, 'capsule-root-digest')
    # Metadata of every forbidden input is acquired before ANY public read.
    forbidden = _metadata_forbidden(forbidden_paths)
    manifest_raw = read_public(manifest_path, forbidden_paths, maximum=65536)
    need(sha(manifest_raw) == expected_capsule_sha256, 'capsule-root-mismatch')
    manifest = parse(manifest_raw)
    exact(manifest, {'schema', 'network_id', 'genesis_hash_hex', 'domain_hex32',
        'program_label', 'role', 'objects'}, 'capsule-fields')
    need(manifest['schema'] == 'kpx4-public-recovery-capsule/v1'
         and manifest['program_label'] == selection.program_label
         and manifest['role'] == selection.role, 'capsule-profile-role')
    _identity(manifest, selection, 'capsule-identity')
    need(type(manifest['objects']) is list and len(manifest['objects']) == len(KINDS),
         'capsule-object-count')
    refs = {}
    for ref in manifest['objects']:
        exact(ref, {'kind', 'sha256', 'bytes'}, 'capsule-object-fields')
        need(type(ref['kind']) is str and ref['kind'] in KINDS and ref['kind'] not in refs,
             'capsule-object-kind')
        hx(ref['sha256'], 32, 'capsule-object-digest')
        uint(ref['bytes'], 'capsule-object-length', positive=True)
        refs[ref['kind']] = ref
    need(list(refs) == sorted(KINDS), 'capsule-object-order')
    for kind, expected in (('descriptor', selection.descriptor_sha256),
        ('parameters_manifest', selection.parameters_manifest_sha256),
        ('public_parameters', selection.public_parameters_sha256),
        ('software_inventory', selection.software_inventory_sha256)):
        need(refs[kind]['sha256'] == expected, 'capsule-static-selection')
    need(refs['public_parameters']['bytes'] == selection.public_parameters_bytes,
         'capsule-PK-length-selection')
    need(type(mirror_roots) in (tuple, list) and bool(mirror_roots), 'mirror-roots')
    roots = [_path(root) for root in mirror_roots]
    output = _path(new_output_directory)
    need(not output.exists() and not any(p.is_symlink() for p in output.parents),
         'fresh-stage-directory-required')
    try:
        output.mkdir(mode=0o700)
    except OSError:
        raise Invalid('stage-directory-unavailable') from None
    owned, paths, rejected, accepted = {}, {}, [], []

    def validate_small_objects():
        descriptor = _descriptor(owned['descriptor'], selection)
        _parameters(owned['parameters_manifest'], selection, descriptor)
        _history(owned['history'], selection)
        _software(owned['software_inventory'], selection)

    # Authenticate role/instance/schema before any large PK object read/copy.
    required = sorted(SMALL_KINDS) + (['public_parameters'] if mode == 'spend_material' else [])
    for kind in required:
        if kind == 'public_parameters':
            validate_small_objects()
        ref = refs[kind]
        destination = output / kind
        success = False
        for ordinal, root in enumerate(roots):
            temporary = output / (kind + '.part-' + str(ordinal))
            try:
                source, before = _open_public(root / 'objects' / 'sha256' / ref['sha256'], forbidden)
                with source:
                    need(before.st_size == ref['bytes'], 'object-length-mismatch')
                    digest, total = hashlib.sha256(), 0
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                    with os.fdopen(fd, 'wb') as target:
                        while chunk := source.read(min(1024 * 1024, ref['bytes'] - total + 1)):
                            total += len(chunk)
                            need(total <= ref['bytes'], 'object-length-mismatch')
                            digest.update(chunk)
                            target.write(chunk)
                        target.flush()
                        os.fsync(target.fileno())
                    after = os.fstat(source.fileno())
                    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                          before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                          after.st_mtime_ns, after.st_ctime_ns), 'public-object-changed')
                need(total == ref['bytes'] and digest.hexdigest() == ref['sha256'],
                     'object-digest-mismatch')
                temporary.chmod(0o400)
                temporary.rename(destination)
                # Only fixed-type JSON objects are retained as owned bytes.
                if kind in SMALL_KINDS:
                    owned[kind] = destination.read_bytes()
                paths[kind] = destination
                accepted.append({'kind': kind, 'sha256': ref['sha256'],
                    'bytes': ref['bytes'], 'mirror_ordinal': ordinal})
                success = True
                break
            except (Invalid, OSError) as error:
                reason = str(error) if isinstance(error, Invalid) else 'public-object-io-failed'
                rejected.append({'kind': kind, 'mirror_ordinal': ordinal, 'reason': reason})
                # Only owned public partial copies may be removed. Preserve the
                # incomplete stage on all-source failure for controller review.
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
        if not success:
            raise Incomplete('matching-public-object-unavailable')
    if mode == 'recognition':
        validate_small_objects()
    receipt = {'schema': 'kpx4-recovery-capsule-stage/v1',
        'status': ('PUBLIC_COMPACT_SPEND_MATERIAL_VERIFIED_AT_COPY' if mode == 'spend_material'
                   else 'PUBLIC_RECOGNITION_MATERIAL_VERIFIED_AT_COPY'),
        'mode': mode, 'role': selection.role, 'domain_hex32': selection.domain_hex32,
        'capsule_sha256': expected_capsule_sha256, 'objects': accepted,
        'rejected_mirror_candidates': rejected, 'public_PK_staged': mode == 'spend_material',
        'current_state_verified': False, 'spend_authorized': False,
        'native_semantics_verified': False, 'selected_node_acceptance_verified': False,
        'executable_selected_or_run': False, 'private_contents_read': False,
        'private_input_paths_or_hashes_emitted': False,
        'same_host_mirror_portability_is_not_independent_provider_availability': True,
        'trusted_host_private_stage_unchanged_during_use_required': True}
    (output / 'PUBLIC-RECEIPT.json').write_bytes(encoded(receipt) + b'\n')
    return StagedCapsule(MappingProxyType(receipt), MappingProxyType(owned),
                         MappingProxyType(paths))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('expected_capsule_sha256')
    parser.add_argument('trusted_selection', type=Path)
    parser.add_argument('new_output', type=Path)
    parser.add_argument('--mirror', action='append', required=True, type=Path)
    parser.add_argument('--forbidden', action='append', default=[], type=Path)
    parser.add_argument('--mode', choices=('recognition', 'spend_material'), default='spend_material')
    args = parser.parse_args()
    try:
        # Even the externally installed selection is metadata-guarded before read.
        selection = TrustedSelection.from_dict(parse(read_public(args.trusted_selection,
            args.forbidden, maximum=65536)))
        result = stage_capsule(args.manifest, args.expected_capsule_sha256, selection,
            args.mirror, args.new_output, args.forbidden, mode=args.mode)
        print(json.dumps(result.public_receipt(), sort_keys=True))
    except (Invalid, OSError):
        print(json.dumps({'status': 'INCOMPLETE_OR_INVALID', 'current_state_verified': False,
                          'spend_authorized': False}), file=__import__('sys').stderr)
        raise SystemExit(2) from None


if __name__ == '__main__':
    main()
