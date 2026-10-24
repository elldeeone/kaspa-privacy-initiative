#!/usr/bin/env python3
"""Externally selected public financial profile; no PK, owner key or execution.

Structural and identity validation does not establish key soundness, current
chain state or funding authority. Selected public crypto software still checks
the actual VK, and proof preparation authenticates the whole PK before backup.
"""
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
import hashlib
import json
import re

HERE = Path(__file__).resolve().parent
SCHEMA = 'kpx6-four-wallet-financial-profile/v1'
PROFILE_ID = '68312927-f203-4317-9816-c47c020eed16'
CLASSIFICATION = 'TESTNET_REHEARSAL_ONLY_ADR0060'
NETWORK = 'testnet-10'
GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
DOMAIN = '2630ed4a338afa60d3e1747a0d8875ba05f4b6694eefc345a977def800c4b89e'
WRAPPER = 'de8ccd620d2957ec9df7ddc45c5acb0222322a4539aa7f2437cc9effccc52734'
EXECUTABLES = ('prover', 'w-codec', 'native-validator', 'node', 'crypto')


def need(value, code):
    if not value:
        raise ValueError(code)


def fields(value, names, code):
    need(type(value) is dict and set(value) == set(names), code)


def integer(value, lower, upper, code):
    need(type(value) is int and lower <= value <= upper, code)
    return value


def hexbytes(value, size=None, code='canonical-profile-hex'):
    need(type(value) is str and len(value) % 2 == 0
         and bool(re.fullmatch('[0-9a-f]+', value)), code)
    raw = bytes.fromhex(value)
    need(size is None or len(raw) == size, code)
    return raw


def digest(value):
    return hashlib.sha256(value).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate-profile-field')
        result[key] = value
    return result


def freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class Financial:
    profile_sha256: str
    raw_bytes: bytes
    financial_profile_id: str
    domain: bytes
    wrapper_domain: bytes
    vk: bytes
    child_template_tail: bytes
    w_tail: bytes
    image_id: bytes
    child_profile_sha256: str
    program_sha256: str
    parameter_manifest_sha256: str
    pk_sha256: str
    pk_bytes: int
    build_identity_sha256: str
    prover_sha256: str
    codec_sha256: str
    private_budget: int
    aggregate_budget: int
    complete_input_bound_units: int
    executables: object
    document: object


def load(raw, expected_sha256):
    """Return immutable Financial from raw bytes and an external whole-file pin."""
    need(type(raw) is bytes, 'profile-raw-bytes-required')
    hexbytes(expected_sha256, 32, 'external-profile-pin')
    need(digest(raw) == expected_sha256, 'external-profile-byte-mismatch')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('profile-number')))
    fields(value, ('schema', 'financial_profile_id', 'classification', 'network_id',
                   'genesis_hash_hex', 'child_domain_hex32', 'wrapper_domain_hex32',
                   'compact', 'settlement', 'W', 'private', 'executables'), 'profile-fields')
    for key, expected in (('schema', SCHEMA), ('financial_profile_id', PROFILE_ID),
                          ('classification', CLASSIFICATION), ('network_id', NETWORK),
                          ('genesis_hash_hex', GENESIS), ('child_domain_hex32', DOMAIN),
                          ('wrapper_domain_hex32', WRAPPER)):
        need(value[key] == expected, 'selected-financial-identity')
    domain = hexbytes(value['child_domain_hex32'], 32)
    wrapper = hexbytes(value['wrapper_domain_hex32'], 32)
    need(domain != wrapper and domain != bytes(32) and wrapper != bytes(32), 'profile-domains')
    compact, settlement, w, private, executables = (value[k] for k in
        ('compact', 'settlement', 'W', 'private', 'executables'))
    fields(compact, ('role', 'output_arity', 'parameter_manifest_sha256', 'vk_hex328',
                     'vk_sha256', 'pk_sha256', 'pk_bytes',
                     'compiled_build_identity_sha256'), 'compact-fields')
    need(compact['role'] == 'compact2', 'compact-role')
    need(integer(compact['output_arity'], 2, 2, 'compact-arity') == 2, 'compact-arity')
    vk = hexbytes(compact['vk_hex328'], 328)
    need(vk != bytes(328) and digest(vk) == compact['vk_sha256'], 'selected-vk-digest')
    for key in ('parameter_manifest_sha256', 'vk_sha256', 'pk_sha256',
                'compiled_build_identity_sha256'):
        hexbytes(compact[key], 32)
    integer(compact['pk_bytes'], 1, 32 * 1024**3, 'selected-pk-length')
    fields(settlement, ('child_profile_sha256', 'child_template_tail_hex',
                       'child_template_tail_sha256', 'image_id_hex32', 'program_sha256',
                       'child_count', 'child_mode', 'journal_bytes', 'payload_bytes',
                       'aggregate_budget'), 'settlement-fields')
    for key, expected in (('child_count', 2), ('child_mode', 2), ('journal_bytes', 424),
                          ('payload_bytes', 8108), ('aggregate_budget', 1600)):
        integer(settlement[key], expected, expected, 'selected-settlement-shape')
    for key in ('child_profile_sha256', 'child_template_tail_sha256', 'image_id_hex32',
                'program_sha256'):
        hexbytes(settlement[key], 32)
    child_tail = hexbytes(settlement['child_template_tail_hex'])
    need(0 < len(child_tail) <= 65535 - 114
         and digest(child_tail) == settlement['child_template_tail_sha256']
         and sum(child_tail.startswith(vk, i) for i in
                 range(max(0, len(child_tail) - len(vk) + 1))) == 1,
         'selected-virtual-child-tail')
    need(sum(child_tail.startswith(bytes(328), i) for i in
             range(max(0, len(child_tail) - 327))) == 1,
         'unselected-wide-virtual-only-sentinel')
    fields(w, ('immutable_tail_hex', 'immutable_tail_sha256'), 'W-fields')
    hexbytes(w['immutable_tail_sha256'], 32)
    tail = hexbytes(w['immutable_tail_hex'])
    image = hexbytes(settlement['image_id_hex32'], 32)
    need(113 < len(tail) <= 65535 - 114 and digest(tail) == w['immutable_tail_sha256'],
         'selected-actual-W-tail')
    # Existing source-fixed W metadata offsets, relative to its state112 prefix.
    expected_metadata = (b'\x75\x20' + wrapper + b'\x75\x20'
                         + bytes.fromhex(settlement['child_template_tail_sha256'])
                         + b'\x75\x20' + image + b'\x75\x08KPX5WS01\x75')
    need(len(expected_metadata) == 113 and tail[:113] == expected_metadata,
         'actual-W-domain-template-image-kind')
    fields(private, ('budget', 'complete_input_bound_units', 'bound_result_sha256'), 'private-fields')
    integer(private['budget'], 1500, 1500, 'selected-private-budget')
    bound = integer(private['complete_input_bound_units'], 1, 15_009_999, 'private-bound')
    hexbytes(private['bound_result_sha256'], 32)
    fields(executables, EXECUTABLES, 'executable-roles')
    for role in EXECUTABLES:
        item = executables[role]
        fields(item, ('basename', 'bytes', 'sha256'), 'executable-fields')
        need(item['basename'] == role, 'fixed-executable-basename')
        integer(item['bytes'], 1, 2**63 - 1, 'executable-length')
        hexbytes(item['sha256'], 32)
    return Financial(expected_sha256, raw, PROFILE_ID, domain, wrapper, vk, child_tail,
        tail, image, settlement['child_profile_sha256'], settlement['program_sha256'],
        compact['parameter_manifest_sha256'], compact['pk_sha256'], compact['pk_bytes'],
        compact['compiled_build_identity_sha256'], executables['prover']['sha256'],
        executables['w-codec']['sha256'], private['budget'], settlement['aggregate_budget'],
        bound, freeze(executables), freeze(value))


def load_path(path, expected_sha256):
    path = Path(path)
    need('..' not in path.parts, 'canonical-profile-path')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'profile-symlink')
    return load(path.read_bytes(), expected_sha256)
