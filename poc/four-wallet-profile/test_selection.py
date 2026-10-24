#!/usr/bin/env python3
"""Profile boundary controls; synthetic metadata is never a financial profile.

No actual crypto key, PK, wallet, proof, source-build or native call is needed.
The loader checks identity/byte structure; public crypto software must later
validate actual keys and the complete program before any trial.
"""
from dataclasses import FrozenInstanceError
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import selection as s


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def fixture():
    vk = bytes(range(256)) + bytes(range(72))  # Structural bytes, not a curve key.
    child = b'PUBLIC_STRUCTURAL_TEST_ONLY' + vk + bytes(328) + b'END'
    image = bytes.fromhex('11' * 32)
    tail = (b'\x75\x20' + bytes.fromhex(s.WRAPPER) + b'\x75\x20'
            + bytes.fromhex(sha(child)) + b'\x75\x20' + image
            + b'\x75\x08KPX5WS01\x75\x51')
    h = sha(b'PUBLIC_STRUCTURAL_TEST_ONLY')
    return {'schema': s.SCHEMA, 'financial_profile_id': s.PROFILE_ID,
        'classification': s.CLASSIFICATION, 'network_id': s.NETWORK,
        'genesis_hash_hex': s.GENESIS, 'child_domain_hex32': s.DOMAIN,
        'wrapper_domain_hex32': s.WRAPPER,
        'compact': {'role': 'compact2', 'output_arity': 2,
            'parameter_manifest_sha256': h, 'vk_hex328': vk.hex(),
            'vk_sha256': sha(vk), 'pk_sha256': h, 'pk_bytes': 1,
            'compiled_build_identity_sha256': h},
        'settlement': {'child_profile_sha256': h,
            'child_template_tail_hex': child.hex(),
            'child_template_tail_sha256': sha(child), 'image_id_hex32': image.hex(),
            'program_sha256': h, 'child_count': 2, 'child_mode': 2,
            'journal_bytes': 424, 'payload_bytes': 8108, 'aggregate_budget': 1600},
        'W': {'immutable_tail_hex': tail.hex(), 'immutable_tail_sha256': sha(tail)},
        'private': {'budget': 1500, 'complete_input_bound_units': 14_957_286,
                    'bound_result_sha256': h},
        'executables': {n: {'basename': n, 'bytes': 1, 'sha256': h}
                        for n in s.EXECUTABLES}}


def load(value):
    raw = encoded(value)
    return s.load(raw, sha(raw))


def patch_tail(value, change):
    tail = bytearray.fromhex(value['W']['immutable_tail_hex'])
    change(tail)
    value['W'] = {'immutable_tail_hex': tail.hex(), 'immutable_tail_sha256': sha(tail)}


class BoundaryControls(unittest.TestCase):
    def rejects(self, change):
        value = fixture()
        change(value)
        with self.assertRaises((ValueError, TypeError)):
            load(value)

    def test_immutable_result_and_raw_pin(self):
        value = fixture()
        f = load(value)
        self.assertEqual(f.domain.hex(), s.DOMAIN)
        self.assertEqual(f.profile_sha256, sha(encoded(value)))
        with self.assertRaises(FrozenInstanceError):
            f.private_budget = 1
        with self.assertRaises(TypeError):
            f.document['private']['budget'] = 1
        value['private']['budget'] = 1
        self.assertEqual(f.private_budget, 1500)

    def test_external_pin_checked_before_json(self):
        with self.assertRaisesRegex(ValueError, 'byte-mismatch'):
            s.load(b'not JSON', '00' * 32)

    def test_duplicate_top_and_nested_fields(self):
        raw = encoded(fixture())
        for old, new in ((b'"schema":', b'"schema":"ignored","schema":'),
                         (b'"pk_bytes":1', b'"pk_bytes":1,"pk_bytes":1')):
            changed = raw.replace(old, new, 1)
            with self.assertRaisesRegex(ValueError, 'duplicate-profile-field'):
                s.load(changed, sha(changed))

    def test_old_or_foreign_authority_refuses(self):
        for key, value in (('network_id', 'mainnet'),
            ('classification', 'PUBLIC_SYNTHETIC_DO_NOT_FUND_UNFUNDED_BENCHMARK_ONLY'),
            ('child_domain_hex32', 'd55d006a9bb253963db4f4e44495e60333df9fcc83c1c3ae220806d0f326a0bb'),
            ('financial_profile_id', 'different')):
            self.rejects(lambda row, k=key, v=value: row.update({k: v}))

    def test_unknown_funding_and_inventory_authority_refuse(self):
        for name in ('funding_authorized', 'current_head', 'software_inventory_sha256'):
            self.rejects(lambda value, n=name: value.update({n: '00' * 32}))

    def test_integer_type_not_bool_float_or_string(self):
        for bad in (True, 1500.0, '1500'):
            self.rejects(lambda value, b=bad: value['private'].update(budget=b))
        self.rejects(lambda value: value['compact'].update(output_arity=True))

    def test_mode32_and_extra_children_refuse(self):
        self.rejects(lambda value: value['settlement'].update(child_mode=32))
        self.rejects(lambda value: value['settlement'].update(child_count=3))

    def test_coherent_hash_tamper_still_binds_W_metadata(self):
        for at in (2, 36, 70):
            self.rejects(lambda value, a=at: patch_tail(value,
                lambda tail: tail.__setitem__(a, tail[a] ^ 1)))
        self.rejects(lambda value: patch_tail(value,
            lambda tail: tail.__setitem__(slice(104, 112), b'KPX5WO01')))

    def test_virtual_zero_slot_and_compact_key_must_be_unique(self):
        for prefix in ('00' * 328, fixture()['compact']['vk_hex328']):
            def change(value, p=prefix):
                raw = bytes.fromhex(p + value['settlement']['child_template_tail_hex'])
                value['settlement']['child_template_tail_hex'] = raw.hex()
                value['settlement']['child_template_tail_sha256'] = sha(raw)
            self.rejects(change)

    def test_key_and_tail_hash_damage_refuse(self):
        self.rejects(lambda value: value['compact'].update(vk_sha256='00' * 32))
        self.rejects(lambda value: value['W'].update(immutable_tail_sha256='00' * 32))
        self.rejects(lambda value: value['private'].update(bound_result_sha256='A' * 64))

    def test_budget_bound_and_executable_role_refuse(self):
        self.rejects(lambda value: value['private'].update(complete_input_bound_units=15_010_000))
        self.rejects(lambda value: value['executables']['prover'].update(basename='../prover'))
        self.rejects(lambda value: value['executables']['prover'].update(bytes=True))
        self.rejects(lambda value: value['executables'].update(extra={'basename': 'extra'}))

    def test_dotdot_and_symlink_refuse_before_read(self):
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('must not read')):
            with self.assertRaisesRegex(ValueError, 'canonical-profile-path'):
                s.load_path('/tmp/../private/profile', '00' * 32)
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / 'link'
            link.symlink_to(Path(directory) / 'missing')
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('must not read')):
                with self.assertRaisesRegex(ValueError, 'profile-symlink'):
                    s.load_path(link, '00' * 32)


if __name__ == '__main__':
    unittest.main()
