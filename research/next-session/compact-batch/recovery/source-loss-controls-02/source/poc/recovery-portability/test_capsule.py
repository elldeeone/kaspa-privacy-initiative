"""Public structural fixtures only: no actual Ark key, backup, native VM or node."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import capsule as c


class PublicFixture:
    """Not a cryptographic/accepted-state fixture; fake PK/VKs are explicit."""
    def __init__(self, parent):
        self.parent = Path(parent)
        self.root = self.parent / 'mirror'
        self.objects = self.root / 'objects/sha256'
        self.objects.mkdir(parents=True)
        self.domain = '13' * 32
        self.pk = b'PUBLIC_TRANSPORT_ONLY_NOT_AN_ARK_PK'
        compact, wide = b'C' * 328, b'W' * 328
        state = b'KPX2ST01' + bytes.fromhex(self.domain) + bytes(72)
        redeem = b'\x4c\x70' + state + b'PUBLIC_NONEXECUTABLE_POLICY_FIXTURE'
        source = {name: '11' * 32 for name in ('lib_rs_sha256', 'circuit_rs_sha256',
            'exact_sha256_rs_sha256', 'request_rs_sha256', 'parameters_rs_sha256',
            'main_rs_sha256', 'setup_rs_sha256', 'build_rs_sha256')}
        self.parameter = {'schema': 'kpx4-public-proving-parameters/v1',
            'role': 'compact2', 'output_arity': 2, 'auth_magic_hex8': c.AUTH_MAGIC,
            'program_label': c.PROGRAM, 'trial_id': 'PUBLIC_STRUCTURE_DO_NOT_FUND',
            'network_id': 'testnet-10', 'genesis_hash_hex': c.GENESIS,
            'domain_hex32': self.domain, 'format': 'arkworks0.6-bn254-uncompressed',
            'pk_bytes': len(self.pk), 'pk_sha256': c.sha(self.pk),
            'vk_hex328': compact.hex(), 'vk_sha256': c.sha(compact),
            'core_source_identity': source, 'compiled_build_identity_sha256': '22' * 32,
            'constraint_shape': {'constraints': 4, 'witness_variables': 5,
                'instances_including_one': 3, 'matrix_sha256': '33' * 32,
                'fft_domain_size': 8},
            'queries': {'a': 8, 'b_g1': 8, 'b_g2': 8, 'l': 5, 'h': 7,
                'instances_including_one': 3},
            'setup_provenance': {'executable_sha256': '44' * 32,
                'source_freeze_sha256': '55' * 32, 'public_setup_report_sha256': '66' * 32}}
        self.descriptor = {'schema': 'kpx4-compact-batch-descriptor/v1',
            'network_id': 'testnet-10', 'genesis_hash_hex': c.GENESIS,
            'domain_hex32': self.domain,
            'founding_outpoint': {'transactionId': 'aa' * 32, 'index': 0},
            'birth_start_hash': 'bb' * 32, 'initial_redeem_hex': redeem.hex(),
            'compact_vk_hex328': compact.hex(), 'wide_vk_hex328': wide.hex(),
            'immutable_policy_sha256': c.sha(redeem[114:]),
            'compact_public_params_manifest_sha256': c.sha(c.encoded(self.parameter)),
            'wide_public_params_manifest_sha256': '77' * 32}
        self.history = {'schema': 'kpx4-compact-batch-history/v1',
            'classification': 'PUBLIC_STRUCTURE_ONLY_DO_NOT_FUND',
            'descriptor_sha256': c.sha(c.encoded(self.descriptor)),
            'records': [{'transaction': {'version': 1, 'id': 'aa' * 32,
                'inputs': [{'previousOutpoint': {'transactionId': 'cc' * 32, 'index': 0},
                    'signatureScript': '', 'sequence': c.U64_MAX, 'computeBudget': 10}],
                'outputs': [{'value': 1, 'scriptPublicKey': '000051', 'covenant': None}],
                'lockTime': 0, 'subnetworkId': '00' * 20, 'gas': 0, 'payload': '', 'mass': 0},
                'entries': [{'amount': 1, 'scriptPublicKey': '000051', 'blockDaaScore': 1,
                    'isCoinbase': False, 'covenantId': None}]}]}
        self.software = {'schema': 'kpx4-recovery-software-inventory/v1',
            'program_label': c.PROGRAM, 'source_base_commit': 'ab' * 20,
            'source_freeze_sha256': '88' * 32,
            'components': [{'component': 'native_validator', 'sha256': '99' * 32}]}
        self.rebuild()

    def rebuild(self):
        self.descriptor['compact_public_params_manifest_sha256'] = c.sha(c.encoded(self.parameter))
        self.history['descriptor_sha256'] = c.sha(c.encoded(self.descriptor))
        self.raw = {'descriptor': c.encoded(self.descriptor), 'history': c.encoded(self.history),
            'parameters_manifest': c.encoded(self.parameter), 'public_parameters': self.pk,
            'software_inventory': c.encoded(self.software)}
        self.refs = [{'kind': kind, 'sha256': c.sha(raw), 'bytes': len(raw)}
                     for kind, raw in sorted(self.raw.items())]
        for raw in self.raw.values():
            (self.objects / c.sha(raw)).write_bytes(raw)
        self.index = {'schema': 'kpx4-public-recovery-capsule/v1', 'network_id': 'testnet-10',
            'genesis_hash_hex': c.GENESIS, 'domain_hex32': self.domain,
            'program_label': c.PROGRAM, 'role': 'compact2', 'objects': self.refs}
        self.index_path = self.parent / 'capsule.json'
        self.index_path.write_bytes(c.encoded(self.index))
        self.root_sha = c.sha(self.index_path.read_bytes())
        self.selection_dict = {'schema': 'kpx4-recovery-capsule-selection/v1',
            'network_id': 'testnet-10', 'genesis_hash_hex': c.GENESIS,
            'domain_hex32': self.domain, 'program_label': c.PROGRAM,
            'role': 'compact2', 'auth_magic_hex8': c.AUTH_MAGIC,
            'descriptor_sha256': c.sha(self.raw['descriptor']),
            'parameters_manifest_sha256': c.sha(self.raw['parameters_manifest']),
            'public_parameters_sha256': c.sha(self.pk), 'public_parameters_bytes': len(self.pk),
            'vk_sha256': self.parameter['vk_sha256'],
            'software_inventory_sha256': c.sha(self.raw['software_inventory'])}
        self.selection = c.TrustedSelection.from_dict(self.selection_dict)

    def run(self, **kwargs):
        return c.stage_capsule(self.index_path, self.root_sha, self.selection,
            kwargs.pop('mirrors', [self.root]), self.parent / kwargs.pop('out', 'stage'), **kwargs)


class CapsuleControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = PublicFixture(self.temporary.name)

    def test_full_material_is_copied_but_never_current_or_executable(self):
        f = self.fixture
        result = f.run()
        report = result.public_receipt()
        self.assertEqual(len(report['objects']), 5)
        self.assertTrue(report['public_PK_staged'])
        for key in ('current_state_verified', 'spend_authorized', 'native_semantics_verified',
                    'selected_node_acceptance_verified', 'executable_selected_or_run', 'private_contents_read'):
            self.assertFalse(report[key])
        self.assertEqual(result.owned_json['history'], f.raw['history'])
        self.assertEqual(result.staged_paths['public_parameters'].read_bytes(), f.pk)
        self.assertEqual(result.staged_paths['public_parameters'].stat().st_mode & 0o777, 0o400)
        self.assertNotEqual(result.staged_paths['public_parameters'].stat().st_ino,
                            (f.objects / c.sha(f.pk)).stat().st_ino)

    def test_recognition_does_not_require_or_open_PK(self):
        f = self.fixture
        (f.objects / c.sha(f.pk)).unlink()
        result = f.run(mode='recognition')
        self.assertEqual(set(result.owned_json), c.SMALL_KINDS)
        self.assertNotIn('public_parameters', result.staged_paths)
        self.assertFalse(result.public_receipt()['public_PK_staged'])
        with self.assertRaisesRegex(c.Incomplete, '^matching-public-object-unavailable$'):
            f.run(mode='spend_material', out='spend')

    def test_corrupt_preferred_mirror_falls_back_to_exact_object(self):
        f = self.fixture
        bad = f.parent / 'bad/objects/sha256'
        bad.mkdir(parents=True)
        for kind, raw in f.raw.items():
            (bad / c.sha(raw)).write_bytes(b'X' * len(raw))
        result = f.run(mirrors=[bad.parents[1], f.root])
        self.assertEqual(len(result.public_receipt()['rejected_mirror_candidates']), 5)
        self.assertTrue(all(row['mirror_ordinal'] == 1 for row in result.public_receipt()['objects']))

    def test_unselected_self_consistent_instance_rejected(self):
        f = self.fixture
        trusted = f.selection
        f.domain = '14' * 32
        f.parameter['domain_hex32'] = f.domain
        f.descriptor['domain_hex32'] = f.domain
        redeem = bytearray.fromhex(f.descriptor['initial_redeem_hex'])
        redeem[10:42] = bytes.fromhex(f.domain)
        f.descriptor['initial_redeem_hex'] = redeem.hex()
        f.rebuild()
        with self.assertRaises(c.Invalid):
            c.stage_capsule(f.index_path, f.root_sha, trusted, [f.root], f.parent / 'stage')

    def test_wrong_role_is_rejected_before_missing_PK(self):
        f = self.fixture
        f.parameter['role'], f.parameter['output_arity'] = 'wide32', 32
        f.rebuild()
        (f.objects / c.sha(f.pk)).unlink()
        with self.assertRaisesRegex(c.Invalid, '^parameter-manifest-role$'):
            f.run()

    def test_duplicate_json_name_and_traversal_never_select_objects(self):
        f = self.fixture
        raw = c.encoded(f.index)
        duplicate = b'{"role":"compact2",' + raw[1:]
        f.index_path.write_bytes(duplicate)
        with self.assertRaisesRegex(c.Invalid, '^duplicate-json-field$'):
            c.stage_capsule(f.index_path, c.sha(duplicate), f.selection, [f.root], f.parent / 'a')
        f.index['objects'][0]['sha256'] = '../secret'
        raw = c.encoded(f.index)
        f.index_path.write_bytes(raw)
        with self.assertRaisesRegex(c.Invalid, '^capsule-object-digest$'):
            c.stage_capsule(f.index_path, c.sha(raw), f.selection, [f.root], f.parent / 'b')

    def test_hardlink_alias_is_rejected_before_content_open(self):
        f = self.fixture
        sentinel = f.parent / 'SYNTHETIC_NON_SEED'
        sentinel.write_bytes(f.raw['history'])
        target = f.objects / c.sha(f.raw['history'])
        target.unlink()
        os.link(sentinel, target)
        original, opens = os.open, []
        def monitored(path, flags, *args, **kwargs):
            if str(path) == target.name:
                opens.append('content-open')
            return original(path, flags, *args, **kwargs)
        with patch('os.open', side_effect=monitored):
            with self.assertRaises(c.Incomplete):
                f.run(forbidden_paths=[sentinel])
        self.assertEqual(opens, [])

    def test_manifest_alias_is_rejected_before_content_open(self):
        f = self.fixture
        sentinel = f.parent / 'SYNTHETIC_NON_SEED'
        os.link(f.index_path, sentinel)
        with self.assertRaisesRegex(c.Invalid, '^public-private-inode-alias$'):
            f.run(forbidden_paths=[sentinel])

    def test_owned_json_and_copied_PK_survive_source_change(self):
        f = self.fixture
        result = f.run()
        for raw in f.raw.values():
            (f.objects / c.sha(raw)).write_bytes(b'X' * len(raw))
        self.assertEqual(result.owned_json['history'], f.raw['history'])
        self.assertEqual(result.staged_paths['public_parameters'].read_bytes(), f.pk)

    def test_source_symlink_and_appended_bytes_fail_closed(self):
        f = self.fixture
        target = f.objects / c.sha(f.pk)
        other = f.parent / 'other-public-object'
        other.write_bytes(f.pk)
        target.unlink()
        target.symlink_to(other)
        with self.assertRaises(c.Incomplete):
            f.run(out='a')
        target.unlink()
        target.write_bytes(f.pk + b'X')
        with self.assertRaises(c.Incomplete):
            f.run(out='b')

    def test_current_and_secret_container_fields_are_not_accepted(self):
        f = self.fixture
        f.history['records'][0]['transaction']['inputs'][0]['private_witness'] = 'FORBIDDEN'
        f.rebuild()
        with self.assertRaisesRegex(c.Invalid, '^history-native-input-fields$'):
            f.run(out='a')
        del f.history['records'][0]['transaction']['inputs'][0]['private_witness']
        f.rebuild()
        f.index['current'] = True
        raw = c.encoded(f.index)
        f.index_path.write_bytes(raw)
        with self.assertRaisesRegex(c.Invalid, '^capsule-fields$'):
            c.stage_capsule(f.index_path, c.sha(raw), f.selection, [f.root], f.parent / 'b')

    def test_wrong_VK_and_shape_claims_fail_before_PK(self):
        f = self.fixture
        f.parameter['vk_hex328'] = (b'Z' * 328).hex()
        f.rebuild()
        with self.assertRaisesRegex(c.Invalid, '^parameter-manifest-selection$'):
            f.run(out='a')
        f.parameter['vk_hex328'] = f.descriptor['compact_vk_hex328']
        f.parameter['queries']['h'] = 8
        f.rebuild()
        with self.assertRaisesRegex(c.Invalid, '^parameter-dimension-claims$'):
            f.run(out='b')


if __name__ == '__main__':
    unittest.main()
