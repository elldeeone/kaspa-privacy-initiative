#!/usr/bin/env python3
"""Offline controls for the fixed public financial-release handoff."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

FINANCIAL = Path(__file__).resolve().parents[1]
LOCAL = FINANCIAL.parent.parent
PROFILE = LOCAL / 'private-batch-public/component-profile.json'
OUTER = LOCAL / 'private-batch-public/outer-selection.json'
spec = importlib.util.spec_from_file_location('qualify_public_release', FINANCIAL / 'qualify_public_release.py')
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def make_core(profile):
    core = bytearray(q.CORE_BYTES)
    core[:8] = b'KPBAEF01'
    core[8:168] = b''.join(bytes.fromhex(profile[name]) for name in (
        'chain_genesis_hex32', 'pool_lineage_hex32', 'profile_id_hex32',
        'domain_hex32', 'service_policy_hex32'))
    core[168:204] = q.FIXED_POINT
    core[204:236] = q.FIXED_OLD_STATE[40:72]
    core[236:268] = q.FIXED_OLD_STATE[76:108]
    core[268:272] = q.FIXED_OLD_STATE[72:76]
    core[272:276] = q.FIXED_OLD_STATE[108:112]
    core[276:284] = q.FIXED_OLD_RESERVE.to_bytes(8, 'little')
    return bytes(core)


def make_projection(core, proof, tail):
    prefix = bytearray(q.PREFIX_BYTES)
    prefix[:8] = b'KPBAFX01'
    prefix[8:12] = b'\x01\x00\x01\x00'
    prefix[12:48] = q.FIXED_POINT
    prefix[48:56] = b'\xff' * 8
    prefix[56:64] = q.FIXED_OLD_RESERVE.to_bytes(8, 'little')
    prefix[64:66] = (37).to_bytes(2, 'little')
    prefix[66:103] = q.FIXED_OLD_SPK
    prefix[103:105] = (1).to_bytes(2, 'little')
    prefix[113:115] = (37).to_bytes(2, 'little')
    prefix[115:152] = q.reserve_spk(q.successor_state(core), tail)
    prefix[189:193] = (q.CORE_BYTES + q.PROOF_BYTES).to_bytes(4, 'little')
    return bytes(prefix) + core + proof


def update_hashes(result, core, proof, projection):
    for party in result['parties']:
        party['effects_sha256'] = q.sha(core)
        party['core_sha256'] = q.sha(core)
        party['proof_sha256'] = q.sha(proof)
        party['projection_sha256'] = q.sha(projection)


def make_result(core, proof, projection):
    parties = []
    for party_id in range(3):
        parties.append({
            'schema': 'kpi-financial-qualification-party/v1',
            'status': 'VERIFIED_AND_DURABLE_EGRESS',
            'scope': q.SCOPE,
            'registered_financial_service': False,
            'party': party_id,
            'model_sha256': q.MODEL_SHA256,
            'trace_sha256': q.TRACE_SHA256,
            'construction_sha256': '11' * 32,
            'validation_sha256': '22' * 32,
            'residual_count': 13127204,
            'actual_R1CS_rows': 13093029,
            'trace_assertions': 33896,
            'context_byte_assertions': 276,
            'historical_NF_assertions': 0,
            'public_challenge': '1',
            'effects_sha256': q.sha(core),
            'core_sha256': q.sha(core),
            'proof_sha256': q.sha(proof),
            'projection_sha256': q.sha(projection),
            'egress_binding_sha256': '33' * 32,
            'payment_privacy_qualified': False,
            'native_settlement_performed': False,
        })
    return {
        'schema': 'kpi-financial-qualification-run/v1',
        'run_id': '44' * 32,
        'status': 'VERIFIED_AND_DURABLE_EGRESS',
        'scope': q.SCOPE,
        'parties': parties,
        'independent_digest_verifier_controls': [
            {'changed_digest_limb': False, 'exit': 0},
            {'changed_digest_limb': True, 'exit': 1}],
        'registered_financial_service': False,
        'payment_privacy_qualified': False,
        'native_settlement_performed': False,
        'private_owner_files_or_keys_read_or_hashed': False,
        'raw_party_diagnostics_read': False,
    }


def fake_host(path, expected_projection, profile, private_canary):
    source = f'''#!/usr/bin/python3
import hashlib,json,pathlib,sys
profile={q.PROFILE_SHA256!r}
domain={profile['domain_hex32']!r}
expected={q.sha(expected_projection)!r}
if pathlib.Path({str(private_canary)!r}).exists():raise SystemExit(97)
if sys.argv[1]=='key-check':
 print(json.dumps({{'component_profile_sha256':profile,'aggregate_vk_sha256':{q.AGGREGATE_VK_SHA256!r},'output_vk_sha256':{q.OUTPUT_VK_SHA256!r},'auth_exit_vk_sha256':{q.AUTH_EXIT_VK_SHA256!r},'domain_hex32':domain,'private_input_read':False}}));raise SystemExit(0)
if sys.argv[1]!='cross-check':raise SystemExit(2)
raw=pathlib.Path(sys.argv[2]).read_bytes();digest=hashlib.sha256(raw).hexdigest()
if digest!=expected:raise SystemExit(3)
out=pathlib.Path(sys.argv[3]);out.mkdir()
j=b'KPBAJR01'+bytes.fromhex(domain)+bytes.fromhex(profile)+bytes.fromhex(digest)
report={{'aggregate_and_six_Output_G16_verified':True,'independent_arkworks_reference_checked':True,'public_state_and_global_balance_verified':True,'projection_sha256':digest,'journal_hex104':j.hex(),'journal_sha256':hashlib.sha256(j).hexdigest(),'R0_or_native_VM_executed':False,'accepted_chain_authority':False}}
(out/'journal.bin').write_bytes(j);(out/'report.json').write_text(json.dumps(report))
print(json.dumps(report))
'''
    path.write_text(source)
    path.chmod(0o700)


class PublicReleaseControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.tail = b'public-test-immutable-native-tail'
        old_spk = q.reserve_spk(q.FIXED_OLD_STATE, self.tail)
        self.identity_patches = [
            mock.patch.object(q, 'NATIVE_TAIL_SHA256', q.sha(self.tail)),
            mock.patch.object(q, 'FIXED_OLD_SPK', old_spk),
        ]
        for patcher in self.identity_patches:
            patcher.start()
        self.profile = json.loads(PROFILE.read_text())
        self.core = make_core(self.profile)
        self.proof = bytes(range(q.PROOF_BYTES))
        self.projection = make_projection(self.core, self.proof, self.tail)
        self.result = make_result(self.core, self.proof, self.projection)
        self.release = self.root / 'release'
        self.release.mkdir()
        self.write_release(self.result, self.core, self.proof, self.projection)
        self.private_canary = self.root / 'owner-private-canary'
        self.private_canary.write_bytes(b'must-not-be-mounted')
        self.host = self.root / 'host.py'
        fake_host(self.host, self.projection, self.profile, self.private_canary)

    def tearDown(self):
        for patcher in reversed(self.identity_patches):
            patcher.stop()
        self.temporary.cleanup()

    def write_release(self, result, core, proof, projection):
        dump(self.release / 'RESULT.json', result)
        (self.release / 'released-core.bin').write_bytes(core)
        (self.release / 'released-proof.bin').write_bytes(proof)
        (self.release / 'released-projection.bin').write_bytes(projection)
        (self.release / 'native-tail.bin').write_bytes(self.tail)

    def qualify(self, output='qualified'):
        with mock.patch.object(q, 'HOST_SHA256', q.sha(self.host.read_bytes())):
            return q.qualify(self.release, PROFILE, OUTER, self.host, self.root / output)

    def test_direct_handoff_and_artifact_contract(self):
        # An imported host assertion in the source directory is ignored.
        dump(self.release / 'report.json', {'forged': True})
        result = self.qualify()
        self.assertTrue(result['aggregate_and_six_Output_G16_verified'])
        for name in ('accepted_head_authority', 'R0_or_native_VM_executed',
                     'native_settlement_performed', 'payment_privacy_qualified'):
            self.assertFalse(result[name])
        artifacts = json.loads((self.root / 'qualified/ARTIFACTS.json').read_text())
        self.assertEqual(artifacts['schema'], 'kpb-qualified-public-financial-artifacts/v1')
        self.assertEqual(set(artifacts['artifacts']), set(q.PUBLIC_ARTIFACT_NAMES))
        self.assertEqual(artifacts['head']['state_hex112'], q.FIXED_OLD_STATE.hex())
        self.assertEqual(artifacts['successor']['state_hex112'], q.successor_state(self.core).hex())
        self.assertEqual(artifacts['successor']['script_public_key_hex37'],
                         q.reserve_spk(q.successor_state(self.core), self.tail).hex())
        self.assertEqual(artifacts['artifacts']['released_core']['sha256'], q.sha(self.core))
        self.assertEqual((self.root / 'qualified/projection.bin').read_bytes(), self.projection)

    def test_result_shape_and_all_three_agreement_refuse(self):
        cases = []
        value = copy.deepcopy(self.result); value['unknown'] = True; cases.append(value)
        value = copy.deepcopy(self.result); value['parties'].pop(); cases.append(value)
        value = copy.deepcopy(self.result); value['parties'][2]['construction_sha256'] = '55' * 32; cases.append(value)
        value = copy.deepcopy(self.result); value['parties'][1]['party'] = 0; cases.append(value)
        value = copy.deepcopy(self.result); value['registered_financial_service'] = True; cases.append(value)
        for value in cases:
            with self.subTest(case=len(value.get('parties', []))):
                with self.assertRaises(q.Refused):
                    q.admit_release(q.encoded(value), self.core, self.proof, self.projection,
                                    self.profile, self.tail)

    def test_artifact_join_mutations_refuse(self):
        changed_core = bytearray(self.core); changed_core[700] ^= 1
        changed_proof = bytearray(self.proof); changed_proof[0] ^= 1
        changed_prefix = bytearray(self.projection); changed_prefix[70] ^= 1
        for core, proof, projection in (
            (bytes(changed_core), self.proof, self.projection),
            (self.core, bytes(changed_proof), self.projection),
            (self.core, self.proof, bytes(changed_prefix)),
            (self.core, self.proof, self.projection + b'\0')):
            with self.assertRaises(q.Refused):
                q.admit_release(q.encoded(self.result), core, proof, projection,
                                self.profile, self.tail)

    def test_wrong_head_and_state_refuse_even_with_rehashed_results(self):
        prefix = bytearray(self.projection); prefix[70] ^= 1
        value = copy.deepcopy(self.result); update_hashes(value, self.core, self.proof, bytes(prefix))
        with self.assertRaises(q.Refused):
            q.admit_release(q.encoded(value), self.core, self.proof, bytes(prefix),
                            self.profile, self.tail)
        successor = bytearray(self.projection); successor[120] ^= 1
        value = copy.deepcopy(self.result); update_hashes(value, self.core, self.proof, bytes(successor))
        with self.assertRaises(q.Refused):
            q.admit_release(q.encoded(value), self.core, self.proof, bytes(successor),
                            self.profile, self.tail)
        core = bytearray(self.core); core[210] ^= 1
        projection = make_projection(bytes(core), self.proof, self.tail)
        value = copy.deepcopy(self.result); update_hashes(value, bytes(core), self.proof, projection)
        with self.assertRaises(q.Refused):
            q.admit_release(q.encoded(value), bytes(core), self.proof, projection,
                            self.profile, self.tail)

    def test_changed_output_with_self_consistent_hashes_requires_direct_crypto(self):
        core = bytearray(self.core); core[700] ^= 1
        projection = make_projection(bytes(core), self.proof, self.tail)
        value = copy.deepcopy(self.result); update_hashes(value, bytes(core), self.proof, projection)
        self.write_release(value, bytes(core), self.proof, projection)
        with self.assertRaises(q.Refused):
            self.qualify('changed-output')

    def test_wrong_host_profile_alias_and_missing_dependency_refuse(self):
        with self.assertRaises(q.Refused):
            q.qualify(self.release, PROFILE, OUTER, self.host, self.root / 'wrong-host')
        profile = self.root / 'profile.json'
        raw = bytearray(PROFILE.read_bytes()); raw[-2] = ord(' ')
        profile.write_bytes(raw)
        with mock.patch.object(q, 'HOST_SHA256', q.sha(self.host.read_bytes())):
            with self.assertRaises(q.Refused):
                q.qualify(self.release, profile, OUTER, self.host, self.root / 'wrong-profile')
        outer = json.loads(OUTER.read_text()); outer['selected'] = True
        outer_raw = q.encoded(outer)
        with mock.patch.object(q, 'OUTER_SELECTION_SHA256', q.sha(outer_raw)):
            with self.assertRaises(q.Refused):
                q.admit_unselected_outer(outer_raw)
        alias = self.root / 'core-alias'
        os.link(self.release / 'released-core.bin', alias)
        with self.assertRaises(q.Refused):
            self.qualify('hardlink')
        alias.unlink()
        self.host.unlink()
        with self.assertRaises((q.Refused, OSError)):
            q.qualify(self.release, PROFILE, OUTER, self.host, self.root / 'missing-host')

    def test_rechecking_same_public_projection_mints_no_authority(self):
        first = self.qualify('first')
        second = self.qualify('second')
        self.assertEqual(first['projection_sha256'], second['projection_sha256'])
        self.assertFalse(first['accepted_head_authority'] or second['accepted_head_authority'])


if __name__ == '__main__':
    unittest.main()
