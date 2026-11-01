"""Controls for the source-only successor financial-round selection.

These fixtures are schema controls.  They are not accepted-head, proof,
privacy, native-execution, or settlement evidence.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid

import successor_round_selection as selected


def raw(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def put(path, value, mode=0o400):
    data = value if type(value) is bytes else raw(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return data


def ref(path, data):
    return {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest()}


class Fixture:
    REQUIRED = (
        'financial/registered_service.cpp',
        'financial/accepted_head.cpp',
        'financial/registered_selection.cpp',
        'financial/registered_construction.cpp',
        'financial/registered_gate_main.cpp',
        'financial/construction.cpp',
        'history/epoch_journal.cpp',
    )

    def __init__(self, root):
        self.root = Path(root)
        self.old_run = '11' * 32
        self.old_projection = '12' * 32
        self.old_head = '13' * 32
        self.successor_state = '4b50424153543031' + '21' * 104
        self.successor_spk = '22' * 37
        self.successor_outpoint = '23' * 36
        state_sha = hashlib.sha256(bytes.fromhex(
            self.successor_state)).hexdigest()
        spk_sha = hashlib.sha256(bytes.fromhex(self.successor_spk)).hexdigest()
        artifacts = {
            'schema': 'kpb-qualified-public-financial-artifacts/v1',
            'status': 'AGGREGATE_AND_SIX_OUTPUT_PROOFS_VERIFIED',
            'run_id': self.old_run,
            'projection_sha256': self.old_projection,
            'successor': {
                'state_hex112': self.successor_state,
                'reserve_sompi': 5_970_000_000,
                'script_public_key_hex37': self.successor_spk,
            },
            'successor_state_sha256': state_sha,
            'successor_script_public_key_hex37': self.successor_spk,
            'R0_or_native_VM_executed': True,
            'R0_receipt_verified': True,
            'full_native_candidate_validated': True,
            'native_settlement_performed': False,
        }
        result = {
            'schema': 'kpi-financial-public-crypto-handoff/v1',
            'status': 'AGGREGATE_AND_SIX_OUTPUT_PROOFS_VERIFIED',
            'run_id': self.old_run,
            'projection_sha256': self.old_projection,
            'successor_state_sha256': state_sha,
            'successor_spk_sha256': spk_sha,
            'R0_or_native_VM_executed': True,
            'R0_receipt_verified': True,
            'full_native_candidate_validated': True,
            'native_settlement_performed': False,
        }
        self.artifacts_path = self.root / 'previous/ARTIFACTS.json'
        self.result_path = self.root / 'previous/RESULT.json'
        artifacts_raw = put(self.artifacts_path, artifacts)
        result_raw = put(self.result_path, result)
        native = {
            'schema': 'kpb-r0-native-successor-receipt/v1',
            'status': 'FULL_NATIVE_CANDIDATE_VALIDATED_UNBROADCAST',
            'predecessor_run_id': self.old_run,
            'predecessor_result_sha256': hashlib.sha256(result_raw).hexdigest(),
            'successor_outpoint_hex36': self.successor_outpoint,
            'successor_state_hex112': self.successor_state,
            'successor_reserve_sompi': 5_970_000_000,
            'successor_script_public_key_hex37': self.successor_spk,
            'R0_receipt_verified': True,
            'full_native_candidate_validated': True,
            'native_settlement_performed': False,
        }
        native_path = self.root / 'previous/NATIVE-SUCCESSOR.json'
        native_raw = put(native_path, native)

        self.trial_id = '22222222-2222-4222-8222-222222222222'
        certs = ['31' * 32, '32' * 32, '33' * 32]
        pem = ['35' * 32, '36' * 32, '37' * 32]
        epoch = {
            'chain_hex32': '81' * 32,
            'domain_hex32': '82' * 32,
            'epoch_hex32': '83' * 32,
            'pool_hex32': '84' * 32,
            'profile_hex32': '85' * 32,
            'service_hex32': '86' * 32,
            'server_certificate_sha256': certs,
        }
        registration_body = {
                'scope': 'UNFUNDED_REGISTERED_RESEARCH_TRIAL_BOOTSTRAP_ONLY',
                'trial_id': self.trial_id,
                'status': 'BOOTSTRAP_ONLY_UNCONFIGURED',
                'registration_nonce_hex32': '38' * 32,
                'registered_driver_configured': False,
                'registered_financial_service_identity': True,
                'testnet_research_only': True,
                'network_or_owner_input_executed': False,
                'certificates': [
                    {'party': index, 'role': 'P' + str(index),
                     'certificate_pem_sha256': pem[index],
                     'certificate_der_sha256': value}
                    for index, value in enumerate(certs)],
                'certificate_authority': {
                    'certificate_pem_sha256': '39' * 32,
                    'certificate_der_sha256': '3a' * 32,
                },
                'epoch_key': epoch,
                'source_selection_sha256': '3b' * 32,
        }
        registration_sha = hashlib.sha256(
            b'KPB/REGISTERED-UNFUNDED-TRIAL/REGISTRATION/v1\0' +
            json.dumps(registration_body, sort_keys=True,
                       separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False).encode()).hexdigest()
        registration = {
            'schema': 'kpb-registered-unfunded-trial-registration/v1',
            'registration_sha256': registration_sha,
            'registration': registration_body,
        }
        trial_root = self.root / 'trial'
        registration_path = trial_root / 'public/registration/REGISTRATION.json'
        registration_raw = put(registration_path, registration)
        trial = {
            'schema': 'kpb-registered-financial-trial-selection-candidate/v1',
            'scope': 'UNFUNDED_REGISTERED_RESEARCH_TRIAL_BOOTSTRAP_ONLY',
            'status': 'UNCONFIGURED_BOOTSTRAPPED',
            'trial_id': self.trial_id,
            'trial_root': str(trial_root),
            'registration_sha256': registration_sha,
            'registration_file': str(registration_path),
            'registration_file_sha256': hashlib.sha256(
                registration_raw).hexdigest(),
            'registered_driver_configured': False,
            'network_node_contacted': False,
            'owner_input_or_mpc_executed': False,
            'native_broadcast_or_settlement_executed': False,
            'certificates': [
                {'party': index, 'role': 'P' + str(index),
                 'certificate_path': str(trial_root /
                    ('public/certificates/P%d.pem' % index)),
                 'certificate_pem_sha256': pem[index],
                 'certificate_der_sha256': value,
                 'private_key_path': str(trial_root /
                    ('private/party-%d/tls/P%d.key' % (index, index))),
                 'private_key_body_exported_or_hashed_in_public_receipts':
                    False}
                for index, value in enumerate(certs)],
            'certificate_authority': {
                'certificate_path': str(trial_root /
                                        'public/certificates/ca.pem'),
                'certificate_pem_sha256': '39' * 32,
                'certificate_der_sha256': '3a' * 32,
                'private_key_path': str(trial_root / 'private/ca/ca.key'),
                'private_key_body_exported_or_hashed_in_public_receipts':
                    False,
            },
            'private_ca_key_path': str(trial_root / 'private/ca/ca.key'),
            'epoch_key': epoch,
            'state': [],
            'source_selection_sha256': '3b' * 32,
            'source_closure': [],
            'initializer': {'path': str(trial_root /
                                        'public/build/registered-trial-init'),
                            'sha256': '3c' * 32},
        }
        trial_path = trial_root / 'public/SELECTION-CANDIDATE.json'
        trial_raw = put(trial_path, trial)

        self.source_closure = []
        source_hashes = {}
        for index, logical in enumerate(self.REQUIRED):
            path = self.root / 'source' / logical
            data = put(path, ('source-%d\n' % index).encode(), 0o444)
            source_hashes[logical] = hashlib.sha256(data).hexdigest()
            self.source_closure.append({
                'logical_path': logical, 'path': str(path),
                'sha256': source_hashes[logical], 'bytes': len(data),
            })
        binary_path = self.root / 'build/mpc-registered-financial-gate'
        binary_raw = put(binary_path, b'configured-registered-driver\n', 0o500)
        build = {
            'schema': 'kpi-registered-financial-gate-build/v1',
            'success': True,
            'configured': True,
            'proof_or_private_input_executed': False,
            'source_sha256': source_hashes,
            'compile': [],
            'link': [{'binary': 'mpc-registered-financial-gate',
                      'exit_code': 0,
                      'sha256': hashlib.sha256(binary_raw).hexdigest()}],
            'controls': [],
            'vendor_artifacts': [],
            'zlib_binary': {},
            'zlib_headers_sha256': '4a' * 32,
        }
        build_path = self.root / 'build/BUILD-RESULT.json'
        build_raw = put(build_path, build)

        self.candidate = {
            'schema': 'kpb-successor-financial-round-candidate/v1',
            'round': 2,
            'predecessor': {
                'artifacts': ref(self.artifacts_path, artifacts_raw),
                'result': ref(self.result_path, result_raw),
                'native_successor': ref(native_path, native_raw),
            },
            'trial': {
                'selection': ref(trial_path, trial_raw),
                'registration': ref(registration_path, registration_raw),
            },
            'driver': {
                'build': ref(build_path, build_raw),
                'binary': ref(binary_path, binary_raw),
            },
            'source_mode': 'REGISTERED_ACCEPTED_HEAD_ONLY',
            'source_closure': self.source_closure,
            'fresh_identity': {
                'trial_id': self.trial_id,
                'run_id': '41' * 32,
                'attempt_id': '42' * 32,
                'cohort_id': '43' * 32,
                'accepted_head_identity_sha256': '44' * 32,
                'owner_contract_sha256': ['45' * 32, '46' * 32,
                                          '47' * 32],
            },
            'prior_identities': [{
                'trial_id': '11111111-1111-4111-8111-111111111111',
                'run_id': self.old_run,
                'attempt_id': '14' * 32,
                'cohort_id': '15' * 32,
                'accepted_head_identity_sha256': self.old_head,
                'projection_sha256': self.old_projection,
                'owner_contract_sha256': ['16' * 32, '17' * 32,
                                          '18' * 32],
            }],
            'head_policy': {
                'expected_outpoint_hex36': self.successor_outpoint,
                'expected_state_hex112': self.successor_state,
                'expected_reserve_sompi': 5_970_000_000,
                'expected_script_public_key_hex37': self.successor_spk,
                'authority': 'DIRECT_CPP_ACCEPTED_FINANCIAL_HEAD_CAPABILITY',
                'serialized_receipt_is_authority': False,
                'fresh_current_utxo_recheck_before_lock': True,
                'fixed_genesis_fallback': False,
            },
            'execution': {
                'network_contacted': False,
                'private_owner_input_read': False,
                'mpc_or_proof_executed': False,
                'native_broadcast_or_settlement_executed': False,
            },
        }
        self.candidate_path = self.root / 'CANDIDATE.json'
        put(self.candidate_path, self.candidate)

    def rewrite_candidate(self):
        self.candidate_path.chmod(0o600)
        put(self.candidate_path, self.candidate)

    def compile(self):
        return selected.compile_selection(self.candidate_path)


class SuccessorRoundSelectionControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = Fixture(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_source_selection_binds_successor_without_minting_authority(self):
        result = self.fixture.compile()
        self.assertEqual(result['status'],
                         'SOURCE_SELECTION_READY_EXECUTION_NOT_RUN')
        self.assertEqual(result['head']['outpoint_hex36'],
                         self.fixture.successor_outpoint)
        self.assertEqual(result['head']['state_hex112'],
                         self.fixture.successor_state)
        self.assertFalse(result['accepted_head_receipt_is_authority'])
        self.assertFalse(result['launch_authorized'])
        self.assertFalse(result['network_contacted'])
        self.assertFalse(result['private_owner_input_read'])

    def test_wrong_predecessor_successor_link_or_fixed_genesis_refuses(self):
        for mutation in ('state', 'outpoint', 'fixed-genesis'):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as root:
                    fixture = Fixture(root)
                    if mutation == 'state':
                        fixture.candidate['head_policy'][
                            'expected_state_hex112'] = '51' * 112
                    elif mutation == 'outpoint':
                        fixture.candidate['head_policy'][
                            'expected_outpoint_hex36'] = '52' * 36
                    else:
                        fixture.candidate['head_policy'][
                            'fixed_genesis_fallback'] = True
                    fixture.rewrite_candidate()
                    with self.assertRaises(ValueError):
                        fixture.compile()

    def test_reused_trial_run_attempt_cohort_head_or_owner_contract_refuses(self):
        for name, prior_key, fresh_key in (
                ('trial', 'trial_id', 'trial_id'),
                ('run', 'run_id', 'run_id'),
                ('attempt', 'attempt_id', 'attempt_id'),
                ('cohort', 'cohort_id', 'cohort_id'),
                ('head', 'accepted_head_identity_sha256',
                 'accepted_head_identity_sha256')):
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as root:
                    fixture = Fixture(root)
                    if name == 'trial':
                        fixture.candidate['prior_identities'][0][prior_key] = \
                            fixture.candidate['fresh_identity'][fresh_key]
                    else:
                        fixture.candidate['fresh_identity'][fresh_key] = \
                            fixture.candidate['prior_identities'][0][prior_key]
                    fixture.rewrite_candidate()
                    with self.assertRaises(ValueError):
                        fixture.compile()
        fixture = Fixture(tempfile.mkdtemp(dir=self.temp.name))
        fixture.candidate['fresh_identity']['owner_contract_sha256'][0] = \
            fixture.candidate['prior_identities'][0][
                'owner_contract_sha256'][1]
        fixture.rewrite_candidate()
        with self.assertRaises(ValueError):
            fixture.compile()

    def test_mutable_hardlinked_or_changed_source_refuses(self):
        for mutation in ('mutable', 'hardlink', 'changed'):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as root:
                    fixture = Fixture(root)
                    target = Path(fixture.source_closure[0]['path'])
                    if mutation == 'mutable':
                        target.chmod(0o664)
                    elif mutation == 'hardlink':
                        os.link(target, Path(root) / 'source-alias')
                    else:
                        target.chmod(0o600)
                        target.write_bytes(b'changed\n')
                        target.chmod(0o444)
                    with self.assertRaises(ValueError):
                        fixture.compile()

    def test_unconfigured_or_source05_build_refuses(self):
        for mutation in ('unconfigured', 'source05'):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as root:
                    fixture = Fixture(root)
                    build_path = Path(
                        fixture.candidate['driver']['build']['path'])
                    build = json.loads(build_path.read_text())
                    build_path.chmod(0o600)
                    if mutation == 'unconfigured':
                        build['configured'] = False
                    else:
                        build['source_sha256'][
                            'financial/run_financial.py'] = '61' * 32
                    data = put(build_path, build)
                    fixture.candidate['driver']['build']['sha256'] = \
                        hashlib.sha256(data).hexdigest()
                    fixture.rewrite_candidate()
                    with self.assertRaises(ValueError):
                        fixture.compile()

    def test_serialized_or_stale_head_policy_never_becomes_authority(self):
        for field in ('serialized_receipt_is_authority',
                      'fresh_current_utxo_recheck_before_lock'):
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as root:
                    fixture = Fixture(root)
                    fixture.candidate['head_policy'][field] = \
                        not fixture.candidate['head_policy'][field]
                    fixture.rewrite_candidate()
                    with self.assertRaises(ValueError):
                        fixture.compile()

    def test_completed_pair_rejects_duplicate_run_projection_or_head(self):
        selection = self.fixture.compile()
        completed = {
            'schema': 'kpb-successor-financial-round-completion/v1',
            'run_id': self.fixture.candidate['fresh_identity']['run_id'],
            'projection_sha256': '71' * 32,
            'accepted_head_identity_sha256':
                self.fixture.candidate['fresh_identity'][
                    'accepted_head_identity_sha256'],
            'selection_sha256': selection['selection_sha256'],
        }
        qualified = selected.validate_completed_pair(selection, completed)
        self.assertTrue(qualified['distinct_round_pair'])
        for field, value in (
                ('run_id', self.fixture.old_run),
                ('projection_sha256', self.fixture.old_projection),
                ('accepted_head_identity_sha256', self.fixture.old_head)):
            with self.subTest(field=field):
                changed = copy.deepcopy(completed)
                changed[field] = value
                with self.assertRaises(ValueError):
                    selected.validate_completed_pair(selection, changed)


if __name__ == '__main__':
    unittest.main()
