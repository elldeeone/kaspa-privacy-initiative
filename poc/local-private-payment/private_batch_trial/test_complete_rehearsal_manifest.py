"""Fail-closed controls for the unfunded lifecycle evidence bridge."""
import copy
import hashlib
from pathlib import Path
import unittest
from unittest import mock

import complete_rehearsal_manifest as bridge


def h(label):
    return hashlib.sha256(label.encode()).hexdigest()


def unsized(value):
    return {key: value[key] for key in ('path', 'sha256')}


class MemoryReader:
    def __init__(self):
        self.rows = {}

    def add(self, name, value):
        raw = value if type(value) is bytes else bridge.private_worker.encoded(value)
        path = str(Path('/public-complete-rehearsal-controls') / name)
        pin = hashlib.sha256(raw).hexdigest()
        self.rows[path] = raw
        return {'path': path, 'sha256': pin, 'bytes': len(raw)}

    def __call__(self, path, expected=None):
        raw = self.rows[str(path)]
        if expected is not None and hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('control-pin')
        return raw


def owner_contract(run_id, owner):
    values = {
        'run_nonce': run_id, 'model': h('model'), 'source': h('source'),
        'pk': h('pk'), 'vk': h('vk'), 'trace': h('trace'),
        'layout': h('layout'), 'cohort': h('cohort'),
        'owner_id': str(owner), 'input_count': '2635409',
        'server_certificate_0': h('server 0'),
        'server_certificate_1': h('server 1'),
        'server_certificate_2': h('server 2'),
        'owner_certificate': h('owner ' + str(owner)),
    }
    order = ('run_nonce', 'model', 'source', 'pk', 'vk', 'trace', 'layout',
             'cohort', 'owner_id', 'input_count', 'server_certificate_0',
             'server_certificate_1', 'server_certificate_2', 'owner_certificate')
    return ('KPI_OWNER_CONTRACT_V2\n' + ''.join(
        name + ' ' + values[name] + '\n' for name in order) + 'END\n').encode()


def intake(reader):
    run_id = h('financial run')
    records = [reader.add('owner-' + str(owner) + '.contract',
                          owner_contract(run_id, owner)) for owner in range(3)]
    parsed = [bridge.owner_contract(reader(Path(row['path']), row['sha256']))
              for row in records]
    selection = {'path': '/public/selection.json', 'sha256': h('selection')}
    result = {'path': '/public/result.json', 'sha256': h('result')}
    head = {'outpoint_hex36': '11' * 36,
            'state_hex112': (b'KPBAST01' + b'\x22' * 104).hex(),
            'reserve_sompi': 6_000_000_000}
    value = {'schema': 'kpb-owner-intake-financial-binding/v1',
        'trial_id': '11111111-1111-4111-8111-111111111111', 'round': 1,
        'input_history_sha256': h('history'),
        'lifecycle_operation_id': 'operation-1', 'financial_run_id': run_id,
        'owner_contracts_sha256': bridge.owner_contracts_identity(parsed),
        'owner_contracts': records,
        'lifecycle_selection_sha256': selection['sha256'],
        'lifecycle_result_sha256': result['sha256'],
        'component_profile_sha256': h('profile'), 'head': head,
        'owner_components': [0, 1, 2], 'bound_before_private_intake': True,
        'controller_read_or_hashed_owner_private_bodies': False}
    return value, selection, result


def artifact_fixture(reader):
    profile = {'domain_hex32': h('domain')}
    profile_raw = bridge.private_worker.encoded(profile)
    profile_sha = hashlib.sha256(profile_raw).hexdigest()
    tail = b'PUBLIC NATIVE TAIL CONTROL'
    tail_sha = hashlib.sha256(tail).hexdigest()
    core, proof = b'C' * 10364, b'P' * 128
    projection = b'X' * 193 + core + proof
    journal = (b'KPBAJR01' + bytes.fromhex(profile['domain_hex32'])
               + bytes.fromhex(profile_sha) + hashlib.sha256(projection).digest())
    host, namespace, report = b'host', b'namespace', {'direct': True}
    contents = {'financial_result': b'financial', 'released_core': core,
        'released_proof': proof, 'released_projection': projection,
        'native_tail': tail, 'retained_projection': projection,
        'journal': journal, 'host_cross_check': b'report',
        'component_profile': profile_raw, 'outer_selection': b'outer',
        'public_host': host, 'namespace_tool': namespace,
        'qualifier_source': bridge.QUALIFIER_PATH.read_bytes()}
    refs = {name: reader.add(name, contents[name]) for name in bridge.ARTIFACT_NAMES}
    head_state = b'KPBAST01' + b'\x22' * 104
    successor_state = (b'KPBAST01' + core[104:136] + core[284:316]
                       + core[348:352] + core[316:348] + core[352:356])
    head_spk = bridge.exit_wire.state_spk(head_state, tail).hex()
    successor_spk = bridge.exit_wire.state_spk(successor_state, tail).hex()
    value = {'schema': 'kpb-qualified-public-financial-artifacts/v1',
        'status': 'AGGREGATE_AND_SIX_OUTPUT_PROOFS_VERIFIED',
        'run_id': h('run'), 'component_profile_sha256': profile_sha,
        'head': {'outpoint_hex36': '11' * 36, 'state_hex112': head_state.hex(),
                 'reserve_sompi': 6_000_000_000,
                 'script_public_key_hex37': head_spk},
        'successor': {'state_hex112': successor_state.hex(),
            'reserve_sompi': int.from_bytes(core[356:364], 'little'),
            'script_public_key_hex37': successor_spk},
        'artifacts': refs, 'effects_sha256': hashlib.sha256(core).hexdigest(),
        'core_sha256': hashlib.sha256(core).hexdigest(),
        'aggregate_proof_sha256': hashlib.sha256(proof).hexdigest(),
        'projection_sha256': hashlib.sha256(projection).hexdigest(),
        'egress_binding_sha256': h('egress'),
        'successor_state_sha256': hashlib.sha256(successor_state).hexdigest(),
        'successor_script_public_key_hex37': successor_spk,
        'accepted_head_authority': False, 'R0_or_native_VM_executed': False,
        'R0_receipt_verified': False, 'full_native_candidate_validated': False,
        'native_settlement_performed': False}
    party = {'core_sha256': value['core_sha256'],
        'effects_sha256': value['effects_sha256'],
        'proof_sha256': value['aggregate_proof_sha256'],
        'projection_sha256': value['projection_sha256'],
        'egress_binding_sha256': value['egress_binding_sha256']}
    patches = {'HOST_SHA256': hashlib.sha256(host).hexdigest(),
        'BWRAP_SHA256': hashlib.sha256(namespace).hexdigest(),
        'admit_profile': lambda raw: profile,
        'admit_unselected_outer': lambda raw: None,
        'admit_release': lambda *args: {'run_id': value['run_id'],
                                        'parties': [party, party, party]},
        'run_host': lambda *args: (report, journal),
        'strict_json': lambda raw: report,
        'successor_state': lambda raw: successor_state,
        'reserve_spk': bridge.exit_wire.state_spk}
    return value, projection, profile_sha, tail_sha, patches


class CompleteRehearsalBridgeControls(unittest.TestCase):
    def test_privacy_recomputes_both_capture_bundles_owner_chain_and_result(self):
        refs = {'comparison_selection': {'path': '/public/comparison.json',
                                         'sha256': h('comparison')}}
        baseline, candidate, owner = {'arm': 'baseline'}, {'arm': 'candidate'}, {'owners': True}
        expected = {'status': 'PASS_BOUNDED_ACTUAL_PRIVACY_IMPROVEMENT'}
        with mock.patch.object(bridge.privacy_capture_bundle, 'produce',
                side_effect=[baseline, candidate]) as produce, \
             mock.patch.object(bridge.privacy_acceptance,
                'read_owner_comparison_chain', return_value=owner) as compare, \
             mock.patch.object(bridge.privacy_acceptance, 'evaluate',
                return_value=expected) as evaluate:
            self.assertEqual(bridge.recompute_actual_privacy(
                refs, baseline, candidate), expected)
            self.assertEqual([call.args[2] for call in produce.call_args_list], [0, 1])
            compare.assert_called_once_with(baseline, candidate)
            evaluate.assert_called_once_with(baseline, candidate, owner)
        with mock.patch.object(bridge.privacy_capture_bundle, 'produce',
                side_effect=[{'arm': 'forged'}, candidate]):
            with self.assertRaisesRegex(ValueError,
                    'privacy-bundles-reproduced-from-actual-capture-chain'):
                bridge.recompute_actual_privacy(refs, baseline, candidate)

    def test_preintake_binding_reopens_three_exact_owner_contracts(self):
        reader = MemoryReader(); value, selection, result = intake(reader)
        trial = {'trial_id': value['trial_id']}
        bridge.exact_intake_binding(reader, value, trial, 1,
            value['input_history_sha256'], selection, result,
            value['lifecycle_operation_id'], value['component_profile_sha256'], value['head'])
        for mutation in ('digest', 'result', 'contract'):
            changed = copy.deepcopy(value)
            if mutation == 'digest': changed['owner_contracts_sha256'] = h('wrong')
            elif mutation == 'result': changed['lifecycle_result_sha256'] = h('wrong')
            else: changed['owner_contracts'][2] = changed['owner_contracts'][1]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                bridge.exact_intake_binding(reader, changed, trial, 1,
                    value['input_history_sha256'], selection, result,
                    value['lifecycle_operation_id'], value['component_profile_sha256'], value['head'])

    def test_artifact_schema_tracks_qualifier_and_reopens_every_record(self):
        self.assertEqual(bridge.ARTIFACT_NAMES,
                         tuple(bridge.QUALIFIER['PUBLIC_ARTIFACT_NAMES']))
        reader = MemoryReader()
        value, projection, profile_sha, tail_sha, patches = artifact_fixture(reader)
        ref = unsized(reader.add('ARTIFACTS.json', value))
        saved = {name: bridge.QUALIFIER[name] for name in patches}
        try:
            bridge.QUALIFIER.update(patches)
            actual, raw_projection, _ = bridge.exact_public_financial_artifacts(
                reader, ref, profile_sha, tail_sha)
            self.assertEqual(actual, value); self.assertEqual(raw_projection, projection)
            reader.rows[value['artifacts']['namespace_tool']['path']] = b'changed'
            with self.assertRaises(ValueError):
                bridge.exact_public_financial_artifacts(reader, ref, profile_sha, tail_sha)
        finally:
            bridge.QUALIFIER.update(saved)

    def test_registered_release_booleans_never_create_authority(self):
        reader = MemoryReader()
        selection = unsized(reader.add('REGISTERED-SELECTION.json', {'selected': True}))
        result = unsized(reader.add('REGISTERED-RESULT.json', {'all_three_agreed': True}))
        with self.assertRaisesRegex(ValueError,
                'registered-hidden-mapping-selected-configured-driver-result-not-executed'):
            bridge.exact_registered_driver_result(reader, selection, result, {}, {})

    def test_service_loss_json_and_boolean_zero_are_both_refused(self):
        trial = {'trial_id': '11111111-1111-4111-8111-111111111111'}
        runs = [h('run 1'), h('run 2')]
        value = {'schema': 'kpb-unfunded-financial-service-loss/v1',
            'trial_id': trial['trial_id'], 'after_round2_history_sha256': h('history'),
            'financial_run_ids': runs, 'process_identities_checked': [101, 102, 103],
            'active_financial_service_processes': 0,
            'active_financial_service_listeners': 0,
            'private_service_state_mounted_to_exit': False,
            'owner_exit_service_dependency': False,
            'controller_read_or_hashed_private_service_state': False}
        with self.assertRaisesRegex(ValueError,
                'ordered-service-loss-producer-and-exit-binding-not-implemented'):
            bridge.exact_service_loss(value, trial, h('history'), runs)
        value['active_financial_service_processes'] = False
        with self.assertRaisesRegex(ValueError, 'financial-service-absent'):
            bridge.exact_service_loss(value, trial, h('history'), runs)

    def test_manifest_schema_and_complete_case_count_are_fixed(self):
        self.assertEqual(bridge.MANIFEST_SCHEMA,
                         'kpb-complete-unfunded-native-lifecycle/v2')
        self.assertEqual(bridge.EXPECTED_KINDS,
            ['genesis', 'payment', 'payment'] + ['exit'] * 9)
        self.assertEqual(len(bridge.CURRENT_HARD_STOPS), 5)
        self.assertIn('release-bound-privacy', bridge.CURRENT_HARD_STOPS[0])
        self.assertIn('configured-driver-result', bridge.CURRENT_HARD_STOPS[1])
        self.assertIn('r0-receipt-reexecution', bridge.CURRENT_HARD_STOPS[2])
        self.assertIn('service-loss-producer', bridge.CURRENT_HARD_STOPS[3])
        self.assertIn('terminal-nine-exit', bridge.CURRENT_HARD_STOPS[4])


if __name__ == '__main__':
    unittest.main()
