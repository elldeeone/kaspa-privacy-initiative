"""Synthetic controls for the actual-capture worker contract.

The fixtures exercise source/schema/binding behavior only.  Their fake public
handoff hashes are not cryptographic or privacy evidence.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import privacy_actual_capture as actual
import privacy_actual_capture_launch as actual_launch
import privacy_capture_model as capture_model
import privacy_capture_producer as capture_producer
import privacy_codec as codec
import privacy_source_closure as source_closure
from test_privacy_capture_producer import p1_channel
from test_privacy_capture_model import (
    colluder_fixture, corrupt_fixture, dispatcher_fixture,
    explicit_dispatcher_fixture, projection, terminal_fixture,
)


def dump(path, value, mode=0o400):
    raw = value if type(value) is bytes else actual.encoded(value)
    path.write_bytes(raw); path.chmod(mode)
    return raw


def rewrite(path, value, mode=0o400):
    path.chmod(0o600)
    return dump(path, value, mode)


def record(path, raw):
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(),
            'bytes': len(raw)}


FAKE_AUTHORITY_RAW = {
    'native_tail': b'native-tail-control',
    'component_profile': b'component-profile-control',
    'outer_selection': b'outer-selection-control',
    'public_host': b'public-host-control',
    'namespace_tool': b'namespace-tool-control',
    'qualifier_source': b'qualifier-source-control',
}
FAKE_AGGREGATE_VK = 'aa' * 32
FAKE_OUTPUT_VK = 'bb' * 32


def fake_financial(root, number, projection_raw):
    root.mkdir()
    run_id = ('%02x' % (40 + number)) * 32
    payloads = {
        'financial_result': b'financial-result-' + bytes([number]),
        'released_core': bytes([50 + number]) * 10364,
        'released_proof': bytes([60 + number]) * 128,
        'released_projection': projection_raw,
        'native_tail': FAKE_AUTHORITY_RAW['native_tail'],
        'retained_projection': projection_raw,
        'journal': bytes([70 + number]) * 104,
        'host_cross_check': b'host-cross-check-' + bytes([number]),
        'component_profile': FAKE_AUTHORITY_RAW['component_profile'],
        'outer_selection': FAKE_AUTHORITY_RAW['outer_selection'],
        'public_host': FAKE_AUTHORITY_RAW['public_host'],
        'namespace_tool': FAKE_AUTHORITY_RAW['namespace_tool'],
        'qualifier_source': FAKE_AUTHORITY_RAW['qualifier_source'],
    }
    leaves = root / 'leaves'; leaves.mkdir()
    records = {}
    for name, raw in payloads.items():
        path = leaves / name; dump(path, raw)
        records[name] = record(path, raw)
    core_sha = records['released_core']['sha256']
    proof_sha = records['released_proof']['sha256']
    projection_sha = records['retained_projection']['sha256']
    effects_sha = ('%02x' % (80 + number)) * 32
    egress_sha = ('%02x' % (90 + number)) * 32
    profile_sha = records['component_profile']['sha256']
    if number == 1:
        head_state, head_reserve, head_spk = '02' * 112, 6_000_000_000, '03' * 37
        next_state, next_reserve, next_spk = '04' * 112, 5_970_000_000, '05' * 37
    else:
        head_state, head_reserve, head_spk = '04' * 112, 5_970_000_000, '05' * 37
        next_state, next_reserve, next_spk = '07' * 112, 5_940_000_000, '08' * 37
    old_point = bytes.fromhex(('%02x' % number) * 36)
    artifacts = {
        'schema': 'kpb-qualified-public-financial-artifacts/v1',
        'status': 'AGGREGATE_AND_SIX_OUTPUT_PROOFS_VERIFIED',
        'run_id': run_id, 'component_profile_sha256': profile_sha,
        'head': {'outpoint_hex36': old_point.hex(),
                 'state_hex112': head_state,
                 'reserve_sompi': head_reserve,
                 'script_public_key_hex37': head_spk},
        'successor': {'state_hex112': next_state,
                      'reserve_sompi': next_reserve,
                      'script_public_key_hex37': next_spk},
        'artifacts': records, 'effects_sha256': effects_sha,
        'core_sha256': core_sha, 'aggregate_proof_sha256': proof_sha,
        'projection_sha256': projection_sha,
        'egress_binding_sha256': egress_sha,
        'successor_state_sha256': hashlib.sha256(
            bytes.fromhex(next_state)).hexdigest(),
        'successor_script_public_key_hex37': next_spk,
        'accepted_head_authority': False,
        'R0_or_native_VM_executed': False, 'R0_receipt_verified': False,
        'full_native_candidate_validated': False,
        'native_settlement_performed': False,
    }
    artifacts_raw = dump(root / 'ARTIFACTS.json', artifacts)
    words = {'construction_sha256': ('%02x' % (100 + number)) * 32,
             'validation_sha256': ('%02x' % (102 + number)) * 32,
             'outer_image_id_hex32': ('%02x' % (104 + number)) * 32}
    result = {
        'schema': 'kpi-financial-public-crypto-handoff/v1',
        'status': 'AGGREGATE_AND_SIX_OUTPUT_PROOFS_VERIFIED',
        'run_id': run_id,
        'source_scope': 'PUBLIC_UNFUNDED_UNREGISTERED_QUALIFICATION_ONLY',
        **words, 'effects_sha256': effects_sha, 'core_sha256': core_sha,
        'aggregate_proof_sha256': proof_sha,
        'projection_sha256': projection_sha,
        'egress_binding_sha256': egress_sha,
        'financial_result_sha256': records['financial_result']['sha256'],
        'component_profile_sha256': profile_sha,
        'aggregate_vk_sha256': FAKE_AGGREGATE_VK,
        'output_vk_sha256': FAKE_OUTPUT_VK,
        'host_sha256': records['public_host']['sha256'],
        'namespace_tool_sha256': records['namespace_tool']['sha256'],
        'qualifier_source_sha256': records['qualifier_source']['sha256'],
        'outer_selection_sha256': records['outer_selection']['sha256'],
        'fixed_old_point_sha256': hashlib.sha256(old_point).hexdigest(),
        'fixed_old_state_sha256': hashlib.sha256(
            bytes.fromhex(head_state)).hexdigest(),
        'native_tail_sha256': records['native_tail']['sha256'],
        'fixed_old_spk_sha256': hashlib.sha256(
            bytes.fromhex(head_spk)).hexdigest(),
        'successor_state_sha256': artifacts['successor_state_sha256'],
        'successor_spk_sha256': hashlib.sha256(
            bytes.fromhex(next_spk)).hexdigest(),
        'journal_sha256': records['journal']['sha256'],
        'all_three_financial_results_agreed': True,
        'aggregate_and_six_Output_G16_verified': True,
        'independent_arkworks_reference_checked': True,
        'public_state_and_global_balance_verified': True,
        'fixed_unfunded_head_and_state_matched': True,
        'registered_financial_service': False,
        'accepted_head_authority': False,
        'R0_or_native_VM_executed': False, 'R0_receipt_verified': False,
        'full_native_candidate_validated': False,
        'native_settlement_performed': False,
        'payment_privacy_qualified': False, 'creator_partition_read': False,
        'private_owner_files_or_keys_read_or_hashed': False,
        'raw_party_diagnostics_read': False,
        'outer_selection_changed': False, 'host_namespace_isolated': True,
        'host_network_namespace_unshared': True,
        'wallet_or_owner_or_host_home_mounted': False,
    }
    result_raw = dump(root / 'RESULT.json', result)
    return {
        'round': number, 'financial_run_id': run_id,
        'financial_artifacts_sha256': hashlib.sha256(
            artifacts_raw).hexdigest(),
        'financial_result_sha256': hashlib.sha256(result_raw).hexdigest(),
        'retained_projection_sha256': projection_sha,
    }


class Fixture:
    def __init__(self, root, classification):
        self.root = Path(root)
        self.capture = self.root / 'captures'; self.capture.mkdir()
        self.evidence = self.root / 'evidence'; self.evidence.mkdir()
        self.state = self.root / 'state'; self.state.mkdir()
        self.output = self.root / 'output'; self.output.mkdir()
        capture_identity = '22222222-2222-4222-8222-222222222222'
        binding = {
            'method_sha256': '13' * 32,
            'selection_sha256': '14' * 32,
            'trial_id': '11111111-1111-4111-8111-111111111111',
            'phase': 'private-batch-privacy',
            'attempt_id': 'actual-capture-test',
        }
        attempts = [
            '33333333-3333-4333-8333-333333333331',
            '33333333-3333-4333-8333-333333333332',
        ]
        cohorts = ['21' * 32, '22' * 32]
        p1_roles = [{
            'round': number, 'kind': kind,
            'role': capture_producer.ROLE_BY_KIND[kind],
            'source_sha256': ('%02x' % (40 + index)) * 32,
            'build_sha256': ('%02x' % (60 + index)) * 32,
            'launch_sha256': ('%02x' % (80 + index)) * 32,
            'fixed_fd': 20 + index,
        } for index, (number, kind) in enumerate(
            capture_producer.CHANNEL_ORDER)]
        for role in p1_roles:
            if role['kind'] == 'corrupt-server-capture':
                role.update({
                    'model_preimage_sha256': 'a1' * 32,
                    'query_store_preimage_sha256': 'a2' * 32,
                    'scalar_capture_manifest_sha256':
                        capture_model.C03_SCALAR_CAPTURE_MANIFEST_SHA256,
                })
        financial, produced_rounds = [], []
        p1_selection = {
            'rounds': [
                {'round': number, 'attempt_id': attempts[number - 1],
                 'cohort_sha256': cohorts[number - 1]}
                for number in (1, 2)],
            'financial_rounds': financial,
            'role_launch_closure': p1_roles,
            'capture_identity': capture_identity,
        }
        transparent = classification == 'ACTUAL_TRANSPARENT_BASELINE'
        for number in (1, 2):
            round_root = self.capture / ('round-' + str(number))
            round_root.mkdir()
            projection_raw, public = projection(number)
            attempt = attempts[number - 1]
            cohort = cohorts[number - 1]
            dispatcher_factory = (explicit_dispatcher_fixture
                                  if transparent else dispatcher_fixture)
            values = {
                'dispatcher-capture': dispatcher_factory(
                    public, cohort_sha256=cohort,
                    run_sha256=('%02x' % (40 + number)) * 32,
                    construction_attempt_sha256=(
                        '%02x' % (46 + number)) * 32,
                    capture_plan_sha256=('%02x' % (48 + number)) * 32),
                'colluder-wallet-capture': colluder_fixture(public),
                'terminal-history':
                    terminal_fixture(public, transparent=transparent),
            }
            for value in values.values():
                value['closure']['attempt_id'] = attempt
                value['closure']['cohort_sha256'] = cohort
                if 'cohort_sha256' in value:
                    value['cohort_sha256'] = cohort
            raws = {'public-projection': dump(
                round_root / 'projection.bin', projection_raw)}
            for kind, filename in actual.CAPTURE_FILES.items():
                if kind not in ('public-projection',
                                'corrupt-server-capture'):
                    raws[kind] = dump(round_root / filename, values[kind])
            financial.append(fake_financial(
                self.evidence / ('round-' + str(number)), number,
                projection_raw))
            c03 = p1_channel(number, p1_selection)
            raws['corrupt-server-capture'] = dump(
                round_root / actual.CAPTURE_FILES[
                    'corrupt-server-capture'], c03)
            with tempfile.TemporaryFile() as channel:
                channel.write(c03); channel.seek(0)
                _, c03_closure = capture_producer._consume_p1(
                    channel.fileno(), p1_selection, number)
            p1_authority = capture_producer._p1_capture_authority(
                p1_selection, number, c03_closure)
            artifact_rows = []
            for kind in actual.PRODUCER_ARTIFACT_ORDER:
                if kind == 'public-projection':
                    records = [{'stream': 'projection', 'value': {
                        'bytes': len(projection_raw),
                        'sha256': hashlib.sha256(
                            projection_raw).hexdigest()}}]
                    artifact_rows.append({
                        'kind': kind, 'producer_record_count': 1,
                        'capture_record_count': 1,
                        'producer_payload_bytes': len(projection_raw),
                        'capture_payload_bytes': len(projection_raw),
                        'record_chain_sha256': hashlib.sha256(
                            actual.encoded(records)).hexdigest(),
                        'capture_root_closed': True,
                        'producer_fd_closed': True})
                elif kind == 'corrupt-server-capture':
                    artifact_rows.append({'kind': kind, **{
                        name: c03_closure[name]
                        for name in actual.PRODUCER_ARTIFACT_FIELDS[1:]}})
                else:
                    closure = values[kind]['closure']
                    artifact_rows.append({'kind': kind, **{
                        name: closure[name]
                        for name in actual.PRODUCER_ARTIFACT_FIELDS[1:]}})
            produced_rounds.append({
                'round': number, 'attempt_id': attempt,
                'cohort_sha256': cohort,
                'p1_capture_authority': p1_authority,
                'artifacts': artifact_rows})
        producer = {
            'schema': 'kpb-capture-producer-receipt/v1',
            'binding': binding, 'classification': classification,
            'capture_identity': capture_identity,
            'producer_source_sha256': hashlib.sha256(
                Path(actual.__file__).with_name(
                    'privacy_capture_producer.py').read_bytes()).hexdigest(),
            'producer_build_sha256': '92' * 32,
            'producer_role_launch_sha256': hashlib.sha256(
                actual.encoded(p1_roles)).hexdigest(),
            'financial_rounds': financial, 'rounds': produced_rounds,
            'append_only_roots_closed': True, 'unknown_record_count': 0,
            'role_hooks_integrated': True,
            'fixed_fd_inheritance_selected': True,
            'launcher_selected': True,
            'launch_authorized': True,
            'actual_receipt_emitted': True,
        }
        producer_raw = dump(self.capture / 'PRODUCER.json', producer)
        runtime = source_closure.runtime_identity()
        self.config = {
            'schema': 'kpb-actual-capture-worker-config/v1',
            'comparison_selection_sha256': '11' * 32,
            'run_selection_sha256': '12' * 32,
            'classification': classification,
            'binding': binding,
            'method_sha256': '13' * 32, 'workload_sha256': '15' * 32,
            'observer_source_sha256': source_closure.digest('observer'),
            'capture_source_sha256': actual.source_sha256(),
            'coverage_policy_sha256': '17' * 32,
            'capture_identity': capture_identity,
            'capture_producer_receipt_sha256': hashlib.sha256(
                producer_raw).hexdigest(),
            'capture_producer_source_sha256':
                producer['producer_source_sha256'],
            'capture_producer_build_sha256':
                producer['producer_build_sha256'],
            'capture_producer_role_launch_sha256':
                producer['producer_role_launch_sha256'],
            'capture_producer_role_launch_closure':
                copy.deepcopy(p1_roles),
            'step3_terminal_gate': actual.STEP3_TERMINAL_GATE,
            'capture_launcher_source_sha256': hashlib.sha256(
                (Path(actual.__file__).with_name(
                    'privacy_actual_capture_launch.py')).read_bytes()
                ).hexdigest(),
            'source_closure_sha256': source_closure.all_digests(),
            'runtime_identity_sha256': source_closure.runtime_digest(),
            'python_runtime_sha256': runtime['python_runtime_sha256'],
            'namespace_tool_sha256': runtime['namespace_tool_sha256'],
            'root_guard_helper_sha256': runtime[
                'root_guard_helper_sha256'],
            'host_runtime_trust_boundary': runtime[
                'host_runtime_trust_boundary'],
            'source_members': source_closure.manifest(
                'actual-capture')['members'],
            'financial_rounds': financial,
        }
        dump(self.state / 'CAPTURE-CONSUMED.json', {
            'schema': 'kpb-actual-capture-consumed/v1',
            'comparison_selection_sha256':
                self.config['comparison_selection_sha256'],
            'run_selection_sha256': self.config['run_selection_sha256'],
            'capture_identity': capture_identity})
        self.fake_authority = {
            'component_profile': hashlib.sha256(
                FAKE_AUTHORITY_RAW['component_profile']).hexdigest(),
            'outer_selection': hashlib.sha256(
                FAKE_AUTHORITY_RAW['outer_selection']).hexdigest(),
            'public_host': hashlib.sha256(
                FAKE_AUTHORITY_RAW['public_host']).hexdigest(),
            'namespace_tool': hashlib.sha256(
                FAKE_AUTHORITY_RAW['namespace_tool']).hexdigest(),
            'aggregate_vk': FAKE_AGGREGATE_VK,
            'output_vk': FAKE_OUTPUT_VK,
            'native_tail': hashlib.sha256(
                FAKE_AUTHORITY_RAW['native_tail']).hexdigest(),
        }

    def produce(self):
        qualifier = hashlib.sha256(
            FAKE_AUTHORITY_RAW['qualifier_source']).hexdigest()
        with mock.patch.dict(actual.FINANCIAL_AUTHORITY,
                             self.fake_authority, clear=True), \
             mock.patch.object(actual, 'selected_qualifier_sha256',
                               return_value=qualifier):
            return actual.produce(
                self.config, self.capture, self.evidence,
                self.state, self.output, salt=bytes([31]) * 32)


class ActualCaptureControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp.cleanup()

    def fixture(self, classification='ACTUAL_HIDDEN_MAPPING_CANDIDATE'):
        return Fixture(self.temp.name, classification)

    def test_hidden_actual_capture_preserves_unmodeled_field_coverage(self):
        fixture = self.fixture(); result = fixture.produce()
        self.assertEqual(result['terminal_scope'], actual.TERMINAL_SCOPE)
        self.assertTrue(result['capture_roots_closed'])
        self.assertTrue(result['exact_union_derived'])
        self.assertFalse(result['predictions_or_truth_mounted'])
        self.assertFalse(
            result['private_artifact_paths_hashes_or_bodies_exported'])
        self.assertEqual([row['view'] for row in result['views']],
                         list(actual.VIEWS))
        expected_unmodeled = {
            'public': 2,
            'dispatcher': 3,
            'corrupt-server-plus-wallet': 4,
            'union': 5,
        }
        for view in result['views']:
            self.assertEqual([row['round'] for row in view['rounds']], [1, 2])
            for row in view['rounds']:
                self.assertEqual(row['missing_artifacts'], 0)
                self.assertEqual(row['unmodeled_artifacts'],
                                 expected_unmodeled[view['view']])
                for category, coverage in row['category_coverage'].items():
                    self.assertEqual(coverage['modeled_artifacts'],
                                     row['category_counts'][category])
                    self.assertEqual(coverage['missing_artifacts'], 0)
                    self.assertGreater(
                        coverage['constraint_modeled_fields'] +
                        coverage['source_assumption_covered_fields'] +
                        coverage['unmodeled_fields'],
                        0)
        corrupt = next(row for row in result['views']
                       if row['view'] == 'corrupt-server-plus-wallet')
        self.assertGreater(corrupt['rounds'][0]['category_coverage'][
            'server-local-shares']['unmodeled_fields'], 0)
        self.assertEqual(corrupt['rounds'][0]['category_coverage'][
            'server-local-shares']['source_assumption_covered_fields'], 0)
        public = json.loads((fixture.output / 'PUBLIC.json').read_text())
        self.assertEqual(public, result)
        self.assertNotIn(str(fixture.capture),
                         (fixture.output / 'PUBLIC.json').read_text())
        construction = json.loads(
            (fixture.output / 'CONSTRUCTION.json').read_text())
        self.assertEqual(construction['terminal_grouping_mode'],
                         'ONE_UNLABELLED_3NF_6TUPLE_GROUP')
        self.assertFalse(construction['direct_owner_mapping_exposed'])
        self.assertTrue((fixture.state / 'MANIFEST.bin').exists())
        self.assertTrue((fixture.state / 'MODELS.json').exists())
        private_models = json.loads(
            (fixture.state / 'MODELS.json').read_text())
        for round_row in private_models['rounds']:
            for view in round_row['derived']['views'].values():
                inventory = view['unmodeled_inventory']
                self.assertFalse(inventory['authorizes_coverage'])
                self.assertEqual(inventory['missing_artifact_count'], 0)
                self.assertGreater(inventory['unmodeled_field_count'], 0)
        public_raw = (fixture.output / 'PUBLIC.json').read_text()
        self.assertNotIn('unmodeled_inventory', public_raw)
        self.assertNotIn('field_path', public_raw)

    def test_actual_p1_capture_requires_wire_bound_authority_not_json(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory,
                              'ACTUAL_HIDDEN_MAPPING_CANDIDATE')
            target = fixture.capture / 'PRODUCER.json'
            producer = json.loads(target.read_text())
            selected = producer['rounds'][0]
            selected['p1_capture_authority']['source_sha256'] = 'f1' * 32
            capture_path = fixture.capture / 'round-1' / \
                actual.CAPTURE_FILES['corrupt-server-capture']
            wire = bytearray(capture_path.read_bytes())
            # Substitute both the HELLO and the receipt row, then rebuild all
            # caller-visible roots while leaving the independently selected
            # aggregate role-launch preimage unchanged.
            wire[112 + 140:112 + 172] = bytes.fromhex('f1' * 32)
            wire[80:112] = hashlib.sha256(wire[112:112 + 332]).digest()
            rewrite(capture_path, bytes(wire))
            chain = hashlib.sha256(wire).hexdigest()
            selected['p1_capture_authority']['closure'][
                'record_chain_sha256'] = chain
            artifact = next(row for row in selected['artifacts']
                            if row['kind'] ==
                            'corrupt-server-capture')
            artifact['record_chain_sha256'] = chain
            raw = rewrite(target, producer)
            fixture.config['capture_producer_receipt_sha256'] = \
                hashlib.sha256(raw).hexdigest()
            with self.assertRaisesRegex(
                    ValueError,
                    'producer-p1-authority-role-launch-join'):
                fixture.produce()

        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory,
                              'ACTUAL_HIDDEN_MAPPING_CANDIDATE')
            projection_raw, public = projection(2)
            value = corrupt_fixture(public, projection_raw)
            target = fixture.capture / 'PRODUCER.json'
            producer = json.loads(target.read_text())
            selected = producer['rounds'][1]
            value['cohort_sha256'] = selected['cohort_sha256']
            value['closure']['attempt_id'] = selected['attempt_id']
            value['closure']['cohort_sha256'] = selected['cohort_sha256']
            rewrite(fixture.capture / 'round-2' /
                    actual.CAPTURE_FILES['corrupt-server-capture'], value)
            selected['p1_capture_authority']['closure'] = \
                copy.deepcopy(value['closure'])
            artifact = next(row for row in selected['artifacts']
                            if row['kind'] ==
                            'corrupt-server-capture')
            for name in actual.PRODUCER_ARTIFACT_FIELDS[1:]:
                artifact[name] = value['closure'][name]
            raw = rewrite(target, producer)
            fixture.config['capture_producer_receipt_sha256'] = \
                hashlib.sha256(raw).hexdigest()
            with self.assertRaisesRegex(
                    ValueError, 'producer-p1-closure-fields'):
                fixture.produce()

    def test_actual_p1_authority_requires_distinct_round_cohorts(self):
        fixture = self.fixture()
        target = fixture.capture / 'PRODUCER.json'
        producer = json.loads(target.read_text())
        first = producer['rounds'][0]['cohort_sha256']
        second = producer['rounds'][1]
        second['cohort_sha256'] = first
        second['p1_capture_authority']['cohort_sha256'] = first
        second['p1_capture_authority']['closure']['cohort_sha256'] = first
        raw = rewrite(target, producer)
        fixture.config['capture_producer_receipt_sha256'] = \
            hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(
                ValueError,
                'producer-distinct-round-attempts-and-cohorts'):
            fixture.produce()

    def test_host_authored_three_group_baseline_is_not_actual_authority(self):
        fixture = self.fixture('ACTUAL_TRANSPARENT_BASELINE')
        with self.assertRaisesRegex(
                ValueError,
                'transparent-baseline-source-authority-unavailable'):
            fixture.produce()
        self.assertFalse((fixture.output / 'CONSTRUCTION.json').exists())
        self.assertFalse((fixture.output / 'PUBLIC.json').exists())

    def test_relabelled_grouping_is_not_an_actual_classification(self):
        fixture = self.fixture()
        fixture.config['classification'] = 'ACTUAL_TRANSPARENT_BASELINE'
        with self.assertRaisesRegex(
                ValueError,
                'transparent-baseline-source-authority-unavailable'):
            fixture.produce()

    def test_missing_hardlinked_or_incomplete_capture_refuses(self):
        for mutation in ('missing', 'hardlink', 'closure'):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = Fixture(directory,
                        'ACTUAL_HIDDEN_MAPPING_CANDIDATE')
                    target = fixture.capture / 'round-1/dispatcher.json'
                    if mutation == 'missing':
                        target.unlink()
                    elif mutation == 'hardlink':
                        (fixture.root / 'alias').hardlink_to(target)
                    else:
                        value = json.loads(target.read_text())
                        value['closure']['capture_record_count'] -= 1
                        rewrite(target, value)
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        fixture.produce()

    def test_symlinked_capture_leaf_refuses_without_following(self):
        fixture = self.fixture()
        target = fixture.capture / 'round-1/dispatcher.json'
        original = fixture.root / 'dispatcher-original.json'
        target.rename(original); target.symlink_to(original)
        with self.assertRaises(OSError):
            fixture.produce()

    def test_candidate_refuses_upload_order_owner_mapping(self):
        fixture = self.fixture()
        target = fixture.capture / 'round-1/dispatcher.json'
        value = json.loads(target.read_text())
        value['release_order_policy'] = 'UPLOAD_ORDER_PUBLIC_EFFECTS'
        rewrite(target, value)
        with self.assertRaisesRegex(
                ValueError, 'dispatcher-release-order-policy'):
            fixture.produce()

    def test_producer_count_mismatch_refuses(self):
        fixture = self.fixture()
        target = fixture.capture / 'PRODUCER.json'
        value = json.loads(target.read_text())
        value['rounds'][0]['artifacts'][0]['capture_record_count'] += 1
        raw = rewrite(target, value)
        fixture.config['capture_producer_receipt_sha256'] = hashlib.sha256(
            raw).hexdigest()
        with self.assertRaisesRegex(ValueError,
                                    'producer-artifact-closed-root'):
            fixture.produce()

    def test_frozen_source_only_producer_receipt_is_explicitly_refused(self):
        fixture = self.fixture()
        target = fixture.capture / 'PRODUCER.json'
        source_only = {
            'schema': 'kpb-capture-producer-source-only/v1',
            'status': 'UNQUALIFIED_SOURCE_ONLY',
            'launch_authorized': False,
            'actual_receipt_emitted': False,
        }
        raw = rewrite(target, source_only)
        fixture.config['capture_producer_receipt_sha256'] = hashlib.sha256(
            raw).hexdigest()
        with self.assertRaisesRegex(
                ValueError, 'source-only-producer-is-not-actual-authority'):
            fixture.produce()

    def test_self_authored_actual_producer_flags_and_closure_refuse(self):
        cases = (
            ('missing-launch-authorized', 'producer-receipt-fields'),
            ('false-actual-receipt',
             'selected-source-produced-capture-authority'),
            ('false-role-hooks',
             'selected-source-produced-capture-authority'),
            ('arbitrary-build',
             'selected-producer-source-build-launch-closure'),
        )
        for mutation, category in cases:
            with self.subTest(mutation=mutation), \
                    tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(
                    directory, 'ACTUAL_HIDDEN_MAPPING_CANDIDATE')
                target = fixture.capture / 'PRODUCER.json'
                value = json.loads(target.read_text())
                if mutation == 'missing-launch-authorized':
                    value.pop('launch_authorized')
                elif mutation == 'false-actual-receipt':
                    value['actual_receipt_emitted'] = False
                elif mutation == 'false-role-hooks':
                    value['role_hooks_integrated'] = False
                else:
                    value['producer_build_sha256'] = 'ff' * 32
                raw = rewrite(target, value)
                fixture.config['capture_producer_receipt_sha256'] = \
                    hashlib.sha256(raw).hexdigest()
                with self.assertRaisesRegex(ValueError, category):
                    fixture.produce()

    def test_transitive_source_drift_refuses(self):
        fixture = self.fixture()
        fixture.config['source_members'][1]['sha256'] = 'ff' * 32
        with self.assertRaisesRegex(ValueError,
                                    'source-closure-exact-actual-capture'):
            fixture.produce()

    def test_worker_namespace_validates_only_actual_capture_role(self):
        fixture = self.fixture()
        with mock.patch.object(source_closure, 'all_digests',
                               side_effect=AssertionError(
                                   'global closure read')), \
                mock.patch.object(source_closure, 'runtime_digest',
                                  side_effect=AssertionError(
                                      'host runtime read')):
            actual.validate_config(fixture.config)
            actual.validate_runtime(
                fixture.config, source_closure.ROOT_GUARD)

    def test_state_and_public_output_roots_cannot_alias(self):
        fixture = self.fixture()
        with self.assertRaisesRegex(ValueError,
                                    'nonoverlapping-root-paths'):
            actual.produce(fixture.config, fixture.capture,
                           fixture.evidence, fixture.state, fixture.state)

    def test_changed_or_reused_financial_evidence_refuses(self):
        for mutation in ('changed-result', 'reused-run'):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = Fixture(directory,
                        'ACTUAL_HIDDEN_MAPPING_CANDIDATE')
                    if mutation == 'changed-result':
                        path = fixture.evidence / 'round-1/RESULT.json'
                        value = json.loads(path.read_text())
                        value['payment_privacy_qualified'] = True
                        rewrite(path, value)
                        fixture.config['financial_rounds'][0][
                            'financial_result_sha256'] = hashlib.sha256(
                                path.read_bytes()).hexdigest()
                    else:
                        fixture.config['financial_rounds'][1][
                            'financial_run_id'] = fixture.config[
                                'financial_rounds'][0]['financial_run_id']
                    with self.assertRaises(ValueError): fixture.produce()

    def test_every_selected_financial_leaf_is_reopened_and_hashed(self):
        for name in actual.PUBLIC_ARTIFACT_NAMES:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                fixture = Fixture(d, 'ACTUAL_HIDDEN_MAPPING_CANDIDATE')
                path = fixture.evidence / 'round-1/leaves' / name
                raw = bytearray(path.read_bytes()); raw[0] ^= 1
                rewrite(path, bytes(raw))
                with self.assertRaisesRegex(ValueError,
                                            'financial-opened-leaf'):
                    fixture.produce()

    def test_hand_authored_public_receipt_cannot_replace_worker_completion(self):
        fixture = self.fixture()
        dump(fixture.output / 'PUBLIC.json', {
            'schema': 'kpb-privacy-actual-capture-receipt/v2',
            'forged': True})
        with self.assertRaisesRegex(ValueError, 'fresh-empty-output-root'):
            fixture.produce()

    def test_public_outputs_do_not_contain_private_paths_or_artifact_hashes(self):
        fixture = self.fixture(); fixture.produce()
        public = (fixture.output / 'PUBLIC.json').read_text()
        construction = (fixture.output / 'CONSTRUCTION.json').read_text()
        exported = public + construction
        self.assertNotIn(str(fixture.capture), exported)
        for number in (1, 2):
            for filename in ('dispatcher.json', 'corrupt-server.json',
                             'colluder-wallet.json', 'terminal.json'):
                raw = (fixture.capture / ('round-' + str(number)) /
                       filename).read_bytes()
                self.assertNotIn(hashlib.sha256(raw).hexdigest(), exported)

    def test_source_only_launcher_never_emits_actual_authority(self):
        plan = {'schema': 'kpb-actual-capture-launch-plan/v1',
                'status': 'SOURCE_ONLY_UNQUALIFIED',
                'producer_receipt_path_present': True,
                'blocker':
                    'GENUINE_FIVE_ROLE_BUILD_SUPERVISION_AND_OUTER_LAUNCH_AUTHORITY_ABSENT'}
        with mock.patch.object(actual_launch, 'admit', return_value=plan):
            self.assertEqual(actual_launch.run('/unused', '00' * 32, 0), plan)
            with self.assertRaisesRegex(
                    ValueError, 'source-only-no-genuine-producer-authority'):
                actual_launch.run('/unused', '00' * 32, 0, execute=True)
        forged = {name: '00' * 32 for name in actual_launch.LAUNCH_FIELDS}
        forged.update({
            'schema': actual_launch.LAUNCH_SCHEMA,
            'operation': 'actual-capture',
            'persistent_capture_consumed': True,
            'capture_roots_closed': True,
            'financial_host_crypto_rechecked': True,
            'network_enabled': False,
            'predictions_or_truth_mounted': False,
            'private_capture_bodies_read_inside_namespace': True,
            'private_artifact_paths_hashes_or_bodies_exported': False,
            'terminal_scope': actual.TERMINAL_SCOPE,
            'step3_terminal_gate': actual.STEP3_TERMINAL_GATE,
        })
        with self.assertRaisesRegex(
                ValueError, 'actual-launch-receipt-disabled-source-only'):
            actual_launch.validate_launch_receipt(forged)
        legacy = {**forged, 'schema': 'kpb-actual-capture-launch/v1'}
        with self.assertRaisesRegex(ValueError, 'launch-authority-flags'):
            actual_launch.validate_launch_receipt(legacy)

    def test_direct_worker_refuses_before_namespace_or_private_read(self):
        with mock.patch('sys.argv', ['privacy_actual_capture.py', '--worker']), \
                mock.patch.object(actual, 'require_namespace') as namespace, \
                mock.patch.object(actual, 'stable_read') as private_read, \
                mock.patch.object(actual, 'produce') as produce:
            with self.assertRaisesRegex(
                    ValueError,
                    'actual-multilanguage-build-runtime-selection-absent'):
                actual.main()
        namespace.assert_not_called()
        private_read.assert_not_called()
        produce.assert_not_called()

    def test_exit_privacy_is_explicitly_out_of_batch_gate_scope(self):
        fixture = self.fixture(); result = fixture.produce()
        self.assertEqual(result['terminal_scope'],
            'PRIVATE_BATCH_TERMINAL_ONLY_EXIT_LINKABILITY_UNMEASURED')
        self.assertEqual(result['step3_terminal_gate'],
            'REQUIRED_SEPARATE_EXIT_LINKABILITY_GATE_BEFORE_STEP3')
        self.assertNotIn('exit_privacy_passed', result)


if __name__ == '__main__':
    unittest.main()
