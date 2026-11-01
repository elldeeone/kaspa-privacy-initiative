#!/usr/bin/env python3
"""Hostile controls for the nonauthorizing observer-readiness adapter."""

import copy
import contextlib
import hashlib
import io
import tempfile
import unittest

import privacy_acceptance as acceptance
import privacy_capture_model as capture_model
import privacy_capture_producer as capture_producer
import privacy_codec as codec
import privacy_observer_readiness as readiness
import privacy_roles as roles
import test_privacy_acceptance as acceptance_fixture
import test_privacy_capture_model as model_fixture
import test_privacy_capture_producer as producer_fixture


def _complete_synthetic_artifact(value):
    """Model a hypothetical post-Step2 complete leaf without authority."""
    result = copy.deepcopy(value)
    for row in result['leakage_ledger']:
        if row['status'] == 'unmodeled':
            family = readiness._field_assumption_family(
                result['kind'], row['category'], row['field_path'])
            if family is None:
                row.update({
                    'status': 'constraint_modeled',
                    'constraint_count': 1,
                    'assumption_sha256': None,
                })
            else:
                row.update({
                    'status': 'source_assumption_covered',
                    'constraint_count': 0,
                    'assumption_sha256': readiness.digest(
                        readiness._family_preimage(family)),
                })
    return result


def _selected(candidate):
    value = producer_fixture.selection()
    value['classification'] = (
        'ACTUAL_HIDDEN_MAPPING_CANDIDATE' if candidate else
        'ACTUAL_TRANSPARENT_BASELINE')
    if not candidate:
        value['binding']['selection_sha256'] = 'a0' * 32
        value['binding']['trial_id'] = \
            'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        value['binding']['attempt_id'] = 'readiness-baseline-source'
        value['capture_identity'] = \
            'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
        for number, row in enumerate(value['financial_rounds'], 1):
            row['financial_run_id'] = ('%02x' % (160 + number)) * 32
        value['rounds'] = [
            {'round': 1,
             'attempt_id': 'cccccccc-cccc-4ccc-8ccc-ccccccccccc1',
             'cohort_sha256': 'b1' * 32},
            {'round': 2,
             'attempt_id': 'dddddddd-dddd-4ddd-8ddd-ddddddddddd2',
             'cohort_sha256': 'b2' * 32},
        ]
        for role in value['role_launch_closure']:
            role['launch_sha256'] = hashlib.sha256(
                b'readiness-baseline-role-launch\0'
                + str(role['round']).encode() + b'\0'
                + role['kind'].encode()).hexdigest()
    return value


def _repair_c1_incoming_tuple(value, public):
    """Bind the synthetic incoming receipt to its declared creator pair."""
    incoming = (1 - public['round']) % 3
    row = value['decrypted_receipts'][0]
    row['value']['tuple_sha256'] = public['tuple_sha256'][2 * incoming]
    row['value']['cm_hex32'] = public['cms_hex32'][2 * incoming]
    source = row['source']
    source['value_sha256'] = hashlib.sha256(
        codec.encoded(row['value'])).hexdigest()
    preimage = {
        'schema': 'kpb-c1-contact-value-event-binding/v1',
        'contact_value_authority_sha256':
            source['contact_value_authority_sha256'],
        'stage_config_sha256': source['stage_config_sha256'],
        'observer_stage': source['observer_stage'],
        'stage_sequence': source['stage_sequence'],
        'operation_id_sha256': source['operation_id_sha256'],
        'contact_owner_component': source['contact_owner_component'],
        'source_event_sequence': source['source_event_sequence'],
        'observed_monotonic_ns': source['observed_monotonic_ns'],
        'stream': 'decrypted-receipt',
        'value_kind': source['value_kind'],
        'value_sha256': source['value_sha256'],
    }
    source['source_event_binding_sha256'] = hashlib.sha256(
        b'KPB_C1_CONTACT_VALUE_EVENT_V1\n'
        + codec.encoded(preimage)).hexdigest()
    records = ([{'stream': 'original', **value['original']}]
        + [{'stream': 'invoice', **item} for item in value['invoices']]
        + [{'stream': 'decrypted-receipt', **item}
           for item in value['decrypted_receipts']])
    value['closure'] = model_fixture.closure(
        records,
        sum(len(codec.encoded(item['value'])) for item in records),
        cohort=value['cohort_sha256'],
        attempt=value['closure']['attempt_id'])
    return value


def _capture_models(candidate, binding):
    selected = _selected(candidate)
    projection_raws, publics = model_fixture.continuous_projection_pair()
    for financial, public in zip(selected['financial_rounds'], publics):
        financial['retained_projection_sha256'] = \
            public['projection_sha256']
    structural = capture_model.public_projection_pair(
        projection_raws, publics)
    role_closure = selected['role_launch_closure']
    role_sha = hashlib.sha256(codec.encoded(role_closure)).hexdigest()
    artifact_rounds = []
    raw_sizes = []
    c1_values = []
    for number in (1, 2):
        index = number - 1
        public = publics[index]
        round_row = selected['rounds'][index]
        projection_raw = projection_raws[index]
        p1_raw = model_fixture.c03_with_projection(
            producer_fixture.p1_channel(number, selected), projection_raw)
        with tempfile.TemporaryFile() as channel:
            channel.write(p1_raw)
            channel.seek(0)
            _, closure = capture_producer._consume_p1(
                channel.fileno(), selected, number)
        p1_authority = capture_producer._p1_capture_authority(
            selected, number, closure)

        terminal = model_fixture.terminal_fixture(public, transparent=False)
        terminal['cohort_sha256'] = round_row['cohort_sha256']
        terminal['closure']['attempt_id'] = round_row['attempt_id']
        terminal['closure']['cohort_sha256'] = round_row['cohort_sha256']
        dispatcher_factory = (
            model_fixture.dispatcher_fixture if candidate else
            model_fixture.explicit_dispatcher_fixture)
        dispatcher = dispatcher_factory(
            public, cohort_sha256=round_row['cohort_sha256'],
            run_sha256=selected['financial_rounds'][index][
                'financial_run_id'])
        dispatcher['closure']['attempt_id'] = round_row['attempt_id']
        dispatcher['closure']['cohort_sha256'] = \
            round_row['cohort_sha256']
        c1_value = model_fixture.qualified_colluder_fixture(
            public, cohort_sha256=round_row['cohort_sha256'],
            attempt_id=round_row['attempt_id'])
        _repair_c1_incoming_tuple(c1_value, public)
        c1_values.append(c1_value)

        terminal_raw = model_fixture.raw(terminal)
        dispatcher_raw = model_fixture.raw(dispatcher)
        artifact_rounds.append([
            structural[index],
            capture_model.terminal(terminal_raw, public),
            capture_model.dispatcher(
                dispatcher_raw, public,
                model_fixture.dispatcher_source_authority(dispatcher)),
            capture_model.corrupt_server_c03(
                p1_raw, public, projection_raw, p1_authority,
                role_closure, role_sha),
        ])
        raw_sizes.append({
            'public-projection': len(projection_raw),
            'terminal-history': len(terminal_raw),
            'dispatcher-capture': len(dispatcher_raw),
            'corrupt-server-capture': len(p1_raw),
            'colluder-wallet-capture': len(model_fixture.raw(c1_value)),
        })

    c1_models = capture_model.colluder_wallet_v2_pair(
        [model_fixture.raw(value) for value in c1_values], publics,
        [model_fixture.c1_contact_value_source_authority(
            value, role_closure=role_sha) for value in c1_values])
    rounds = []
    for number, (public, artifacts, c1_model) in enumerate(
            zip(publics, artifact_rounds, c1_models), 1):
        artifacts.append(c1_model)
        complete = [_complete_synthetic_artifact(row)
                    for row in artifacts]
        rounds.append({
            'round': number,
            'public': public,
            'typed_artifacts': complete,
            'derived': readiness._derive_synthetic_view(
                public, complete, {
                    family: readiness.digest(
                        readiness._family_preimage(family))
                    for family in readiness.SELECTED_ASSUMPTION_FAMILIES
                }),
        })
    return ({
        'schema': 'kpb-private-actual-capture-models/v1',
        'binding': binding,
        'rounds': rounds,
    }, projection_raws, raw_sizes, copy.deepcopy(role_closure), role_sha)


def _owner_truth(binding, projection_raws, publics):
    result = []
    for owner in codec.OWNERS:
        owner_rows = []
        for number, (projection_raw, public) in enumerate(
                zip(projection_raws, publics), 1):
            body = projection_raw[193:]
            rows = [body[692 + 520 * slot:692 + 520 * (slot + 1)]
                    for slot in (2 * owner, 2 * owner + 1)]
            owner_rows.append(codec.truth_record(
                binding, owner, number, public['context_sha256'],
                bytes.fromhex(public['nfs_hex32'][owner]), rows))
        result.append(owner_rows)
    return result


def _run(candidate):
    result_bundle = acceptance_fixture.bundle(candidate)
    classification = result_bundle['classification']
    binding = result_bundle['binding']
    (models_value, projection_raws, raw_sizes, role_closure,
     role_sha) = _capture_models(candidate, binding)
    models_by_view = {view: [] for view in acceptance.VIEWS}
    terminals = []
    for row in models_value['rounds']:
        terminals.append(next(
            artifact for artifact in row['typed_artifacts']
            if artifact['kind'] == 'terminal-history'))
        for view in acceptance.VIEWS:
            models_by_view[view].append(codec.assignments(
                row['public'], row['derived']['views'][view]['constraints']))
    workloads = {view: capture_model.workload_candidates(
        models_by_view[view], terminals) for view in acceptance.VIEWS}
    lattice = roles._candidate_lattice(models_by_view, workloads)

    run_context = {
        'classification': classification,
        'binding': binding,
        'capture_identity': result_bundle['capture_identity'],
        'method_sha256': result_bundle['method_sha256'],
        'workload_sha256': result_bundle['workload_sha256'],
        'observer_source_sha256':
            result_bundle['observer_source_sha256'],
        'capture_source_sha256': result_bundle['capture_source_sha256'],
        'coverage_policy_sha256':
            result_bundle['coverage_policy_sha256'],
        'capture_producer_receipt_sha256': '00' * 32,
        'capture_producer_role_launch_sha256': role_sha,
        'capture_producer_role_launch_closure': role_closure,
        'typed_artifact_manifest_sha256': readiness.digest(
            readiness._typed_artifact_manifest(
                classification, binding, result_bundle['capture_identity'],
                role_sha,
                {(row['round'], row['kind']): row for row in role_closure},
                models_value['rounds'])),
        'mascot_process_state':
            copy.deepcopy(readiness.MASCOT_PROCESS_STATE_MISSING),
        'source_closure_sha256': result_bundle['source_closure_sha256'],
        'runtime_identity_sha256':
            result_bundle['runtime_identity_sha256'],
    }
    producer_sha = readiness.digest(
        readiness._synthetic_producer_receipt_preimage(
            run_context, result_bundle['comparison_selection_sha256'],
            result_bundle['run_selection_sha256']))
    run_context['capture_producer_receipt_sha256'] = producer_sha
    result_bundle['capture_manifest_seal_sha256'] = \
        run_context['typed_artifact_manifest_sha256']
    result_bundle['capture_producer_receipt_sha256'] = producer_sha
    capture_views = []
    for view in acceptance.VIEWS:
        rounds = []
        for number, derived in enumerate(
                (row['derived'] for row in models_value['rounds']), 1):
            item = readiness._expected_capture_round(number, view, derived)
            item['artifact_bytes'] = sum(
                raw_sizes[number - 1][kind]
                for kind in readiness.VIEW_KINDS[view])
            rounds.append(item)
        capture_views.append({
            'view': view,
            'categories': list(acceptance.REQUIRED_CATEGORIES[view]),
            'rounds': rounds,
            'coverage': {
                'modeled_artifacts': sum(
                    row['modeled_artifacts'] for row in rounds),
                'unmodeled_artifacts': 0,
                'missing_artifacts': 0,
                'terminal_modeled': True,
            },
        })
    capture = {
        'schema': 'kpb-privacy-actual-capture-receipt/v2',
        'comparison_selection_sha256':
            result_bundle['comparison_selection_sha256'],
        'run_selection_sha256': result_bundle['run_selection_sha256'],
        'classification': classification,
        'binding': binding,
        'method_sha256': result_bundle['method_sha256'],
        'workload_sha256': result_bundle['workload_sha256'],
        'observer_source_sha256':
            result_bundle['observer_source_sha256'],
        'capture_source_sha256': result_bundle['capture_source_sha256'],
        'coverage_policy_sha256':
            result_bundle['coverage_policy_sha256'],
        'capture_identity': result_bundle['capture_identity'],
        'capture_manifest_seal_sha256':
            result_bundle['capture_manifest_seal_sha256'],
        'construction_classification_receipt_sha256':
            result_bundle['construction_classification_receipt_sha256'],
        'terminal_scope': acceptance.TERMINAL_SCOPE,
        'step3_terminal_gate': acceptance.STEP3_TERMINAL_GATE,
        'capture_producer_receipt_sha256':
            result_bundle['capture_producer_receipt_sha256'],
        'source_closure_sha256': result_bundle['source_closure_sha256'],
        'runtime_identity_sha256':
            result_bundle['runtime_identity_sha256'],
        'views': capture_views,
        'capture_roots_closed': True,
        'exact_union_derived': True,
        'predictions_or_truth_mounted': False,
        'private_artifact_paths_hashes_or_bodies_exported': False,
    }
    capture_sha = readiness.digest(capture)

    observations = []
    predictions = {}
    label = 'candidate' if candidate else 'baseline'
    for index, view in enumerate(acceptance.VIEWS):
        captured = capture_views[index]
        categories = {
            category: {
                name: sum(round_row['category_coverage'][category][name]
                          for round_row in captured['rounds'])
                for name in captured['rounds'][0][
                    'category_coverage'][category]
            }
            for category in captured['rounds'][0]['category_coverage']
        }
        predicted = codec.prediction(
            binding, view, models_by_view[view], captured['coverage'],
            category_coverage=categories, workload=workloads[view],
            lattice_attestation=lattice)
        capsule, seal = codec.seal(
            predicted, hashlib.sha256(
                ('readiness-' + label + '-' + view).encode()).digest())
        predictions[view] = predicted
        observations.append({
            'view': view,
            'capsule_seal_sha256': seal,
            'capsule_bytes': len(capsule),
            'rounds': [{
                name: (number if name == 'round' else model[name])
                for name in readiness.PRETRUTH_ROUND_FIELDS
            } for number, model in enumerate(models_by_view[view], 1)],
            'coverage': captured['coverage'],
            'category_coverage': categories,
            'workload': {name: workloads[view][name] for name in
                ('full_workload_candidates',
                 'cross_round_constraints_modeled',
                 'terminal_constraints_modeled',
                 'candidate_set_commitment_sha256')},
            'lattice_attestation': lattice,
        })
    observation = {
        'schema': 'kpb-direct-observation-receipt/v2',
        'binding': binding,
        'comparison_selection_sha256':
            result_bundle['comparison_selection_sha256'],
        'run_selection_sha256': result_bundle['run_selection_sha256'],
        'capture_receipt_sha256': capture_sha,
        'capture_manifest_seal_sha256':
            capture['capture_manifest_seal_sha256'],
        'construction_classification_receipt_sha256':
            capture['construction_classification_receipt_sha256'],
        'capture_producer_receipt_sha256':
            capture['capture_producer_receipt_sha256'],
        'source_closure_sha256': capture['source_closure_sha256'],
        'runtime_identity_sha256': capture['runtime_identity_sha256'],
        'terminal_scope': acceptance.TERMINAL_SCOPE,
        'step3_terminal_gate': acceptance.STEP3_TERMINAL_GATE,
        'views': observations,
        'predictions_frozen_before_truth': True,
        'private_view_or_prediction_records_exported': False,
    }
    observation_sha = readiness.digest(observation)
    barrier = {
        'schema': 'kpb-direct-prediction-barrier/v2',
        'binding': binding,
        'comparison_selection_sha256':
            result_bundle['comparison_selection_sha256'],
        'run_selection_sha256': result_bundle['run_selection_sha256'],
        'capture_receipt_sha256': capture_sha,
        'capture_manifest_seal_sha256':
            capture['capture_manifest_seal_sha256'],
        'construction_classification_receipt_sha256':
            capture['construction_classification_receipt_sha256'],
        'capture_producer_receipt_sha256':
            capture['capture_producer_receipt_sha256'],
        'source_closure_sha256': capture['source_closure_sha256'],
        'runtime_identity_sha256': capture['runtime_identity_sha256'],
        'terminal_scope': acceptance.TERMINAL_SCOPE,
        'step3_terminal_gate': acceptance.STEP3_TERMINAL_GATE,
        'observation_receipt_sha256': observation_sha,
        'capsules': [{
            'view': row['view'],
            'capsule_seal_sha256': row['capsule_seal_sha256'],
        } for row in observations],
    }
    barrier_sha = readiness.digest(barrier)

    truths = _owner_truth(
        binding, projection_raws,
        [row['public'] for row in models_value['rounds']])
    aggregate_views = []
    scoring_views = []
    for view, observed in zip(acceptance.VIEWS, observations):
        leaves = [codec.score_owner(
            predictions[view], truth, observed['capsule_seal_sha256'])
            for truth in truths]
        aggregate_views.append(codec.aggregate(
            predictions[view], leaves, observed['capsule_seal_sha256']))
        scoring_views.append({
            'view': view,
            'capsule_seal_sha256': observed['capsule_seal_sha256'],
            'owner_truth': copy.deepcopy(truths),
        })
    scoring = {
        'schema': 'kpb-observer-readiness-private-scoring/v1',
        'barrier_sha256': barrier_sha,
        'views': scoring_views,
    }
    score_receipts = [{
        'schema': 'kpb-private-score-completed/v2',
        'binding': binding,
        'comparison_selection_sha256':
            result_bundle['comparison_selection_sha256'],
        'run_selection_sha256': result_bundle['run_selection_sha256'],
        'barrier_sha256': barrier_sha,
        'owner_component': owner,
        'source_closure_sha256': result_bundle['source_closure_sha256'],
        'runtime_identity_sha256':
            result_bundle['runtime_identity_sha256'],
        'step3_terminal_gate': acceptance.STEP3_TERMINAL_GATE,
        'per_owner_counts_or_truth_exported': False,
    } for owner in codec.OWNERS]
    aggregate = {
        'schema': 'kpb-public-all-view-direct-counts/v2',
        'binding': binding,
        'comparison_selection_sha256':
            result_bundle['comparison_selection_sha256'],
        'run_selection_sha256': result_bundle['run_selection_sha256'],
        'capture_receipt_sha256': capture_sha,
        'barrier_sha256': barrier_sha,
        'capture_producer_receipt_sha256':
            result_bundle['capture_producer_receipt_sha256'],
        'source_closure_sha256': result_bundle['source_closure_sha256'],
        'runtime_identity_sha256':
            result_bundle['runtime_identity_sha256'],
        'step3_terminal_gate': acceptance.STEP3_TERMINAL_GATE,
        'lattice_attestation': lattice,
        'views': aggregate_views,
        'private_records_masks_or_per_owner_counts_exported': False,
    }
    result_bundle.update({
        'capture_receipt_sha256': capture_sha,
        'observation_receipt_sha256': observation_sha,
        'barrier_sha256': barrier_sha,
        'score_receipt_sha256': [readiness.digest(row)
                                 for row in score_receipts],
        'aggregate_result_sha256': readiness.digest(aggregate),
        'lattice_attestation': lattice,
        'views': aggregate_views,
    })
    return {
        'classification': classification,
        'run_context': run_context,
        'capture_models': models_value,
        'capture_receipt': capture,
        'observation_receipt': observation,
        'barrier': barrier,
        'scoring_transcript': scoring,
        'score_receipts': score_receipts,
        'aggregate_result': aggregate,
        'acceptance_bundle': result_bundle,
    }


def _input():
    baseline = _run(False)
    candidate = _run(True)
    unsigned = {
        'schema': readiness.INPUT_SCHEMA,
        'classification': readiness.CLASSIFICATION,
        'assumption_selection':
            readiness._test_only_assumption_selection_preimage(),
        'baseline': baseline,
        'candidate': candidate,
        'owner_comparison': acceptance_fixture.owner_comparison(
            baseline['acceptance_bundle'], candidate['acceptance_bundle']),
        'truth_mounted_before_barrier': False,
        'requested_actions': {
            'production_configured': False,
            'launch': False,
            'network': False,
            'funds': False,
            'mainnet': False,
        },
        'claimed_privacy_status': None,
    }
    return readiness.seal_preimage(unsigned)


def _reseal(value):
    value['preimage_sha256'] = readiness.digest({
        name: value[name] for name in readiness.OUTER_FIELDS[:-1]})
    return value


class ObserverReadinessControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = _input()

    def fresh(self):
        return copy.deepcopy(self.fixture)

    def test_complete_synthetic_chain_stops_without_mascot_process_receipt(self):
        value = self.fresh()
        self.assertTrue(any(
            row['status'] == 'source_assumption_covered'
            for artifact in value['candidate']['capture_models']['rounds'][0]
                ['typed_artifacts']
            for row in artifact['leakage_ledger']))
        self.assertGreater(
            value['candidate']['capture_receipt']['views'][0]['rounds'][0]
                ['category_coverage']['public-bytes']
                ['source_assumption_covered_fields'],
            0)
        result = readiness.evaluate(value)
        self.assertEqual(result['status'], readiness.STOP_MODEL_RECOMPUTATION)
        self.assertFalse(readiness.SOURCE_STATUS[
            'readiness_mechanics_implemented'])
        self.assertEqual(readiness.SOURCE_STATUS[
            'mascot_process_state_applicability'], 'MISSING')
        self.assertFalse(readiness.SOURCE_STATUS[
            'mascot_process_state_authority'])
        self.assertEqual(readiness.SOURCE_STATUS[
            'p1_actual_run_closure_applicability'], 'MISSING')
        self.assertFalse(readiness.SOURCE_STATUS[
            'p1_actual_run_closure_authority'])
        self.assertEqual(
            tuple(readiness.SOURCE_STATUS['p1_actual_run_missing_families']),
            readiness.P1_ACTUAL_RUN_MISSING_FAMILIES)
        self.assertEqual(len(readiness.P1_ACTUAL_RUN_MISSING_FAMILIES), 9)
        self.assertEqual(set(result), {
            'schema', 'status', 'classification', 'production_configured',
            'actual_capture_configured', 'launch_authorized',
            'network_enabled', 'funds_enabled', 'mainnet_enabled',
            'privacy_status_minted', 'privacy_pass_claim',
        })
        self.assertFalse(any(
            result[name] for name in result if name.endswith(
                ('configured', 'authorized', 'enabled', 'minted', 'claim'))))
        self.assertNotIn('PASS', codec.encoded(result).decode())

    def test_production_configured_zero_selection_is_not_readiness(self):
        value = self.fresh()
        value['assumption_selection'] = {
            'schema': 'kpb-private-observer-assumption-selection/v1',
            'configured': False,
            'selected_assumptions': [],
            'selection_authority': False,
        }
        self.assertEqual(readiness.evaluate(_reseal(value))['status'],
                         readiness.STOP_ASSUMPTION_SELECTION)

    def test_every_high_risk_family_disposition_is_exact(self):
        families = ('S4', 'S6', 'S6A', 'S8', 'S9', 'S10', 'S11',
                    'S12', 'S13')
        for family in families:
            with self.subTest(family=family):
                value = self.fresh()
                row = next(item for item in value['assumption_selection'][
                    'selected_assumptions'] if item['family'] == family)
                row['disposition'] = 'UNSELECTED'
                self.assertEqual(
                    readiness.evaluate(_reseal(value))['status'],
                    readiness.STOP_ASSUMPTION_SELECTION)

    def test_s13_is_open_nonselectable_and_never_premise_coverage(self):
        selection = self.fresh()['assumption_selection']
        row = next(item for item in selection['selected_assumptions']
                   if item['family'] == 'S13')
        self.assertEqual(
            row['disposition'],
            'NONSELECTABLE_REDUCTION_TARGET_OPEN_UNRESOLVED')
        premise_hashes = readiness._validate_assumptions(selection)
        self.assertNotIn('S13', premise_hashes)
        self.assertNotIn('S6', premise_hashes)
        self.assertIn('S6A', premise_hashes)

    def test_json_bool_integer_aliases_do_not_satisfy_exact_schemas(self):
        value = self.fresh()
        selection = value['assumption_selection']
        s8 = next(row for row in selection['selected_assumptions']
                  if row['family'] == 'S8')
        s8['preimage']['mascot_branch_requirements'][
            'cache_hit_or_static_reuse'][
                'get_fresh_preserves_scalar'] = 1
        with self.assertRaises(readiness._Stop):
            readiness._validate_assumptions(selection)

        candidate = self.fresh()['candidate']
        candidate['run_context']['mascot_process_state'][
            'source_receipt_present'] = 0
        with self.assertRaises(readiness._Stop):
            readiness._run_context(candidate)

        candidate = self.fresh()['candidate']
        private_round = candidate['capture_models']['rounds'][0]
        p1 = next(row for row in private_round['typed_artifacts']
                  if row['kind'] == 'corrupt-server-capture')
        p1['inventory']['mac_key_share_count'] = True
        with self.assertRaises(readiness._Stop):
            readiness._validate_artifact_round(
                private_round, readiness._run_context(candidate))

    def test_altered_family_preimage_is_rejected_even_when_outer_resealed(self):
        value = self.fresh()
        row = value['assumption_selection']['selected_assumptions'][3]
        row['preimage']['profile'] = 'ALTERED'
        row['preimage_sha256'] = readiness.digest(row['preimage'])
        self.assertEqual(readiness.evaluate(_reseal(value))['status'],
                         readiness.STOP_ASSUMPTION_SELECTION)

    def test_altered_outer_preimage_is_rejected(self):
        value = self.fresh()
        value['candidate']['capture_receipt'][
            'capture_manifest_seal_sha256'] = 'ff' * 32
        self.assertEqual(readiness.evaluate(value)['status'],
                         readiness.STOP_SYNTHETIC_SEAL)

    def test_truth_before_barrier_is_rejected(self):
        value = self.fresh()
        value['truth_mounted_before_barrier'] = True
        self.assertEqual(readiness.evaluate(_reseal(value))['status'],
                         readiness.STOP_TRUTH_BEFORE_BARRIER)

    def test_missing_category_is_rejected(self):
        value = self.fresh()
        row = value['candidate']['capture_receipt']['views'][0]['rounds'][0]
        del row['category_coverage']['amounts']
        del row['category_counts']['amounts']
        self.assertEqual(readiness.evaluate(_reseal(value))['status'],
                         readiness.STOP_MISSING_OR_UNMODELED)

    def test_any_step2_unmodeled_field_is_rejected(self):
        value = self.fresh()
        private_round = value['candidate']['capture_models']['rounds'][0]
        artifact = next(row for row in private_round['typed_artifacts']
                        if row['kind'] == 'public-projection')
        leakage = artifact['leakage_ledger'][0]
        leakage.update({
            'status': 'unmodeled',
            'constraint_count': 0,
            'assumption_sha256': None,
        })
        private_round['derived'] = readiness._derive_synthetic_view(
            private_round['public'], private_round['typed_artifacts'], {
                family: readiness.digest(
                    readiness._family_preimage(family))
                for family in readiness.SELECTED_ASSUMPTION_FAMILIES
            })
        self.assertEqual(readiness.evaluate(_reseal(value))['status'],
                         readiness.STOP_STEP2_OPEN)

    def test_incomplete_terminal_is_rejected(self):
        value = self.fresh()
        view = value['candidate']['capture_receipt']['views'][0]
        view['rounds'][1]['terminal_modeled'] = False
        view['coverage']['terminal_modeled'] = False
        self.assertEqual(readiness.evaluate(_reseal(value))['status'],
                         readiness.STOP_MISSING_OR_UNMODELED)

    def test_union_lattice_violation_is_rejected_before_scorer(self):
        value = self.fresh()
        union = value['candidate']['aggregate_result']['views'][-1]
        union['rounds'][0]['joint_candidates'] = 541
        self.assertEqual(readiness.evaluate(_reseal(value))['status'],
                         readiness.STOP_LATTICE)

    def test_copied_p1_or_c1_provenance_is_rejected(self):
        kinds = ('corrupt-server-capture', 'colluder-wallet-capture')
        for kind in kinds:
            with self.subTest(kind=kind):
                value = self.fresh()
                baseline = next(row for row in value['baseline'][
                    'capture_models']['rounds'][0]['typed_artifacts']
                    if row['kind'] == kind)
                candidate_rows = value['candidate']['capture_models'][
                    'rounds'][0]['typed_artifacts']
                candidate = next(row for row in candidate_rows
                                 if row['kind'] == kind)
                candidate['artifact_sha256'] = baseline['artifact_sha256']
                private_round = value['candidate']['capture_models'][
                    'rounds'][0]
                private_round['derived'] = \
                    readiness._derive_synthetic_view(
                        private_round['public'], candidate_rows, {
                            family: readiness.digest(
                                readiness._family_preimage(family))
                            for family in readiness.SELECTED_ASSUMPTION_FAMILIES
                        })
                self.assertEqual(
                    readiness.evaluate(_reseal(value))['status'],
                    readiness.STOP_MODEL_RECOMPUTATION)

    def test_public_inventory_content_cannot_be_resealed_away(self):
        value = self.fresh()
        private_round = value['candidate']['capture_models']['rounds'][0]
        public = next(row for row in private_round['typed_artifacts']
                      if row['kind'] == 'public-projection')
        public['inventory']['projection_bytes'] = 1
        private_round['derived'] = readiness._derive_synthetic_view(
            private_round['public'], private_round['typed_artifacts'], {
                family: readiness.digest(
                    readiness._family_preimage(family))
                for family in readiness.SELECTED_ASSUMPTION_FAMILIES
            })
        self.assertEqual(readiness.evaluate(_reseal(value))['status'],
                         readiness.STOP_MODEL_RECOMPUTATION)

    def test_stale_p1_launch_cannot_hide_behind_fresh_artifact_hash(self):
        value = self.fresh()
        baseline = next(row for row in value['baseline']['capture_models']
            ['rounds'][0]['typed_artifacts']
            if row['kind'] == 'corrupt-server-capture')
        private_round = value['candidate']['capture_models']['rounds'][0]
        candidate_rows = private_round['typed_artifacts']
        index = next(index for index, row in enumerate(candidate_rows)
                     if row['kind'] == 'corrupt-server-capture')
        candidate_original = candidate_rows[index]
        copied = copy.deepcopy(baseline)
        copied['artifact_sha256'] = 'fe' * 32
        copied['inventory']['attempt_id'] = \
            candidate_original['inventory']['attempt_id']
        copied['inventory']['cohort_sha256'] = \
            candidate_original['inventory']['cohort_sha256']
        candidate_rows[index] = copied
        private_round['derived'] = readiness._derive_synthetic_view(
            private_round['public'], candidate_rows, {
                family: readiness.digest(
                    readiness._family_preimage(family))
                for family in readiness.SELECTED_ASSUMPTION_FAMILIES
            })
        self.assertNotEqual(
            copied['inventory']['c03_launch_sha256'],
            candidate_original['inventory']['c03_launch_sha256'])
        self.assertEqual(readiness.evaluate(_reseal(value))['status'],
                         readiness.STOP_MODEL_RECOMPUTATION)

    def test_caller_mascot_cache_hit_and_unequal_alpha_are_rejected(self):
        value = self.fresh()
        for number, private_round in enumerate(
                value['candidate']['capture_models']['rounds'], 1):
            p1 = next(row for row in private_round['typed_artifacts']
                      if row['kind'] == 'corrupt-server-capture')
            p1['inventory']['mac_key_share_count'] = number - 1
            p1['inventory']['mascot_cache_branch'] = 'CacheHit'
            p1['inventory']['mac_key_share_sha256'] = \
                ('11' if number == 1 else '22') * 32
            private_round['derived'] = readiness._derive_synthetic_view(
                private_round['public'], private_round['typed_artifacts'], {
                    family: readiness.digest(
                        readiness._family_preimage(family))
                    for family in readiness.SELECTED_ASSUMPTION_FAMILIES
                })
        self.assertEqual(readiness.evaluate(_reseal(value))['status'],
                         readiness.STOP_MODEL_RECOMPUTATION)

    def test_nonterminal_cross_round_payload_is_rejected_at_typed_seam(self):
        value = self.fresh()
        candidate = value['candidate']
        private_round = candidate['capture_models']['rounds'][0]
        public = next(row for row in private_round['typed_artifacts']
                      if row['kind'] == 'public-projection')
        public['cross_round_links'] = [{'owner_truth': 'smuggled'}]
        with self.assertRaises(readiness._Stop) as stopped:
            readiness._validate_artifact_round(
                private_round, readiness._run_context(candidate))
        self.assertEqual(stopped.exception.status,
                         readiness.STOP_MODEL_RECOMPUTATION)

    def test_any_pass_claim_is_rejected(self):
        value = self.fresh()
        value['claimed_privacy_status'] = \
            'PASS_BOUNDED_SYNTHETIC_MODEL_CHECK'
        self.assertEqual(readiness.evaluate(_reseal(value))['status'],
                         readiness.STOP_PASS_CLAIM)

    def test_action_request_is_rejected(self):
        for name in readiness.REQUEST_FIELDS:
            with self.subTest(name=name):
                value = self.fresh()
                value['requested_actions'][name] = True
                self.assertEqual(readiness.evaluate(_reseal(value))['status'],
                                 readiness.STOP_ACTION_REQUEST)

    def test_cli_is_canonical_and_emits_only_one_fixed_stop_token(self):
        with self.assertRaises(ValueError):
            readiness.parse(b'{"a":1,"a":2}\n')
        with self.assertRaises(ValueError):
            readiness.parse(b'{ "a":1 }\n')
        with tempfile.NamedTemporaryFile() as value:
            value.write(codec.encoded({}))
            value.flush()
            cases = (
                [], ['--help'], ['--unknown'], ['/dev/null', 'extra'],
                [value.name],
            )
            for argv in cases:
                with self.subTest(argv=argv):
                    output = io.StringIO()
                    errors = io.StringIO()
                    with contextlib.redirect_stdout(output), \
                            contextlib.redirect_stderr(errors):
                        code = readiness.main(argv)
                    self.assertEqual(code, 2)
                    self.assertEqual(
                        output.getvalue(), readiness.STOP_INPUT_SHAPE + '\n')
                    self.assertEqual(errors.getvalue(), '')


if __name__ == '__main__':
    unittest.main()

