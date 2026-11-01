"""Public synthetic controls only. No Original, actual truth or MPC views."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

import privacy_codec as codec
import privacy_observer as observer
import privacy_owner

BOUND = {'method_sha256': hashlib.sha256(b'PUBLIC MODEL METHOD').hexdigest(),
    'selection_sha256': hashlib.sha256(b'PUBLIC MODEL SELECTION').hexdigest(),
    'trial_id': '0d8205ba-82ef-452c-a762-9ad3f17cb91c', 'phase': 'private-batch-privacy', 'attempt_id': 'public-control-01'}
TRUTH_INPUTS = ([2, 1, 0], [1, 0, 2])
TRUTH_CREATORS = ([2, 0, 1, 2, 1, 0], [1, 2, 0, 1, 0, 2])


def digest(value):
    return hashlib.sha256(value).hexdigest()


def row(round_number, position):
    tag = bytes([round_number, position])
    ciphertext = bytes([position + 1]) * 264
    return (hashlib.sha256(b'PUBLIC MODEL CM ' + tag).digest()
            + hashlib.sha512(b'PUBLIC MODEL CV ' + tag).digest()
            + ciphertext + hashlib.sha256(ciphertext).digest()
            + hashlib.sha512(b'PUBLIC MODEL PROOF ' + tag).digest() * 2)


def public(round_number):
    rows = [row(round_number, i) for i in range(6)]
    nfs = [digest(b'PUBLIC MODEL NF ' + bytes([round_number, i]))
           for i in range(3)]
    nfs.sort(key=lambda value: int.from_bytes(bytes.fromhex(value), 'little'))
    return {'round': round_number, 'projection_sha256': digest(b'PUBLIC MODEL PROJECTION ' + bytes([round_number])),
        'context_sha256': digest(b'PUBLIC MODEL CONTEXT ' + bytes([round_number])),
        'nfs_hex32': nfs,
        'cms_hex32': [item[:32].hex() for item in rows], 'tuple_sha256': [digest(item) for item in rows]}


def colluder_constraints(round_number, incoming=True):
    p = public(round_number); out = codec.empty_constraints()
    index = TRUTH_INPUTS[round_number - 1].index(1)
    out['input_edges'] = [{'owner_component': 1, 'slot_id': p['nfs_hex32'][index], 'provenance': 'colluder-knowledge'}]
    for i, creator in enumerate(TRUTH_CREATORS[round_number - 1]):
        if creator == 1:
            out['creator_edges'].append({'owner_component': 1, 'slot_id': p['tuple_sha256'][i], 'provenance': 'colluder-knowledge'})
    if incoming:
        sender = 0 if round_number == 1 else 2
        received = TRUTH_CREATORS[round_number - 1].index(sender)
        out['creator_edges'].append({'owner_component': sender, 'slot_id': p['tuple_sha256'][received], 'provenance': 'colluder-knowledge'})
    return out


def truths(component):
    return [codec.truth_record(BOUND, component, r, public(r)['context_sha256'],
        bytes.fromhex(public(r)['nfs_hex32'][TRUTH_INPUTS[r - 1].index(component)]),
        [row(r, i) for i, creator in enumerate(TRUTH_CREATORS[r - 1]) if creator == component]) for r in (1, 2)]


def predicted(view='union', incoming=True, unmodeled=0, terminal=False):
    models = [codec.assignments(public(r), colluder_constraints(r, incoming)) for r in (1, 2)]
    return codec.prediction(BOUND, view, models, {'modeled_artifacts': 2, 'unmodeled_artifacts': unmodeled,
        'missing_artifacts': 0, 'terminal_modeled': terminal})


def predicted_v2(view='union', incoming=True):
    models = [codec.assignments(public(r), colluder_constraints(r, incoming))
              for r in (1, 2)]
    joint = [[left, right] for left in range(len(models[0]['joint']))
             for right in range(len(models[1]['joint']))]
    workload = {
        'schema': 'kpb-two-round-candidate-join/v1',
        'round_candidate_counts': [len(model['joint']) for model in models],
        'cross_round_link_count': 0,
        'cross_round_constraints_modeled': True,
        'terminal_constraints_modeled': True,
        'joint': joint,
        'workload_joint_candidates': len(joint),
        'full_workload_candidates': len(joint),
        'round_candidate_set_commitment_sha256': digest(b'rounds'),
        'candidate_set_commitment_sha256': digest(b'workload'),
        'honest_vector_swap_structural_candidates': len(joint),
        'truth_scored': False,
    }
    return codec.prediction(
        BOUND, view, models,
        {'modeled_artifacts': 4, 'unmodeled_artifacts': 0,
         'missing_artifacts': 0, 'terminal_modeled': True},
        category_coverage={
            'amounts': {'modeled_artifacts': 2,
                        'unmodeled_artifacts': 0,
                        'missing_artifacts': 0,
                        'constraint_modeled_fields': 1,
                        'source_assumption_covered_fields': 0,
                        'unmodeled_fields': 0}},
        workload=workload,
        lattice_attestation={
            'exact_union_artifact_set': True,
            'exact_union_constraints': True,
            'candidate_subset_lattice_verified': True,
            'full_workload_subset_lattice_verified': True,
        })


def result(value):
    raw, seal = codec.seal(value, bytes([19]) * 32)
    checked = codec.unseal(raw, seal)
    leaves = [codec.score_owner(checked, truths(i), seal) for i in range(3)]
    return codec.aggregate(checked, leaves, seal)


class CandidateControls(unittest.TestCase):
    def test_exact_unconstrained_and_colluder_counts(self):
        base = codec.assignments(public(1), codec.empty_constraints())
        self.assertEqual((base['input_owner_assignments'], base['output_creator_assignments'],
                          base['output_pair_partitions'], base['joint_candidates']), (6, 90, 15, 540))
        own = codec.assignments(public(1), colluder_constraints(1, incoming=False))
        self.assertEqual((own['input_owner_assignments'], own['output_creator_assignments'],
                          own['output_pair_partitions'], own['joint_candidates']), (2, 6, 3, 12))

    def test_known_incoming_edge_still_allows_unknown_graph_alternative(self):
        actual = result(predicted())
        for measured in actual['rounds']:
            self.assertEqual((measured['input_owner_assignments'], measured['output_creator_assignments'],
                              measured['output_pair_partitions'], measured['joint_candidates']), (2, 3, 3, 6))
            self.assertTrue(measured['truth_retained'])
            self.assertTrue(measured['honest_input_swap_retained'])
            self.assertTrue(measured['honest_graph_alternative_retained'])
            self.assertEqual(measured['strict_H1_status'],
                             'PASS_BOUNDED_DIRECT_CHECK')
            self.assertEqual(measured['correct_unique_inputs'], 0)
            self.assertEqual(measured['correct_unique_outputs'], 0)
            self.assertEqual(measured['nf_to_created_pair_relations'], 6)
            self.assertEqual(measured['nf_pair_candidate_count_histogram'], {'1': 1, '6': 2})
            self.assertEqual(measured['correct_unique_pair_links'], 0)
        self.assertEqual(actual['combined_terminal_status'], 'UNQUALIFIED')

    def test_v2_workload_retains_consistent_unknown_graph_alternative(self):
        predicted_value = predicted_v2()
        raw, seal = codec.seal(predicted_value, bytes([19]) * 32)
        checked = codec.unseal(raw, seal)
        leaves = [codec.score_owner(checked, truths(i), seal)
                  for i in range(3)]
        measured = codec.aggregate(checked, leaves, seal)
        self.assertEqual(measured['schema'],
                         'kpb-public-direct-linkage-counts/v2')
        self.assertTrue(measured['workload']['truth_vector_retained'])
        self.assertTrue(
            measured['workload']['honest_graph_alternative_retained'])
        self.assertGreater(measured['workload']['full_workload_candidates'], 1)
        self.assertEqual(measured['workload']['correct_unique_full_vectors'], 0)
        self.assertTrue(all(row['honest_nf_pair_candidate_floor_met']
                            for row in measured['rounds']))
        self.assertEqual(measured['combined_terminal_status'],
                         'PASS_BOUNDED_DIRECT_CHECK')

    def test_terminal_join_cannot_hide_a_unique_honest_output_in_many_vectors(self):
        """Full-vector ambiguity must not mask a unique eligible graph edge."""
        models = [codec.assignments(
            public(round_number), colluder_constraints(round_number, True))
            for round_number in (1, 2)]
        # Both links are true in the frozen workload.  They leave twelve full
        # vectors, including truth and the required common honest graph
        # alternative, but every surviving vector assigns round-2 output slot
        # 4 to owner 0.  That output is not part of the colluder-known set.
        links = ((0, 0, 1, 5), (0, 2, 1, 2))
        joint = []
        for left in range(len(models[0]['joint'])):
            for right in range(len(models[1]['joint'])):
                candidates = (models[0]['joint'][left],
                              models[1]['joint'][right])
                if all(candidates[input_round]['inputs'][input_slot]
                       == candidates[output_round]['outputs'][output_slot]
                       for input_round, input_slot, output_round, output_slot
                       in links):
                    joint.append([left, right])
        self.assertEqual(len(joint), 12)
        workload = {
            'schema': 'kpb-two-round-candidate-join/v1',
            'round_candidate_counts': [len(model['joint'])
                                       for model in models],
            'cross_round_link_count': len(links),
            'cross_round_constraints_modeled': True,
            'terminal_constraints_modeled': True,
            'joint': joint,
            'workload_joint_candidates': len(joint),
            'full_workload_candidates': len(joint),
            'round_candidate_set_commitment_sha256': digest(b'linked-rounds'),
            'candidate_set_commitment_sha256': digest(b'linked-workload'),
            'honest_vector_swap_structural_candidates': len(joint),
            'truth_scored': False,
        }
        predicted_value = codec.prediction(
            BOUND, 'union', models,
            {'modeled_artifacts': 4, 'unmodeled_artifacts': 0,
             'missing_artifacts': 0, 'terminal_modeled': True},
            category_coverage={
                'amounts': {'modeled_artifacts': 2,
                            'unmodeled_artifacts': 0,
                            'missing_artifacts': 0,
                            'constraint_modeled_fields': 1,
                            'source_assumption_covered_fields': 0,
                            'unmodeled_fields': 0}},
            workload=workload,
            lattice_attestation={
                'exact_union_artifact_set': True,
                'exact_union_constraints': True,
                'candidate_subset_lattice_verified': True,
                'full_workload_subset_lattice_verified': True,
            })
        measured = result(predicted_value)
        self.assertTrue(measured['workload']['truth_vector_retained'])
        self.assertTrue(
            measured['workload']['honest_graph_alternative_retained'])
        self.assertEqual(measured['workload']['full_workload_candidates'], 12)
        self.assertEqual(measured['workload']['correct_unique_outputs'], 1)
        self.assertFalse(measured['workload'][
            'honest_nf_pair_candidate_floor_met'])
        self.assertEqual(measured['combined_terminal_status'], 'FAIL')

    def test_real_literal_pair_tag_control_detected_before_truth(self):
        models = []
        for r in (1, 2):
            p = public(r)
            export = {'schema': 'kpb-direct-export-model-control/v1', 'scope': 'SYNTHETIC_OBSERVER_CONTROL',
                'exports': [{'tuple_sha256': p['tuple_sha256'][i], 'pair_tag_hex32': digest(b'public pair ' + bytes([creator]))}
                            for i, creator in enumerate(TRUTH_CREATORS[r - 1])]}
            leak, complete = observer.extract_json(codec.encoded(export), p)
            self.assertTrue(complete)
            models.append(codec.assignments(p, observer.merge(colluder_constraints(r), leak)))
        value = codec.prediction(BOUND, 'union', models, {'modeled_artifacts': 4, 'unmodeled_artifacts': 0,
            'missing_artifacts': 0, 'terminal_modeled': False})
        measured = result(value)
        self.assertEqual([item['output_pair_partitions'] for item in measured['rounds']], [1, 1])
        self.assertEqual([item['output_creator_assignments'] for item in measured['rounds']], [1, 1])
        self.assertTrue(all(item['forbidden_exports'] >= 3 for item in measured['rounds']))

    def test_constructor_map_and_individual_delta_controls(self):
        for r in (1, 2):
            p = public(r)
            exported = {'schema': 'kpb-direct-export-model-control/v1', 'scope': 'SYNTHETIC_OBSERVER_CONTROL',
                'exports': ([{'owner_component': creator, 'tuple_sha256': p['tuple_sha256'][i]}
                             for i, creator in enumerate(TRUTH_CREATORS[r - 1])]
                    + [{'owner_component': component, 'nf_hex32': p['nfs_hex32'][i]}
                       for i, component in enumerate(TRUTH_INPUTS[r - 1])]
                    + [{'owner_component': 0, 'private_delta_hex32': '01' * 32}])}
            extracted, complete = observer.extract_json(codec.encoded(exported), p)
            model = codec.assignments(p, observer.merge(colluder_constraints(r), extracted))
            self.assertTrue(complete); self.assertEqual(model['joint_candidates'], 1)
            self.assertEqual(extracted['individual_delta_exports'], 1)
            self.assertGreaterEqual(model['forbidden_exports'], 10)

    def test_terminal_nf_to_pair_link_is_not_lost_without_owner_label(self):
        p = public(1)
        # This is a payment-graph disclosure even though the terminal record
        # never names an owner.  Pair-only constraints cannot express it.
        owner = TRUTH_INPUTS[0][0]
        pair = [p['tuple_sha256'][i]
                for i, creator in enumerate(TRUTH_CREATORS[0])
                if creator == owner]
        terminal = {'schema': 'kpb-direct-export-model-control/v1',
            'scope': 'SYNTHETIC_OBSERVER_CONTROL', 'exports': [{
                'nf_created_pair': {'nf_hex32': p['nfs_hex32'][0],
                                    'tuple_sha256': pair}}]}
        extracted, complete = observer.extract_json(codec.encoded(terminal), p)
        self.assertTrue(complete)
        self.assertEqual(extracted['nf_pair_edges'], [{
            'nf_hex32': p['nfs_hex32'][0], 'tuple_sha256': pair,
            'provenance': 'direct-export'}])
        model = codec.assignments(p, extracted)
        self.assertEqual(model['nf_to_created_pair_relations'], 6)
        self.assertLess(model['nf_to_created_pair_relations'],
                        codec.assignments(p, codec.empty_constraints())[
                            'nf_to_created_pair_relations'])
        self.assertEqual(model['forbidden_exports'], 1)
        self.assertTrue(all(
            candidate['inputs'][0]
            == candidate['outputs'][p['tuple_sha256'].index(pair[0])]
            == candidate['outputs'][p['tuple_sha256'].index(pair[1])]
            for candidate in model['joint']))

    def test_malformed_nf_pair_edge_refuses_instead_of_being_ignored(self):
        p = public(1); constraints = codec.empty_constraints()
        constraints['nf_pair_edges'] = [{
            'nf_hex32': p['nfs_hex32'][0],
            'tuple_sha256': [p['tuple_sha256'][0], p['tuple_sha256'][0]],
            'provenance': 'terminal-grouping'}]
        with self.assertRaises(ValueError):
            codec.assignments(p, constraints)

    def test_wrong_unique_predictions_separate_from_correct(self):
        models = []
        for r in (1, 2):
            p = public(r); edges = codec.empty_constraints()
            edges['input_edges'] = [{'owner_component': 2 - component if component != 1 else 1,
                'slot_id': p['nfs_hex32'][i], 'provenance': 'direct-export'} for i, component in enumerate(TRUTH_INPUTS[r - 1])]
            edges['creator_edges'] = [{'owner_component': 2 - creator if creator != 1 else 1,
                'slot_id': p['tuple_sha256'][i], 'provenance': 'direct-export'} for i, creator in enumerate(TRUTH_CREATORS[r - 1])]
            models.append(codec.assignments(p, edges))
        value = codec.prediction(BOUND, 'dispatcher', models, {'modeled_artifacts': 2, 'unmodeled_artifacts': 0,
            'missing_artifacts': 0, 'terminal_modeled': False})
        measured = result(value)
        for item in measured['rounds']:
            self.assertFalse(item['truth_retained']); self.assertEqual(item['wrong_unique_inputs'], 2)
            self.assertEqual(item['wrong_unique_outputs'], 4)

    def test_unmodeled_corrupt_view_cannot_become_a_pass(self):
        value = predicted(incoming=False, unmodeled=1)
        measured = result(value)
        self.assertTrue(all(item['truth_retained']
                            and item['honest_graph_alternative_retained']
                            for item in measured['rounds']))
        self.assertTrue(all(item['strict_H1_status'] == 'UNQUALIFIED' for item in measured['rounds']))

    def test_legitimate_private_colluder_material_is_not_a_false_honest_export(self):
        p = public(1); known = colluder_constraints(1)
        own_nf = next(edge['slot_id'] for edge in known['input_edges'] if edge['owner_component'] == 1)
        raw = codec.encoded({'owner_component': 1, 'nf_hex32': own_nf, 'private_delta_hex32': '01' * 32})
        model, coverage = observer.collect(p, [('corrupt-server-raw', raw, None)], known)
        self.assertEqual(model['forbidden_exports'], 0)
        self.assertEqual(coverage['unmodeled_artifacts'], 1)

    def test_candidate_tampering_wrong_context_and_duplicate_keys_refuse(self):
        value = predicted(); raw, seal = codec.seal(value, bytes([19]) * 32)
        changed = copy.deepcopy(value); changed['models'][0]['joint'].pop()
        changed_raw, changed_seal = codec.seal(changed, bytes([18]) * 32)
        with self.assertRaises(ValueError): codec.unseal(changed_raw, changed_seal)
        with self.assertRaises(ValueError): codec.unseal(raw, '00' * 32)
        with self.assertRaises(ValueError): codec.parse(b'{"a":0,"a":1}')
        wrong = truths(0); wrong[0]['context_sha256'] = '00' * 32
        with self.assertRaises(ValueError): codec.score_owner(value, wrong, seal)

    def test_private_mask_intersection_not_independent_nonempty_flags(self):
        value = predicted(incoming=False)
        _, seal = codec.seal(value, bytes([19]) * 32)
        leaves = [codec.score_owner(value, truths(i), seal) for i in range(3)]
        for component, leaf in enumerate(leaves):
            for part in leaf['rounds']:
                part['joint_masks'][0] = 1 << component
        measured = codec.aggregate(value, leaves, seal)
        self.assertTrue(all(not item['truth_retained'] for item in measured['rounds']))

    def test_salted_truth_commitment_checks_all_original_bindings(self):
        truth = truths(0)[0]; salt = bytes([7]) * 32
        public_commit = {'schema': 'kpb-owner-truth-commitment/v1', 'binding': BOUND, 'owner_component': 0, 'round': 1,
            'salted_commitment_sha256': digest(privacy_owner.TRUTH_TAG + salt + codec.encoded(truth)), 'truth_or_identifiers_exported': False}
        packed = codec.encoded({'schema': 'kpb-salted-owner-truth/v1', 'salt_hex32': salt.hex(), 'truth': truth})
        self.assertEqual(privacy_owner.open_truth(packed, public_commit, BOUND, 0, 1), truth)
        with self.assertRaises(ValueError): privacy_owner.open_truth(packed, public_commit, BOUND, 2, 1)
        wrong = copy.deepcopy(public_commit); wrong['salted_commitment_sha256'] = '00' * 32
        with self.assertRaises(ValueError): privacy_owner.open_truth(packed, wrong, BOUND, 0, 1)

    def test_actual_route_metadata_is_required_and_fixed(self):
        value = {'schema': 'kpb-observed-invoice-route/v1', 'round': 1, 'source_owner_component': 0,
            'target_owner_component': 1, 'invoice_leaf_path': '/PRIVATE_FIXTURE/owner-1/INVOICE208.bin',
            'source_operation_id': 'public-pay-model', 'target_invoice_operation_id': 'public-invoice-model',
            'launch_monotonic_ns': 100, 'complete_monotonic_ns': 200, 'worker_returncode': 0}
        self.assertEqual(observer.route_record(value), value)
        self.assertEqual(observer.route_record({**value, 'worker_returncode': 2})['worker_returncode'], 2)
        with self.assertRaises(ValueError): observer.route_record({**value, 'owner_secret': 'forbidden'})


class NamespaceControls(unittest.TestCase):
    def test_one_owner_scorer_uses_private_leafs_and_refuses_repeat(self):
        source = Path(__file__).absolute().parent
        with tempfile.TemporaryDirectory(prefix='kpb-public-diagnostic-control-') as directory:
            base = Path(directory); inputs = base / 'inputs'; inputs.mkdir()
            state = base / 'state'; state.mkdir(); out = base / 'out'; out.mkdir()
            def save(name, value, mode=0o400):
                path = inputs / name; raw = value if type(value) is bytes else codec.encoded(value)
                path.write_bytes(raw); path.chmod(mode)
                return path, digest(raw)
            sources = []
            mounts = []
            guarded_read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
            for name in ('privacy_codec.py', 'privacy_capture_model.py',
                         'privacy_observer.py', 'privacy_owner.py',
                         'privacy_roles.py', 'privacy_source_closure.py'):
                path = source / name; alias = '/software/' + name
                sources.append({'path': alias, 'sha256': digest(guarded_read(path))})
                mounts += ['--ro-bind', str(path), alias]
            receipts, capsules = [], []
            for view in codec.VIEWS:
                value = predicted(view=view); raw, seal = codec.seal(value, bytes([19]) * 32)
                path, _ = save(view + '.bin', raw)
                mounts += ['--ro-bind', str(path), '/capsules/' + view + '.bin']
                receipts.append({'view': view, 'capsule_seal_sha256': seal, 'capsule_bytes': len(raw), 'rounds': [], 'coverage': value['coverage']})
                capsules.append({'view': view, 'path': '/capsules/' + view + '.bin'})
            observation, obs_sha = save('observation.json', {'schema': 'kpb-direct-observation-receipt/v1', 'binding': BOUND,
                'views': receipts, 'predictions_frozen_before_truth': True, 'private_view_or_prediction_records_exported': False})
            barrier, bar_sha = save('barrier.json', {'schema': 'kpb-direct-prediction-barrier/v1', 'binding': BOUND,
                'observation_receipt_sha256': obs_sha, 'capsules': [{'view': row['view'], 'capsule_seal_sha256': row['capsule_seal_sha256']} for row in receipts]})
            mounts += ['--ro-bind', str(observation), '/observation.json', '--ro-bind', str(barrier), '/barrier.json']
            commitments = []
            for r, truth in enumerate(truths(0), 1):
                salt = bytes([r + 3]) * 32
                packed, _ = save('truth-' + str(r) + '.json', {'schema': 'kpb-salted-owner-truth/v1', 'salt_hex32': salt.hex(), 'truth': truth}, 0o600)
                commit, commit_sha = save('commit-' + str(r) + '.json', {'schema': 'kpb-owner-truth-commitment/v1', 'binding': BOUND,
                    'owner_component': 0, 'round': r, 'salted_commitment_sha256': digest(privacy_owner.TRUTH_TAG + salt + codec.encoded(truth)),
                    'truth_or_identifiers_exported': False})
                mounts += ['--ro-bind', str(packed), '/truth/round' + str(r) + '.json', '--ro-bind', str(commit), '/commit-' + str(r) + '.json']
                commitments.append({'path': '/commit-' + str(r) + '.json', 'sha256': commit_sha})
            config, _ = save('config.json', {'binding': BOUND, 'source_members': sources, 'owner_component': 0,
                'barrier': {'path': '/barrier.json', 'sha256': bar_sha}, 'observation_receipt': {'path': '/observation.json', 'sha256': obs_sha},
                'capsules': capsules, 'truth_commitments': commitments})
            marker, _ = save('marker.json', {'schema': 'kpb-private-diagnostic-namespace/v1', 'operation': 'score', 'network': 'disabled',
                'truth_owner_slots': 1, 'colluder_owner_slots': 0, 'corrupt_server_slots': 0})
            command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
                '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
                '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', *mounts,
                '--ro-bind', str(config), '/CONFIG.json', '--ro-bind', str(marker), '/NAMESPACE.json',
                '--bind', str(state), '/state', '--bind', str(out), '/out',
                '/usr/bin/python3', '-B', '/software/privacy_roles.py', 'score']
            first = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(first.returncode, 0, 'public-fixture isolated scorer refused')
            public_result = codec.parse((out / 'PUBLIC.json').read_bytes())
            self.assertEqual(set(public_result), {'schema', 'binding', 'per_owner_counts_or_truth_exported'})
            self.assertFalse(public_result['per_owner_counts_or_truth_exported'])
            self.assertTrue((state / 'COUNTS.json').exists())
            second = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(second.returncode, 2)


if __name__ == '__main__':
    unittest.main()
