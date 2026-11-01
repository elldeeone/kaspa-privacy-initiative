#!/usr/bin/env python3
"""Controls for the CONFIGURED0 EdDSA/financial admission blocker.

These controls authenticate public structural evidence only.  They do not
mint an owner-input, financial, launch, or network authority.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import unittest


FINANCIAL = Path(__file__).resolve().parents[1]
MPC = FINANCIAL.parent
REPOSITORY = FINANCIAL.parents[3]
RELATION_EVIDENCE = (
    MPC.parent / 'private-batch-relation' / 'evidence' /
    '2026-10-28-full-financial-source')


def load(path):
    return json.loads(path.read_bytes())


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def require_consistent(blocker, selection, program):
    """Refuse any substitution in the frozen public candidate identities."""
    relation = blocker['candidate_relation']
    signature = relation['signature_component']
    model = selection['financial_model']
    selected_signature = selection['public_exporter']['signature_matrix']
    checks = (
        relation['model_identity'] == model['model_identity'] ==
        program['model_sha256'],
        relation['source_identity'] == model['source_identity'] ==
        program['source_sha256'],
        relation['final_matrix_fingerprint'] == model['matrix_fingerprint'],
        relation['graph_identity'] == program['expected_graph_sha256'],
        relation['trace_identity'] == program['trace']['sha256'],
        relation['owner_column_layout_identity'] ==
        model['layout_identity'] == program['layout']['sha256'],
        relation['prefix_recipe_identity'] ==
        model['prefix_recipe_identity'] ==
        program['prefix_recipe']['sha256'],
        relation['owner_input_counts'] == program['owner_input_counts'],
        signature['matrix_sha256'] == selected_signature['sha256'] ==
        program['original_signature_matrix_sha256'],
        signature['mapping_sha256'] ==
        program['original_signature_mapping_sha256'],
        signature['instances_each'] == 67,
        signature['variables_each'] == 10049,
        signature['constraints_each'] == 10065,
        signature['component_copies'] == 3,
    )
    if not all(checks):
        raise ValueError('registered relation candidate identity mismatch')


class RegisteredRelationAdmissionBlockerControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blocker = load(FINANCIAL /
                           'REGISTERED-RELATION-ADMISSION-BLOCKER.json')
        cls.selection = load(FINANCIAL /
                             'REGISTERED-ACTUAL-HEAD-SELECTION.json')
        cls.program = load(RELATION_EVIDENCE /
                           'public-final-financial-program.json')

    def test_exact_public_candidate_is_cross_bound_but_not_authority(self):
        require_consistent(self.blocker, self.selection, self.program)
        self.assertEqual(
            self.blocker['status'],
            'CONFIGURED0_RELATION_ADMISSION_BLOCKED')
        self.assertEqual(
            self.blocker['classification'],
            'PUBLIC_STRUCTURAL_RELATION_CANDIDATE_NO_ADMISSION_AUTHORITY')
        self.assertFalse(self.blocker['configured'])
        self.assertFalse(self.blocker['authority_minted'])
        self.assertFalse(self.blocker['launch_authorized'])
        self.assertFalse(self.blocker['network_used'])

    def test_blocker_source_snapshot_hashes_are_current(self):
        for name, record in self.blocker['source_snapshot'].items():
            with self.subTest(name=name):
                self.assertEqual(sha256(REPOSITORY / record['path']),
                                 record['sha256'])

    def test_current_source_is_matrix_equivalent_but_not_selected(self):
        evidence = self.blocker['current_source_matrix_equivalence']
        self.assertEqual(
            evidence['current_source_table_sha256'],
            '04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7')
        self.assertEqual(
            evidence['selected_matrix_fingerprint'],
            self.blocker['candidate_relation']['final_matrix_fingerprint'])
        self.assertEqual(evidence['constraints_regenerated'], 13093029)
        self.assertTrue(evidence['all_axes_byte_identical'])
        self.assertFalse(evidence['selected'])
        self.assertFalse(evidence['authority'])
        self.assertFalse(evidence['setup_provenance_eligible'])
        self.assertFalse(evidence['launch_authorized'])

    def test_wrong_relation_matrix_mapping_layout_or_owner_count_refuses(self):
        mutations = (
            ('model', lambda b, s, p:
             b['candidate_relation'].__setitem__('model_identity', '11' * 32)),
            ('source', lambda b, s, p:
             s['financial_model'].__setitem__('source_identity', '22' * 32)),
            ('final-matrix', lambda b, s, p:
             s['financial_model'].__setitem__('matrix_fingerprint', '33' * 32)),
            ('signature-matrix', lambda b, s, p:
             s['public_exporter']['signature_matrix'].__setitem__(
                 'sha256', '44' * 32)),
            ('signature-mapping', lambda b, s, p:
             p.__setitem__('original_signature_mapping_sha256', '55' * 32)),
            ('trace', lambda b, s, p:
             p['trace'].__setitem__('sha256', '66' * 32)),
            ('layout', lambda b, s, p:
             p['layout'].__setitem__('sha256', '77' * 32)),
            ('recipe', lambda b, s, p:
             p['prefix_recipe'].__setitem__('sha256', '88' * 32)),
            ('owner-count', lambda b, s, p:
             p['owner_input_counts'].__setitem__(1, 2635408)),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                blocker = deepcopy(self.blocker)
                selection = deepcopy(self.selection)
                program = deepcopy(self.program)
                mutate(blocker, selection, program)
                with self.assertRaises(ValueError):
                    require_consistent(blocker, selection, program)

    def test_registered_selection_remains_compile_time_configured0(self):
        config = (FINANCIAL /
                  'registered_service_selection.hpp').read_text()
        match = re.search(
            r'^#define KPI_REGISTERED_FINANCIAL_CONFIGURED ([01])$',
            config, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), '0')
        self.assertFalse(self.selection['configured'])
        self.assertEqual(self.selection['status'], 'UNCONFIGURED_BLOCKED')
        self.assertTrue(
            self.selection['public_exporter']['signature_matrix']
            ['ephemeral_candidate_must_be_materialized_and_reviewed'])
        state = self.blocker['selected_state']
        self.assertFalse(state['immutable_exporter_spec_selected'])
        self.assertFalse(state['owner_input_admission_authority_present'])
        self.assertFalse(state['serialized_receipt_authority'])

    def test_current_export_descriptor_cannot_prove_eddsa_selection(self):
        exporter = (FINANCIAL / 'export_registered_program.py').read_text()
        descriptor = exporter.split("lines = [", 1)[1].split(
            "with (output / 'REGISTERED-EXPORT.txt')", 1)[0]
        self.assertIn("'TRACE'", descriptor)
        self.assertIn("'LAYOUT'", descriptor)
        self.assertNotIn('SIGNATURE_MATRIX', descriptor)
        self.assertNotIn('SIGNATURE_MAPPING', descriptor)

        selection_source = (FINANCIAL / 'registered_selection.cpp').read_text()
        descriptor_type = selection_source.split('struct Descriptor {', 1)[1]
        descriptor_type = descriptor_type.split('};', 1)[0]
        self.assertNotIn('signature', descriptor_type.lower())
        missing = {item['id'] for item in self.blocker['missing_bindings']}
        self.assertIn('export_descriptor_omits_signature_matrix', missing)
        self.assertIn('export_descriptor_omits_signature_mapping', missing)

    def test_layout_hash_is_the_exact_owner_map_identity_not_a_count_receipt(self):
        relation = self.blocker['candidate_relation']
        self.assertEqual(
            relation['owner_column_layout_identity'],
            '9a3ee5f5eb98384273e2b608f71a60f89c49e6fc9c1029586f8f201b84617e1e')
        self.assertEqual(relation['owner_roles'], [0, 1, 2])
        self.assertEqual(relation['owner_input_counts'], [2635409] * 3)
        self.assertEqual(
            self.blocker['required_future_seam']
            ['owner_column_map_identity_rule'],
            'authenticated canonical layout bytes and their SHA-256; never counts or a caller digest')

        parser = (MPC / 'trace' / 'trace_witness.cpp').read_text()
        self.assertIn(
            'selected_artifact(expected.layout_path, expected.layout_sha256',
            parser)
        self.assertIn('role != "owner" + std::to_string(', parser)
        self.assertIn('column <= selected.columns.back()', parser)
        self.assertIn('used_columns[column]', parser)
        self.assertIn('trace-layout-trailing-data', parser)

    def test_future_seam_is_live_move_only_and_receipts_never_mint(self):
        seam = self.blocker['required_future_seam']
        self.assertEqual(seam['status'], 'ABSENT_CONFIGURED0')
        self.assertEqual(seam['proposed_type'],
                         'SelectedRelationAdmissionAuthority')
        self.assertEqual(
            seam['mint_only_from'],
            'live RegisteredFinancialSelection plus its authenticated immutable exporter SPEC and parsed TraceProgram')
        self.assertTrue(seam['move_only'])
        self.assertTrue(seam['single_consume'])
        self.assertFalse(seam['public_constructor'])
        self.assertFalse(seam['json_restore'])
        self.assertFalse(seam['digest_restore'])
        self.assertFalse(seam['bool_restore'])


if __name__ == '__main__':
    unittest.main()
