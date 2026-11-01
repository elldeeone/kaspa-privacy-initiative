"""Adversarial controls for the frozen terminal Exit-privacy contract."""
import copy
import hashlib
import itertools
from pathlib import Path
import tempfile
import unittest
import uuid

import terminal_exit_privacy as terminal
import terminal_exit_privacy_acceptance as acceptance


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Fixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.raw = {}

        def add(name, body=None):
            path = (self.root / name).resolve()
            raw = body if body is not None else (name + '\n').encode()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            self.raw[path] = raw
            return {'path': str(path), 'sha256': digest(raw), 'bytes': len(raw)}

        self.add = add
        trial_id = str(uuid.uuid4())
        freeze_nonce = '10' * 32
        source_closure = terminal.current_source_closure()
        def marked_root(operation_id, path):
            root = Path(path).resolve()
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            root.chmod(0o700)
            body = {
                'schema': 'kpb-terminal-exit-source-owned-root/v1',
                'trial_id': trial_id,
                'freeze_nonce_hex32': freeze_nonce,
                'operation_id': operation_id,
                'output_root': str(root),
                'created_monotonic_ns': 500,
                'state': 'EMPTY_PRE_RESULT',
                'result_record_count': 0,
            }
            marker = add(str(root.relative_to(self.root) /
                             '.terminal-exit-pre-result-root.json'),
                         terminal.encoded(body))
            return {'operation_id': operation_id, 'output_root': str(root),
                    'root_marker': marker}
        runtime = terminal.current_runtime_closure()
        registered = []
        for round_number in (1, 2):
            artifacts_value = {
                'schema': 'kpb-terminal-registered-public-artifacts/v1',
                'trial_id': trial_id,
                'round': round_number,
                'accepted_head_sha256': f'{300 + round_number:064x}',
                'owner_contract_set_sha256': f'{310 + round_number:064x}',
                'public_projection_sha256': f'{320 + round_number:064x}',
                'source_closure_sha256': terminal.closure_sha(source_closure),
                'runtime_closure_sha256': terminal.closure_sha(runtime),
            }
            artifacts = add(f'registered/r{round_number}-artifacts.json',
                            terminal.encoded(artifacts_value))
            selection_value = {
                'schema': 'kpb-terminal-registered-round-selection/v1',
                'trial_id': trial_id,
                'round': round_number,
                'public_artifacts_sha256': artifacts['sha256'],
                'source_closure_sha256': terminal.closure_sha(source_closure),
                'runtime_closure_sha256': terminal.closure_sha(runtime),
                'selected_and_configured': True,
                'network_or_funding': False,
            }
            driver_selection = add(f'registered/r{round_number}-selection.json',
                                   terminal.encoded(selection_value))
            result_value = {
                'schema': 'kpb-terminal-registered-round-result/v1',
                'trial_id': trial_id,
                'round': round_number,
                'driver_selection_sha256': driver_selection['sha256'],
                'public_artifacts_sha256': artifacts['sha256'],
                'accepted_head_sha256': artifacts_value['accepted_head_sha256'],
                'owner_contract_set_sha256':
                    artifacts_value['owner_contract_set_sha256'],
                'all_three_party_agreement': True,
                'durable_egress': True,
                'executed_registered_driver': True,
                'network_or_funding': False,
            }
            driver_result = add(f'registered/r{round_number}-result.json',
                                terminal.encoded(result_value))
            registered.append({
                'round': round_number,
                'driver_selection': driver_selection,
                'driver_result': driver_result,
                'public_artifacts': artifacts,
            })
        exit_plans = []
        owner_receipts = []
        for ordinal in range(9):
            owner = ordinal % 3
            output_root = (self.root / f'exit/{ordinal}').resolve()
            operation_id = f'terminal-exit-{ordinal}'
            owner_receipt = {
                'schema': 'kpb-terminal-exit-private-owner-receipt/v1',
                'trial_id': trial_id,
                'freeze_nonce_hex32': freeze_nonce,
                'ordinal': ordinal,
                'operation_id': operation_id,
                'owner_component': owner,
                'salt_hex32': f'{500 + ordinal:064x}',
                'private_original_or_body_exported': False,
            }
            owner_receipts.append(owner_receipt)
            exit_plans.append({'ordinal': ordinal,
                **marked_root(operation_id, output_root),
                'owner_receipt_seal_sha256': digest(terminal.encoded(owner_receipt))})
        self.lifecycle = {}
        self.service_loss = {}
        self.scan_selection = {}
        self.scan_result = {}
        self.owner_receipts = owner_receipts
        service_plan = marked_root('terminal-service-loss',
                                   self.root / 'service-loss')
        scan_plan = marked_root('terminal-cold-scan', self.root / 'scan')
        baseline_capture_plan = marked_root('terminal-baseline-capture',
                                             self.root / 'capture/baseline')
        candidate_capture_plan = marked_root('terminal-candidate-capture',
                                              self.root / 'capture/candidate')
        roots = [service_plan, *exit_plans, scan_plan,
                 baseline_capture_plan, candidate_capture_plan]
        roots_seal = digest(terminal.encoded(roots))
        barrier_value = {
            'schema': 'kpb-terminal-exit-pre-result-barrier/v1',
            'trial_id': trial_id,
            'freeze_nonce_hex32': freeze_nonce,
            'method_sha256': '11' * 32,
            'workload_sha256': '12' * 32,
            'source_closure_sha256': terminal.closure_sha(source_closure),
            'runtime_closure_sha256': terminal.closure_sha(runtime),
            'terminal_roots_sha256': roots_seal,
            'created_monotonic_ns': 900,
            'state': 'FROZEN_BEFORE_RESULTS',
            'result_record_count': 0,
        }
        pre_result_barrier = add('barrier/PRE-RESULT.json',
                                 terminal.encoded(barrier_value))
        self.selection = {
            'schema': terminal.FREEZE_SCHEMA,
            'phase': 'terminal-exit-privacy',
            'status': 'FROZEN_UNEXECUTED',
            'trial_id': trial_id,
            'freeze_nonce_hex32': freeze_nonce,
            'freeze_monotonic_ns': 1_000,
            'method_sha256': '11' * 32,
            'workload_sha256': '12' * 32,
            'observer_model_sha256': terminal.current_model_sha256(),
            'coverage_policy_sha256': '13' * 32,
            'colluding_owner_component': 1,
            'source_closure': source_closure,
            'runtime_closure': runtime,
            'registered_evidence': registered,
            'terminal_plan': {
                'pre_result_barrier': pre_result_barrier,
                'terminal_roots_sha256': roots_seal,
                'service_loss': service_plan,
                'exits': exit_plans,
                'cold_scan': scan_plan,
            },
            'baseline': {
                'classification': terminal.CLASSIFICATIONS[0],
                'operation_id': baseline_capture_plan['operation_id'],
                'capture_identity': str(uuid.uuid4()),
                'attempt_id': 'terminal-baseline-01',
                'output_root': baseline_capture_plan['output_root'],
                'root_marker': baseline_capture_plan['root_marker'],
                'transparent_owner_labels': True,
            },
            'candidate': {
                'classification': terminal.CLASSIFICATIONS[1],
                'operation_id': candidate_capture_plan['operation_id'],
                'capture_identity': str(uuid.uuid4()),
                'attempt_id': 'terminal-candidate-01',
                'output_root': candidate_capture_plan['output_root'],
                'root_marker': candidate_capture_plan['root_marker'],
                'transparent_owner_labels': False,
            },
            'thresholds': dict(terminal.FROZEN_THRESHOLDS),
            'coverage_categories': list(terminal.COVERAGE_CATEGORIES),
            'execution_started': False,
            'private_truth_or_bodies_exported': False,
            'rehearsal_authorized': False,
        }
        self.selection_sha = digest(terminal.encoded(self.selection))
        self.truth = {
            'schema': terminal.TRUTH_SCHEMA,
            'selection_sha256': self.selection_sha,
            'exits': [
                {'exit_id': f'exit-{ordinal}',
                 'owner_receipt': self.owner_receipts[ordinal]}
                for ordinal in range(9)
            ],
            'private_originals_or_bodies_exported': False,
        }

    def close(self):
        self.temp.cleanup()

    def read(self, path, expected):
        path = Path(path).resolve()
        raw = path.read_bytes()
        if digest(raw) != expected:
            raise ValueError('fixture-sha256')
        return raw

    def reseal_capture(self, bundle, rehash_side=True):
        if rehash_side:
            token_sources = {}
            for exit_row in bundle['exits']:
                for token in terminal._exit_tokens(exit_row, bundle['attempts']):
                    token_sources.setdefault(token, set()).add(
                        exit_row['release_receipt']['sha256'])
            for mapping in bundle['side_information']['mappings']:
                token = (mapping['category'], mapping['value'])
                if token in token_sources:
                    mapping['evidence_sha256'] = terminal.mapping_evidence_sha(
                        bundle['classification'], mapping['category'],
                        mapping['value'], mapping['owner_components'],
                        token_sources[token])
            exits = {row['exit_id']: row for row in bundle['exits']}
            for row in bundle['side_information']['joint_constraints']:
                row['evidence_sha256'] = terminal.joint_evidence_sha(
                    bundle['classification'], row['left_exit_id'],
                    row['right_exit_id'], row['categories'],
                    row['allowed_owner_pairs'],
                    (exits[row['left_exit_id']]['release_receipt']['sha256'],
                     exits[row['right_exit_id']]['release_receipt']['sha256']))
            receipts = [row['release_receipt']['sha256']
                        for row in bundle['exits']]
            for row in bundle['side_information']['assignment_constraints']:
                row['evidence_sha256'] = terminal.assignment_evidence_sha(
                    bundle['classification'], row['owners'], receipts)
        evidence = [{key: row[key] for key in ('ordinal', 'input_history',
            'lifecycle_selection', 'lifecycle_result', 'released_candidate',
            'release_selection', 'release_receipt', 'case')}
            for row in bundle['exits']]
        bundle['lifecycle_evidence_sha256'] = terminal.evidence_sha(evidence)
        capture = {
            'schema': 'kpb-terminal-exit-capture-authority/v1',
            'selection_sha256': bundle['selection_sha256'],
            'classification': bundle['classification'],
            'capture_identity': bundle['capture_identity'],
            'attempt_id': bundle['attempt_id'],
            'consumed_barrier_sha256':
                bundle['consumed_pre_result_barrier']['sha256'],
            'exits': bundle['exits'],
            'attempts': bundle['attempts'],
            'service_observations': bundle['service_observations'],
            'cold_scan_observations': bundle['cold_scan_observations'],
            'side_information': bundle['side_information'],
            'coverage_categories': bundle['coverage_categories'],
            'unknown_record_count': 0,
            'capture_closed': True,
        }
        arm = 'candidate' if bundle['classification'] == terminal.CLASSIFICATIONS[1] \
            else 'baseline'
        bundle['capture_authority'] = self.add(
            f'capture/{arm}/CAPTURE-{uuid.uuid4()}.json', terminal.encoded(capture))
        return bundle

    def bundle(self, candidate=False):
        arm_name = 'candidate' if candidate else 'baseline'
        arm = self.selection[arm_name]
        exits = []
        attempts = []
        mappings = []
        lifecycle = []
        transaction_offset = 120 if candidate else 20
        script_offset = 101 if candidate else 1
        prior_txid = '00' * 32
        for ordinal, plan in enumerate(self.selection['terminal_plan']['exits']):
            owner = ordinal % 3
            exit_id = f'exit-{ordinal}'
            route = f'route-{ordinal}'
            contact = f'contact-{ordinal}'
            cohort = f'cohort-{ordinal}'
            script = '0000aa20' + f'{ordinal + script_offset:064x}' + '87'
            txid = f'{ordinal + transaction_offset:064x}'
            amount = 200_000_000 + ordinal
            observed = 3_000 + ordinal * 100
            attempt = {
                'sequence': ordinal,
                'exit_id': exit_id,
                'kind': 'accepted',
                'monotonic_ns': 2_900 + ordinal * 100,
                'route_id': route,
                'contact_id': contact,
                'cohort_id': cohort,
                'transaction_id_hex32': txid,
            }
            history_value = {
                'schema': 'kpb-terminal-exit-input-history/v1',
                'trial_id': self.selection['trial_id'],
                'ordinal': ordinal,
                'operation_id': plan['operation_id'],
                'previous_transaction_id_hex32': prior_txid,
            }
            history = self.add(f'exit/{ordinal}/{arm_name}/history.json',
                               terminal.encoded(history_value))
            selection_value = {
                'schema': 'kpb-terminal-exit-lifecycle-selection/v1',
                'trial_id': self.selection['trial_id'],
                'ordinal': ordinal,
                'operation_id': plan['operation_id'],
                'input_history_sha256': history['sha256'],
                'owner_receipt_seal_sha256': plan['owner_receipt_seal_sha256'],
                'source_closure_sha256': terminal.closure_sha(
                    self.selection['source_closure']),
                'runtime_closure_sha256': terminal.closure_sha(
                    self.selection['runtime_closure']),
                'owner_label_exported': False,
            }
            lifecycle_selection = self.add(
                f'exit/{ordinal}/{arm_name}/lifecycle-selection.json',
                terminal.encoded(selection_value))
            candidate_value = {
                'schema': 'kpb-terminal-exit-released-candidate/v1',
                'trial_id': self.selection['trial_id'],
                'ordinal': ordinal,
                'operation_id': plan['operation_id'],
                'exit_id': exit_id,
                'transaction_id_hex32': txid,
                'payout_script_hex37': script,
                'amount_sompi': amount,
                'native_order': ordinal,
            }
            released_candidate = self.add(
                f'exit/{ordinal}/{arm_name}/released-candidate.json',
                terminal.encoded(candidate_value))
            result_value = {
                'schema': 'kpb-terminal-exit-lifecycle-result/v1',
                'trial_id': self.selection['trial_id'],
                'ordinal': ordinal,
                'operation_id': plan['operation_id'],
                'selection_sha256': lifecycle_selection['sha256'],
                'owner_receipt_seal_sha256': plan['owner_receipt_seal_sha256'],
                'candidate_sha256': released_candidate['sha256'],
                'completed_monotonic_ns': observed - 20,
                'owner_label_exported': False,
            }
            lifecycle_result = self.add(
                f'exit/{ordinal}/{arm_name}/lifecycle-result.json',
                terminal.encoded(result_value))
            release_selection_value = {
                'schema': 'kpb-terminal-exit-release-selection/v1',
                'trial_id': self.selection['trial_id'],
                'ordinal': ordinal,
                'operation_id': plan['operation_id'],
                'lifecycle_result_sha256': lifecycle_result['sha256'],
                'candidate_sha256': released_candidate['sha256'],
                'owner_receipt_seal_sha256': plan['owner_receipt_seal_sha256'],
                'route_id': route,
                'contact_id': contact,
                'cohort_id': cohort,
                'launch_monotonic_ns': attempt['monotonic_ns'],
                'owner_label_exported': False,
            }
            release_selection = self.add(
                f'exit/{ordinal}/{arm_name}/release-selection.json',
                terminal.encoded(release_selection_value))
            release_receipt_value = {
                'schema': 'kpb-terminal-exit-release-receipt/v1',
                'trial_id': self.selection['trial_id'],
                'ordinal': ordinal,
                'operation_id': plan['operation_id'],
                'release_selection_sha256': release_selection['sha256'],
                'candidate_sha256': released_candidate['sha256'],
                'transaction_id_hex32': txid,
                'route_id': route,
                'contact_id': contact,
                'cohort_id': cohort,
                'attempts': [attempt],
                'observed_monotonic_ns': observed,
                'accepted': True,
            }
            release_receipt = self.add(
                f'exit/{ordinal}/{arm_name}/release-receipt.json',
                terminal.encoded(release_receipt_value))
            case_value = {
                'schema': 'kpb-terminal-exit-native-case/v1',
                'trial_id': self.selection['trial_id'],
                'ordinal': ordinal,
                'operation_id': plan['operation_id'],
                'candidate_sha256': released_candidate['sha256'],
                'transaction_id_hex32': txid,
                'payout_script_hex37': script,
                'amount_sompi': amount,
                'native_order': ordinal,
            }
            case = self.add(f'exit/{ordinal}/{arm_name}/CASE.json',
                            terminal.encoded(case_value))
            evidence = {
                'ordinal': ordinal,
                'input_history': history,
                'lifecycle_selection': lifecycle_selection,
                'lifecycle_result': lifecycle_result,
                'released_candidate': released_candidate,
                'release_selection': release_selection,
                'release_receipt': release_receipt,
                'case': case,
            }
            lifecycle.append(evidence)
            exits.append({
                'ordinal': ordinal,
                'exit_id': exit_id,
                'input_history': evidence['input_history'],
                'case': evidence['case'],
                'lifecycle_selection': evidence['lifecycle_selection'],
                'lifecycle_result': evidence['lifecycle_result'],
                'released_candidate': evidence['released_candidate'],
                'release_selection': evidence['release_selection'],
                'release_receipt': evidence['release_receipt'],
                'transaction_id_hex32': txid,
                'payout_script_hex37': script,
                'amount_sompi': amount,
                'native_order': ordinal,
                'observed_monotonic_ns': observed,
                'origin_route_id': route,
                'contact_id': contact,
                'cohort_id': cohort,
            })
            attempts.append(attempt)
            visible = ([owner] if not candidate or owner == 1 else [0, 2])
            mappings.extend([
                {'category': 'origin-route', 'value': route,
                 'owner_components': visible, 'evidence_sha256': f'{80 + ordinal:064x}'},
                {'category': 'native-order', 'value': str(ordinal),
                 'owner_components': visible, 'evidence_sha256': f'{100 + ordinal:064x}'},
                {'category': 'contact', 'value': contact,
                 'owner_components': visible, 'evidence_sha256': f'{120 + ordinal:064x}'},
                {'category': 'cohort', 'value': cohort,
                 'owner_components': visible, 'evidence_sha256': f'{140 + ordinal:064x}'},
                {'category': 'invoice-script', 'value': script,
                 'owner_components': visible, 'evidence_sha256': f'{200 + ordinal:064x}'},
                {'category': 'payout-amount', 'value': str(200_000_000 + ordinal),
                 'owner_components': visible, 'evidence_sha256': f'{220 + ordinal:064x}'},
                {'category': 'transaction-id', 'value': txid,
                 'owner_components': visible, 'evidence_sha256': f'{240 + ordinal:064x}'},
            ])
            if candidate:
                if owner == 1:
                    mappings.append({'category': 'colluder-receipt', 'value': exit_id,
                        'owner_components': [1], 'evidence_sha256': f'{160 + ordinal:064x}'})
            else:
                mappings.append({'category': 'transparent-owner-label', 'value': exit_id,
                    'owner_components': [owner], 'evidence_sha256': f'{180 + ordinal:064x}'})
            prior_txid = txid
        self.lifecycle[arm_name] = lifecycle
        mappings.append({'category': 'timing-bucket', 'value': '0',
            'owner_components': [0, 1, 2], 'evidence_sha256': f'{199:064x}'})
        service = []
        for index, stage in enumerate(
                ['after-service-loss'] + [f'before-exit-{n}' for n in range(9)]
                + ['after-cold-scan']):
            observed = 4_500 if stage == 'after-cold-scan' else 2_000 + index * 50
            service.append({
                'sequence': index,
                'stage': stage,
                'monotonic_ns': observed,
                'active_processes': 0,
                'active_listeners': 0,
                'private_service_state_mounted': False,
                'owner_exit_service_dependency': False,
            })
        service_value = {
            'schema': 'kpb-terminal-exit-service-loss-result/v1',
            'trial_id': self.selection['trial_id'],
            'operation_id': self.selection['terminal_plan']['service_loss']['operation_id'],
            'classification': arm['classification'],
            'observations': service,
            'private_service_state_exported': False,
        }
        self.service_loss[arm_name] = self.add(
            f'service-loss/{arm_name}/result.json', terminal.encoded(service_value))
        scans = [
            {'scan_slot': owner, 'monotonic_ns': 4_200 + owner,
             'status': 'COMPLETE_ZERO_RESERVE', 'terminal_reserve_sompi': 0,
             'payout_script_or_exit_id_exported': False}
            for owner in range(3)
        ]
        scan_selection_value = {
            'schema': 'kpb-terminal-exit-cold-scan-selection/v1',
            'trial_id': self.selection['trial_id'],
            'operation_id': self.selection['terminal_plan']['cold_scan']['operation_id'],
            'classification': arm['classification'],
            'history_tail_transaction_id_hex32': exits[-1]['transaction_id_hex32'],
        }
        self.scan_selection[arm_name] = self.add(
            f'scan/{arm_name}/selection.json', terminal.encoded(scan_selection_value))
        scan_result_value = {
            'schema': 'kpb-terminal-exit-cold-scan-result/v1',
            'trial_id': self.selection['trial_id'],
            'operation_id': self.selection['terminal_plan']['cold_scan']['operation_id'],
            'selection_sha256': self.scan_selection[arm_name]['sha256'],
            'observations': scans,
            'private_original_or_claim_exported': False,
        }
        self.scan_result[arm_name] = self.add(
            f'scan/{arm_name}/result.json', terminal.encoded(scan_result_value))
        token_rows = {}
        for exit_row in exits:
            owner = exit_row['ordinal'] % 3
            visible = ([owner] if not candidate or owner == 1 else [0, 2])
            for category, value in terminal._exit_tokens(exit_row, attempts):
                token_rows.setdefault((category, value), {
                    'owners': set(), 'receipts': set()})
                token_rows[(category, value)]['owners'].update(visible)
                token_rows[(category, value)]['receipts'].add(
                    exit_row['release_receipt']['sha256'])
        existing = {(row['category'], row['value']) for row in mappings}
        for (category, value), observed in token_rows.items():
            if category.startswith('attempt-') and (category, value) not in existing:
                mappings.append({'category': category, 'value': value,
                    'owner_components': sorted(observed['owners']),
                    'evidence_sha256': '00' * 32})
        for mapping in mappings:
            observed = token_rows[(mapping['category'], mapping['value'])]
            mapping['evidence_sha256'] = terminal.mapping_evidence_sha(
                arm['classification'], mapping['category'], mapping['value'],
                mapping['owner_components'], observed['receipts'])

        all_owner_pairs = [[left, right] for left in range(3) for right in range(3)]
        joint_constraints = [{
            'left_exit_id': f'exit-{left}',
            'right_exit_id': f'exit-{right}',
            'categories': list(terminal.JOINT_CATEGORIES),
            'allowed_owner_pairs': all_owner_pairs,
            'evidence_sha256': terminal.joint_evidence_sha(
                arm['classification'], f'exit-{left}', f'exit-{right}',
                list(terminal.JOINT_CATEGORIES), all_owner_pairs,
                (lifecycle[left]['release_receipt']['sha256'],
                 lifecycle[right]['release_receipt']['sha256'])),
        } for left in range(9) for right in range(left + 1, 9)]
        truth_vector = tuple(index % 3 for index in range(9))
        if candidate:
            assignment_vectors = []
            for honest_zero_slots in itertools.combinations(
                    [index for index in range(9) if index % 3 != 1], 3):
                zero = set(honest_zero_slots)
                assignment_vectors.append(tuple(
                    1 if index % 3 == 1 else 0 if index in zero else 2
                    for index in range(9)))
        else:
            assignment_vectors = [truth_vector]
        assignment_constraints = [{
            'categories': list(terminal.ASSIGNMENT_CATEGORIES),
            'owners': list(owners),
            'evidence_sha256': terminal.assignment_evidence_sha(
                arm['classification'], list(owners),
                [row['release_receipt']['sha256'] for row in exits]),
        } for owners in assignment_vectors]
        side_information = {
            'schema': 'kpb-terminal-exit-union-side-information/v1',
            'mappings': mappings,
            'joint_constraints': joint_constraints,
            'assignment_constraints': assignment_constraints,
            'prior_payout_scripts_hex37': [],
            'prior_transaction_ids_hex32': [],
            'invoice_record_count': 9,
            'contact_record_count': 9,
            'private_truth_or_bodies_exported': False,
        }
        consumed_value = {
            'schema': 'kpb-terminal-exit-consumed-pre-result-barrier/v1',
            'pre_result_barrier_sha256':
                self.selection['terminal_plan']['pre_result_barrier']['sha256'],
            'selection_sha256': self.selection_sha,
            'classification': arm['classification'],
            'capture_identity': arm['capture_identity'],
            'attempt_id': arm['attempt_id'],
            'consumed_monotonic_ns': 1_400,
            'state': 'CONSUMED_ONCE_BEFORE_RESULTS',
        }
        consumed_barrier = self.add(
            f'capture/{arm_name}/CONSUMED.json', terminal.encoded(consumed_value))
        capture_value = {
            'schema': 'kpb-terminal-exit-capture-authority/v1',
            'selection_sha256': self.selection_sha,
            'classification': arm['classification'],
            'capture_identity': arm['capture_identity'],
            'attempt_id': arm['attempt_id'],
            'consumed_barrier_sha256': consumed_barrier['sha256'],
            'exits': exits,
            'attempts': attempts,
            'service_observations': service,
            'cold_scan_observations': scans,
            'side_information': side_information,
            'coverage_categories': list(terminal.COVERAGE_CATEGORIES),
            'unknown_record_count': 0,
            'capture_closed': True,
        }
        capture_authority = self.add(
            f'capture/{arm_name}/CAPTURE.json', terminal.encoded(capture_value))
        return {
            'schema': terminal.BUNDLE_SCHEMA,
            'classification': arm['classification'],
            'selection_sha256': self.selection_sha,
            'trial_id': self.selection['trial_id'],
            'capture_identity': arm['capture_identity'],
            'attempt_id': arm['attempt_id'],
            'capture_started_monotonic_ns': 1_500,
            'capture_completed_monotonic_ns': 5_000,
            'source_closure_sha256': terminal.closure_sha(self.selection['source_closure']),
            'runtime_closure_sha256': terminal.closure_sha(self.selection['runtime_closure']),
            'registered_evidence_sha256': terminal.evidence_sha(self.selection['registered_evidence']),
            'lifecycle_evidence_sha256': terminal.evidence_sha(lifecycle),
            'capture_authority': capture_authority,
            'consumed_pre_result_barrier': consumed_barrier,
            'service_loss_barrier': self.service_loss[arm_name],
            'cold_scan': {
                'selection': self.scan_selection[arm_name],
                'result': self.scan_result[arm_name],
            },
            'exits': exits,
            'attempts': attempts,
            'service_observations': service,
            'cold_scan_observations': scans,
            'side_information': side_information,
            'coverage_categories': list(terminal.COVERAGE_CATEGORIES),
            'capture_complete': True,
            'truth_or_private_bodies_exported': False,
        }


class TerminalExitPrivacyControls(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def tearDown(self):
        self.f.close()

    def test_frozen_selection_reopens_exact_source_runtime_and_evidence(self):
        self.assertEqual(terminal.validate_freeze(self.f.selection, self.f.read),
                         self.f.selection)
        source_paths = {Path(row['path']).as_posix()
                        for row in self.f.selection['source_closure']}
        self.assertTrue(any(path.endswith('/new_private_trial.py')
                            for path in source_paths))
        self.assertTrue(any(path.endswith('/bootstrap/gn3_runtime.py')
                            for path in source_paths))
        self.assertTrue(any(path.endswith('/privacy_codec.py')
                            for path in source_paths))
        self.assertTrue(any(path.endswith('/privacy_owner.py')
                            for path in source_paths))
        changed = copy.deepcopy(self.f.selection)
        changed['source_closure'][0]['path'] = changed['runtime_closure'][0]['path']
        changed['source_closure'][0]['sha256'] = changed['runtime_closure'][0]['sha256']
        changed['source_closure'][0]['bytes'] = changed['runtime_closure'][0]['bytes']
        with self.assertRaisesRegex(ValueError, 'source-closure'):
            terminal.validate_freeze(changed, self.f.read)
        changed = copy.deepcopy(self.f.selection)
        fake = self.f.add('attacker-runtime.bin')
        changed['runtime_closure'][0] = {
            'role': terminal.RUNTIME_ROLES[0], **fake}
        with self.assertRaisesRegex(ValueError, 'not-caller-selected'):
            terminal.validate_freeze(changed, self.f.read)

    def test_numeric_time_without_durable_pre_result_barrier_refuses(self):
        changed = copy.deepcopy(self.f.selection)
        barrier = terminal.parse(self.f.read(
            Path(changed['terminal_plan']['pre_result_barrier']['path']),
            changed['terminal_plan']['pre_result_barrier']['sha256']))
        barrier['result_record_count'] = 1
        changed['terminal_plan']['pre_result_barrier'] = self.f.add(
            'barrier/FORGED-PRE-RESULT.json', terminal.encoded(barrier))
        with self.assertRaisesRegex(ValueError, 'durable-one-shot-pre-result'):
            terminal.validate_freeze(changed, self.f.read)

    def test_private_scorer_revalidates_exact_freeze(self):
        changed = copy.deepcopy(self.f.selection)
        changed['source_closure'][0]['sha256'] = 'ff' * 32
        changed_sha = digest(terminal.encoded(changed))
        with self.assertRaisesRegex(ValueError, 'source-closure'):
            terminal.compare_private(changed, changed_sha, self.f.bundle(False),
                self.f.bundle(True), self.f.truth, self.f.read)

    def test_boolean_threshold_alias_and_future_result_in_freeze_refuse(self):
        changed = copy.deepcopy(self.f.selection)
        changed['thresholds']['exit_count'] = True
        with self.assertRaisesRegex(ValueError, 'threshold'):
            terminal.validate_freeze(changed, self.f.read)
        changed = copy.deepcopy(self.f.selection)
        changed['terminal_plan']['cold_scan']['result'] = self.f.scan_result
        with self.assertRaisesRegex(ValueError, 'cold-scan-plan-fields'):
            terminal.validate_freeze(changed, self.f.read)

    def test_missing_relabelled_or_reordered_exit_evidence_refuses(self):
        baseline = self.f.bundle()
        for mutate in ('missing', 'relabelled', 'reordered'):
            changed = copy.deepcopy(baseline)
            if mutate == 'missing':
                changed['exits'].pop()
            elif mutate == 'relabelled':
                changed['classification'] = terminal.CLASSIFICATIONS[1]
            else:
                changed['exits'][0], changed['exits'][1] = changed['exits'][1], changed['exits'][0]
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                terminal.validate_bundle(self.f.selection, self.f.selection_sha, changed, self.f.read)

    def test_actual_result_outside_preselected_output_root_refuses(self):
        changed = copy.deepcopy(self.f.bundle(True))
        changed['exits'][0]['case'] = self.f.scan_result['candidate']
        with self.assertRaisesRegex(ValueError, 'outside-planned-root'):
            terminal.validate_bundle(self.f.selection, self.f.selection_sha,
                                     changed, self.f.read)

    def test_self_consistent_arbitrary_lifecycle_body_refuses(self):
        changed = copy.deepcopy(self.f.bundle(True))
        fake = self.f.add('exit/0/candidate/fake-lifecycle-result.json',
                          terminal.encoded({'schema': 'attacker-authored'}))
        changed['exits'][0]['lifecycle_result'] = fake
        self.f.reseal_capture(changed)
        with self.assertRaisesRegex(ValueError, 'lifecycle-result-body-fields'):
            terminal.validate_bundle(self.f.selection, self.f.selection_sha,
                                     changed, self.f.read)

    def test_duplicate_or_previously_known_payout_scripts_refuse(self):
        candidate = self.f.bundle(True)
        changed = copy.deepcopy(candidate)
        changed['exits'][1]['payout_script_hex37'] = changed['exits'][0]['payout_script_hex37']
        with self.assertRaisesRegex(ValueError,
                                    'semantic-released-candidate|fresh-distinct'):
            terminal.validate_bundle(self.f.selection, self.f.selection_sha, changed, self.f.read)
        changed = copy.deepcopy(candidate)
        changed['side_information']['prior_payout_scripts_hex37'] = [
            changed['exits'][0]['payout_script_hex37']]
        self.f.reseal_capture(changed)
        with self.assertRaisesRegex(ValueError, 'fresh-distinct-payout-scripts'):
            terminal.validate_bundle(self.f.selection, self.f.selection_sha, changed, self.f.read)

    def test_retry_rejection_orphan_and_reorg_coverage_cannot_be_omitted(self):
        candidate = self.f.bundle(True)
        changed = copy.deepcopy(candidate)
        changed['coverage_categories'].remove('reorg-history')
        with self.assertRaisesRegex(ValueError, 'coverage'):
            terminal.validate_bundle(self.f.selection, self.f.selection_sha, changed, self.f.read)
        changed = copy.deepcopy(candidate)
        changed['attempts'][0]['kind'] = 'retry'
        with self.assertRaisesRegex(ValueError,
                                    'semantic-release-receipt|accepted-exit-attempt'):
            terminal.validate_bundle(self.f.selection, self.f.selection_sha, changed, self.f.read)
        changed = copy.deepcopy(candidate)
        changed['side_information']['mappings'] = [row for row in
            changed['side_information']['mappings']
            if not (row['category'] == 'origin-route' and row['value'] == 'route-0')]
        self.f.reseal_capture(changed)
        with self.assertRaisesRegex(ValueError, 'complete-side-mapping'):
            terminal.validate_bundle(self.f.selection, self.f.selection_sha,
                                     changed, self.f.read)

    def test_attempt_and_nary_assignment_correlations_are_scored(self):
        candidate = self.f.bundle(True)
        changed = copy.deepcopy(candidate)
        changed['side_information']['mappings'] = [row for row in
            changed['side_information']['mappings']
            if row['category'] != 'attempt-contact']
        self.f.reseal_capture(changed)
        with self.assertRaisesRegex(ValueError, 'coverage|complete-side-mapping'):
            terminal.validate_bundle(self.f.selection, self.f.selection_sha,
                                     changed, self.f.read)

        changed = copy.deepcopy(candidate)
        truth = [index % 3 for index in range(9)]
        changed['side_information']['assignment_constraints'] = [{
            'categories': list(terminal.ASSIGNMENT_CATEGORIES),
            'owners': truth,
            'evidence_sha256': '00' * 32,
        }]
        self.f.reseal_capture(changed)
        result = terminal.compare_private(
            self.f.selection, self.f.selection_sha, self.f.bundle(False),
            changed, self.f.truth, self.f.read)
        self.assertEqual(result['candidate_joint_assignments'], 1)
        self.assertEqual(result['status'], terminal.MODEL_FAIL_STATUS)

    def test_arbitrary_side_evidence_digest_refuses(self):
        changed = copy.deepcopy(self.f.bundle(True))
        changed['side_information']['mappings'][0]['evidence_sha256'] = 'ff' * 32
        self.f.reseal_capture(changed, rehash_side=False)
        with self.assertRaisesRegex(ValueError, 'side-mapping-evidence-binding'):
            terminal.validate_bundle(self.f.selection, self.f.selection_sha,
                                     changed, self.f.read)

    def test_service_reappearance_or_late_loss_refuses(self):
        candidate = self.f.bundle(True)
        changed = copy.deepcopy(candidate)
        changed['service_observations'][4]['active_processes'] = 1
        with self.assertRaisesRegex(ValueError, 'service-remained-absent'):
            terminal.validate_bundle(self.f.selection, self.f.selection_sha, changed, self.f.read)
        changed = copy.deepcopy(candidate)
        changed['capture_started_monotonic_ns'] = 900
        with self.assertRaisesRegex(ValueError, 'freeze-before-capture'):
            terminal.validate_bundle(self.f.selection, self.f.selection_sha, changed, self.f.read)

    def test_cold_scan_is_after_all_nine_exits_and_exports_no_identifiers(self):
        candidate = self.f.bundle(True)
        changed = copy.deepcopy(candidate)
        changed['cold_scan_observations'][0]['monotonic_ns'] = 3_100
        with self.assertRaisesRegex(ValueError, 'cold-scan-after-exits'):
            terminal.validate_bundle(self.f.selection, self.f.selection_sha, changed, self.f.read)
        changed = copy.deepcopy(candidate)
        changed['cold_scan_observations'][0]['payout_script_or_exit_id_exported'] = True
        with self.assertRaisesRegex(ValueError, 'cold-scan-public-boundary'):
            terminal.validate_bundle(self.f.selection, self.f.selection_sha, changed, self.f.read)

    def test_transparent_baseline_and_ambiguous_union_candidate_pass_model(self):
        baseline = self.f.bundle(False)
        candidate = self.f.bundle(True)
        result = terminal.compare_private(self.f.selection, self.f.selection_sha,
                                          baseline, candidate, self.f.truth, self.f.read)
        self.assertEqual(result['status'], terminal.MODEL_PASS_STATUS)
        self.assertEqual(result['baseline_joint_assignments'], 1)
        self.assertGreaterEqual(result['candidate_joint_assignments'], 2)
        self.assertEqual(result['honest_owners_with_strict_gain'], 2)
        self.assertTrue(result['all_honest_owner_counts_nonregressed'])
        self.assertFalse(result['private_truth_or_owner_labels_exported'])
        raw = terminal.encoded(result)
        self.assertNotIn(b'exit-0', raw)

    def test_route_or_order_leakage_collapses_candidate_and_fails(self):
        candidate = self.f.bundle(True)
        for mapping in candidate['side_information']['mappings']:
            if mapping['category'] in ('origin-route', 'native-order'):
                ordinal = int(mapping['value'].split('-')[-1]) \
                    if mapping['category'] == 'origin-route' else int(mapping['value'])
                mapping['owner_components'] = [ordinal % 3]
        self.f.reseal_capture(candidate)
        result = terminal.compare_private(self.f.selection, self.f.selection_sha,
            self.f.bundle(False), candidate, self.f.truth, self.f.read)
        self.assertEqual(result['status'], terminal.MODEL_FAIL_STATUS)
        self.assertEqual(result['candidate_joint_assignments'], 1)

    def test_one_fixed_honest_exit_fails_even_with_many_joint_candidates(self):
        candidate = self.f.bundle(True)
        for mapping in candidate['side_information']['mappings']:
            if mapping['value'] in ('route-0', '0', 'contact-0', 'cohort-0') \
                    or mapping['value'] == candidate['exits'][0]['payout_script_hex37'] \
                    or mapping['value'] == str(candidate['exits'][0]['amount_sompi']) \
                    or mapping['value'] == candidate['exits'][0]['transaction_id_hex32']:
                if mapping['category'] != 'timing-bucket':
                    mapping['owner_components'] = [0]
        self.f.reseal_capture(candidate)
        result = terminal.compare_private(self.f.selection, self.f.selection_sha,
            self.f.bundle(False), candidate, self.f.truth, self.f.read)
        self.assertGreater(result['candidate_joint_assignments'], 2)
        self.assertEqual(result['minimum_honest_exit_eligible_owners'], 1)
        self.assertEqual(result['status'], terminal.MODEL_FAIL_STATUS)

    def test_colluder_receipts_are_exact_singleton_selected_owner(self):
        candidate = self.f.bundle(True)
        for mapping in candidate['side_information']['mappings']:
            if mapping['category'] == 'colluder-receipt':
                mapping['owner_components'] = [0, 1, 2]
        self.f.reseal_capture(candidate)
        with self.assertRaisesRegex(ValueError, 'one-colluder'):
            terminal.validate_bundle(self.f.selection, self.f.selection_sha,
                                     candidate, self.f.read)

    def test_truth_relabel_and_private_export_refuse(self):
        truth = copy.deepcopy(self.f.truth)
        truth['exits'][0]['owner_receipt']['owner_component'] = 2
        with self.assertRaisesRegex(ValueError, 'truth-owner-receipt-binding'):
            terminal.compare_private(self.f.selection, self.f.selection_sha,
                self.f.bundle(False), self.f.bundle(True), truth, self.f.read)
        swapped = copy.deepcopy(self.f.truth)
        for row in swapped['exits']:
            owner = row['owner_receipt']['owner_component']
            if owner in (0, 2):
                row['owner_receipt']['owner_component'] = 2 - owner
        with self.assertRaisesRegex(ValueError, 'truth-owner-receipt-binding'):
            terminal.compare_private(self.f.selection, self.f.selection_sha,
                self.f.bundle(False), self.f.bundle(True), swapped, self.f.read)
        candidate = self.f.bundle(True)
        candidate['truth_or_private_bodies_exported'] = True
        with self.assertRaisesRegex(ValueError, 'forbidden-private-export'):
            terminal.validate_bundle(self.f.selection, self.f.selection_sha, candidate, self.f.read)

    def test_source_only_acceptance_never_authorizes_rehearsal(self):
        score = terminal.compare_private(self.f.selection, self.f.selection_sha,
            self.f.bundle(False), self.f.bundle(True), self.f.truth, self.f.read)
        result = acceptance.evaluate(self.f.selection_sha,
            score['baseline_bundle_sha256'], score['candidate_bundle_sha256'], score)
        self.assertEqual(result['model_status'], terminal.MODEL_PASS_STATUS)
        self.assertEqual(result['privacy_status'], 'UNQUALIFIED_SOURCE_ONLY')
        self.assertFalse(result['actual_capture_and_private_score_executed'])
        self.assertFalse(result['rehearsal_authorized'])
        with self.assertRaisesRegex(ValueError, 'score-bundle-binding'):
            acceptance.evaluate(self.f.selection_sha, 'ff' * 32,
                score['candidate_bundle_sha256'], score)
        forged = copy.deepcopy(score)
        forged.update(status=terminal.MODEL_PASS_STATUS,
            baseline_joint_assignments=0, candidate_joint_assignments=0,
            minimum_honest_owner_candidate_exit_sets=0,
            minimum_honest_exit_eligible_owners=0,
            honest_owners_with_strict_gain=0,
            all_honest_owner_counts_nonregressed=False,
            baseline_truth_retained=False, candidate_truth_retained=False,
            transparent_baseline_control_passed=False,
            union_observer_scored=False)
        with self.assertRaisesRegex(ValueError, 'score-status-semantics'):
            acceptance.evaluate(self.f.selection_sha,
                forged['baseline_bundle_sha256'],
                forged['candidate_bundle_sha256'], forged)


if __name__ == '__main__':
    unittest.main()
