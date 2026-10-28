"""Public fixtures only: no production registry, Original, notes or views."""

import copy
import json
import hashlib
import multiprocessing
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import method03_budget as budget


def public_fixture(offset=0, labels=None):
    owners = [{'owner_component': i,
               'funding_spk_hex36': '000020' + bytes([100 + i + offset]).hex() * 32 + 'ac',
               'initial_public_sha256': bytes([20 + i]).hex() * 32} for i in range(3)]
    spec = {'schema': 'kpb-method03-budget-spec/v1',
            'binding': {'method_sha256': '11' * 32, 'selection_sha256': '22' * 32,
                        'trial_id': '00000000-0000-4000-8000-000000000001',
                        'phase': 'private-exit-route-03',
                        'attempt_id': '00000000-0000-4000-8000-000000000002'},
            'identity_policy': budget.FUNDING_POLICY,
            'profile_id_hex32': budget.PROFILE, 'domain_hex32': budget.DOMAIN,
            'source_sha256': '33' * 32, 'slot_grammar_sha256': '44' * 32,
            'selected_view_labels': labels or sorted(budget.VIEW_KINDS),
            'bootstrap': {'trial_id': '00000000-0000-4000-8000-000000000003',
                          'trial_sha256': '55' * 32, 'selection_sha256': '66' * 32,
                          'generator_sha256': '77' * 32, 'worker_sha256': '88' * 32},
            'owners': owners}
    facts = {'schema': 'kpb-method03-bootstrap-budget-facts/v1',
             'bootstrap': copy.deepcopy(spec['bootstrap']),
             'profile_id_hex32': budget.PROFILE, 'domain_hex32': budget.DOMAIN,
             'owners': copy.deepcopy(owners)}
    return spec, facts


def view_refs(claim):
    for label in claim._spec['selected_view_labels']:
        if label not in claim._view_intakes:
            budget.claim_view_intake_once(claim, label)
    return [{'label': label, 'kind': budget.VIEW_KINDS[label], 'binding': dict(claim._spec['binding']),
             'source_sha256': claim._spec['source_sha256'],
             'public_plan_sha256': '91' * 32,
             'slot_grammar_sha256': claim._spec['slot_grammar_sha256'],
             'actual_unlabelled_universe_sha256': 'a1' * 32,
             'salted_public_seal': {'path': '/public/' + label + '-seal.json', 'sha256': '92' * 32},
             'salted_commitment_sha256': '93' * 32,
             'completion': {'observed_launcher_pid': os.getpid(), 'returncode': 0,
                            'completed_monotonic_ns': time.monotonic_ns(),
                            'event_ref': {'path': '/public/' + label + '-completion.json',
                                          'sha256': '94' * 32}}}
            for label in claim._spec['selected_view_labels']]


def race_reserve(start, results):
    start.wait()
    try:
        budget.reserve(*public_fixture())
    except (ValueError, OSError):
        results.put('refused')
    else:
        results.put('reserved')


class PublicBudgetControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='method03-public-budget-')
        self.registry = Path(self.temp.name) / 'registry'
        self.registry.mkdir(mode=0o700)
        info = self.registry.stat()
        # Test-only source fixtures. There is no production override argument,
        # initializer or CLI; the shipped module stays UNSELECTED.
        self.patches = [mock.patch.object(budget, 'REGISTRY_ROOT', self.registry),
                        mock.patch.object(budget, 'REGISTRY_ADMISSION', (info.st_dev, info.st_ino)),
                        mock.patch.object(budget, 'SELECTED_IDENTITY_POLICY', budget.FUNDING_POLICY)]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temp.cleanup()

    def claim(self, offset=0, labels=None):
        return budget.reserve(*public_fixture(offset, labels))

    def test_unselected_refuses_before_any_registry_access(self):
        with mock.patch.object(budget, 'SELECTED_IDENTITY_POLICY', 'UNSELECTED'), \
             mock.patch.object(budget, '_open_registry') as opened:
            with self.assertRaises(budget.BudgetRefusal):
                self.claim()
            opened.assert_not_called()
        with mock.patch.object(budget, 'REGISTRY_ADMISSION', None):
            with self.assertRaises(budget.BudgetRefusal):
                self.claim()
        self.assertEqual(list(self.registry.iterdir()), [])

    def test_reservation_requires_bootstrap_facts_before_any_registry_access(self):
        spec, _facts = public_fixture()
        self.assertEqual(budget.validate_spec(spec), spec)  # Pure validation remains available.
        with mock.patch.object(budget, '_open_registry') as opened:
            with self.assertRaises(budget.BudgetRefusal):
                budget.reserve(spec, None)
            opened.assert_not_called()
        self.assertEqual(list(self.registry.iterdir()), [])

    def test_strict_pure_spec_and_bootstrap_binding(self):
        spec, facts = public_fixture()
        detached = budget.validate_spec(spec, facts)
        spec['owners'][0]['initial_public_sha256'] = 'ff' * 32
        self.assertNotEqual(spec, detached)
        changes = [lambda x: x.update(accepted=True),
                   lambda x: x.update(registry_path='/tmp/reset'),
                   lambda x: x['binding'].update(phase='private-exit-route-02'),
                   lambda x: x['binding'].update(trial_id=x['binding']['trial_id'].upper() + 'x'),
                   lambda x: x.update(profile_id_hex32='99' * 32),
                   lambda x: x.update(domain_hex32='99' * 32),
                   lambda x: x['owners'][0].update(owner_component=False),
                   lambda x: x['owners'][1].update(funding_spk_hex36=x['owners'][0]['funding_spk_hex36']),
                   lambda x: x.update(selected_view_labels=[{}]),
                   lambda x: x.update(selected_view_labels=['SECONDARY', 'PRIMARY'])]
        for change in changes:
            value, own_facts = public_fixture()
            change(value)
            with self.subTest(value=value), self.assertRaises(budget.BudgetRefusal):
                budget.validate_spec(value, own_facts)
        value, own_facts = public_fixture()
        own_facts['bootstrap']['trial_sha256'] = 'aa' * 32
        with self.assertRaises(budget.BudgetRefusal):
            budget.validate_spec(value, own_facts)

    def test_all_method02_public_funding_keys_refuse_without_writes(self):
        for forbidden in budget.FORBIDDEN_METHOD02_FUNDING:
            spec, facts = public_fixture()
            spec['owners'][0]['funding_spk_hex36'] = forbidden
            facts['owners'][0]['funding_spk_hex36'] = forbidden
            with self.assertRaises(budget.BudgetRefusal):
                budget.reserve(spec, facts)
        self.assertEqual(list(self.registry.iterdir()), [])

    def test_reservation_precedes_intake_and_uses_three_cloexec_metadata_directories(self):
        claim = self.claim()
        self.assertEqual(len(list(self.registry.iterdir())), 3)
        for key in claim._keys:
            self.assertEqual((self.registry / key).stat().st_mode & 0o777, 0o700)
            record = self.registry / key / 'reservation.json'
            self.assertTrue(record.is_file())
            self.assertEqual(record.stat().st_nlink, 1)
            self.assertEqual(record.stat().st_mode & 0o777, 0o400)
        with self.assertRaises(TypeError):
            copy.copy(claim)

    def test_method_attempt_source_and_backup_aliases_do_not_reopen(self):
        first = self.claim()
        spec, facts = public_fixture()
        spec['binding'].update(method_sha256='aa' * 32, selection_sha256='bb' * 32,
                               trial_id='00000000-0000-4000-8000-000000000010',
                               attempt_id='00000000-0000-4000-8000-000000000011')
        spec['source_sha256'] = 'cc' * 32
        spec['bootstrap']['trial_id'] = facts['bootstrap']['trial_id'] = '00000000-0000-4000-8000-000000000012'
        spec['bootstrap']['trial_sha256'] = facts['bootstrap']['trial_sha256'] = 'dd' * 32
        with self.assertRaises(FileExistsError):
            budget.reserve(spec, facts)
        self.assertEqual(set(p.name for p in self.registry.iterdir()), set(first._keys))

    def test_crash_after_atomic_mkdir_consumes_budget_even_without_record(self):
        with mock.patch.object(budget.os, 'fsync', side_effect=OSError('public synthetic crash')):
            with self.assertRaises(OSError):
                self.claim()
        markers = list(self.registry.iterdir())
        self.assertEqual(len(markers), 1)
        self.assertEqual(list(markers[0].iterdir()), [])
        with self.assertRaises(FileExistsError):
            self.claim()
        self.assertTrue(markers[0].is_dir())

    def test_partial_overlap_never_rolls_back_prior_consumption(self):
        spec, facts = public_fixture()
        keys = sorted(budget._identity_key(row) for row in spec['owners'])
        (self.registry / keys[1]).mkdir(mode=0o700)
        with self.assertRaises(FileExistsError):
            budget.reserve(spec, facts)
        self.assertTrue((self.registry / keys[0] / 'reservation.json').is_file())
        self.assertTrue((self.registry / keys[1]).is_dir())
        self.assertFalse((self.registry / keys[2]).exists())

    def test_existing_file_symlink_or_crash_directory_are_all_consumed(self):
        spec, facts = public_fixture()
        first = min(budget._identity_key(row) for row in spec['owners'])
        marker = self.registry / first
        for kind in ('file', 'symlink', 'directory'):
            if kind == 'file':
                marker.write_text('public canary')
            elif kind == 'symlink':
                marker.symlink_to(Path(self.temp.name) / 'public-missing-target')
            else:
                marker.mkdir(mode=0o700)
            with self.subTest(kind=kind), self.assertRaises(FileExistsError):
                budget.reserve(spec, facts)
            if kind == 'directory':
                marker.rmdir()  # Test-only teardown, never library behavior.
            else:
                marker.unlink()

    def test_fresh_process_attempt_race_has_only_one_complete_winner(self):
        context = multiprocessing.get_context('fork')
        start = context.Event()
        results = context.Queue()
        workers = [context.Process(target=race_reserve, args=(start, results)) for _ in range(2)]
        for worker in workers:
            worker.start()
        start.set()
        outcome = [results.get(timeout=30) for _ in workers]
        for worker in workers:
            worker.join(30)
            self.assertEqual(worker.exitcode, 0)
        self.assertEqual(sorted(outcome), ['refused', 'reserved'])
        self.assertEqual(len(list(self.registry.iterdir())), 3)

    def test_missing_replaced_or_aliased_registry_fails_closed(self):
        old = self.registry.with_name('old-registry')
        self.registry.rename(old)
        with self.assertRaises(FileNotFoundError):
            self.claim()
        self.registry.mkdir(mode=0o700)
        with self.assertRaises(budget.BudgetRefusal):
            self.claim()
        self.registry.rmdir()
        self.registry.symlink_to(old, target_is_directory=True)
        with self.assertRaises(budget.BudgetRefusal):
            self.claim()

    def test_all_selected_seals_are_required_before_any_truth(self):
        claim = self.claim()
        with self.assertRaises(budget.BudgetRefusal):
            budget.claim_truth_once(claim, {'accepted': True}, 0)
        refs = view_refs(claim)
        with self.assertRaises(budget.BudgetRefusal):
            budget.mark_views_sealed(claim, refs[:1])
        for bad in ('observation_sha256', 'prediction_sha256', 'models', 'masks', 'own_arrival_ids', 'salt'):
            invalid = copy.deepcopy(refs)
            invalid[0][bad] = 'private-data-must-not-be-here'
            with self.subTest(field=bad), self.assertRaises(budget.BudgetRefusal):
                budget.mark_views_sealed(claim, invalid)
        barrier = budget.mark_views_sealed(claim, refs)
        for component in (2, 0, 1):
            receipt = budget.claim_truth_once(claim, barrier, component)
            self.assertEqual(receipt['owner_component'], component)
            with self.assertRaises(FileExistsError):
                budget.claim_truth_once(claim, barrier, component)
        with self.assertRaises(budget.BudgetRefusal):
            budget.mark_views_sealed(claim, refs)

    def test_wrong_binding_source_universe_and_completion_are_not_seals(self):
        claim = self.claim()
        for field in ('binding', 'source_sha256', 'slot_grammar_sha256', 'time', 'returncode'):
            refs = view_refs(claim)
            if field == 'binding':
                refs[0]['binding']['selection_sha256'] = 'af' * 32
            elif field == 'time':
                refs[0]['completion']['completed_monotonic_ns'] = claim._ready_ns - 1
            elif field == 'returncode':
                refs[0]['completion']['returncode'] = False
            else:
                refs[0][field] = 'af' * 32
            with self.subTest(field=field), self.assertRaises(budget.BudgetRefusal):
                budget.mark_views_sealed(claim, refs)

    def test_partial_view_marker_failure_never_grants_truth(self):
        claim = self.claim()
        real = budget._write_metadata
        calls = 0

        def fail_second(*arguments):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('public synthetic partial barrier crash')
            return real(*arguments)

        refs = view_refs(claim)
        with mock.patch.object(budget, '_write_metadata', side_effect=fail_second):
            with self.assertRaises(OSError):
                budget.mark_views_sealed(claim, refs)
        self.assertIsNone(claim._barrier)
        self.assertEqual(sum((self.registry / key / 'views-sealed.json').exists() for key in claim._keys), 1)
        with self.assertRaises(budget.BudgetRefusal):
            budget.claim_truth_once(claim, {'accepted': True}, 0)
        with self.assertRaises(FileExistsError):
            budget.mark_views_sealed(claim, view_refs(claim))

    def test_marker_or_claim_replacement_cannot_authorize_truth(self):
        claim = self.claim()
        barrier = budget.mark_views_sealed(claim, view_refs(claim))
        key = claim._keys[0]
        marker = self.registry / key / 'views-sealed.json'
        marker.chmod(0o600)
        with self.assertRaises(budget.BudgetRefusal):
            budget.claim_truth_once(claim, barrier, 0)
        marker.chmod(0o400)
        own = self.registry / key
        own.rename(own.with_name(key + '-public-backup'))
        own.mkdir(mode=0o700)
        with self.assertRaises(budget.BudgetRefusal):
            budget.claim_truth_once(claim, barrier, 0)

    def test_reservation_refs_are_write_time_metadata_only_and_bind_one_owner(self):
        claim = self.claim()
        real_open = os.open
        with mock.patch.object(budget.os, 'open', wraps=real_open) as opened:
            refs = budget.reservation_refs(claim)
        self.assertEqual([ref['owner_component'] for ref in refs], [0, 1, 2])
        self.assertTrue(all(call.args[1] & os.O_DIRECTORY for call in opened.call_args_list))
        for owner, ref in enumerate(refs):
            raw = Path(ref['path']).read_bytes()  # Public synthetic fixture only.
            record = json.loads(raw)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), ref['sha256'])
            self.assertEqual(record['owner_component'], owner)
            self.assertEqual(record['funding_spk_hex36'], claim._spec['owners'][owner]['funding_spk_hex36'])
            self.assertEqual(record['binding'], claim._spec['binding'])
            self.assertEqual(record['slot_grammar_sha256'], claim._spec['slot_grammar_sha256'])
            self.assertNotIn('actual_unlabelled_universe_sha256', record)

    def test_one_view_intake_per_exact_prediction_or_coverage_label(self):
        claim = self.claim()
        with self.assertRaises(budget.BudgetRefusal):
            budget.claim_view_intake_once(claim, 'arbitrary-missing-view')
        for label in sorted(budget.VIEW_KINDS):
            ref = budget.claim_view_intake_once(claim, label)
            value = json.loads(Path(ref['path']).read_bytes())
            self.assertEqual(value['operation'], 'observe-view')
            self.assertEqual(value['kind'], budget.VIEW_KINDS[label])
            self.assertIsNone(value['actual_unlabelled_universe_sha256'])
            self.assertIsNone(value['all_seals_sha256'])
            with self.assertRaises(FileExistsError):
                budget.claim_view_intake_once(claim, label)

    def test_future_actual_universe_is_only_bound_after_intake_and_capture(self):
        spec, facts = public_fixture()
        spec['actual_unlabelled_universe_sha256'] = 'a1' * 32
        with self.assertRaises(budget.BudgetRefusal):
            budget.reserve(spec, facts)
        claim = self.claim()
        refs = view_refs(claim)
        wrong = copy.deepcopy(refs)
        wrong[-1]['actual_unlabelled_universe_sha256'] = 'a2' * 32
        with self.assertRaises(budget.BudgetRefusal):
            budget.mark_views_sealed(claim, wrong)
        wrong = copy.deepcopy(refs)
        wrong[0]['kind'] = 'prediction'
        with self.assertRaises(budget.BudgetRefusal):
            budget.mark_views_sealed(claim, wrong)
        barrier = budget.mark_views_sealed(claim, refs)
        public = budget.barrier_ref(claim, barrier)
        body = json.loads(Path(public['path']).read_bytes())
        self.assertEqual(body['actual_unlabelled_universe_sha256'], 'a1' * 32)
        self.assertEqual(body['slot_grammar_sha256'], '44' * 32)
        self.assertEqual(len(body['completed_view_refs']), 3)

    def test_closed_aggregate_intake_is_one_shot_after_three_actual_scores(self):
        claim = self.claim()
        barrier = budget.mark_views_sealed(claim, view_refs(claim))
        with self.assertRaises(budget.BudgetRefusal):
            budget.claim_aggregate_once(claim, barrier, [])
        completions = []
        for owner in range(3):
            permit = budget.claim_truth_once(claim, barrier, owner)
            value = json.loads(Path(permit['path']).read_bytes())
            self.assertEqual(value['operation'], 'score-owner')
            self.assertEqual(value['owner_component'], owner)
            self.assertEqual(value['actual_unlabelled_universe_sha256'], 'a1' * 32)
            completions.append({'owner_component': owner, 'binding': dict(claim._spec['binding']),
                                'source_sha256': claim._spec['source_sha256'],
                                'slot_grammar_sha256': claim._spec['slot_grammar_sha256'],
                                'actual_unlabelled_universe_sha256': 'a1' * 32,
                                'completion': {'observed_launcher_pid': os.getpid(), 'returncode': 0,
                                               'completed_monotonic_ns': time.monotonic_ns(),
                                               'event_ref': {'path': '/public/score-' + str(owner) + '.json',
                                                             'sha256': 'be' * 32}}})
        invalid = copy.deepcopy(completions)
        invalid[0]['models'] = [1]
        with self.assertRaises(budget.BudgetRefusal):
            budget.claim_aggregate_once(claim, barrier, invalid)
        ref = budget.claim_aggregate_once(claim, barrier, completions)
        self.assertEqual(json.loads(Path(ref['path']).read_bytes())['operation'], 'aggregate')
        with self.assertRaises(FileExistsError):
            budget.claim_aggregate_once(claim, barrier, completions)


    def test_description_and_owner_ref_require_issued_claim_and_real_owner(self):
        claim = self.claim()
        for fake in ({'reserved': True}, {'accepted': True}, object(), None):
            with self.subTest(fake=type(fake).__name__):
                with self.assertRaises(budget.BudgetRefusal):
                    budget.describe_claim(fake)
                with self.assertRaises(budget.BudgetRefusal):
                    budget.owner_record_ref(fake, 0)
        for owner in (False, True, -1, 3, '0', None):
            with self.subTest(owner=owner), self.assertRaises(budget.BudgetRefusal):
                budget.owner_record_ref(claim, owner)
        for owner in range(3):
            self.assertEqual(budget.owner_record_ref(claim, owner), budget.reservation_refs(claim)[owner])

    def test_claim_description_is_detached_public_metadata_without_body_open(self):
        claim = self.claim()
        real_open = os.open
        with mock.patch.object(budget.os, 'open', wraps=real_open) as opened:
            description = budget.describe_claim(claim)
            own = budget.owner_record_ref(claim, 1)
        self.assertTrue(all(call.args[1] & os.O_DIRECTORY for call in opened.call_args_list))
        self.assertEqual(description['schema'], 'kpb-method03-issued-budget-description/v1')
        self.assertEqual(description['spec_sha256'], budget._digest(claim._spec))
        self.assertEqual(description['profile_id_hex32'], budget.PROFILE)
        self.assertEqual(description['domain_hex32'], budget.DOMAIN)
        self.assertEqual(description['slot_grammar_sha256'], '44' * 32)
        self.assertNotIn('actual_unlabelled_universe_sha256', description)
        self.assertNotIn('seed_hex32', json.dumps(description))
        description['binding']['selection_sha256'] = 'af' * 32
        description['owners'][0]['funding_spk_hex36'] = 'modified-public-fixture'
        description['owner_record_refs'][1]['metadata'][0] = -1
        own['metadata'][0] = -2
        fresh = budget.describe_claim(claim)
        self.assertEqual(fresh['binding'], claim._spec['binding'])
        self.assertEqual(fresh['owners'], claim._spec['owners'])
        self.assertEqual(fresh['owner_record_refs'][1], budget.owner_record_ref(claim, 1))


if __name__ == '__main__':
    unittest.main()
