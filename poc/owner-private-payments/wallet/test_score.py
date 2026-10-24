"""Synthetic diagnostic controls only; no actual owner/private/PK/proof access."""
from contextlib import ExitStack
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import paths
import run_score
import score_codec as codec
import score_worker
import test_boundary as boundary

SESSION = '11' * 32
PROJECTION = '22' * 32
STRATEGY = '33' * 32
PREDICTIONS = '44' * 32
OBSERVER = '55' * 32
BUNDLE = '66' * 32


def capsule():
    return codec.capsule(SESSION, PROJECTION, STRATEGY, bytes([7]) * 32,
                          0, [False, True, True, False, True, True], [0, 1, 1, 0, 2, 2])


class Encodings(unittest.TestCase):
    def test_fixed_width_salted_capsule_and_strict_context(self):
        raw = capsule(); self.assertEqual(len(raw), 176)
        self.assertEqual(codec.parse_capsule(raw, SESSION, PROJECTION, STRATEGY),
                         (0, [False, True, True, False, True, True], [0, 1, 1, 0, 2, 2]))
        changed = codec.capsule(SESSION, PROJECTION, STRATEGY, bytes([8]) * 32,
                                0, [False, True, True, False, True, True], [0, 1, 1, 0, 2, 2])
        self.assertNotEqual(paths.digest(raw), paths.digest(changed))
        for candidate in (raw[:-1], raw + b'\0', raw[:169] + b'\xff' + raw[170:],
                          raw[:136] + bytes(32) + raw[168:]):
            with self.assertRaises(ValueError):
                codec.parse_capsule(candidate, SESSION, PROJECTION, STRATEGY)
        with self.assertRaises(ValueError):
            codec.parse_capsule(raw, '99' * 32, PROJECTION, STRATEGY)

    def test_incoming_values_constrain_candidates_without_excluding_creator_targets(self):
        available = [180_000_000] * 3
        # Knowing two incoming values that sum to the honest creator total
        # removes inconsistent cross-pairs; neither row gets a known label.
        proposed, assignments, partitions = codec.infer((0, 3), {0: 80_000_000, 3: 100_000_000,
            1: 70_000_000, 2: 110_000_000, 4: 65_000_000, 5: 115_000_000}, {0: 0, 3: 0},
            available, 0, bytes([1]) * 32)
        self.assertEqual((assignments, partitions), (2, 1))
        self.assertEqual(proposed[1], proposed[2]); self.assertEqual(proposed[4], proposed[5])
        self.assertNotEqual(proposed[1], proposed[4])
        self.assertEqual([i for i, label in enumerate(proposed) if label == 0], [0, 3])
        raw = codec.capsule(SESSION, PROJECTION, STRATEGY, bytes([7]) * 32, 0,
                            [False, True, True, False, True, True], proposed)
        _, eligible, _ = codec.parse_capsule(raw, SESSION, PROJECTION, STRATEGY)
        self.assertTrue(eligible[1] and eligible[2] and eligible[4] and eligible[5])
        with self.assertRaisesRegex(ValueError, 'INCOMPLETE'):
            codec.infer((0, 3), {1: 60_000_000, 2: 60_000_000,
                4: 60_000_000, 5: 60_000_000}, {0: 0, 3: 0}, available, 0, bytes([1]) * 32)
        labelled, assignments, partitions = codec.infer((0, 3),
            {1: 70_000_000}, {0: 0, 3: 0, 1: 1}, available, 0, bytes([1]) * 32)
        self.assertEqual(labelled[1], 1)
        # Actual issuance knowledge excludes this creator fact; an amount-only
        # observation above did not exclude any additional creator target.
        issued_capsule = codec.capsule(SESSION, PROJECTION, STRATEGY, bytes([7]) * 32, 0,
            [False, False, True, False, True, True], labelled)
        self.assertEqual(sum(codec.parse_capsule(issued_capsule, SESSION, PROJECTION, STRATEGY)[1]), 3)

    def test_all_small_counts_bounded_and_only_global_totals_returned(self):
        records = [codec.counts(SESSION, PROJECTION, BUNDLE, 2, 2, 0, 0, 1, 0),
                   codec.counts(SESSION, PROJECTION, BUNDLE, 2, 1, 2, 2, 0, 1),
                   codec.counts(SESSION, PROJECTION, BUNDLE, 2, 0, 2, 1, 0, 0)]
        self.assertTrue(all(len(row) == 142 for row in records))
        result = codec.aggregate(records, SESSION, PROJECTION, BUNDLE)
        self.assertEqual(result['coordinator_only'], {'eligible_count': 6, 'matched_count': 3,
                                                     'label_invariant_groups_matched': 1})
        self.assertEqual(result['one_colluder'], {'eligible_count': 4, 'matched_count': 3,
                                                'excluded_known_creator_count': 2,
                                                'label_invariant_unknown_groups_matched': 1})
        self.assertNotIn('owner', result); self.assertNotIn('rows', result)
        for values in ((2, 3, 2, 0, 0, 0), (2, 0, 3, 0, 0, 0), (2, 0, 0, 1, 0, 0),
                       (True, 1, 2, 0, 0, 0), (2, 0, 0, 0, 0, 1)):
            with self.assertRaises(ValueError):
                codec.counts(SESSION, PROJECTION, BUNDLE, *values)
        with self.assertRaises(ValueError):
            codec.aggregate(records[:2], SESSION, PROJECTION, BUNDLE)
        with self.assertRaisesRegex(ValueError, 'one-colluder'):
            codec.aggregate([codec.counts(SESSION, PROJECTION, BUNDLE, 2, 1, 2, 1, 0, 0)] * 3,
                            SESSION, PROJECTION, BUNDLE)

    def test_prediction_and_capsule_no_subset_or_context_relabelling(self):
        value = {'schema': 'kpx7-public-creator-prediction/v1', 'experiment_sha256': codec.EXPERIMENT,
            'session_sha256': SESSION, 'projection_sha256': PROJECTION, 'strategy_sha256': STRATEGY,
            'guesses_creator_index': [0, 0, 1, 1, 2, 2]}
        codec.prediction(value, SESSION, PROJECTION)
        for mutate in (lambda v: v.update(experiment_sha256='00' * 32),
                       lambda v: v.update(guesses_creator_index=[True, 0, 1, 1, 2, 2]),
                       lambda v: v.update(guesses_creator_index=[0, 0, 0, 0, 1, 2]),
                       lambda v: v.update(owner_map=[])):
            candidate = copy.deepcopy(value); mutate(candidate)
            with self.assertRaises(ValueError):
                codec.prediction(candidate, SESSION, PROJECTION)
        with self.assertRaises(ValueError):
            codec.capsule(SESSION, PROJECTION, STRATEGY, bytes([7]) * 32, 0,
                [False, False, True, True, True, True], [0, 1, 1, 0, 2, 2])

    def test_label_swap_group_recovery_preserved_and_ambiguity_recorded_before_truth(self):
        proposed, assignments, partitions = codec.infer((0, 3),
            {0: 80_000_000, 3: 100_000_000, 1: 70_000_000, 2: 110_000_000,
             4: 65_000_000, 5: 115_000_000}, {0: 0, 3: 0}, [180_000_000] * 3, 0, bytes([2]) * 32)
        self.assertEqual(proposed, [0, 2, 2, 0, 1, 1])
        self.assertEqual((assignments, partitions), (2, 1))
        truth = [0, 1, 1, 0, 2, 2]
        records = []
        for owner in range(3):
            positions = [i for i, creator in enumerate(truth) if creator == owner]
            exact = sum(proposed[i] == owner for i in positions)
            grouped = int(len({proposed[i] for i in positions}) == 1)
            records.append(codec.counts(SESSION, PROJECTION, BUNDLE, 2, exact,
                0 if owner == 0 else 2, 0 if owner == 0 else exact,
                grouped, 0 if owner == 0 else grouped))
        result = codec.aggregate(records, SESSION, PROJECTION, BUNDLE)
        self.assertEqual(result['one_colluder']['matched_count'], 0)
        self.assertEqual(result['one_colluder']['label_invariant_unknown_groups_matched'], 2)
        _, unlabelled, ambiguous = codec.infer((0, 3), {0: 80_000_000, 3: 100_000_000},
            {0: 0, 3: 0}, [180_000_000] * 3, 0, bytes([2]) * 32)
        self.assertEqual((unlabelled, ambiguous), (6, 3))


class OneShot(boundary.Boundary):
    def test_new_diagnostics_parent_durable_before_reservation_file(self):
        original_fsync = score_worker.os.fsync
        original_write = score_worker.write_new
        events = []
        def fsync(fd):
            info = score_worker.os.fstat(fd)
            if info.st_ino == self.a.owner.stat().st_ino:
                events.append('owner-directory-durable')
            return original_fsync(fd)
        def reserve_write(path, raw, mode):
            self.assertIn('owner-directory-durable', events)
            events.append('reservation-write')
            return original_write(path, raw, mode)
        with patch.object(score_worker.os, 'fsync', side_effect=fsync), \
             patch.object(score_worker, 'write_new', side_effect=reserve_write):
            score_worker.reserve(self.a, 'SCORING-CLOSED', {'experiment_sha256': codec.EXPERIMENT})
        self.assertEqual(events, ['owner-directory-durable', 'reservation-write'])

    def test_different_original_authorization_rejects_before_truth(self):
        selected = self.a.owner / 'attempts' / '000001'
        session = {'roster': ['10' * 32, '20' * 32, '30' * 32]}
        nf, cv, root, effects = bytes([4]) * 32, bytes([5]) * 64, bytes([6]) * 32, bytes([7]) * 32
        body = SimpleNamespace(old_state=SimpleNamespace(cm_root=root),
                               spends=[SimpleNamespace(nf=nf, cv=cv)])
        auth = {'schema': 'kpx7-owner-spend-authorization/v1', 'session_sha256': SESSION,
            'effects_digest_hex32': bytes([8]).hex() * 32, 'nf_hex32': nf.hex(), 'cv_hex64': cv.hex(),
            'statement_hex200': (b'KPX7SP01' + score_worker.DOMAIN + root + nf + cv + effects).hex(),
            'proof_hex128': bytes([9]).hex() * 128}
        calls = []
        def own_public_record(path):
            calls.append(path.name)
            if path.name == 'SESSION.json':
                return {'session': session, 'session_sha256': SESSION}
            if path.name == 'AUTHORIZATION.json':
                return auth
            raise AssertionError('truth read before original effects matched')
        with patch.object(score_worker.financial, 'private_json', side_effect=own_public_record):
            with self.assertRaisesRegex(ValueError, 'original-authorized-financial-effects'):
                score_worker.own_truth(selected, session, SESSION, body, effects)
        self.assertEqual(calls, ['SESSION.json', 'AUTHORIZATION.json'])

    def test_one_reserved_bundle_before_truth_and_reject_all_repeats(self):
        selected = self.a.owner / 'attempts' / '000001'; selected.mkdir(parents=True)
        prediction = {'schema': 'kpx7-public-creator-prediction/v1', 'experiment_sha256': codec.EXPERIMENT,
            'session_sha256': SESSION, 'projection_sha256': PROJECTION, 'strategy_sha256': STRATEGY,
            'guesses_creator_index': [0, 1, 1, 0, 2, 2]}
        observer = {'schema': 'kpx7-colluder-observer-seal/v1', 'experiment_sha256': codec.EXPERIMENT,
            'session_sha256': SESSION, 'projection_sha256': PROJECTION, 'strategy_sha256': STRATEGY,
            'capsule_seal_sha256': paths.digest(capsule()), 'excluded_known_creator_count': 2,
            'unknown_creator_target_count': 4, 'candidate_creator_assignments': 6, 'candidate_partitions': 3,
            'hash_tie_break_used': True, 'unique_partition_from_constraints': False,
            'scope': 'SEALED_ONE_COLLUDER_STRATEGY_NOT_ANONYMITY_QUALIFICATION'}
        bundle = {'schema': 'kpx7-owner-privacy-prediction-bundle/v1', 'experiment_sha256': codec.EXPERIMENT,
            'session_sha256': SESSION, 'projection_sha256': PROJECTION,
            'coordinator_predictions_sha256': PREDICTIONS, 'colluder_observer_receipt_sha256': OBSERVER,
            'colluder_capsule_seal_sha256': paths.digest(capsule())}
        a = self.a
        a.projection_sha256 = PROJECTION; a.predictions = 'pred'; a.predictions_sha256 = PREDICTIONS
        a.observer_receipt = 'obs'; a.observer_receipt_sha256 = OBSERVER
        a.bundle = 'bundle'; a.bundle_sha256 = BUNDLE; a.capsule = 'capsule'
        def truth(*args):
            self.assertTrue((a.owner / 'diagnostics' / 'SCORING-CLOSED').is_file())
            return 1, (1, 2), {i: {'kind': 'change', 'recipient_id_hex32': '77' * 32} for i in (1, 2)}
        with ExitStack() as stack:
            stack.enter_context(patch.object(score_worker, 'selected_public', return_value=(
                {'roster': ['00' * 32, '11' * 32, '22' * 32]}, SESSION, object(), None, None, bytes(32))))
            stack.enter_context(patch.object(score_worker, 'completed_attempt', return_value=selected))
            stack.enter_context(patch.object(score_worker, 'strategy_digest', return_value=STRATEGY))
            stack.enter_context(patch.object(score_worker, 'public_json',
                side_effect=lambda path, pin: {'pred': prediction, 'obs': observer, 'bundle': bundle}[path]))
            read = stack.enter_context(patch.object(score_worker, 'stable_read', return_value=capsule()))
            own = stack.enter_context(patch.object(score_worker, 'own_truth', side_effect=truth))
            score_worker.score(a)
            self.assertEqual(own.call_count, 1)
            self.assertEqual((a.owner / 'diagnostics' / 'COUNTS.bin').stat().st_size, 142)
            for pin in (BUNDLE, 'ff' * 32):
                a.bundle_sha256 = pin; read.reset_mock(); own.reset_mock()
                with self.assertRaises(FileExistsError):
                    score_worker.score(a)
                read.assert_not_called(); own.assert_not_called()

    def test_closed_aggregate_mounts_only_three_count_leaves_and_never_owner_roots(self):
        leaves = []
        for index, parent in enumerate(self.new):
            folder = parent / 'owner' / 'diagnostics'; folder.mkdir(mode=0o700)
            leaf = folder / 'COUNTS.bin'
            paths.write_new(leaf, codec.counts(SESSION, PROJECTION, BUNDLE, 2, 1,
                0 if index == 0 else 2, 0 if index == 0 else 1, 0, 0), 0o400); leaves.append(leaf)
        a = SimpleNamespace(operation='aggregate', experiment_sha256=codec.EXPERIMENT,
            exclude_old_trial=self.old, exclude_new_private_directory=self.new, output=self.root / 'sum-stage',
            count_file=leaves, session_sha256=SESSION, projection_sha256=PROJECTION,
            bundle_sha256=BUNDLE, owner_directory=None, execute=False)
        for name in run_score.PUBLIC_NAMES:
            setattr(a, name, None)
        a.observer_receipt = self.root / 'observer-public.json'
        paths.write_new(a.observer_receipt, b'PUBLIC-ONLY-NO-EXECUTION')
        a.observer_receipt_sha256 = paths.digest(a.observer_receipt.read_bytes())
        a.bundle = self.root / 'bundle-public.json'; paths.write_new(a.bundle, b'PUBLIC-ONLY-NO-EXECUTION')
        a.bundle_sha256 = paths.digest(a.bundle.read_bytes())
        original = paths.stable_read
        def no_private_read(path, *args, **kwargs):
            self.assertNotIn(Path(path), leaves)
            return original(path, *args, **kwargs)
        with patch.object(paths, 'stable_read', side_effect=no_private_read):
            self.assertFalse(run_score.run(a)['executed'])
        command = paths.parse((a.output / 'PRIVATE-PLAN.json').read_bytes())['command']
        for parent in self.new:
            self.assertNotIn(str(parent), command)
            self.assertNotIn(str(parent / 'owner'), command)
            self.assertNotIn(str(parent / 'mpc'), command)
        self.assertFalse(any('/parameters/' in argument or '/runtime/' in argument for argument in command))
        self.assertIn('--unshare-all', command)
        self.assertEqual(sum(argument == '--ro-bind' for argument in command), 12)


for inherited in tuple(name for name in dir(boundary.Boundary) if name.startswith('test_')):
    setattr(OneShot, inherited, None)

if __name__ == '__main__':
    unittest.main(verbosity=2)
